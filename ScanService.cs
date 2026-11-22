using System.Diagnostics;
using System.Text.Json;

namespace GitleaksScanner;

/// <summary>
/// Εκτελεί ένα scan από την αρχή ως το τέλος: προετοιμασία πηγής (clone), gitleaks,
/// masking/κρυπτογράφηση των ευρημάτων και αποθήκευση.
/// </summary>
/// <param name="store">Η βάση.</param>
/// <param name="keys">Τα κλειδιά HMAC και κρυπτογράφησης.</param>
public sealed class ScanService(Store store, ScannerKeys keys)
{
    /// <summary>Μέγιστος χρόνος για clone και για gitleaks.</summary>
    static readonly TimeSpan ScanTimeout = TimeSpan.FromMinutes(10);

    static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>Από πού θα σκαναριστεί ο κώδικας.</summary>
    /// <param name="Source">Το κανονικοποιημένο όνομα της πηγής (URL ή απόλυτο path), για το ιστορικό.</param>
    /// <param name="ScanPath">Ο φάκελος που θα σκανάρει το gitleaks.</param>
    /// <param name="IsGitRepo">Αν ο φάκελος είναι git repository.</param>
    /// <param name="IsLocal">Αν είναι τοπικός φάκελος (και όχι clone).</param>
    /// <param name="WebBaseUrl">Βάση για links προς τα αρχεία στο web, αν υπάρχει.</param>
    sealed record SourceInfo(string Source, string ScanPath, bool IsGitRepo, bool IsLocal, string? WebBaseUrl);

    /// <summary>
    /// Εκτελεί ένα scan και επιστρέφει την προβολή του, όπως τη βλέπει το UI.
    /// Ο προσωρινός φάκελος (clone και report με raw secrets) σβήνεται πάντα στο τέλος.
    /// </summary>
    /// <param name="req">Το αίτημα του χρήστη.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η προβολή του scan, ή σφάλμα 400/500.</returns>
    public async Task<IResult> RunAsync(ScanRequest req, CancellationToken ct)
    {
        var input = req.Source?.Trim() ?? "";
        if (input.Length == 0)
            return Results.BadRequest(new { error = "Δώσε URL repository ή τοπικό φάκελο." });
        var maskMode = req.Mask == "full" ? "full" : "partial";

        var workDir = Path.Combine(Path.GetTempPath(), "gitleaks-scan-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workDir);
        var startedAt = DateTime.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var (source, error) = await PrepareSourceAsync(req, input, workDir, ct);
            if (source is null) return error!;

            var mode = source.IsGitRepo && req.Mode != "dir" ? "git" : "dir";
            var (raw, glError) = await RunGitleaksAsync(source.ScanPath, mode, Path.Combine(workDir, "report.json"), ct);
            if (raw is null) return glError!;

            var findings = await ToStoredFindingsAsync(raw, source, mode, maskMode);
            raw.Clear();

            // Ένα τοπικό repo σκανάρεται πάντα με όλο το ιστορικό (δεν γίνεται shallow clone).
            var fullHistory = mode == "git" && (source.IsLocal || req.FullHistory);
            var scanId = store.SaveScan(source.Source, mode, fullHistory, maskMode, startedAt,
                stopwatch.ElapsedMilliseconds, findings);
            return Results.Ok(ScanView.Build(store, scanId));
        }
        catch (TimeoutException)
        {
            return Results.Problem("Το scan ξεπέρασε το χρονικό όριο.");
        }
        finally
        {
            try { Directory.Delete(workDir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Ετοιμάζει την πηγή του scan: έναν υπάρχοντα τοπικό φάκελο, ή clone ενός https repository.
    /// </summary>
    /// <remarks>
    /// Επιτρέπεται μόνο https (όχι <c>file://</c>, <c>ext::</c> κ.λπ.). Από ξένα repos σβήνεται το
    /// <c>.gitleaks.toml</c>, γιατί θα μπορούσε να απενεργοποιεί κανόνες και να κρύβει secrets.
    /// </remarks>
    /// <param name="req">Το αίτημα.</param>
    /// <param name="input">Το URL ή ο φάκελος, χωρίς κενά.</param>
    /// <param name="workDir">Ο προσωρινός φάκελος για το clone.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η πηγή, ή <c>null</c> μαζί με το σφάλμα που πρέπει να επιστραφεί.</returns>
    static async Task<(SourceInfo? Source, IResult? Error)> PrepareSourceAsync(
        ScanRequest req, string input, string workDir, CancellationToken ct)
    {
        if (Directory.Exists(input))
        {
            var path = Path.GetFullPath(input).TrimEnd(Path.DirectorySeparatorChar);
            return (new SourceInfo(path, path, Directory.Exists(Path.Combine(path, ".git")), IsLocal: true, null), null);
        }

        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            return (null, Results.BadRequest(new { error = "Το input πρέπει να είναι https:// URL ή υπάρχων τοπικός φάκελος." }));

        var scanPath = Path.Combine(workDir, "repo");
        var cloneArgs = new List<string>
        {
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "clone", "--quiet", "--no-tags"
        };
        if (!req.FullHistory) cloneArgs.AddRange(["--depth", "1"]);
        cloneArgs.AddRange(["--", input, scanPath]);

        var clone = await ProcessRunner.RunAsync("git", cloneArgs, null, ScanTimeout, ct,
            env: new() { ["GIT_TERMINAL_PROMPT"] = "0" });
        if (clone.ExitCode != 0)
        {
            var hint = RepoUrl.IsGitHubProfile(uri) ? " (Αυτό είναι προφίλ χρήστη, όχι repository.)" : "";
            return (null, Results.BadRequest(new { error = "Το clone απέτυχε: " + clone.StdErr.Trim() + hint }));
        }

        var repoConfig = Path.Combine(scanPath, ".gitleaks.toml");
        if (!req.UseRepoConfig && File.Exists(repoConfig)) File.Delete(repoConfig);

        return (new SourceInfo(RepoUrl.Normalize(uri), scanPath, IsGitRepo: true, IsLocal: false, RepoUrl.WebBase(uri)), null);
    }

    /// <summary>
    /// Τρέχει το gitleaks σε έναν φάκελο και διαβάζει το JSON report του.
    /// </summary>
    /// <remarks>
    /// Τρέχει χωρίς <c>--redact</c>, γιατί το raw secret χρειάζεται για το masking, το κλειδί και
    /// την κρυπτογράφηση. Υπάρχει μόνο στο report του προσωρινού φακέλου, που σβήνεται στο τέλος.
    /// </remarks>
    /// <param name="scanPath">Ο φάκελος.</param>
    /// <param name="mode">"git" ή "dir".</param>
    /// <param name="reportPath">Πού θα γράψει το gitleaks το report.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα ευρήματα, ή <c>null</c> μαζί με το σφάλμα.</returns>
    static async Task<(List<GitleaksFinding>? Findings, IResult? Error)> RunGitleaksAsync(
        string scanPath, string mode, string reportPath, CancellationToken ct)
    {
        var args = new List<string>
        {
            mode, scanPath,
            "--report-format", "json",
            "--report-path", reportPath,
            "--no-banner",
            "--exit-code", "0",
            "--log-level", "error"
        };
        var scan = await ProcessRunner.RunAsync("gitleaks", args, null, ScanTimeout, ct);
        if (scan.ExitCode != 0)
            return (null, Results.Problem("Το gitleaks απέτυχε: " + (scan.StdErr + scan.StdOut).Trim()));

        var findings = File.Exists(reportPath)
            ? JsonSerializer.Deserialize<List<GitleaksFinding>>(await File.ReadAllTextAsync(reportPath, ct), JsonOptions) ?? []
            : [];
        return (findings, null);
    }

    /// <summary>
    /// Μετατρέπει τα ευρήματα του gitleaks στη μορφή που αποθηκεύεται: σχετικά paths, σταθερό
    /// κλειδί (HMAC), masked εκδοχές για τη λίστα, και κρυπτογραφημένα secret/match/κώδικας για το unmask.
    /// </summary>
    /// <param name="raw">Τα ευρήματα του gitleaks (με raw secrets).</param>
    /// <param name="source">Η πηγή του scan.</param>
    /// <param name="mode">"git" ή "dir".</param>
    /// <param name="maskMode">"partial" ή "full".</param>
    /// <returns>Τα ευρήματα, χωρίς κανένα raw secret σε μη κρυπτογραφημένη μορφή.</returns>
    async Task<List<StoredFinding>> ToStoredFindingsAsync(List<GitleaksFinding> raw, SourceInfo source, string mode, string maskMode)
    {
        var ctxReader = new CodeContext(source.ScanPath, mode);
        var findings = new List<StoredFinding>(raw.Count);
        foreach (var f in raw)
        {
            var file = ctxReader.Relative(f.File);
            var snippet = await ctxReader.GetAsync(file, f.Commit, f.StartLine, f.EndLine);
            findings.Add(new StoredFinding
            {
                Key = Secrets.Key(keys.Hmac, f.RuleID, file, f.Secret),
                RuleId = f.RuleID,
                Description = f.Description,
                File = file,
                StartLine = f.StartLine,
                EndLine = f.EndLine,
                Commit = f.Commit,
                Author = f.Author,
                Email = f.Email,
                Date = f.Date,
                Message = f.Message,
                Entropy = f.Entropy,
                SecretMasked = Secrets.Mask(f.Secret, maskMode),
                MatchMasked = Secrets.MaskMatch(f.Match, f.Secret, maskMode),
                SecretEnc = Secrets.Encrypt(keys.Encryption, f.Secret),
                MatchEnc = Secrets.Encrypt(keys.Encryption, f.Match),
                ContextEnc = snippet is null ? null : Secrets.Encrypt(keys.Encryption, CodeContext.Serialize(snippet)),
                Link = source.WebBaseUrl is not null && !string.IsNullOrEmpty(f.Commit)
                    ? $"{source.WebBaseUrl}/blob/{f.Commit}/{file}" + (f.StartLine > 0 ? $"#L{f.StartLine}" : "")
                    : null
            });
        }
        return findings;
    }
}
