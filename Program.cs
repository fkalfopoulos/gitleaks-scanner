using System.Diagnostics;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Ακούμε ΜΟΝΟ στο localhost: το app τρέχει εντολές στο μηχάνημά σου,
// δεν πρέπει να είναι προσβάσιμο από το δίκτυο.
builder.WebHost.UseUrls("http://localhost:5080");

var dataDir = Path.Combine(builder.Environment.ContentRootPath, "data");
Directory.CreateDirectory(dataDir);
var store = new Store(Path.Combine(dataDir, "scanner.db"));
store.Init();
var hmacKey = Secrets.LoadOrCreateKey(Path.Combine(dataDir, "hmac.key"));
var encKey = Secrets.LoadOrCreateKey(Path.Combine(dataDir, "enc.key"));

// Δεχόμαστε αιτήματα μόνο με Host "localhost": μια κακόβουλη ιστοσελίδα μπορεί με DNS rebinding
// να κάνει το domain της να δείχνει στο 127.0.0.1 και να διαβάσει το API (π.χ. το unmask).
builder.Configuration["AllowedHosts"] = "localhost";

builder.Services.AddHttpClient("github", c =>
{
    c.BaseAddress = new Uri("https://api.github.com/");
    c.DefaultRequestHeaders.UserAgent.ParseAdd("gitleaks-scanner/1.0");
    c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
    c.Timeout = TimeSpan.FromSeconds(30);
});

var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();

var jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
var scanTimeout = TimeSpan.FromMinutes(10);

app.MapGet("/api/health", async () =>
{
    var gl = await ProcessRunner.RunAsync("gitleaks", ["version"], null, TimeSpan.FromSeconds(10));
    var git = await ProcessRunner.RunAsync("git", ["--version"], null, TimeSpan.FromSeconds(10));
    return Results.Ok(new
    {
        gitleaks = gl.ExitCode == 0 ? gl.StdOut.Trim() : null,
        git = git.ExitCode == 0 ? git.StdOut.Trim() : null
    });
});

// ---------- Scan ----------

app.MapPost("/api/scan", async (ScanRequest req, CancellationToken ct) =>
{
    var input = req.Source?.Trim() ?? "";
    if (input.Length == 0)
        return Results.BadRequest(new { error = "Δώσε URL repository ή τοπικό φάκελο." });
    var maskMode = req.Mask == "full" ? "full" : "partial";

    var workDir = Path.Combine(Path.GetTempPath(), "gitleaks-scan-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(workDir);
    var reportPath = Path.Combine(workDir, "report.json");
    var startedAt = DateTime.UtcNow;
    var stopwatch = Stopwatch.StartNew();

    try
    {
        string source, scanPath;
        bool isGitRepo;
        var isLocal = Directory.Exists(input);
        string? webBaseUrl = null;

        if (isLocal)
        {
            // Τοπικός φάκελος
            scanPath = Path.GetFullPath(input).TrimEnd(Path.DirectorySeparatorChar);
            source = scanPath;
            isGitRepo = Directory.Exists(Path.Combine(scanPath, ".git"));
        }
        else if (Uri.TryCreate(input, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps)
        {
            // Απομακρυσμένο repo: μόνο https, για να μην επιτρέπονται file://, ext:: κ.λπ.
            source = NormalizeUrl(uri);
            scanPath = Path.Combine(workDir, "repo");
            var cloneArgs = new List<string>
            {
                "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                "clone", "--quiet", "--no-tags"
            };
            if (!req.FullHistory) cloneArgs.AddRange(["--depth", "1"]);
            cloneArgs.AddRange(["--", input, scanPath]);

            var clone = await ProcessRunner.RunAsync("git", cloneArgs, null, scanTimeout, ct,
                env: new() { ["GIT_TERMINAL_PROMPT"] = "0" });
            if (clone.ExitCode != 0)
            {
                var hint = uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
                           && uri.AbsolutePath.Trim('/').Split('/').Length == 1
                    ? " (Αυτό είναι προφίλ χρήστη, όχι repository.)" : "";
                return Results.BadRequest(new { error = "Το clone απέτυχε: " + clone.StdErr.Trim() + hint });
            }

            isGitRepo = true;
            webBaseUrl = GuessWebUrl(uri);

            // Ένα ξένο repo μπορεί να έχει δικό του .gitleaks.toml που απενεργοποιεί κανόνες
            // και κρύβει secrets. Το αγνοούμε, εκτός αν ο χρήστης το ζητήσει ρητά.
            var repoConfig = Path.Combine(scanPath, ".gitleaks.toml");
            if (!req.UseRepoConfig && File.Exists(repoConfig)) File.Delete(repoConfig);
        }
        else
        {
            return Results.BadRequest(new { error = "Το input πρέπει να είναι https:// URL ή υπάρχων τοπικός φάκελος." });
        }

        var mode = isGitRepo && req.Mode != "dir" ? "git" : "dir";
        // Χωρίς --redact: χρειαζόμαστε το raw secret για το masking και το κλειδί.
        // Υπάρχει μόνο στο report.json του temp φακέλου, που σβήνεται στο finally.
        var glArgs = new List<string>
        {
            mode, scanPath,
            "--report-format", "json",
            "--report-path", reportPath,
            "--no-banner",
            "--exit-code", "0",
            "--log-level", "error"
        };

        var scan = await ProcessRunner.RunAsync("gitleaks", glArgs, null, scanTimeout, ct);
        if (scan.ExitCode != 0)
            return Results.Problem("Το gitleaks απέτυχε: " + (scan.StdErr + scan.StdOut).Trim());

        var raw = File.Exists(reportPath)
            ? JsonSerializer.Deserialize<List<GitleaksFinding>>(await File.ReadAllTextAsync(reportPath, ct), jsonOptions) ?? []
            : [];

        var ctxReader = new CodeContext(scanPath, mode);
        var findings = new List<StoredFinding>(raw.Count);
        foreach (var f in raw)
        {
            var file = ctxReader.Relative(f.File);
            var snippet = await ctxReader.GetAsync(file, f.Commit, f.StartLine, f.EndLine);
            findings.Add(new StoredFinding
            {
                Key = Secrets.Key(hmacKey, f.RuleID, file, f.Secret),
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
                SecretEnc = Secrets.Encrypt(encKey, f.Secret),
                MatchEnc = Secrets.Encrypt(encKey, f.Match),
                ContextEnc = snippet is null ? null : Secrets.Encrypt(encKey, CodeContext.Serialize(snippet)),
                Link = webBaseUrl is not null && !string.IsNullOrEmpty(f.Commit)
                ? $"{webBaseUrl}/blob/{f.Commit}/{file}" + (f.StartLine > 0 ? $"#L{f.StartLine}" : "")
                : null
            });
        }
        raw.Clear();

        // Ένα τοπικό repo σκανάρεται πάντα με όλο το ιστορικό (δεν γίνεται shallow clone).
        var fullHistory = mode == "git" && (isLocal || req.FullHistory);
        var scanId = store.SaveScan(source, mode, fullHistory,
            maskMode, startedAt, stopwatch.ElapsedMilliseconds, findings);
        return Results.Ok(BuildScanView(store, scanId));
    }
    catch (TimeoutException)
    {
        return Results.Problem("Το scan ξεπέρασε το χρονικό όριο.");
    }
    finally
    {
        // Σβήνουμε το clone και το report (περιέχουν raw secrets)
        try { Directory.Delete(workDir, recursive: true); } catch { /* best effort */ }
    }
});

// ---------- GitHub χρήστης / οργανισμός ----------

// Επιστρέφει τα δημόσια repos ενός χρήστη ή οργανισμού στο GitHub.
// Χωρίς token το GitHub επιτρέπει 60 αιτήματα την ώρα (1 αίτημα = έως 100 repos).
app.MapGet("/api/github/{owner}/repos", async (string owner, IHttpClientFactory http, CancellationToken ct) =>
{
    if (!System.Text.RegularExpressions.Regex.IsMatch(owner, "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$"))
        return Results.BadRequest(new { error = "Άκυρο όνομα χρήστη GitHub." });

    var client = http.CreateClient("github");
    var repos = new List<GitHubRepo>();
    for (var page = 1; page <= 10; page++)
    {
        using var res = await client.GetAsync($"users/{owner}/repos?per_page=100&type=owner&sort=pushed&page={page}", ct);
        if (res.StatusCode == System.Net.HttpStatusCode.NotFound)
            return Results.NotFound(new { error = $"Ο χρήστης '{owner}' δεν βρέθηκε στο GitHub." });
        if (res.StatusCode is System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.TooManyRequests)
            return Results.Problem("Το GitHub API έφτασε το όριο αιτημάτων (60/ώρα χωρίς token). Δοκίμασε σε λίγο.");
        res.EnsureSuccessStatusCode();
        var batch = await res.Content.ReadFromJsonAsync<List<GitHubRepo>>(ct) ?? [];
        repos.AddRange(batch);
        if (batch.Count < 100) break;
    }
    return Results.Ok(repos.Select(r => new
    {
        r.Name,
        url = r.Html_Url,
        r.Description,
        r.Fork,
        r.Archived,
        sizeKb = r.Size,
        pushedAt = r.Pushed_At,
        r.Language
    }));
});

// ---------- Ιστορικό ----------

app.MapGet("/api/scans", () => Results.Ok(store.ListScans()));

app.MapGet("/api/scans/{id:long}", (long id) =>
    BuildScanView(store, id) is { } view ? Results.Ok(view) : Results.NotFound());

app.MapDelete("/api/scans/{id:long}", (long id) =>
    store.DeleteScan(id) ? Results.NoContent() : Results.NotFound());

// ---------- Unmask ----------

// Αποκρυπτογραφεί ΕΝΑ εύρημα, μόνο όταν ζητηθεί ρητά. Δεν γίνεται cache στον browser.
app.MapGet("/api/findings/{id:long}/reveal", (long id, HttpContext ctx) =>
{
    var enc = store.GetEncrypted(id);
    if (enc is null) return Results.NotFound();
    if (enc.Value.Match is null)
        return Results.BadRequest(new { error = "Αυτό το scan έγινε πριν προστεθεί το unmask. Κάνε rescan." });
    ctx.Response.Headers.CacheControl = "no-store";
    try
    {
        return Results.Ok(new
        {
            secret = Secrets.Decrypt(encKey, enc.Value.Secret),
            match = Secrets.Decrypt(encKey, enc.Value.Match),
            context = CodeContext.Deserialize(Secrets.Decrypt(encKey, enc.Value.Context))
        });
    }
    catch (System.Security.Cryptography.CryptographicException)
    {
        return Results.Problem("Η αποκρυπτογράφηση απέτυχε (άλλαξε το data/enc.key;).");
    }
});

// ---------- Triage ----------

app.MapPut("/api/triage", (TriageRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Source) || string.IsNullOrWhiteSpace(req.Key))
        return Results.BadRequest(new { error = "Λείπει source ή key." });
    if (!Store.TriageStatuses.Contains(req.Status))
        return Results.BadRequest(new { error = "Άκυρο status." });
    var note = (req.Note ?? "").Trim();
    if (note.Length > 2000) note = note[..2000];
    store.SetTriage(req.Source, req.Key, req.Status!, note);
    return Results.NoContent();
});

app.Run();

// ---------- Helpers ----------

/// Συνδυάζει ευρήματα, triage και σύγκριση με το προηγούμενο scan.
static object? BuildScanView(Store store, long scanId)
{
    var scan = store.GetScan(scanId);
    if (scan is null) return null;

    var findings = store.GetFindings(scanId);
    var triage = store.GetTriage(scan.Source);
    var prevId = store.PreviousScanId(scan);

    HashSet<string>? prevKeys = null;
    List<StoredFinding> fixedList = [];
    if (prevId is long p)
    {
        var prev = store.GetFindings(p);
        prevKeys = prev.Select(f => f.Key).ToHashSet();
        var currentKeys = findings.Select(f => f.Key).ToHashSet();
        // Ένα ανά κλειδί: στο full history το ίδιο secret εμφανίζεται σε πολλά commits.
        fixedList = prev.Where(f => !currentKeys.Contains(f.Key)).DistinctBy(f => f.Key).ToList();
    }

    object View(StoredFinding f, string? diff)
    {
        var t = triage.TryGetValue(f.Key, out var tr) ? tr : ("pending", "");
        return new
        {
            f.Id,
            f.CanUnmask,
            f.Key,
            f.RuleId,
            f.Description,
            f.File,
            f.StartLine,
            f.EndLine,
            f.Commit,
            f.Author,
            f.Email,
            f.Date,
            f.Message,
            f.Entropy,
            f.SecretMasked,
            f.MatchMasked,
            f.Link,
            diff,
            triage = new { status = t.Item1, note = t.Item2 }
        };
    }

    var items = findings
        .Select(f => View(f, prevKeys is null ? null : prevKeys.Contains(f.Key) ? "existing" : "new"))
        .ToList();
    var newCount = prevKeys is null ? 0 : findings.Where(f => !prevKeys.Contains(f.Key)).Select(f => f.Key).Distinct().Count();

    return new
    {
        scan,
        previousScanId = prevId,
        stats = new
        {
            total = findings.Count,
            unique = findings.Select(f => f.Key).Distinct().Count(),
            @new = newCount,
            @fixed = fixedList.Count
        },
        findings = items,
        @fixed = fixedList.Select(f => View(f, "fixed")).ToList()
    };
}

/// Ίδιο repo = ίδιο source, ανεξάρτητα από κεφαλαία στο host, "/" στο τέλος ή ".git".
static string NormalizeUrl(Uri uri)
{
    var path = uri.AbsolutePath.TrimEnd('/');
    if (path.EndsWith(".git", StringComparison.OrdinalIgnoreCase)) path = path[..^4];
    return $"https://{uri.Host.ToLowerInvariant()}{path}";
}

static string? GuessWebUrl(Uri uri)
{
    // Για GitHub/GitLab/Bitbucket φτιάχνουμε link προς το αρχείο στο commit
    var host = uri.Host.ToLowerInvariant();
    return host is "github.com" or "gitlab.com" or "bitbucket.org" ? NormalizeUrl(uri) : null;
}

record ScanRequest(string? Source, bool FullHistory = true, string? Mask = "partial", string? Mode = null,
    bool UseRepoConfig = false);

record GitHubRepo(string Name, string Html_Url, string? Description, bool Fork, bool Archived,
    long Size, string? Pushed_At, string? Language);

record TriageRequest(string? Source, string? Key, string? Status, string? Note);

/// Το JSON του gitleaks. Περιέχει το raw secret, οπότε δεν επιστρέφεται ποτέ στον client.
class GitleaksFinding
{
    public string? RuleID { get; set; }
    public string? Description { get; set; }
    public string? File { get; set; }
    public int StartLine { get; set; }
    public int EndLine { get; set; }
    public string? Match { get; set; }
    public string? Secret { get; set; }
    public string? Commit { get; set; }
    public string? Author { get; set; }
    public string? Email { get; set; }
    public string? Date { get; set; }
    public string? Message { get; set; }
    public double Entropy { get; set; }
}

static class ProcessRunner
{
    public record Result(int ExitCode, string StdOut, string StdErr);

    // Χρησιμοποιούμε ArgumentList (όχι ένα string) ώστε να μην υπάρχει shell injection.
    public static async Task<Result> RunAsync(string file, IEnumerable<string> args, string? cwd,
        TimeSpan timeout, CancellationToken ct = default, Dictionary<string, string>? env = null)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = cwd ?? Environment.CurrentDirectory
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (env is not null) foreach (var (k, v) in env) psi.Environment[k] = v;

        using var proc = new Process { StartInfo = psi };
        try { proc.Start(); }
        catch (System.ComponentModel.Win32Exception)
        {
            return new Result(-1, "", $"Δεν βρέθηκε το '{file}'. Είναι εγκατεστημένο;");
        }

        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            if (ct.IsCancellationRequested) throw;
            throw new TimeoutException();
        }
        return new Result(proc.ExitCode, await stdout, await stderr);
    }
}
