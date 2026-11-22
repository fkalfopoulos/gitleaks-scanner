using System.Diagnostics;
using GitleaksScanner.Application.Abstractions;
using GitleaksScanner.Application.Common;
using GitleaksScanner.Application.Contracts;
using GitleaksScanner.Domain;
using Microsoft.Extensions.Logging;

namespace GitleaksScanner.Application.Services;

/// <summary>
/// Η use case "νέο scan": προετοιμασία πηγής, gitleaks, masking/κρυπτογράφηση και αποθήκευση.
/// </summary>
/// <param name="sources">Προετοιμάζει τον φάκελο (clone).</param>
/// <param name="gitleaks">Εκτελεί το gitleaks.</param>
/// <param name="protector">Κλειδιά και κρυπτογράφηση.</param>
/// <param name="repository">Η αποθήκευση.</param>
/// <param name="queries">Φτιάχνει την προβολή του scan που επιστρέφεται.</param>
/// <param name="logger">Ο logger.</param>
public sealed class ScanService(
    ISourceProvider sources,
    IGitleaksRunner gitleaks,
    ISecretProtector protector,
    IScanRepository repository,
    ScanQueryService queries,
    ILogger<ScanService> logger)
{
    /// <summary>
    /// Εκτελεί ένα scan και επιστρέφει την προβολή του. Ο προσωρινός φάκελος (clone και report
    /// με raw secrets) σβήνεται πάντα στο τέλος, ακόμα και αν κάτι αποτύχει.
    /// </summary>
    /// <param name="req">Το αίτημα του χρήστη.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η προβολή του scan, ή σφάλμα.</returns>
    public async Task<Result<ScanViewDto>> RunAsync(ScanRequest req, CancellationToken ct)
    {
        var input = req.Source?.Trim() ?? "";
        if (input.Length == 0)
            return Result<ScanViewDto>.Fail(ErrorKind.Validation, "Δώσε URL repository ή τοπικό φάκελο.");
        var maskMode = SecretMasking.Normalize(req.Mask);
        var startedAt = DateTime.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        var prepared = await sources.PrepareAsync(input, req.FullHistory, req.UseRepoConfig, ct);
        if (!prepared.IsSuccess)
        {
            logger.LogWarning("Αποτυχία προετοιμασίας πηγής {Input}: {Error}", input, prepared.Error!.Message);
            return Result<ScanViewDto>.Fail(prepared.Error!);
        }

        await using var workspace = prepared.Value!;
        var mode = workspace.IsGitRepo && req.Mode != "dir" ? "git" : "dir";
        logger.LogInformation("Έναρξη scan {Source} (mode {Mode}, full history {FullHistory})",
            workspace.Source, mode, req.FullHistory);

        var scan = await gitleaks.ScanAsync(workspace, mode, ct);
        if (!scan.IsSuccess)
        {
            logger.LogError("Το gitleaks απέτυχε για {Source}: {Error}", workspace.Source, scan.Error!.Message);
            return Result<ScanViewDto>.Fail(scan.Error!);
        }

        var findings = await ProtectAsync(scan.Value!, workspace, mode, maskMode);

        // Ένα τοπικό repo σκανάρεται πάντα με όλο το ιστορικό (δεν γίνεται shallow clone).
        var fullHistory = mode == "git" && (workspace.IsLocal || req.FullHistory);
        var scanId = repository.SaveScan(workspace.Source, mode, fullHistory, maskMode, startedAt,
            stopwatch.ElapsedMilliseconds, findings);

        logger.LogInformation("Ολοκληρώθηκε το scan #{ScanId} για {Source}: {Count} ευρήματα σε {Ms} ms",
            scanId, workspace.Source, findings.Count, stopwatch.ElapsedMilliseconds);
        return queries.Get(scanId);
    }

    /// <summary>
    /// Μετατρέπει τα ευρήματα του gitleaks στη μορφή που αποθηκεύεται: σχετικά paths, σταθερό
    /// κλειδί (HMAC), masked εκδοχές για τη λίστα, και κρυπτογραφημένα secret/match/κώδικας για το unmask.
    /// </summary>
    /// <param name="raw">Τα ευρήματα του gitleaks (με raw secrets).</param>
    /// <param name="workspace">Ο φάκελος του scan, για ανάγνωση του κώδικα.</param>
    /// <param name="mode">"git" ή "dir".</param>
    /// <param name="maskMode">"partial" ή "full".</param>
    /// <returns>Τα ευρήματα, χωρίς κανένα raw secret σε μη κρυπτογραφημένη μορφή.</returns>
    async Task<List<StoredFinding>> ProtectAsync(List<RawFinding> raw, ISourceWorkspace workspace, string mode, string maskMode)
    {
        var findings = new List<StoredFinding>(raw.Count);
        foreach (var f in raw)
        {
            var file = workspace.RelativePath(f.File);
            var snippet = await workspace.ReadSnippetAsync(file, f.Commit, f.StartLine, f.EndLine, gitMode: mode == "git");
            findings.Add(new StoredFinding
            {
                Key = protector.ComputeKey(f.RuleID, file, f.Secret),
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
                SecretMasked = SecretMasking.Mask(f.Secret, maskMode),
                MatchMasked = SecretMasking.MaskMatch(f.Match, f.Secret, maskMode),
                SecretEnc = protector.Encrypt(f.Secret),
                MatchEnc = protector.Encrypt(f.Match),
                ContextEnc = snippet is null ? null : protector.Encrypt(System.Text.Json.JsonSerializer.Serialize(snippet)),
                Link = workspace.WebBaseUrl is not null && !string.IsNullOrEmpty(f.Commit)
                    ? $"{workspace.WebBaseUrl}/blob/{f.Commit}/{file}" + (f.StartLine > 0 ? $"#L{f.StartLine}" : "")
                    : null
            });
        }
        return findings;
    }
}
