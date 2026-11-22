using GitleaksScanner.Application.Abstractions;
using GitleaksScanner.Application.Common;
using GitleaksScanner.Application.Contracts;
using GitleaksScanner.Domain;
using Microsoft.Extensions.Logging;

namespace GitleaksScanner.Application.Services;

/// <summary>
/// Use cases ανάγνωσης: ιστορικό, προβολή scan (με triage και σύγκριση), διαγραφή.
/// </summary>
/// <param name="repository">Η αποθήκευση.</param>
/// <param name="logger">Ο logger.</param>
public sealed class ScanQueryService(IScanRepository repository, ILogger<ScanQueryService> logger)
{
    /// <summary>Επιστρέφει το ιστορικό των scans.</summary>
    /// <returns>Τα scans, από το νεότερο.</returns>
    public List<ScanInfo> List() => repository.ListScans();

    /// <summary>
    /// Συνδυάζει τα ευρήματα ενός scan με το triage του repo και τα συγκρίνει με το προηγούμενο
    /// scan που είχε τις ίδιες ρυθμίσεις.
    /// </summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <returns>Η προβολή, ή NotFound.</returns>
    public Result<ScanViewDto> Get(long scanId)
    {
        var scan = repository.GetScan(scanId);
        if (scan is null) return Result<ScanViewDto>.Fail(ErrorKind.NotFound, $"Το scan #{scanId} δεν υπάρχει.");

        var findings = repository.GetFindings(scanId);
        var triage = repository.GetTriage(scan.Source);
        var prevId = repository.PreviousScanId(scan);

        HashSet<string>? prevKeys = null;
        List<StoredFinding> fixedList = [];
        if (prevId is long p) (prevKeys, fixedList) = ScanComparison.Diff(repository.GetFindings(p), findings);

        var items = findings
            .Select(f => View(f, triage, prevKeys is null ? null : prevKeys.Contains(f.Key) ? "existing" : "new"))
            .ToList();
        var newCount = prevKeys is null ? 0 : findings.Where(f => !prevKeys.Contains(f.Key)).Select(f => f.Key).Distinct().Count();
        var stats = new ScanStats(findings.Count, findings.Select(f => f.Key).Distinct().Count(), newCount, fixedList.Count);

        return Result<ScanViewDto>.Ok(new ScanViewDto(scan, prevId, stats, items,
            fixedList.Select(f => View(f, triage, "fixed")).ToList()));
    }

    /// <summary>Διαγράφει ένα scan. Το triage κρατιέται, γιατί ανήκει στο repo.</summary>
    /// <param name="scanId">Το id.</param>
    /// <returns><c>true</c> αν διαγράφηκε, ή NotFound.</returns>
    public Result<bool> Delete(long scanId)
    {
        if (!repository.DeleteScan(scanId)) return Result<bool>.Fail(ErrorKind.NotFound, $"Το scan #{scanId} δεν υπάρχει.");
        logger.LogInformation("Διαγράφηκε το scan #{ScanId}", scanId);
        return Result<bool>.Ok(true);
    }

    /// <summary>Φτιάχνει την προβολή ενός ευρήματος για το UI. Δεν περιέχει ποτέ το raw secret.</summary>
    /// <param name="f">Το εύρημα.</param>
    /// <param name="triage">Το triage του repo.</param>
    /// <param name="diff">"new", "existing", "fixed" ή <c>null</c>.</param>
    /// <returns>Η προβολή.</returns>
    static FindingView View(StoredFinding f, Dictionary<string, (string Status, string Note)> triage, string? diff)
    {
        var t = triage.TryGetValue(f.Key, out var tr) ? tr : (TriageStatus.Pending, "");
        return new FindingView(f.Id, f.CanUnmask, f.Key, f.RuleId, f.Description, f.File, f.StartLine, f.EndLine,
            f.Commit, f.Author, f.Email, f.Date, f.Message, f.Entropy, f.SecretMasked, f.MatchMasked, f.Link,
            diff, new TriageView(t.Item1, t.Item2));
    }
}
