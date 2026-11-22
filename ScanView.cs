namespace GitleaksScanner;

/// <summary>
/// Φτιάχνει την προβολή ενός scan για το UI: ευρήματα, triage και σύγκριση με το προηγούμενο scan.
/// </summary>
public static class ScanView
{
    /// <summary>
    /// Συνδυάζει τα ευρήματα ενός scan με το triage του repo και τα συγκρίνει με το προηγούμενο
    /// scan που είχε τις ίδιες ρυθμίσεις.
    /// </summary>
    /// <param name="store">Η βάση.</param>
    /// <param name="scanId">Το id του scan.</param>
    /// <returns>Η προβολή (scan, stats, findings, fixed), ή <c>null</c> αν δεν υπάρχει το scan.</returns>
    public static object? Build(Store store, long scanId)
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
            (prevKeys, fixedList) = Diff(prev, findings);
        }

        var items = findings
            .Select(f => View(f, triage, prevKeys is null ? null : prevKeys.Contains(f.Key) ? "existing" : "new"))
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
            @fixed = fixedList.Select(f => View(f, triage, "fixed")).ToList()
        };
    }

    /// <summary>
    /// Συγκρίνει δύο scans: επιστρέφει τα κλειδιά του προηγούμενου και όσα ευρήματά του δεν
    /// υπάρχουν πια (ένα ανά κλειδί, γιατί στο full history το ίδιο secret εμφανίζεται σε πολλά commits).
    /// </summary>
    /// <param name="previous">Τα ευρήματα του προηγούμενου scan.</param>
    /// <param name="current">Τα ευρήματα του τρέχοντος scan.</param>
    /// <returns>Τα κλειδιά του προηγούμενου scan και τα "διορθωμένα" ευρήματα.</returns>
    public static (HashSet<string> PreviousKeys, List<StoredFinding> Fixed) Diff(
        IReadOnlyList<StoredFinding> previous, IReadOnlyList<StoredFinding> current)
    {
        var prevKeys = previous.Select(f => f.Key).ToHashSet();
        var currentKeys = current.Select(f => f.Key).ToHashSet();
        var fixedList = previous.Where(f => !currentKeys.Contains(f.Key)).DistinctBy(f => f.Key).ToList();
        return (prevKeys, fixedList);
    }

    /// <summary>
    /// Φτιάχνει την προβολή ενός ευρήματος για το UI. Δεν περιέχει ποτέ το raw secret.
    /// </summary>
    /// <param name="f">Το εύρημα.</param>
    /// <param name="triage">Το triage του repo (κλειδί → status, σημείωση).</param>
    /// <param name="diff">"new", "existing", "fixed", ή <c>null</c> αν δεν υπάρχει προηγούμενο scan.</param>
    /// <returns>Ένα ανώνυμο αντικείμενο για JSON.</returns>
    static object View(StoredFinding f, Dictionary<string, (string Status, string Note)> triage, string? diff)
    {
        var t = triage.TryGetValue(f.Key, out var tr) ? tr : ("pending", "");
        return new
        {
            f.Id, f.CanUnmask, f.Key, f.RuleId, f.Description, f.File, f.StartLine, f.EndLine,
            f.Commit, f.Author, f.Email, f.Date, f.Message, f.Entropy, f.SecretMasked, f.MatchMasked, f.Link,
            diff,
            triage = new { status = t.Item1, note = t.Item2 }
        };
    }
}
