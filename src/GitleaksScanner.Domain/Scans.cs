namespace GitleaksScanner.Domain;

/// <summary>Τα στοιχεία ενός scan.</summary>
/// <param name="Id">Το id.</param>
/// <param name="Source">Το repo ή ο φάκελος.</param>
/// <param name="Mode">"git" ή "dir".</param>
/// <param name="FullHistory">Αν σκαναρίστηκε όλο το ιστορικό.</param>
/// <param name="MaskMode">"partial" ή "full".</param>
/// <param name="StartedAt">Πότε ξεκίνησε (ISO 8601, UTC).</param>
/// <param name="DurationMs">Πόσο κράτησε.</param>
/// <param name="Count">Πόσα ευρήματα βρέθηκαν.</param>
public record ScanInfo(long Id, string Source, string Mode, bool FullHistory, string MaskMode,
    string StartedAt, long DurationMs, int Count);

/// <summary>Ένα εύρημα όπως αποθηκεύεται. Δεν περιέχει ποτέ το raw secret σε αναγνώσιμη μορφή.</summary>
public class StoredFinding
{
    /// <summary>Το id στη βάση.</summary>
    public long Id { get; set; }
    /// <summary>Αν υπάρχουν κρυπτογραφημένα δεδομένα για unmask (όχι σε παλιά scans).</summary>
    public bool CanUnmask { get; set; }
    /// <summary>Το secret, κρυπτογραφημένο. Μόνο κατά την αποθήκευση· δεν διαβάζεται μαζί με τη λίστα.</summary>
    public byte[]? SecretEnc { get; set; }
    /// <summary>Το match, κρυπτογραφημένο. Μόνο κατά την αποθήκευση.</summary>
    public byte[]? MatchEnc { get; set; }
    /// <summary>Ο κώδικας γύρω από το εύρημα, κρυπτογραφημένος. Μόνο κατά την αποθήκευση.</summary>
    public byte[]? ContextEnc { get; set; }
    /// <summary>Σταθερό κλειδί (HMAC), κοινό για το ίδιο leak σε όλα τα scans.</summary>
    public string Key { get; set; } = "";
    /// <summary>Ο κανόνας του gitleaks.</summary>
    public string? RuleId { get; set; }
    /// <summary>Η περιγραφή του κανόνα.</summary>
    public string? Description { get; set; }
    /// <summary>Το σχετικό path του αρχείου.</summary>
    public string? File { get; set; }
    /// <summary>Η πρώτη γραμμή.</summary>
    public int StartLine { get; set; }
    /// <summary>Η τελευταία γραμμή.</summary>
    public int EndLine { get; set; }
    /// <summary>Το commit (μόνο σε git mode).</summary>
    public string? Commit { get; set; }
    /// <summary>Ο συγγραφέας του commit.</summary>
    public string? Author { get; set; }
    /// <summary>Το email του συγγραφέα.</summary>
    public string? Email { get; set; }
    /// <summary>Η ημερομηνία του commit.</summary>
    public string? Date { get; set; }
    /// <summary>Το μήνυμα του commit.</summary>
    public string? Message { get; set; }
    /// <summary>Η εντροπία του secret.</summary>
    public double Entropy { get; set; }
    /// <summary>Το secret με μερική ή πλήρη απόκρυψη.</summary>
    public string? SecretMasked { get; set; }
    /// <summary>Το match με κρυμμένο το secret.</summary>
    public string? MatchMasked { get; set; }
    /// <summary>Link προς το αρχείο στο GitHub/GitLab/Bitbucket, αν υπάρχει.</summary>
    public string? Link { get; set; }
}

/// <summary>Ένα κομμάτι κώδικα γύρω από ένα εύρημα.</summary>
/// <param name="Start">Ο αριθμός της πρώτης γραμμής.</param>
/// <param name="Lines">Οι γραμμές.</param>
public record CodeSnippet(int Start, string[] Lines);

/// <summary>Οι καταστάσεις triage ενός ευρήματος.</summary>
public static class TriageStatus
{
    /// <summary>Η προεπιλογή: δεν έχει ελεγχθεί ακόμα.</summary>
    public const string Pending = "pending";

    /// <summary>Όλες οι επιτρεπτές τιμές.</summary>
    public static readonly string[] All = [Pending, "confirmed", "false_positive", "ignored", "fixed", "risk_accepted"];

    /// <summary>Ελέγχει αν μια τιμή είναι έγκυρο status.</summary>
    /// <param name="status">Η τιμή.</param>
    /// <returns><c>true</c> αν είναι μία από τις <see cref="All"/>.</returns>
    public static bool IsValid(string? status) => status is not null && All.Contains(status);
}

/// <summary>Σύγκριση των ευρημάτων δύο scans.</summary>
public static class ScanComparison
{
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
}
