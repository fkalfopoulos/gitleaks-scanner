namespace GitleaksScanner;

/// <summary>Τα κλειδιά της εφαρμογής, που φορτώνονται μία φορά από τον φάκελο <c>data/</c>.</summary>
/// <param name="Hmac">Κλειδί για το HMAC που ταυτοποιεί τα ευρήματα (βλ. <see cref="Secrets.Key"/>).</param>
/// <param name="Encryption">Κλειδί AES για την κρυπτογράφηση των secrets (βλ. <see cref="Secrets.Encrypt"/>).</param>
public sealed record ScannerKeys(byte[] Hmac, byte[] Encryption);

/// <summary>Το σώμα του αιτήματος για νέο scan.</summary>
/// <param name="Source">https URL repository ή τοπικός φάκελος.</param>
/// <param name="FullHistory">Αν θα σκαναριστεί όλο το ιστορικό ή μόνο το τελευταίο commit.</param>
/// <param name="Mask">"partial" (τελευταίοι χαρακτήρες ορατοί) ή "full".</param>
/// <param name="Mode">"dir" για σκανάρισμα μόνο των τρεχόντων αρχείων· αλλιώς git.</param>
/// <param name="UseRepoConfig">Αν θα χρησιμοποιηθεί το <c>.gitleaks.toml</c> ενός ξένου repo.</param>
public record ScanRequest(string? Source, bool FullHistory = true, string? Mask = "partial", string? Mode = null,
    bool UseRepoConfig = false);

/// <summary>Ένα δημόσιο repository όπως το επιστρέφει το GitHub API.</summary>
/// <param name="Name">Το όνομα.</param>
/// <param name="Html_Url">Το URL του repo.</param>
/// <param name="Description">Η περιγραφή.</param>
/// <param name="Fork">Αν είναι fork.</param>
/// <param name="Archived">Αν είναι archived.</param>
/// <param name="Size">Μέγεθος σε KB.</param>
/// <param name="Pushed_At">Πότε έγινε το τελευταίο push.</param>
/// <param name="Language">Η κύρια γλώσσα.</param>
public record GitHubRepo(string Name, string Html_Url, string? Description, bool Fork, bool Archived,
    long Size, string? Pushed_At, string? Language);

/// <summary>Το σώμα του αιτήματος για αλλαγή triage ενός ευρήματος.</summary>
/// <param name="Source">Το repo του ευρήματος.</param>
/// <param name="Key">Το σταθερό κλειδί του ευρήματος.</param>
/// <param name="Status">Το νέο status (βλ. <see cref="Store.TriageStatuses"/>).</param>
/// <param name="Note">Προαιρετική σημείωση.</param>
public record TriageRequest(string? Source, string? Key, string? Status, string? Note);

/// <summary>
/// Ένα εύρημα όπως το γράφει το gitleaks στο JSON report.
/// Περιέχει το raw secret, οπότε δεν επιστρέφεται ποτέ στον client και δεν αποθηκεύεται αυτούσιο.
/// </summary>
public class GitleaksFinding
{
    /// <summary>Ο κανόνας του gitleaks που ταίριαξε (π.χ. "aws-access-token").</summary>
    public string? RuleID { get; set; }
    /// <summary>Η περιγραφή του κανόνα.</summary>
    public string? Description { get; set; }
    /// <summary>Το αρχείο (σε dir mode απόλυτο path).</summary>
    public string? File { get; set; }
    /// <summary>Η πρώτη γραμμή του ευρήματος.</summary>
    public int StartLine { get; set; }
    /// <summary>Η τελευταία γραμμή του ευρήματος.</summary>
    public int EndLine { get; set; }
    /// <summary>Το κείμενο που ταίριαξε (περιέχει το secret).</summary>
    public string? Match { get; set; }
    /// <summary>Το raw secret.</summary>
    public string? Secret { get; set; }
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
    /// <summary>Η εντροπία του secret (πόσο "τυχαίο" φαίνεται).</summary>
    public double Entropy { get; set; }
}
