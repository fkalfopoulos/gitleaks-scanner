using GitleaksScanner.Domain;

namespace GitleaksScanner.Application.Contracts;

/// <summary>Το αίτημα για νέο scan.</summary>
/// <param name="Source">https URL repository ή τοπικός φάκελος.</param>
/// <param name="FullHistory">Αν θα σκαναριστεί όλο το ιστορικό.</param>
/// <param name="Mask">"partial" ή "full".</param>
/// <param name="Mode">"dir" για μόνο τα τρέχοντα αρχεία· αλλιώς git.</param>
/// <param name="UseRepoConfig">Αν θα χρησιμοποιηθεί το <c>.gitleaks.toml</c> ενός ξένου repo.</param>
public record ScanRequest(string? Source, bool FullHistory = true, string? Mask = "partial", string? Mode = null,
    bool UseRepoConfig = false);

/// <summary>Το αίτημα για αλλαγή triage.</summary>
/// <param name="Source">Το repo.</param>
/// <param name="Key">Το κλειδί του ευρήματος.</param>
/// <param name="Status">Το νέο status.</param>
/// <param name="Note">Προαιρετική σημείωση.</param>
public record TriageRequest(string? Source, string? Key, string? Status, string? Note);

/// <summary>Ένα δημόσιο repository στο GitHub.</summary>
/// <param name="Name">Το όνομα.</param>
/// <param name="Url">Το URL.</param>
/// <param name="Description">Η περιγραφή.</param>
/// <param name="Fork">Αν είναι fork.</param>
/// <param name="Archived">Αν είναι archived.</param>
/// <param name="SizeKb">Μέγεθος σε KB.</param>
/// <param name="PushedAt">Το τελευταίο push.</param>
/// <param name="Language">Η κύρια γλώσσα.</param>
public record GitHubRepo(string Name, string Url, string? Description, bool Fork, bool Archived,
    long SizeKb, string? PushedAt, string? Language);

/// <summary>Ένα εύρημα όπως το επιστρέφει το gitleaks (με raw secret: δεν φεύγει ποτέ από τον server).</summary>
/// <param name="RuleID">Ο κανόνας.</param>
/// <param name="Description">Η περιγραφή.</param>
/// <param name="File">Το αρχείο.</param>
/// <param name="StartLine">Η πρώτη γραμμή.</param>
/// <param name="EndLine">Η τελευταία γραμμή.</param>
/// <param name="Match">Το κείμενο που ταίριαξε.</param>
/// <param name="Secret">Το raw secret.</param>
/// <param name="Commit">Το commit.</param>
/// <param name="Author">Ο συγγραφέας.</param>
/// <param name="Email">Το email του συγγραφέα.</param>
/// <param name="Date">Η ημερομηνία.</param>
/// <param name="Message">Το μήνυμα του commit.</param>
/// <param name="Entropy">Η εντροπία.</param>
public record RawFinding(string? RuleID, string? Description, string? File, int StartLine, int EndLine,
    string? Match, string? Secret, string? Commit, string? Author, string? Email, string? Date,
    string? Message, double Entropy);

/// <summary>Οι εκδόσεις των εξωτερικών εργαλείων.</summary>
/// <param name="Gitleaks">Η έκδοση του gitleaks, ή <c>null</c> αν δεν είναι εγκατεστημένο.</param>
/// <param name="Git">Η έκδοση του git, ή <c>null</c>.</param>
public record ToolVersions(string? Gitleaks, string? Git);

/// <summary>Το αποτέλεσμα του unmask ενός ευρήματος.</summary>
/// <param name="Secret">Το raw secret.</param>
/// <param name="Match">Το κείμενο που ταίριαξε.</param>
/// <param name="Context">Ο κώδικας γύρω από το εύρημα.</param>
public record RevealResult(string? Secret, string? Match, CodeSnippet? Context);

/// <summary>Το triage ενός ευρήματος.</summary>
/// <param name="Status">Το status.</param>
/// <param name="Note">Η σημείωση.</param>
public record TriageView(string Status, string Note);

/// <summary>Ένα εύρημα όπως το βλέπει το UI (χωρίς raw secret).</summary>
/// <param name="Id">Το id.</param>
/// <param name="CanUnmask">Αν υπάρχουν δεδομένα για unmask.</param>
/// <param name="Key">Το σταθερό κλειδί.</param>
/// <param name="RuleId">Ο κανόνας.</param>
/// <param name="Description">Η περιγραφή.</param>
/// <param name="File">Το αρχείο.</param>
/// <param name="StartLine">Η πρώτη γραμμή.</param>
/// <param name="EndLine">Η τελευταία γραμμή.</param>
/// <param name="Commit">Το commit.</param>
/// <param name="Author">Ο συγγραφέας.</param>
/// <param name="Email">Το email.</param>
/// <param name="Date">Η ημερομηνία.</param>
/// <param name="Message">Το μήνυμα του commit.</param>
/// <param name="Entropy">Η εντροπία.</param>
/// <param name="SecretMasked">Το secret με απόκρυψη.</param>
/// <param name="MatchMasked">Το match με απόκρυψη.</param>
/// <param name="Link">Link προς το αρχείο.</param>
/// <param name="Diff">"new", "existing", "fixed" ή <c>null</c>.</param>
/// <param name="Triage">Το triage.</param>
public record FindingView(long Id, bool CanUnmask, string Key, string? RuleId, string? Description, string? File,
    int StartLine, int EndLine, string? Commit, string? Author, string? Email, string? Date, string? Message,
    double Entropy, string? SecretMasked, string? MatchMasked, string? Link, string? Diff, TriageView Triage);

/// <summary>Στατιστικά ενός scan.</summary>
/// <param name="Total">Σύνολο ευρημάτων.</param>
/// <param name="Unique">Μοναδικά leaks.</param>
/// <param name="New">Νέα από το προηγούμενο scan.</param>
/// <param name="Fixed">Διορθωμένα από το προηγούμενο scan.</param>
public record ScanStats(int Total, int Unique, int New, int Fixed);

/// <summary>Η πλήρης προβολή ενός scan για το UI.</summary>
/// <param name="Scan">Τα στοιχεία του scan.</param>
/// <param name="PreviousScanId">Το scan σύγκρισης, ή <c>null</c>.</param>
/// <param name="Stats">Τα στατιστικά.</param>
/// <param name="Findings">Τα ευρήματα.</param>
/// <param name="Fixed">Τα διορθωμένα (από το προηγούμενο scan).</param>
public record ScanViewDto(ScanInfo Scan, long? PreviousScanId, ScanStats Stats, List<FindingView> Findings, List<FindingView> Fixed);
