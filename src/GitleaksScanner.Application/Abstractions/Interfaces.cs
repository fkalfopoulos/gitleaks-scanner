using GitleaksScanner.Application.Common;
using GitleaksScanner.Application.Contracts;
using GitleaksScanner.Domain;

namespace GitleaksScanner.Application.Abstractions;

/// <summary>Αποθήκευση scans, ευρημάτων και triage. Υλοποιείται στην Infrastructure (SQLite).</summary>
public interface IScanRepository
{
    /// <summary>Αποθηκεύει ένα scan και όλα τα ευρήματά του (ή όλα ή τίποτα).</summary>
    /// <param name="source">Το κανονικοποιημένο όνομα της πηγής.</param>
    /// <param name="mode">"git" ή "dir".</param>
    /// <param name="fullHistory">Αν σκαναρίστηκε όλο το ιστορικό.</param>
    /// <param name="maskMode">"partial" ή "full".</param>
    /// <param name="startedAt">Πότε ξεκίνησε.</param>
    /// <param name="durationMs">Πόσο κράτησε.</param>
    /// <param name="findings">Τα ευρήματα.</param>
    /// <returns>Το id του νέου scan.</returns>
    long SaveScan(string source, string mode, bool fullHistory, string maskMode, DateTime startedAt,
        long durationMs, IReadOnlyList<StoredFinding> findings);

    /// <summary>Επιστρέφει τα πιο πρόσφατα scans.</summary>
    /// <param name="limit">Το μέγιστο πλήθος.</param>
    /// <returns>Τα scans, από το νεότερο.</returns>
    List<ScanInfo> ListScans(int limit = 200);

    /// <summary>Επιστρέφει ένα scan.</summary>
    /// <param name="id">Το id.</param>
    /// <returns>Το scan, ή <c>null</c>.</returns>
    ScanInfo? GetScan(long id);

    /// <summary>Βρίσκει το προηγούμενο scan του ίδιου repo με τις ίδιες ρυθμίσεις.</summary>
    /// <param name="scan">Το scan.</param>
    /// <returns>Το id του προηγούμενου, ή <c>null</c>.</returns>
    long? PreviousScanId(ScanInfo scan);

    /// <summary>Διαγράφει ένα scan (όχι το triage).</summary>
    /// <param name="id">Το id.</param>
    /// <returns><c>true</c> αν διαγράφηκε.</returns>
    bool DeleteScan(long id);

    /// <summary>Επιστρέφει τα ευρήματα ενός scan, χωρίς τα κρυπτογραφημένα δεδομένα.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <returns>Τα ευρήματα.</returns>
    List<StoredFinding> GetFindings(long scanId);

    /// <summary>Επιστρέφει τα κρυπτογραφημένα δεδομένα ενός ευρήματος.</summary>
    /// <param name="findingId">Το id του ευρήματος.</param>
    /// <returns>Τα δεδομένα, ή <c>null</c> αν δεν υπάρχει.</returns>
    (byte[]? Secret, byte[]? Match, byte[]? Context)? GetEncrypted(long findingId);

    /// <summary>Επιστρέφει το triage όλων των ευρημάτων ενός repo.</summary>
    /// <param name="source">Το repo.</param>
    /// <returns>Κλειδί ευρήματος → (status, σημείωση).</returns>
    Dictionary<string, (string Status, string Note)> GetTriage(string source);

    /// <summary>Ορίζει το triage ενός ευρήματος.</summary>
    /// <param name="source">Το repo.</param>
    /// <param name="key">Το κλειδί του ευρήματος.</param>
    /// <param name="status">Το status.</param>
    /// <param name="note">Η σημείωση.</param>
    void SetTriage(string source, string key, string status, string note);
}

/// <summary>Κρυπτογραφικές λειτουργίες για τα secrets. Υλοποιείται στην Infrastructure.</summary>
public interface ISecretProtector
{
    /// <summary>Υπολογίζει το σταθερό κλειδί ενός ευρήματος (HMAC του κανόνα, του αρχείου και του secret).</summary>
    /// <param name="ruleId">Ο κανόνας.</param>
    /// <param name="file">Το σχετικό path.</param>
    /// <param name="secret">Το raw secret.</param>
    /// <returns>32 δεκαεξαδικοί χαρακτήρες.</returns>
    string ComputeKey(string? ruleId, string? file, string? secret);

    /// <summary>Κρυπτογραφεί ένα κείμενο.</summary>
    /// <param name="plain">Το κείμενο.</param>
    /// <returns>Τα κρυπτογραφημένα bytes, ή <c>null</c> αν είναι κενό.</returns>
    byte[]? Encrypt(string? plain);

    /// <summary>Αποκρυπτογραφεί δεδομένα.</summary>
    /// <param name="blob">Τα κρυπτογραφημένα bytes.</param>
    /// <returns>Το κείμενο, ή <c>null</c> αν δεν υπάρχουν δεδομένα.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Λάθος κλειδί ή αλλοιωμένα δεδομένα.</exception>
    string? Decrypt(byte[]? blob);
}

/// <summary>
/// Ένας φάκελος έτοιμος για scan (τοπικός ή clone). Όταν γίνει dispose, σβήνονται τα
/// προσωρινά αρχεία, που μπορεί να περιέχουν raw secrets.
/// </summary>
public interface ISourceWorkspace : IAsyncDisposable
{
    /// <summary>Το κανονικοποιημένο όνομα της πηγής, για το ιστορικό.</summary>
    string Source { get; }
    /// <summary>Ο φάκελος που θα σκαναριστεί.</summary>
    string ScanPath { get; }
    /// <summary>Αν είναι git repository.</summary>
    bool IsGitRepo { get; }
    /// <summary>Αν είναι τοπικός φάκελος (και όχι clone).</summary>
    bool IsLocal { get; }
    /// <summary>Βάση για links προς τα αρχεία στο web, αν υπάρχει.</summary>
    string? WebBaseUrl { get; }
    /// <summary>Ο φάκελος για προσωρινά αρχεία (π.χ. το report του gitleaks).</summary>
    string TempDirectory { get; }

    /// <summary>Μετατρέπει ένα απόλυτο path μέσα στο repo σε σχετικό.</summary>
    /// <param name="file">Το path.</param>
    /// <returns>Το σχετικό path.</returns>
    string RelativePath(string? file);

    /// <summary>Διαβάζει τις γραμμές γύρω από ένα εύρημα.</summary>
    /// <param name="relFile">Το σχετικό path.</param>
    /// <param name="commit">Το commit (σε git mode), ή <c>null</c>.</param>
    /// <param name="startLine">Η πρώτη γραμμή.</param>
    /// <param name="endLine">Η τελευταία γραμμή.</param>
    /// <param name="gitMode">Αν το αρχείο διαβάζεται από το commit.</param>
    /// <returns>Το κομμάτι κώδικα, ή <c>null</c>.</returns>
    Task<CodeSnippet?> ReadSnippetAsync(string relFile, string? commit, int startLine, int endLine, bool gitMode);
}

/// <summary>Ετοιμάζει την πηγή ενός scan (τοπικός φάκελος ή clone). Υλοποιείται στην Infrastructure.</summary>
public interface ISourceProvider
{
    /// <summary>Ετοιμάζει τον φάκελο για scan.</summary>
    /// <param name="input">URL ή τοπικός φάκελος.</param>
    /// <param name="fullHistory">Αν το clone θα έχει όλο το ιστορικό.</param>
    /// <param name="useRepoConfig">Αν θα κρατηθεί το <c>.gitleaks.toml</c> ενός ξένου repo.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Ο φάκελος, ή σφάλμα.</returns>
    Task<Result<ISourceWorkspace>> PrepareAsync(string input, bool fullHistory, bool useRepoConfig, CancellationToken ct);
}

/// <summary>Εκτελεί το gitleaks. Υλοποιείται στην Infrastructure.</summary>
public interface IGitleaksRunner
{
    /// <summary>Σκανάρει έναν φάκελο και επιστρέφει τα ευρήματα (με raw secrets).</summary>
    /// <param name="workspace">Ο φάκελος.</param>
    /// <param name="mode">"git" ή "dir".</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα ευρήματα, ή σφάλμα.</returns>
    Task<Result<List<RawFinding>>> ScanAsync(ISourceWorkspace workspace, string mode, CancellationToken ct);

    /// <summary>Επιστρέφει τις εκδόσεις των git και gitleaks.</summary>
    /// <returns>Οι εκδόσεις (<c>null</c> για όποιο λείπει).</returns>
    Task<ToolVersions> GetVersionsAsync();
}

/// <summary>Πρόσβαση στο GitHub API. Υλοποιείται στην Infrastructure.</summary>
public interface IGitHubClient
{
    /// <summary>Επιστρέφει τα δημόσια repos ενός χρήστη ή οργανισμού.</summary>
    /// <param name="owner">Ο χρήστης ή ο οργανισμός (ήδη ελεγμένος).</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα repos, ή σφάλμα.</returns>
    Task<Result<List<GitHubRepo>>> ListReposAsync(string owner, CancellationToken ct);
}
