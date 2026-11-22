using System.Text.Json;

namespace GitleaksScanner;

/// <summary>
/// Διαβάζει τις γραμμές κώδικα γύρω από ένα εύρημα, όσο υπάρχει ακόμα το clone.
/// </summary>
/// <remarks>
/// Σε git mode τις παίρνει από το αρχείο ΣΤΟ commit του ευρήματος (μπορεί να έχει σβηστεί
/// από τότε), σε dir mode από το αρχείο στον δίσκο.
/// </remarks>
/// <param name="repoPath">Ο φάκελος του repo.</param>
/// <param name="mode">"git" ή "dir".</param>
public class CodeContext(string repoPath, string mode)
{
    const int Around = 4;              // γραμμές πριν και μετά
    const int MaxLines = 40;           // π.χ. ένα private key πιάνει πολλές γραμμές
    const int MaxLineChars = 400;      // minified αρχεία έχουν τεράστιες γραμμές
    const long MaxFileBytes = 2_000_000;

    readonly Dictionary<string, string[]?> _cache = [];
    readonly string _root = Path.GetFullPath(repoPath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

    /// <summary>Ένα κομμάτι κώδικα.</summary>
    /// <param name="Start">Ο αριθμός της πρώτης γραμμής.</param>
    /// <param name="Lines">Οι γραμμές.</param>
    public record Snippet(int Start, string[] Lines);

    /// <summary>
    /// Μετατρέπει ένα απόλυτο path μέσα στο repo σε σχετικό (π.χ. "src/config.py").
    /// </summary>
    /// <remarks>
    /// Το gitleaks σε dir mode δίνει απόλυτο path, μαζί με τον τυχαίο temp φάκελο. Χωρίς αυτή τη
    /// μετατροπή, το ίδιο αρχείο θα είχε διαφορετικό όνομα, άρα και κλειδί, σε κάθε scan.
    /// </remarks>
    /// <param name="file">Το path όπως το έδωσε το gitleaks.</param>
    /// <returns>Το σχετικό path, ή το ίδιο το path αν είναι ήδη σχετικό ή εκτός repo.</returns>
    public string Relative(string? file)
    {
        if (string.IsNullOrEmpty(file)) return "";
        if (!Path.IsPathRooted(file)) return file;
        var full = Path.GetFullPath(file);
        return full.StartsWith(_root, StringComparison.Ordinal) ? full[_root.Length..] : file;
    }

    /// <summary>Επιστρέφει τις γραμμές γύρω από ένα εύρημα (±4, έως 40 συνολικά).</summary>
    /// <param name="relFile">Το σχετικό path του αρχείου.</param>
    /// <param name="commit">Το commit του ευρήματος (μόνο σε git mode).</param>
    /// <param name="startLine">Η πρώτη γραμμή του ευρήματος.</param>
    /// <param name="endLine">Η τελευταία γραμμή του ευρήματος.</param>
    /// <returns>Το κομμάτι κώδικα, ή <c>null</c> για binary/πολύ μεγάλα αρχεία ή άκυρες γραμμές.</returns>
    public async Task<Snippet?> GetAsync(string relFile, string? commit, int startLine, int endLine)
    {
        if (startLine <= 0 || relFile.Length == 0) return null;
        var lines = await LoadAsync(relFile, mode == "git" ? commit : null);
        if (lines is null) return null;

        var end = Math.Max(endLine, startLine);
        var from = Math.Max(1, startLine - Around);
        var to = Math.Min(lines.Length, Math.Min(end + Around, from + MaxLines - 1));
        if (from > to) return null;
        var slice = lines[(from - 1)..to]
            .Select(l => l.Length > MaxLineChars ? l[..MaxLineChars] + " …" : l)
            .ToArray();
        return new Snippet(from, slice);
    }

    /// <summary>
    /// Διαβάζει όλες τις γραμμές ενός αρχείου (από το commit ή από τον δίσκο), με cache ανά (commit, αρχείο).
    /// Δεν διαβάζει ποτέ εκτός repo (π.χ. μέσω "../" ή symlink).
    /// </summary>
    /// <param name="relFile">Το σχετικό path.</param>
    /// <param name="commit">Το commit, ή <c>null</c> για το αρχείο στον δίσκο.</param>
    /// <returns>Οι γραμμές, ή <c>null</c> αν το αρχείο είναι binary, πολύ μεγάλο ή δεν διαβάστηκε.</returns>
    async Task<string[]?> LoadAsync(string relFile, string? commit)
    {
        var cacheKey = $"{commit}\n{relFile}";
        if (_cache.TryGetValue(cacheKey, out var hit)) return hit;

        string? text = null;
        if (!string.IsNullOrEmpty(commit))
        {
            // Το commit είναι hex από το gitleaks, άρα το "commit:path" δεν ξεκινά ποτέ με "-".
            var r = await ProcessRunner.RunAsync("git", ["-C", repoPath, "show", $"{commit}:{relFile}"],
                null, TimeSpan.FromSeconds(20));
            if (r.ExitCode == 0 && r.StdOut.Length <= MaxFileBytes) text = r.StdOut;
        }
        else
        {
            // Δεν διαβάζουμε ποτέ έξω από το repo (π.χ. μέσω "../" ή symlink).
            var full = Path.GetFullPath(Path.Combine(repoPath, relFile));
            var info = new FileInfo(full);
            if (full.StartsWith(_root, StringComparison.Ordinal) && info.Exists
                && info.LinkTarget is null && info.Length <= MaxFileBytes)
                text = await File.ReadAllTextAsync(full);
        }

        var lines = text is null || text.Contains('\0') ? null : text.ReplaceLineEndings("\n").Split('\n');
        return _cache[cacheKey] = lines;
    }

    /// <summary>Μετατρέπει ένα κομμάτι κώδικα σε JSON, για κρυπτογράφηση και αποθήκευση.</summary>
    /// <param name="s">Το κομμάτι.</param>
    /// <returns>Το JSON.</returns>
    public static string Serialize(Snippet s) => JsonSerializer.Serialize(s);
    /// <summary>Διαβάζει ένα κομμάτι κώδικα από JSON.</summary>
    /// <param name="json">Το JSON, ή <c>null</c>.</param>
    /// <returns>Το κομμάτι, ή <c>null</c>.</returns>
    public static Snippet? Deserialize(string? json) => json is null ? null : JsonSerializer.Deserialize<Snippet>(json);
}
