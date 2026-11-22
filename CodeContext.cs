using System.Text.Json;

/// Διαβάζει τις γραμμές κώδικα γύρω από ένα εύρημα, όσο υπάρχει ακόμα το clone.
/// Σε git mode τις παίρνει από το αρχείο ΣΤΟ commit του ευρήματος (μπορεί να έχει σβηστεί
/// από τότε), σε dir mode από το αρχείο στον δίσκο.
class CodeContext(string repoPath, string mode)
{
    const int Around = 4;              // γραμμές πριν και μετά
    const int MaxLines = 40;           // π.χ. ένα private key πιάνει πολλές γραμμές
    const int MaxLineChars = 400;      // minified αρχεία έχουν τεράστιες γραμμές
    const long MaxFileBytes = 2_000_000;

    readonly Dictionary<string, string[]?> _cache = [];
    readonly string _root = Path.GetFullPath(repoPath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

    public record Snippet(int Start, string[] Lines);

    /// Το gitleaks σε dir mode δίνει απόλυτο path (μαζί με τον temp φάκελο). Το κάνουμε
    /// σχετικό, αλλιώς το ίδιο αρχείο θα είχε διαφορετικό όνομα, άρα και κλειδί, σε κάθε scan.
    public string Relative(string? file)
    {
        if (string.IsNullOrEmpty(file)) return "";
        if (!Path.IsPathRooted(file)) return file;
        var full = Path.GetFullPath(file);
        return full.StartsWith(_root, StringComparison.Ordinal) ? full[_root.Length..] : file;
    }

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

    public static string Serialize(Snippet s) => JsonSerializer.Serialize(s);
    public static Snippet? Deserialize(string? json) => json is null ? null : JsonSerializer.Deserialize<Snippet>(json);
}
