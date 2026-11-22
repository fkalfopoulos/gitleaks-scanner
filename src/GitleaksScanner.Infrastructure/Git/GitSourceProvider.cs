using GitleaksScanner.Application.Abstractions;
using GitleaksScanner.Application.Common;
using GitleaksScanner.Domain;
using Microsoft.Extensions.Logging;

namespace GitleaksScanner.Infrastructure.Git;

/// <summary>
/// Υλοποίηση του <see cref="ISourceProvider"/>: τοπικός φάκελος ή <c>git clone</c> σε προσωρινό φάκελο.
/// </summary>
/// <param name="logger">Ο logger.</param>
public sealed class GitSourceProvider(ILogger<GitSourceProvider> logger) : ISourceProvider
{
    /// <summary>Μέγιστος χρόνος για ένα clone.</summary>
    internal static readonly TimeSpan CloneTimeout = TimeSpan.FromMinutes(10);

    /// <inheritdoc/>
    /// <remarks>
    /// Επιτρέπεται μόνο https (όχι <c>file://</c>, <c>ext::</c> κ.λπ.), και το git δεν ζητά ποτέ
    /// κωδικό. Από ξένα repos σβήνεται το <c>.gitleaks.toml</c>, γιατί θα μπορούσε να απενεργοποιεί
    /// κανόνες και να κρύβει secrets.
    /// </remarks>
    public async Task<Result<ISourceWorkspace>> PrepareAsync(string input, bool fullHistory, bool useRepoConfig, CancellationToken ct)
    {
        var temp = Path.Combine(Path.GetTempPath(), "gitleaks-scan-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);

        if (Directory.Exists(input))
        {
            var path = Path.GetFullPath(input).TrimEnd(Path.DirectorySeparatorChar);
            return Result<ISourceWorkspace>.Ok(new SourceWorkspace(path, path, Directory.Exists(Path.Combine(path, ".git")),
                isLocal: true, webBaseUrl: null, temp));
        }

        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            Directory.Delete(temp, recursive: true);
            return Result<ISourceWorkspace>.Fail(ErrorKind.Validation, "Το input πρέπει να είναι https:// URL ή υπάρχων τοπικός φάκελος.");
        }

        var scanPath = Path.Combine(temp, "repo");
        var args = new List<string> { "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "clone", "--quiet", "--no-tags" };
        if (!fullHistory) args.AddRange(["--depth", "1"]);
        args.AddRange(["--", input, scanPath]);

        logger.LogDebug("git clone {Url} (full history: {FullHistory})", uri, fullHistory);
        ProcessRunner.Result clone;
        try
        {
            clone = await ProcessRunner.RunAsync("git", args, null, CloneTimeout, ct, env: new() { ["GIT_TERMINAL_PROMPT"] = "0" });
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            Directory.Delete(temp, recursive: true);   // να μη μείνει μισό clone στον δίσκο
            if (ex is OperationCanceledException) throw;
            return Result<ISourceWorkspace>.Fail(ErrorKind.Failure, "Το clone ξεπέρασε το χρονικό όριο.");
        }
        if (clone.ExitCode != 0)
        {
            Directory.Delete(temp, recursive: true);
            var hint = RepoUrl.IsGitHubProfile(uri) ? " (Αυτό είναι προφίλ χρήστη, όχι repository.)" : "";
            return Result<ISourceWorkspace>.Fail(ErrorKind.Validation, "Το clone απέτυχε: " + clone.StdErr.Trim() + hint);
        }

        var repoConfig = Path.Combine(scanPath, ".gitleaks.toml");
        if (!useRepoConfig && File.Exists(repoConfig))
        {
            File.Delete(repoConfig);
            logger.LogInformation("Αγνοήθηκε το .gitleaks.toml του {Url}", uri);
        }

        return Result<ISourceWorkspace>.Ok(new SourceWorkspace(RepoUrl.Normalize(uri), scanPath, isGitRepo: true,
            isLocal: false, RepoUrl.WebBase(uri), temp));
    }

    /// <summary>Ένας φάκελος έτοιμος για scan, με προσωρινό φάκελο που σβήνεται στο dispose.</summary>
    sealed class SourceWorkspace : ISourceWorkspace
    {
        readonly CodeSnippetReader _reader;

        /// <summary>Δημιουργεί τον workspace.</summary>
        /// <param name="source">Το κανονικοποιημένο όνομα της πηγής.</param>
        /// <param name="scanPath">Ο φάκελος για scan.</param>
        /// <param name="isGitRepo">Αν είναι git repository.</param>
        /// <param name="isLocal">Αν είναι τοπικός φάκελος.</param>
        /// <param name="webBaseUrl">Βάση για links.</param>
        /// <param name="tempDirectory">Ο προσωρινός φάκελος.</param>
        public SourceWorkspace(string source, string scanPath, bool isGitRepo, bool isLocal, string? webBaseUrl, string tempDirectory)
        {
            Source = source;
            ScanPath = scanPath;
            IsGitRepo = isGitRepo;
            IsLocal = isLocal;
            WebBaseUrl = webBaseUrl;
            TempDirectory = tempDirectory;
            _reader = new CodeSnippetReader(scanPath);
        }

        /// <inheritdoc/>
        public string Source { get; }
        /// <inheritdoc/>
        public string ScanPath { get; }
        /// <inheritdoc/>
        public bool IsGitRepo { get; }
        /// <inheritdoc/>
        public bool IsLocal { get; }
        /// <inheritdoc/>
        public string? WebBaseUrl { get; }
        /// <inheritdoc/>
        public string TempDirectory { get; }

        /// <inheritdoc/>
        public string RelativePath(string? file) => _reader.Relative(file);

        /// <inheritdoc/>
        public Task<CodeSnippet?> ReadSnippetAsync(string relFile, string? commit, int startLine, int endLine, bool gitMode) =>
            _reader.GetAsync(relFile, gitMode ? commit : null, startLine, endLine);

        /// <summary>Σβήνει τον προσωρινό φάκελο (clone και report, που περιέχουν raw secrets).</summary>
        /// <returns>Ολοκληρωμένο task.</returns>
        public ValueTask DisposeAsync()
        {
            try { Directory.Delete(TempDirectory, recursive: true); } catch { /* best effort */ }
            return ValueTask.CompletedTask;
        }
    }
}
