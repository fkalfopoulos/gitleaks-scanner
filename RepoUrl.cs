namespace GitleaksScanner;

/// <summary>
/// Βοηθητικές μέθοδοι για τα URLs των repositories.
/// </summary>
public static class RepoUrl
{
    /// <summary>
    /// Κανονικοποιεί το URL ενός repo, ώστε το ίδιο repo να αναγνωρίζεται ως ίδιο ανεξάρτητα από
    /// κεφαλαία στο host, "/" στο τέλος ή κατάληξη ".git".
    /// </summary>
    /// <param name="uri">Το URL όπως το έδωσε ο χρήστης.</param>
    /// <returns>Π.χ. "https://github.com/user/repo" για το "https://GitHub.com/user/repo.git/".</returns>
    public static string Normalize(Uri uri)
    {
        var path = uri.AbsolutePath.TrimEnd('/');
        if (path.EndsWith(".git", StringComparison.OrdinalIgnoreCase)) path = path[..^4];
        return $"https://{uri.Host.ToLowerInvariant()}{path}";
    }

    /// <summary>
    /// Επιστρέφει τη βάση για links προς αρχεία στο web UI του host (GitHub, GitLab, Bitbucket).
    /// </summary>
    /// <param name="uri">Το URL του repo.</param>
    /// <returns>Το URL του repo στο web, ή <c>null</c> για άγνωστους hosts.</returns>
    public static string? WebBase(Uri uri)
    {
        var host = uri.Host.ToLowerInvariant();
        return host is "github.com" or "gitlab.com" or "bitbucket.org" ? Normalize(uri) : null;
    }

    /// <summary>
    /// Ελέγχει αν ένα URL είναι προφίλ χρήστη GitHub (π.χ. github.com/user) και όχι repository.
    /// </summary>
    /// <param name="uri">Το URL.</param>
    /// <returns><c>true</c> αν είναι προφίλ.</returns>
    public static bool IsGitHubProfile(Uri uri) =>
        uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
        && uri.AbsolutePath.Trim('/').Split('/').Length == 1;
}
