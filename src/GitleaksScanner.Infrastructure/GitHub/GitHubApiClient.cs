using System.Net;
using System.Net.Http.Json;
using GitleaksScanner.Application.Abstractions;
using GitleaksScanner.Application.Common;
using GitleaksScanner.Application.Contracts;

namespace GitleaksScanner.Infrastructure.GitHub;

/// <summary>Υλοποίηση του <see cref="IGitHubClient"/> με το GitHub REST API.</summary>
/// <param name="http">Ο HTTP client (ρυθμισμένος στο <see cref="DependencyInjection"/>).</param>
public sealed class GitHubApiClient(HttpClient http) : IGitHubClient
{
    /// <summary>Ένα repo όπως το επιστρέφει το GitHub API (snake_case πεδία).</summary>
    /// <param name="Name">Το όνομα.</param>
    /// <param name="Html_Url">Το URL.</param>
    /// <param name="Description">Η περιγραφή.</param>
    /// <param name="Fork">Αν είναι fork.</param>
    /// <param name="Archived">Αν είναι archived.</param>
    /// <param name="Size">Μέγεθος σε KB.</param>
    /// <param name="Pushed_At">Το τελευταίο push.</param>
    /// <param name="Language">Η γλώσσα.</param>
    sealed record ApiRepo(string Name, string Html_Url, string? Description, bool Fork, bool Archived,
        long Size, string? Pushed_At, string? Language);

    /// <inheritdoc/>
    /// <remarks>Έως 1000 repos, σε σελίδες των 100. Χωρίς token το GitHub επιτρέπει 60 αιτήματα την ώρα.</remarks>
    public async Task<Result<List<GitHubRepo>>> ListReposAsync(string owner, CancellationToken ct)
    {
        var repos = new List<GitHubRepo>();
        for (var page = 1; page <= 10; page++)
        {
            using var res = await http.GetAsync($"users/{owner}/repos?per_page=100&type=owner&sort=pushed&page={page}", ct);
            if (res.StatusCode == HttpStatusCode.NotFound)
                return Result<List<GitHubRepo>>.Fail(ErrorKind.NotFound, $"Ο χρήστης '{owner}' δεν βρέθηκε στο GitHub.");
            if (res.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
                return Result<List<GitHubRepo>>.Fail(ErrorKind.RateLimited, "Το GitHub API έφτασε το όριο αιτημάτων (60/ώρα χωρίς token). Δοκίμασε σε λίγο.");
            if (!res.IsSuccessStatusCode)
                return Result<List<GitHubRepo>>.Fail(ErrorKind.Failure, $"Το GitHub API απάντησε {(int)res.StatusCode}.");

            var batch = await res.Content.ReadFromJsonAsync<List<ApiRepo>>(ct) ?? [];
            repos.AddRange(batch.Select(r => new GitHubRepo(r.Name, r.Html_Url, r.Description, r.Fork, r.Archived,
                r.Size, r.Pushed_At, r.Language)));
            if (batch.Count < 100) break;
        }
        return Result<List<GitHubRepo>>.Ok(repos);
    }
}
