using System.Net;
using System.Text.RegularExpressions;

namespace GitleaksScanner;

/// <summary>
/// Τα HTTP endpoints του API. Κάθε endpoint είναι μια method, για να είναι ευανάγνωστο και τεκμηριωμένο.
/// </summary>
public static partial class Api
{
    /// <summary>Καταχωρεί όλα τα endpoints του API στην εφαρμογή.</summary>
    /// <param name="app">Η εφαρμογή.</param>
    public static void MapApi(this WebApplication app)
    {
        var api = app.MapGroup("/api");
        api.MapGet("/health", Health);
        api.MapPost("/scan", Scan);
        api.MapGet("/github/{owner}/repos", GitHubRepos);
        api.MapGet("/scans", ListScans);
        api.MapGet("/scans/{id:long}", GetScan);
        api.MapDelete("/scans/{id:long}", DeleteScan);
        api.MapGet("/findings/{id:long}/reveal", Reveal);
        api.MapPut("/triage", SetTriage);
    }

    /// <summary>Ελέγχει ότι τα git και gitleaks είναι εγκατεστημένα και επιστρέφει τις εκδόσεις τους.</summary>
    /// <returns>Οι εκδόσεις, ή <c>null</c> για όποιο εργαλείο λείπει.</returns>
    static async Task<IResult> Health()
    {
        var gl = await ProcessRunner.RunAsync("gitleaks", ["version"], null, TimeSpan.FromSeconds(10));
        var git = await ProcessRunner.RunAsync("git", ["--version"], null, TimeSpan.FromSeconds(10));
        return Results.Ok(new
        {
            gitleaks = gl.ExitCode == 0 ? gl.StdOut.Trim() : null,
            git = git.ExitCode == 0 ? git.StdOut.Trim() : null
        });
    }

    /// <summary>Εκτελεί νέο scan (βλ. <see cref="ScanService.RunAsync"/>).</summary>
    /// <param name="req">Το αίτημα.</param>
    /// <param name="scanner">Η υπηρεσία scan.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η προβολή του νέου scan, ή σφάλμα.</returns>
    static Task<IResult> Scan(ScanRequest req, ScanService scanner, CancellationToken ct) => scanner.RunAsync(req, ct);

    /// <summary>Regex για έγκυρο όνομα χρήστη ή οργανισμού στο GitHub.</summary>
    [GeneratedRegex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")]
    private static partial Regex GitHubOwnerRegex();

    /// <summary>
    /// Επιστρέφει τα δημόσια repos ενός χρήστη ή οργανισμού στο GitHub (έως 1000, σε σελίδες των 100).
    /// </summary>
    /// <param name="owner">Ο χρήστης ή ο οργανισμός.</param>
    /// <param name="http">Το factory των HTTP clients.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα repos, ή 400/404 ή σφάλμα ορίου αιτημάτων.</returns>
    static async Task<IResult> GitHubRepos(string owner, IHttpClientFactory http, CancellationToken ct)
    {
        if (!GitHubOwnerRegex().IsMatch(owner))
            return Results.BadRequest(new { error = "Άκυρο όνομα χρήστη GitHub." });

        var client = http.CreateClient("github");
        var repos = new List<GitHubRepo>();
        for (var page = 1; page <= 10; page++)
        {
            using var res = await client.GetAsync($"users/{owner}/repos?per_page=100&type=owner&sort=pushed&page={page}", ct);
            if (res.StatusCode == HttpStatusCode.NotFound)
                return Results.NotFound(new { error = $"Ο χρήστης '{owner}' δεν βρέθηκε στο GitHub." });
            if (res.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
                return Results.Problem("Το GitHub API έφτασε το όριο αιτημάτων (60/ώρα χωρίς token). Δοκίμασε σε λίγο.");
            res.EnsureSuccessStatusCode();
            var batch = await res.Content.ReadFromJsonAsync<List<GitHubRepo>>(ct) ?? [];
            repos.AddRange(batch);
            if (batch.Count < 100) break;
        }
        return Results.Ok(repos.Select(r => new
        {
            r.Name, url = r.Html_Url, r.Description, r.Fork, r.Archived, sizeKb = r.Size, pushedAt = r.Pushed_At, r.Language
        }));
    }

    /// <summary>Επιστρέφει το ιστορικό των scans.</summary>
    /// <param name="store">Η βάση.</param>
    /// <returns>Τα scans, από το νεότερο.</returns>
    static IResult ListScans(Store store) => Results.Ok(store.ListScans());

    /// <summary>Επιστρέφει την προβολή ενός scan (ευρήματα, triage, σύγκριση).</summary>
    /// <param name="id">Το id του scan.</param>
    /// <param name="store">Η βάση.</param>
    /// <returns>Η προβολή, ή 404.</returns>
    static IResult GetScan(long id, Store store) =>
        ScanView.Build(store, id) is { } view ? Results.Ok(view) : Results.NotFound();

    /// <summary>Διαγράφει ένα scan. Το triage των ευρημάτων κρατιέται, γιατί ανήκει στο repo.</summary>
    /// <param name="id">Το id του scan.</param>
    /// <param name="store">Η βάση.</param>
    /// <returns>204, ή 404 αν δεν υπήρχε.</returns>
    static IResult DeleteScan(long id, Store store) =>
        store.DeleteScan(id) ? Results.NoContent() : Results.NotFound();

    /// <summary>
    /// Αποκρυπτογραφεί ΕΝΑ εύρημα (secret, match, κώδικας γύρω του), μόνο όταν ζητηθεί ρητά.
    /// Η απάντηση δεν αποθηκεύεται στην cache του browser.
    /// </summary>
    /// <param name="id">Το id του ευρήματος.</param>
    /// <param name="store">Η βάση.</param>
    /// <param name="keys">Τα κλειδιά.</param>
    /// <param name="ctx">Το HTTP context, για το header Cache-Control.</param>
    /// <returns>Τα αποκρυπτογραφημένα δεδομένα, ή 400/404/500.</returns>
    static IResult Reveal(long id, Store store, ScannerKeys keys, HttpContext ctx)
    {
        var enc = store.GetEncrypted(id);
        if (enc is null) return Results.NotFound();
        if (enc.Value.Match is null)
            return Results.BadRequest(new { error = "Αυτό το scan έγινε πριν προστεθεί το unmask. Κάνε rescan." });
        ctx.Response.Headers.CacheControl = "no-store";
        try
        {
            return Results.Ok(new
            {
                secret = Secrets.Decrypt(keys.Encryption, enc.Value.Secret),
                match = Secrets.Decrypt(keys.Encryption, enc.Value.Match),
                context = CodeContext.Deserialize(Secrets.Decrypt(keys.Encryption, enc.Value.Context))
            });
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return Results.Problem("Η αποκρυπτογράφηση απέτυχε (άλλαξε το data/enc.key;).");
        }
    }

    /// <summary>Αλλάζει το triage (status και σημείωση) ενός ευρήματος για όλα τα scans του repo.</summary>
    /// <param name="req">Το αίτημα.</param>
    /// <param name="store">Η βάση.</param>
    /// <returns>204, ή 400 αν το αίτημα είναι άκυρο.</returns>
    static IResult SetTriage(TriageRequest req, Store store)
    {
        if (string.IsNullOrWhiteSpace(req.Source) || string.IsNullOrWhiteSpace(req.Key))
            return Results.BadRequest(new { error = "Λείπει source ή key." });
        if (!Store.TriageStatuses.Contains(req.Status))
            return Results.BadRequest(new { error = "Άκυρο status." });
        var note = (req.Note ?? "").Trim();
        if (note.Length > 2000) note = note[..2000];
        store.SetTriage(req.Source, req.Key, req.Status!, note);
        return Results.NoContent();
    }
}
