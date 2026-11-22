using GitleaksScanner.Application.Abstractions;
using GitleaksScanner.Application.Common;
using GitleaksScanner.Application.Contracts;
using GitleaksScanner.Application.Services;

namespace GitleaksScanner.Api;

/// <summary>
/// Τα HTTP endpoints. Κάθε endpoint καλεί μια use case της Application και μεταφράζει το
/// <see cref="Result{T}"/> σε HTTP απάντηση· δεν περιέχει επιχειρησιακή λογική.
/// </summary>
public static class Endpoints
{
    /// <summary>Καταχωρεί όλα τα endpoints του API.</summary>
    /// <param name="app">Η εφαρμογή.</param>
    public static void MapEndpoints(this WebApplication app)
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

    /// <summary>Επιστρέφει τις εκδόσεις των git και gitleaks.</summary>
    /// <param name="gitleaks">Ο runner του gitleaks.</param>
    /// <returns>Οι εκδόσεις.</returns>
    static async Task<IResult> Health(IGitleaksRunner gitleaks) => Results.Ok(await gitleaks.GetVersionsAsync());

    /// <summary>Εκτελεί νέο scan.</summary>
    /// <param name="req">Το αίτημα.</param>
    /// <param name="scans">Η use case.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Η προβολή του scan, ή σφάλμα.</returns>
    static async Task<IResult> Scan(ScanRequest req, ScanService scans, CancellationToken ct) =>
        (await scans.RunAsync(req, ct)).ToHttp();

    /// <summary>Επιστρέφει τα δημόσια repos ενός χρήστη GitHub.</summary>
    /// <param name="owner">Ο χρήστης ή ο οργανισμός.</param>
    /// <param name="findings">Η use case.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα repos, ή σφάλμα.</returns>
    static async Task<IResult> GitHubRepos(string owner, FindingService findings, CancellationToken ct) =>
        (await findings.ListGitHubReposAsync(owner, ct)).ToHttp();

    /// <summary>Επιστρέφει το ιστορικό των scans.</summary>
    /// <param name="queries">Η use case.</param>
    /// <returns>Τα scans.</returns>
    static IResult ListScans(ScanQueryService queries) => Results.Ok(queries.List());

    /// <summary>Επιστρέφει την προβολή ενός scan.</summary>
    /// <param name="id">Το id.</param>
    /// <param name="queries">Η use case.</param>
    /// <returns>Η προβολή, ή 404.</returns>
    static IResult GetScan(long id, ScanQueryService queries) => queries.Get(id).ToHttp();

    /// <summary>Διαγράφει ένα scan.</summary>
    /// <param name="id">Το id.</param>
    /// <param name="queries">Η use case.</param>
    /// <returns>204, ή 404.</returns>
    static IResult DeleteScan(long id, ScanQueryService queries) => queries.Delete(id).ToNoContent();

    /// <summary>Αποκρυπτογραφεί ένα εύρημα. Η απάντηση δεν αποθηκεύεται στην cache του browser.</summary>
    /// <param name="id">Το id του ευρήματος.</param>
    /// <param name="findings">Η use case.</param>
    /// <param name="ctx">Το HTTP context.</param>
    /// <returns>Τα δεδομένα, ή σφάλμα.</returns>
    static IResult Reveal(long id, FindingService findings, HttpContext ctx)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        return findings.Reveal(id).ToHttp();
    }

    /// <summary>Αλλάζει το triage ενός ευρήματος.</summary>
    /// <param name="req">Το αίτημα.</param>
    /// <param name="findings">Η use case.</param>
    /// <returns>204, ή 400.</returns>
    static IResult SetTriage(TriageRequest req, FindingService findings) => findings.SetTriage(req).ToNoContent();

    /// <summary>
    /// Μεταφράζει ένα αποτέλεσμα σε HTTP: 200 με την τιμή, ή το status που αντιστοιχεί στο σφάλμα
    /// με σώμα <c>{ "error": "…" }</c> (που δείχνει το UI).
    /// </summary>
    /// <typeparam name="T">Ο τύπος της τιμής.</typeparam>
    /// <param name="result">Το αποτέλεσμα.</param>
    /// <returns>Η HTTP απάντηση.</returns>
    static IResult ToHttp<T>(this Result<T> result) => result.IsSuccess ? Results.Ok(result.Value) : Error(result.Error!);

    /// <summary>Όπως η <see cref="ToHttp{T}"/>, αλλά με 204 (χωρίς σώμα) στην επιτυχία.</summary>
    /// <typeparam name="T">Ο τύπος της τιμής.</typeparam>
    /// <param name="result">Το αποτέλεσμα.</param>
    /// <returns>Η HTTP απάντηση.</returns>
    static IResult ToNoContent<T>(this Result<T> result) => result.IsSuccess ? Results.NoContent() : Error(result.Error!);

    /// <summary>Μεταφράζει ένα σφάλμα της Application σε HTTP status.</summary>
    /// <param name="error">Το σφάλμα.</param>
    /// <returns>Η HTTP απάντηση.</returns>
    static IResult Error(AppError error) => Results.Json(new { error = error.Message }, statusCode: error.Kind switch
    {
        ErrorKind.Validation => StatusCodes.Status400BadRequest,
        ErrorKind.NotFound => StatusCodes.Status404NotFound,
        ErrorKind.RateLimited => StatusCodes.Status429TooManyRequests,
        _ => StatusCodes.Status500InternalServerError,
    });
}
