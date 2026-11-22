using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using GitleaksScanner.Application.Abstractions;
using GitleaksScanner.Application.Common;
using GitleaksScanner.Application.Contracts;
using GitleaksScanner.Domain;
using Microsoft.Extensions.Logging;

namespace GitleaksScanner.Application.Services;

/// <summary>
/// Use cases για μεμονωμένα ευρήματα (unmask, triage) και για την αναζήτηση repos στο GitHub.
/// </summary>
/// <param name="repository">Η αποθήκευση.</param>
/// <param name="protector">Η κρυπτογράφηση.</param>
/// <param name="github">Το GitHub API.</param>
/// <param name="logger">Ο logger.</param>
public sealed partial class FindingService(
    IScanRepository repository,
    ISecretProtector protector,
    IGitHubClient github,
    ILogger<FindingService> logger)
{
    /// <summary>
    /// Αποκρυπτογραφεί ΕΝΑ εύρημα (secret, match, κώδικας γύρω του). Καταγράφεται στο log ως
    /// audit (ποιο εύρημα, πότε), αλλά ΠΟΤΕ το ίδιο το secret.
    /// </summary>
    /// <param name="findingId">Το id του ευρήματος.</param>
    /// <returns>Τα αποκρυπτογραφημένα δεδομένα, ή σφάλμα.</returns>
    public Result<RevealResult> Reveal(long findingId)
    {
        var enc = repository.GetEncrypted(findingId);
        if (enc is null) return Result<RevealResult>.Fail(ErrorKind.NotFound, "Το εύρημα δεν υπάρχει.");
        if (enc.Value.Match is null)
            return Result<RevealResult>.Fail(ErrorKind.Validation, "Αυτό το scan έγινε πριν προστεθεί το unmask. Κάνε rescan.");

        try
        {
            var context = protector.Decrypt(enc.Value.Context) is { } json ? JsonSerializer.Deserialize<CodeSnippet>(json) : null;
            var result = new RevealResult(protector.Decrypt(enc.Value.Secret), protector.Decrypt(enc.Value.Match), context);
            logger.LogInformation("Audit: unmask του ευρήματος #{FindingId}", findingId);
            return Result<RevealResult>.Ok(result);
        }
        catch (CryptographicException)
        {
            logger.LogError("Αποτυχία αποκρυπτογράφησης του ευρήματος #{FindingId} (άλλαξε το κλειδί;)", findingId);
            return Result<RevealResult>.Fail(ErrorKind.Failure, "Η αποκρυπτογράφηση απέτυχε (άλλαξε το appdata/enc.key;).");
        }
    }

    /// <summary>Αλλάζει το triage (status και σημείωση) ενός ευρήματος για όλα τα scans του repo.</summary>
    /// <param name="req">Το αίτημα.</param>
    /// <returns><c>true</c>, ή σφάλμα ελέγχου.</returns>
    public Result<bool> SetTriage(TriageRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Source) || string.IsNullOrWhiteSpace(req.Key))
            return Result<bool>.Fail(ErrorKind.Validation, "Λείπει source ή key.");
        if (!TriageStatus.IsValid(req.Status))
            return Result<bool>.Fail(ErrorKind.Validation, "Άκυρο status.");

        var note = (req.Note ?? "").Trim();
        if (note.Length > 2000) note = note[..2000];
        repository.SetTriage(req.Source, req.Key, req.Status!, note);
        logger.LogInformation("Triage {Key} στο {Source}: {Status}", req.Key, req.Source, req.Status);
        return Result<bool>.Ok(true);
    }

    /// <summary>Regex για έγκυρο όνομα χρήστη ή οργανισμού στο GitHub.</summary>
    [GeneratedRegex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")]
    private static partial Regex GitHubOwnerRegex();

    /// <summary>Επιστρέφει τα δημόσια repos ενός χρήστη ή οργανισμού στο GitHub, αφού ελέγξει το όνομα.</summary>
    /// <param name="owner">Ο χρήστης ή ο οργανισμός.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <returns>Τα repos, ή σφάλμα.</returns>
    public Task<Result<List<GitHubRepo>>> ListGitHubReposAsync(string owner, CancellationToken ct) =>
        GitHubOwnerRegex().IsMatch(owner)
            ? github.ListReposAsync(owner, ct)
            : Task.FromResult(Result<List<GitHubRepo>>.Fail(ErrorKind.Validation, "Άκυρο όνομα χρήστη GitHub."));
}
