using GitleaksScanner.Application.Abstractions;
using GitleaksScanner.Infrastructure.Git;
using GitleaksScanner.Infrastructure.GitHub;
using GitleaksScanner.Infrastructure.Persistence;
using GitleaksScanner.Infrastructure.Security;
using Microsoft.Extensions.DependencyInjection;

namespace GitleaksScanner.Infrastructure;

/// <summary>Καταχώριση των υλοποιήσεων της Infrastructure στο dependency injection.</summary>
public static class DependencyInjection
{
    /// <summary>
    /// Καταχωρεί τη βάση SQLite, την κρυπτογράφηση, το git/gitleaks και το GitHub API.
    /// Δημιουργεί τον φάκελο δεδομένων και τη βάση, αν δεν υπάρχουν.
    /// </summary>
    /// <param name="services">Η συλλογή υπηρεσιών.</param>
    /// <param name="dataDirectory">Ο φάκελος για τη βάση και τα κλειδιά (δεν πρέπει να μπει ποτέ στο git).</param>
    /// <returns>Την ίδια συλλογή, για αλυσιδωτές κλήσεις.</returns>
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, string dataDirectory)
    {
        Directory.CreateDirectory(dataDirectory);

        var repository = new SqliteScanRepository(Path.Combine(dataDirectory, "scanner.db"));
        repository.Init();
        services.AddSingleton<IScanRepository>(repository);
        services.AddSingleton<ISecretProtector>(AesSecretProtector.FromDirectory(dataDirectory));
        services.AddSingleton<ISourceProvider, GitSourceProvider>();
        services.AddSingleton<IGitleaksRunner, GitleaksCliRunner>();

        services.AddHttpClient<IGitHubClient, GitHubApiClient>(c =>
        {
            c.BaseAddress = new Uri("https://api.github.com/");
            c.DefaultRequestHeaders.UserAgent.ParseAdd("gitleaks-scanner/1.0");
            c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            c.Timeout = TimeSpan.FromSeconds(30);
        });
        return services;
    }
}
