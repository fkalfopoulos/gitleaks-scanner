using GitleaksScanner.Application.Services;
using Microsoft.Extensions.DependencyInjection;

namespace GitleaksScanner.Application;

/// <summary>Καταχώριση των υπηρεσιών του Application layer στο dependency injection.</summary>
public static class DependencyInjection
{
    /// <summary>Καταχωρεί τις use cases (scan, ερωτήματα, ευρήματα).</summary>
    /// <param name="services">Η συλλογή υπηρεσιών.</param>
    /// <returns>Την ίδια συλλογή, για αλυσιδωτές κλήσεις.</returns>
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddSingleton<ScanService>();
        services.AddSingleton<ScanQueryService>();
        services.AddSingleton<FindingService>();
        return services;
    }
}
