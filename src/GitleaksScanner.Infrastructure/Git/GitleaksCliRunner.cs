using System.Text.Json;
using GitleaksScanner.Application.Abstractions;
using GitleaksScanner.Application.Common;
using GitleaksScanner.Application.Contracts;

namespace GitleaksScanner.Infrastructure.Git;

/// <summary>Υλοποίηση του <see cref="IGitleaksRunner"/> με το εκτελέσιμο <c>gitleaks</c>.</summary>
public sealed class GitleaksCliRunner : IGitleaksRunner
{
    static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    /// <inheritdoc/>
    /// <remarks>
    /// Τρέχει χωρίς <c>--redact</c>, γιατί το raw secret χρειάζεται για το masking, το κλειδί και
    /// την κρυπτογράφηση. Υπάρχει μόνο στο report του προσωρινού φακέλου, που σβήνεται στο τέλος.
    /// </remarks>
    public async Task<Result<List<RawFinding>>> ScanAsync(ISourceWorkspace workspace, string mode, CancellationToken ct)
    {
        var reportPath = Path.Combine(workspace.TempDirectory, "report.json");
        string[] args =
        [
            mode, workspace.ScanPath,
            "--report-format", "json", "--report-path", reportPath,
            "--no-banner", "--exit-code", "0", "--log-level", "error"
        ];
        try
        {
            var run = await ProcessRunner.RunAsync("gitleaks", args, null, GitSourceProvider.CloneTimeout, ct);
            if (run.ExitCode != 0)
                return Result<List<RawFinding>>.Fail(ErrorKind.Failure, "Το gitleaks απέτυχε: " + (run.StdErr + run.StdOut).Trim());
        }
        catch (TimeoutException)
        {
            return Result<List<RawFinding>>.Fail(ErrorKind.Failure, "Το scan ξεπέρασε το χρονικό όριο.");
        }

        var findings = File.Exists(reportPath)
            ? JsonSerializer.Deserialize<List<RawFinding>>(await File.ReadAllTextAsync(reportPath, ct), JsonOptions) ?? []
            : [];
        return Result<List<RawFinding>>.Ok(findings);
    }

    /// <inheritdoc/>
    public async Task<ToolVersions> GetVersionsAsync()
    {
        var gl = await ProcessRunner.RunAsync("gitleaks", ["version"], null, TimeSpan.FromSeconds(10));
        var git = await ProcessRunner.RunAsync("git", ["--version"], null, TimeSpan.FromSeconds(10));
        return new ToolVersions(gl.ExitCode == 0 ? gl.StdOut.Trim() : null, git.ExitCode == 0 ? git.StdOut.Trim() : null);
    }
}
