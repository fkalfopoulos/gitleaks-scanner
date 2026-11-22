using System.Diagnostics;

namespace GitleaksScanner.Infrastructure.Git;

/// <summary>
/// Εκτελεί εξωτερικά προγράμματα (git, gitleaks) με ασφάλεια και χρονικό όριο.
/// </summary>
internal static class ProcessRunner
{
    /// <summary>Το αποτέλεσμα μιας εκτέλεσης.</summary>
    /// <param name="ExitCode">Ο κωδικός εξόδου (0 = επιτυχία, −1 = το πρόγραμμα δεν βρέθηκε).</param>
    /// <param name="StdOut">Η κανονική έξοδος.</param>
    /// <param name="StdErr">Η έξοδος σφαλμάτων.</param>
    public record Result(int ExitCode, string StdOut, string StdErr);

    /// <summary>
    /// Τρέχει ένα πρόγραμμα με τα ορίσματα που δίνονται και περιμένει να τελειώσει.
    /// Τα ορίσματα περνούν ένα-ένα (<c>ArgumentList</c>) και όχι ως ένα string μέσω shell,
    /// οπότε ένα URL όπως <c>"x; rm -rf ~"</c> δεν μπορεί να εκτελέσει εντολές.
    /// </summary>
    /// <param name="file">Το πρόγραμμα (π.χ. "git").</param>
    /// <param name="args">Τα ορίσματα.</param>
    /// <param name="cwd">Ο φάκελος εργασίας, ή <c>null</c> για τον τρέχοντα.</param>
    /// <param name="timeout">Μέγιστος χρόνος· μετά το πρόγραμμα τερματίζεται.</param>
    /// <param name="ct">Token ακύρωσης.</param>
    /// <param name="env">Επιπλέον μεταβλητές περιβάλλοντος.</param>
    /// <returns>Ο κωδικός εξόδου και οι έξοδοι του προγράμματος.</returns>
    /// <exception cref="TimeoutException">Αν ξεπεραστεί το <paramref name="timeout"/>.</exception>
    /// <exception cref="OperationCanceledException">Αν ακυρωθεί το <paramref name="ct"/>.</exception>
    public static async Task<Result> RunAsync(string file, IEnumerable<string> args, string? cwd,
        TimeSpan timeout, CancellationToken ct = default, Dictionary<string, string>? env = null)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            WorkingDirectory = cwd ?? Environment.CurrentDirectory
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (env is not null) foreach (var (k, v) in env) psi.Environment[k] = v;

        using var proc = new Process { StartInfo = psi };
        try { proc.Start(); }
        catch (System.ComponentModel.Win32Exception)
        {
            return new Result(-1, "", $"Δεν βρέθηκε το '{file}'. Είναι εγκατεστημένο;");
        }

        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            if (ct.IsCancellationRequested) throw;
            throw new TimeoutException();
        }
        return new Result(proc.ExitCode, await stdout, await stderr);
    }
}
