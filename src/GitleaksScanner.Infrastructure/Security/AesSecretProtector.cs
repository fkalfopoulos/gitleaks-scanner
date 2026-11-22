using System.Security.Cryptography;
using System.Text;
using GitleaksScanner.Application.Abstractions;

namespace GitleaksScanner.Infrastructure.Security;

/// <summary>
/// Υλοποίηση του <see cref="ISecretProtector"/>: HMAC-SHA256 για τα κλειδιά των ευρημάτων και
/// AES-256-GCM για την κρυπτογράφηση των secrets.
/// </summary>
/// <param name="hmacKey">Κλειδί 32 bytes για το HMAC.</param>
/// <param name="encryptionKey">Κλειδί 32 bytes για το AES.</param>
public sealed class AesSecretProtector(byte[] hmacKey, byte[] encryptionKey) : ISecretProtector
{
    const int NonceSize = 12;
    const int TagSize = 16;

    /// <summary>
    /// Φτιάχνει protector με τα κλειδιά <c>hmac.key</c> και <c>enc.key</c> ενός φακέλου, ή
    /// δημιουργεί νέα τυχαία κλειδιά αν δεν υπάρχουν.
    /// </summary>
    /// <param name="directory">Ο φάκελος των κλειδιών.</param>
    /// <returns>Ο protector.</returns>
    public static AesSecretProtector FromDirectory(string directory) =>
        new(LoadOrCreateKey(Path.Combine(directory, "hmac.key")), LoadOrCreateKey(Path.Combine(directory, "enc.key")));

    /// <inheritdoc/>
    /// <remarks>
    /// Δεν περιέχει το commit, οπότε το ίδιο leak αναγνωρίζεται σε κάθε scan, ακόμα και σε shallow
    /// clone. Είναι HMAC με τοπικό κλειδί και όχι απλό SHA-256: ένα secret χαμηλής εντροπίας
    /// (π.χ. ένας κωδικός) δεν μπορεί να βρεθεί με brute force από τη βάση.
    /// </remarks>
    public string ComputeKey(string? ruleId, string? file, string? secret)
    {
        var data = Encoding.UTF8.GetBytes($"{ruleId}\n{file}\n{secret}");
        return Convert.ToHexStringLower(HMACSHA256.HashData(hmacKey, data))[..32];
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Μορφή: nonce (12 bytes) | tag (16 bytes) | ciphertext. Κάθε κλήση παίρνει νέο τυχαίο nonce,
    /// οπότε το ίδιο secret κρυπτογραφείται κάθε φορά διαφορετικά. Το GCM ελέγχει και την ακεραιότητα.
    /// </remarks>
    public byte[]? Encrypt(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        var data = Encoding.UTF8.GetBytes(plain);
        var output = new byte[NonceSize + TagSize + data.Length];
        var nonce = output.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(encryptionKey, TagSize);
        aes.Encrypt(nonce, data, output.AsSpan(NonceSize + TagSize), output.AsSpan(NonceSize, TagSize));
        return output;
    }

    /// <inheritdoc/>
    public string? Decrypt(byte[]? blob)
    {
        if (blob is null || blob.Length < NonceSize + TagSize) return null;
        var plain = new byte[blob.Length - NonceSize - TagSize];
        using var aes = new AesGcm(encryptionKey, TagSize);
        aes.Decrypt(blob.AsSpan(0, NonceSize), blob.AsSpan(NonceSize + TagSize), blob.AsSpan(NonceSize, TagSize), plain);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>
    /// Διαβάζει ένα κλειδί 32 bytes από αρχείο, ή δημιουργεί νέο τυχαίο αν δεν υπάρχει.
    /// Σε macOS/Linux το αρχείο γίνεται αναγνώσιμο μόνο από τον χρήστη (chmod 600).
    /// </summary>
    /// <param name="path">Η διαδρομή του αρχείου.</param>
    /// <returns>Το κλειδί.</returns>
    static byte[] LoadOrCreateKey(string path)
    {
        if (File.Exists(path)) return File.ReadAllBytes(path);
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, key);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return key;
    }
}
