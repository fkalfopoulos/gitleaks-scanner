using System.Security.Cryptography;
using System.Text;

/// Χειρισμός των raw secrets. Το raw secret ΔΕΝ αποθηκεύεται ποτέ και δεν φεύγει ποτέ
/// από τον server: κρατάμε μόνο μια masked εκδοχή και ένα HMAC για ταυτοποίηση.
static class Secrets
{
    const string Dots = "••••••";

    /// Μερική απόκρυψη: δείχνει μόνο τους τελευταίους χαρακτήρες, ώστε να αναγνωρίζεις
    /// ΠΟΙΟ key διέρρευσε χωρίς να μπορεί να ανακατασκευαστεί. Το πολύ 6 χαρακτήρες και
    /// ποτέ πάνω από το 1/4 του secret, για να μη μένει εκτεθειμένο ένα κοντό secret.
    /// Το μήκος του secret δεν αποκαλύπτεται (σταθερός αριθμός τελειών).
    public static string Mask(string? secret, string mode)
    {
        if (string.IsNullOrEmpty(secret)) return "";
        if (mode == "full") return "REDACTED";
        var show = Math.Min(6, secret.Length / 4);
        return show == 0 ? Dots : Dots + secret[^show..];
    }

    /// Αντικαθιστά το secret μέσα στο "match" (τη γραμμή κώδικα γύρω του).
    public static string MaskMatch(string? match, string? secret, string mode)
    {
        if (string.IsNullOrEmpty(match)) return "";
        if (string.IsNullOrEmpty(secret)) return match;
        return match.Replace(secret, Mask(secret, mode));
    }

    /// Σταθερό κλειδί ενός ευρήματος: ίδιος κανόνας + ίδιο αρχείο + ίδιο secret.
    /// Δεν περιέχει το commit, οπότε το ίδιο leak αναγνωρίζεται σε κάθε scan, ακόμα και
    /// σε shallow clone όπου το HEAD αλλάζει. Είναι HMAC με τοπικό κλειδί και όχι απλό
    /// SHA-256: ένα secret χαμηλής εντροπίας δεν μπορεί να βρεθεί με brute force από τη βάση.
    public static string Key(byte[] hmacKey, string? ruleId, string? file, string? secret)
    {
        var data = Encoding.UTF8.GetBytes($"{ruleId}\n{file}\n{secret}");
        return Convert.ToHexStringLower(HMACSHA256.HashData(hmacKey, data))[..32];
    }

    // ---------- Κρυπτογράφηση για το unmask ----------
    // AES-256-GCM. Μορφή: nonce(12) | tag(16) | ciphertext. Το κλειδί βρίσκεται σε άλλο
    // αρχείο από τη βάση: αν μοιραστείς ή χάσεις μόνο το scanner.db, τα secrets δεν διαβάζονται.

    public static byte[]? Encrypt(byte[] key, string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        var data = Encoding.UTF8.GetBytes(plain);
        var output = new byte[12 + 16 + data.Length];
        var nonce = output.AsSpan(0, 12);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, data, output.AsSpan(28), output.AsSpan(12, 16));
        return output;
    }

    public static string? Decrypt(byte[] key, byte[]? blob)
    {
        if (blob is null || blob.Length < 28) return null;
        var plain = new byte[blob.Length - 28];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(28), blob.AsSpan(12, 16), plain);
        return Encoding.UTF8.GetString(plain);
    }

    public static byte[] LoadOrCreateKey(string path)
    {
        if (File.Exists(path)) return File.ReadAllBytes(path);
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, key);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return key;
    }
}
