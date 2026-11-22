using System.Security.Cryptography;
using System.Text;

namespace GitleaksScanner;

/// <summary>
/// Χειρισμός των raw secrets: masking για εμφάνιση, HMAC για ταυτοποίηση και κρυπτογράφηση
/// (AES-256-GCM) για το unmask.
/// </summary>
/// <remarks>
/// Το raw secret δεν αποθηκεύεται ποτέ σε αναγνώσιμη μορφή και δεν στέλνεται στον browser,
/// εκτός αν ο χρήστης πατήσει ρητά "Unmask" σε ένα εύρημα.
/// </remarks>
public static class Secrets
{
    const string Dots = "••••••";

    /// <summary>
    /// Κρύβει ένα secret αφήνοντας ορατούς μόνο τους τελευταίους χαρακτήρες, ώστε να αναγνωρίζεις
    /// ΠΟΙΟ key διέρρευσε χωρίς να μπορεί να ανακατασκευαστεί.
    /// </summary>
    /// <remarks>
    /// Το πολύ 6 χαρακτήρες και ποτέ πάνω από το 1/4 του secret, για να μη μένει εκτεθειμένο ένα
    /// κοντό secret. Το μήκος δεν αποκαλύπτεται (σταθερός αριθμός τελειών).
    /// </remarks>
    /// <param name="secret">Το raw secret.</param>
    /// <param name="mode">"partial" για μερική απόκρυψη, "full" για πλήρη.</param>
    /// <returns>Π.χ. "••••••vW3xY5", ή "REDACTED" σε πλήρη απόκρυψη, ή κενό αν δεν υπάρχει secret.</returns>
    public static string Mask(string? secret, string mode)
    {
        if (string.IsNullOrEmpty(secret)) return "";
        if (mode == "full") return "REDACTED";
        var show = Math.Min(6, secret.Length / 4);
        return show == 0 ? Dots : Dots + secret[^show..];
    }

    /// <summary>Αντικαθιστά το secret μέσα στο "match" (το κείμενο γύρω του) με τη masked εκδοχή του.</summary>
    /// <param name="match">Το κείμενο που ταίριαξε ο κανόνας.</param>
    /// <param name="secret">Το raw secret.</param>
    /// <param name="mode">"partial" ή "full".</param>
    /// <returns>Το κείμενο με κρυμμένο το secret.</returns>
    public static string MaskMatch(string? match, string? secret, string mode)
    {
        if (string.IsNullOrEmpty(match)) return "";
        if (string.IsNullOrEmpty(secret)) return match;
        return match.Replace(secret, Mask(secret, mode));
    }

    /// <summary>
    /// Υπολογίζει το σταθερό κλειδί ενός ευρήματος από τον κανόνα, το αρχείο και το secret.
    /// </summary>
    /// <remarks>
    /// Δεν περιέχει το commit, οπότε το ίδιο leak αναγνωρίζεται σε κάθε scan, ακόμα και σε shallow
    /// clone όπου το HEAD αλλάζει. Είναι HMAC με τοπικό κλειδί και όχι απλό SHA-256: ένα secret
    /// χαμηλής εντροπίας (π.χ. ένας κωδικός) δεν μπορεί να βρεθεί με brute force από τη βάση.
    /// </remarks>
    /// <param name="hmacKey">Το τοπικό κλειδί HMAC.</param>
    /// <param name="ruleId">Ο κανόνας του gitleaks.</param>
    /// <param name="file">Το (σχετικό) path του αρχείου.</param>
    /// <param name="secret">Το raw secret.</param>
    /// <returns>32 δεκαεξαδικοί χαρακτήρες.</returns>
    public static string Key(byte[] hmacKey, string? ruleId, string? file, string? secret)
    {
        var data = Encoding.UTF8.GetBytes($"{ruleId}\n{file}\n{secret}");
        return Convert.ToHexStringLower(HMACSHA256.HashData(hmacKey, data))[..32];
    }

    /// <summary>
    /// Κρυπτογραφεί ένα κείμενο με AES-256-GCM, που εξασφαλίζει και ότι δεν θα αλλοιωθεί.
    /// </summary>
    /// <remarks>
    /// Μορφή αποτελέσματος: nonce (12 bytes) | tag (16 bytes) | ciphertext. Κάθε κλήση παίρνει
    /// νέο τυχαίο nonce, οπότε το ίδιο secret κρυπτογραφείται κάθε φορά διαφορετικά.
    /// </remarks>
    /// <param name="key">Κλειδί 32 bytes.</param>
    /// <param name="plain">Το κείμενο.</param>
    /// <returns>Τα κρυπτογραφημένα bytes, ή <c>null</c> αν το κείμενο είναι κενό.</returns>
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

    /// <summary>Αποκρυπτογραφεί δεδομένα που κρυπτογραφήθηκαν με την <see cref="Encrypt"/>.</summary>
    /// <param name="key">Το ίδιο κλειδί που χρησιμοποιήθηκε στην κρυπτογράφηση.</param>
    /// <param name="blob">Τα κρυπτογραφημένα bytes.</param>
    /// <returns>Το αρχικό κείμενο, ή <c>null</c> αν δεν υπάρχουν δεδομένα.</returns>
    /// <exception cref="CryptographicException">Αν το κλειδί είναι λάθος ή τα δεδομένα έχουν αλλοιωθεί.</exception>
    public static string? Decrypt(byte[] key, byte[]? blob)
    {
        if (blob is null || blob.Length < 28) return null;
        var plain = new byte[blob.Length - 28];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(28), blob.AsSpan(12, 16), plain);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>
    /// Διαβάζει ένα κλειδί 32 bytes από αρχείο, ή δημιουργεί νέο τυχαίο αν δεν υπάρχει.
    /// Σε macOS/Linux το αρχείο γίνεται αναγνώσιμο μόνο από τον χρήστη (chmod 600).
    /// </summary>
    /// <param name="path">Η διαδρομή του αρχείου.</param>
    /// <returns>Το κλειδί.</returns>
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
