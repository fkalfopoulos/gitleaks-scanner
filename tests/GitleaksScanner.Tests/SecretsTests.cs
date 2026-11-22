using System.Security.Cryptography;
using GitleaksScanner.Domain;
using GitleaksScanner.Infrastructure.Security;

namespace GitleaksScanner.Tests;

/// <summary>Tests για το masking, το HMAC και την κρυπτογράφηση των secrets.</summary>
public class SecretsTests
{
    static readonly byte[] KeyA = RandomNumberGenerator.GetBytes(32);
    static readonly byte[] KeyB = RandomNumberGenerator.GetBytes(32);
    static readonly AesSecretProtector A = new(KeyA, KeyA);
    static readonly AesSecretProtector B = new(KeyB, KeyB);
    // Ψεύτικο token με τη μορφή GitHub PAT, μόνο για τα tests. Το "gitleaks:allow" λέει στο
    // gitleaks να μην το αναφέρει (αλλιώς το CI και ο έλεγχος πριν από το commit θα το έβρισκαν).
    const string Token = "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"; // gitleaks:allow

    /// <summary>Ελέγχει ότι η μερική απόκρυψη δείχνει μόνο τους 6 τελευταίους χαρακτήρες ενός μεγάλου secret.</summary>
    [Fact]
    public void Mask_Partial_ShowsOnlyLastSixCharacters()
    {
        var masked = SecretMasking.Mask(Token, "partial");
        Assert.Equal("••••••vW3xY5", masked);
        Assert.DoesNotContain(Token[..10], masked);
    }

    /// <summary>
    /// Ελέγχει ότι σε κοντά secrets φαίνεται το πολύ το 1/4 τους, και σε πολύ κοντά τίποτα,
    /// ώστε ένας κωδικός 8 χαρακτήρων να μη μένει σχεδόν εκτεθειμένος.
    /// </summary>
    /// <param name="secret">Το secret.</param>
    /// <param name="expected">Η αναμενόμενη masked μορφή.</param>
    [Theory]
    [InlineData("abc", "••••••")]
    [InlineData("password", "••••••rd")]
    [InlineData("1234567890123456", "••••••3456")]
    public void Mask_Partial_ShortSecretsRevealAtMostAQuarter(string secret, string expected) =>
        Assert.Equal(expected, SecretMasking.Mask(secret, "partial"));

    /// <summary>Ελέγχει ότι η πλήρης απόκρυψη δεν δείχνει τίποτα από το secret.</summary>
    [Fact]
    public void Mask_Full_HidesEverything() => Assert.Equal("REDACTED", SecretMasking.Mask(Token, "full"));

    /// <summary>Ελέγχει ότι το secret αντικαθίσταται μέσα στη γραμμή κώδικα.</summary>
    [Fact]
    public void MaskMatch_ReplacesSecretInContext()
    {
        var masked = SecretMasking.MaskMatch($"token = \"{Token}\"", Token, "partial");
        Assert.Equal("token = \"••••••vW3xY5\"", masked);
    }

    /// <summary>
    /// Ελέγχει ότι το κλειδί είναι σταθερό για το ίδιο leak και διαφορετικό όταν αλλάζει
    /// οτιδήποτε από κανόνα, αρχείο ή secret.
    /// </summary>
    [Fact]
    public void Key_IsStableAndDistinct()
    {
        var k = A.ComputeKey("github-pat", "config.ini", Token);
        Assert.Equal(k, A.ComputeKey("github-pat", "config.ini", Token));
        Assert.NotEqual(k, A.ComputeKey("github-pat", "other.ini", Token));
        Assert.NotEqual(k, A.ComputeKey("generic", "config.ini", Token));
        Assert.NotEqual(k, A.ComputeKey("github-pat", "config.ini", Token + "x"));
        Assert.Equal(32, k.Length);
    }

    /// <summary>
    /// Ελέγχει ότι το κλειδί εξαρτάται από το τοπικό HMAC key: χωρίς αυτό, δεν μπορείς να
    /// "μαντέψεις" ποιο secret αντιστοιχεί σε ένα κλειδί της βάσης.
    /// </summary>
    [Fact]
    public void Key_DependsOnHmacKey() =>
        Assert.NotEqual(A.ComputeKey("r", "f", "password"), B.ComputeKey("r", "f", "password"));

    /// <summary>Ελέγχει ότι ό,τι κρυπτογραφείται αποκρυπτογραφείται ίδιο, και με ελληνικά.</summary>
    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var text = $"κωδικός: {Token}";
        Assert.Equal(text, A.Decrypt(A.Encrypt(text)));
    }

    /// <summary>Ελέγχει ότι το ίδιο κείμενο κρυπτογραφείται κάθε φορά διαφορετικά (τυχαίο nonce).</summary>
    [Fact]
    public void Encrypt_UsesRandomNonce() =>
        Assert.NotEqual(A.Encrypt(Token), A.Encrypt(Token));

    /// <summary>Ελέγχει ότι με λάθος κλειδί η αποκρυπτογράφηση αποτυγχάνει αντί να επιστρέψει σκουπίδια.</summary>
    [Fact]
    public void Decrypt_WithWrongKey_Throws() =>
        Assert.ThrowsAny<CryptographicException>(() => B.Decrypt(A.Encrypt(Token)));

    /// <summary>Ελέγχει ότι αλλοιωμένα δεδομένα εντοπίζονται (το GCM ελέγχει και την ακεραιότητα).</summary>
    [Fact]
    public void Decrypt_TamperedData_Throws()
    {
        var blob = A.Encrypt(Token)!;
        blob[^1] ^= 0x01;
        Assert.ThrowsAny<CryptographicException>(() => A.Decrypt(blob));
    }

    /// <summary>Ελέγχει ότι κενά δεδομένα δεν κρυπτογραφούνται.</summary>
    [Fact]
    public void Encrypt_EmptyReturnsNull()
    {
        Assert.Null(A.Encrypt(""));
        Assert.Null(A.Decrypt(null));
    }
}
