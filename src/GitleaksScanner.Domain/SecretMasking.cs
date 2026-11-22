namespace GitleaksScanner.Domain;

/// <summary>
/// Οι κανόνες απόκρυψης των secrets για εμφάνιση στο UI.
/// </summary>
public static class SecretMasking
{
    const string Dots = "••••••";

    /// <summary>Μερική απόκρυψη: φαίνονται μόνο οι τελευταίοι χαρακτήρες.</summary>
    public const string Partial = "partial";

    /// <summary>Πλήρης απόκρυψη.</summary>
    public const string Full = "full";

    /// <summary>Μετατρέπει ό,τι ζήτησε ο χρήστης σε έγκυρο τρόπο απόκρυψης (προεπιλογή: μερική).</summary>
    /// <param name="mode">Η τιμή του αιτήματος.</param>
    /// <returns><see cref="Full"/> ή <see cref="Partial"/>.</returns>
    public static string Normalize(string? mode) => mode == Full ? Full : Partial;

    /// <summary>
    /// Κρύβει ένα secret αφήνοντας ορατούς μόνο τους τελευταίους χαρακτήρες, ώστε να αναγνωρίζεις
    /// ΠΟΙΟ key διέρρευσε χωρίς να μπορεί να ανακατασκευαστεί.
    /// </summary>
    /// <remarks>
    /// Το πολύ 6 χαρακτήρες και ποτέ πάνω από το 1/4 του secret, για να μη μένει εκτεθειμένο ένα
    /// κοντό secret. Το μήκος δεν αποκαλύπτεται (σταθερός αριθμός τελειών).
    /// </remarks>
    /// <param name="secret">Το raw secret.</param>
    /// <param name="mode"><see cref="Partial"/> ή <see cref="Full"/>.</param>
    /// <returns>Π.χ. "••••••vW3xY5", ή "REDACTED" σε πλήρη απόκρυψη, ή κενό αν δεν υπάρχει secret.</returns>
    public static string Mask(string? secret, string mode)
    {
        if (string.IsNullOrEmpty(secret)) return "";
        if (mode == Full) return "REDACTED";
        var show = Math.Min(6, secret.Length / 4);
        return show == 0 ? Dots : Dots + secret[^show..];
    }

    /// <summary>Αντικαθιστά το secret μέσα στο "match" (το κείμενο γύρω του) με τη masked εκδοχή του.</summary>
    /// <param name="match">Το κείμενο που ταίριαξε ο κανόνας.</param>
    /// <param name="secret">Το raw secret.</param>
    /// <param name="mode"><see cref="Partial"/> ή <see cref="Full"/>.</param>
    /// <returns>Το κείμενο με κρυμμένο το secret.</returns>
    public static string MaskMatch(string? match, string? secret, string mode)
    {
        if (string.IsNullOrEmpty(match)) return "";
        if (string.IsNullOrEmpty(secret)) return match;
        return match.Replace(secret, Mask(secret, mode));
    }
}
