namespace GitleaksScanner.Application.Common;

/// <summary>Το είδος ενός σφάλματος, ώστε το presentation layer να το μεταφράσει σε HTTP status.</summary>
public enum ErrorKind
{
    /// <summary>Άκυρο αίτημα από τον χρήστη (HTTP 400).</summary>
    Validation,
    /// <summary>Δεν βρέθηκε αυτό που ζητήθηκε (HTTP 404).</summary>
    NotFound,
    /// <summary>Αποτυχία εξωτερικού εργαλείου ή υπηρεσίας (HTTP 500/502).</summary>
    Failure,
    /// <summary>Εξωτερική υπηρεσία αρνήθηκε λόγω ορίου αιτημάτων (HTTP 429).</summary>
    RateLimited,
}

/// <summary>Ένα σφάλμα με είδος και μήνυμα για τον χρήστη.</summary>
/// <param name="Kind">Το είδος.</param>
/// <param name="Message">Το μήνυμα (στα ελληνικά, εμφανίζεται στο UI).</param>
public record AppError(ErrorKind Kind, string Message);

/// <summary>
/// Το αποτέλεσμα μιας λειτουργίας: είτε τιμή είτε σφάλμα. Αντί για exceptions στα αναμενόμενα
/// σφάλματα (π.χ. λάθος input), που κάνουν τη ροή του κώδικα πιο δύσκολη στην παρακολούθηση.
/// </summary>
/// <typeparam name="T">Ο τύπος της τιμής.</typeparam>
public readonly record struct Result<T>
{
    /// <summary>Η τιμή, αν πέτυχε.</summary>
    public T? Value { get; }

    /// <summary>Το σφάλμα, αν απέτυχε.</summary>
    public AppError? Error { get; }

    /// <summary>Αν πέτυχε.</summary>
    public bool IsSuccess => Error is null;

    /// <summary>Δημιουργεί αποτέλεσμα (χρησιμοποιείται από τις στατικές μεθόδους).</summary>
    /// <param name="value">Η τιμή.</param>
    /// <param name="error">Το σφάλμα.</param>
    Result(T? value, AppError? error)
    {
        Value = value;
        Error = error;
    }

    /// <summary>Δημιουργεί επιτυχημένο αποτέλεσμα.</summary>
    /// <param name="value">Η τιμή.</param>
    /// <returns>Το αποτέλεσμα.</returns>
    public static Result<T> Ok(T value) => new(value, null);

    /// <summary>Δημιουργεί αποτυχημένο αποτέλεσμα.</summary>
    /// <param name="kind">Το είδος του σφάλματος.</param>
    /// <param name="message">Το μήνυμα.</param>
    /// <returns>Το αποτέλεσμα.</returns>
    public static Result<T> Fail(ErrorKind kind, string message) => new(default, new AppError(kind, message));

    /// <summary>Μεταφέρει ένα σφάλμα σε αποτέλεσμα άλλου τύπου.</summary>
    /// <param name="error">Το σφάλμα.</param>
    /// <returns>Το αποτέλεσμα.</returns>
    public static Result<T> Fail(AppError error) => new(default, error);
}
