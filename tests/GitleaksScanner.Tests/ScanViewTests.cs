namespace GitleaksScanner.Tests;

/// <summary>Tests για τη σύγκριση δύο scans του Gitleaks Scanner.</summary>
public class ScanViewTests
{
    /// <summary>Φτιάχνει ένα εύρημα με το κλειδί που δίνεται.</summary>
    /// <param name="key">Το κλειδί.</param>
    /// <param name="commit">Το commit.</param>
    /// <returns>Το εύρημα.</returns>
    static StoredFinding F(string key, string commit = "c1") => new() { Key = key, Commit = commit };

    /// <summary>Ελέγχει ότι "διορθωμένα" είναι όσα υπήρχαν πριν και δεν υπάρχουν τώρα.</summary>
    [Fact]
    public void Diff_FindsFixed()
    {
        var (prevKeys, fixedList) = ScanView.Diff([F("a"), F("b")], [F("b"), F("c")]);
        Assert.Equal(["a", "b"], prevKeys.Order());
        Assert.Equal("a", Assert.Single(fixedList).Key);
    }

    /// <summary>
    /// Ελέγχει ότι ένα secret που εμφανίζεται σε πολλά commits μετρά ως ένα "διορθωμένο", όχι ως πολλά.
    /// </summary>
    [Fact]
    public void Diff_CountsEachLeakOnce()
    {
        var (_, fixedList) = ScanView.Diff([F("a", "c1"), F("a", "c2"), F("a", "c3")], []);
        Assert.Single(fixedList);
    }
}
