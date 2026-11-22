namespace GitleaksScanner.Tests;

/// <summary>Tests για την ανάγνωση του κώδικα γύρω από ένα εύρημα.</summary>
public sealed class CodeContextTests : IDisposable
{
    readonly string _root = Path.Combine(Path.GetTempPath(), $"gl-ctx-{Guid.NewGuid():N}");
    readonly string _outside;

    /// <summary>Φτιάχνει ένα προσωρινό "repo" με ένα αρχείο 20 γραμμών και ένα αρχείο έξω από αυτό.</summary>
    public CodeContextTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "src"));
        File.WriteAllLines(Path.Combine(_root, "src", "app.py"), Enumerable.Range(1, 20).Select(i => $"line {i}"));
        File.WriteAllBytes(Path.Combine(_root, "image.bin"), [0x89, 0x50, 0x00, 0x47]);
        _outside = _root + "-outside.txt";
        File.WriteAllText(_outside, "SECRET OUTSIDE REPO");
    }

    /// <summary>Σβήνει τα προσωρινά αρχεία.</summary>
    public void Dispose()
    {
        Directory.Delete(_root, recursive: true);
        File.Delete(_outside);
    }

    /// <summary>Ελέγχει ότι τα απόλυτα paths μέσα στο repo γίνονται σχετικά, ώστε το κλειδί να μην αλλάζει ανά scan.</summary>
    [Fact]
    public void Relative_StripsRepoRoot()
    {
        var ctx = new CodeContext(_root, "dir");
        Assert.Equal(Path.Combine("src", "app.py"), ctx.Relative(Path.Combine(_root, "src", "app.py")));
        Assert.Equal("src/app.py", ctx.Relative("src/app.py"));
    }

    /// <summary>Ελέγχει ότι επιστρέφονται ±4 γραμμές γύρω από το εύρημα, με σωστή αρίθμηση.</summary>
    [Fact]
    public async Task GetAsync_ReturnsLinesAround()
    {
        var snippet = await new CodeContext(_root, "dir").GetAsync(Path.Combine("src", "app.py"), null, 10, 10);
        Assert.NotNull(snippet);
        Assert.Equal(6, snippet.Start);
        Assert.Equal(9, snippet.Lines.Length);
        Assert.Equal("line 10", snippet.Lines[4]);
    }

    /// <summary>Ελέγχει ότι στην αρχή του αρχείου το κομμάτι ξεκινά από τη γραμμή 1.</summary>
    [Fact]
    public async Task GetAsync_ClampsAtFileStart()
    {
        var snippet = await new CodeContext(_root, "dir").GetAsync(Path.Combine("src", "app.py"), null, 2, 2);
        Assert.Equal(1, snippet!.Start);
        Assert.Equal("line 1", snippet.Lines[0]);
    }

    /// <summary>
    /// Ελέγχει ότι δεν διαβάζονται αρχεία έξω από το repo μέσω "../". Αλλιώς ένα κακόβουλο path
    /// στο report θα μπορούσε να αποκαλύψει οποιοδήποτε αρχείο του υπολογιστή.
    /// </summary>
    [Fact]
    public async Task GetAsync_RefusesPathTraversal()
    {
        var escape = Path.Combine("..", Path.GetFileName(_outside));
        Assert.Null(await new CodeContext(_root, "dir").GetAsync(escape, null, 1, 1));
    }

    /// <summary>Ελέγχει ότι τα binary αρχεία δεν επιστρέφονται ως κώδικας.</summary>
    [Fact]
    public async Task GetAsync_SkipsBinaryFiles() =>
        Assert.Null(await new CodeContext(_root, "dir").GetAsync("image.bin", null, 1, 1));

    /// <summary>Ελέγχει ότι ένα κομμάτι κώδικα επιβιώνει τη μετατροπή σε JSON και πίσω.</summary>
    [Fact]
    public void Serialize_RoundTrips()
    {
        var s = new CodeContext.Snippet(3, ["a", "β"]);
        var back = CodeContext.Deserialize(CodeContext.Serialize(s));
        Assert.Equal(3, back!.Start);
        Assert.Equal(["a", "β"], back.Lines);
    }
}
