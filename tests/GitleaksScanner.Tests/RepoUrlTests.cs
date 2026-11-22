namespace GitleaksScanner.Tests;

/// <summary>Tests για την κανονικοποίηση των URLs των repositories.</summary>
public class RepoUrlTests
{
    /// <summary>Ελέγχει ότι διαφορετικές γραφές του ίδιου repo καταλήγουν στο ίδιο URL.</summary>
    /// <param name="url">Το URL όπως το έγραψε ο χρήστης.</param>
    [Theory]
    [InlineData("https://github.com/user/repo")]
    [InlineData("https://GitHub.com/user/repo")]
    [InlineData("https://github.com/user/repo/")]
    [InlineData("https://github.com/user/repo.git")]
    [InlineData("https://github.com/user/repo.git/")]
    public void Normalize_SameRepoSameSource(string url) =>
        Assert.Equal("https://github.com/user/repo", RepoUrl.Normalize(new Uri(url)));

    /// <summary>Ελέγχει ότι links φτιάχνονται μόνο για γνωστούς hosts.</summary>
    [Fact]
    public void WebBase_OnlyForKnownHosts()
    {
        Assert.Equal("https://gitlab.com/g/p", RepoUrl.WebBase(new Uri("https://gitlab.com/g/p.git")));
        Assert.Null(RepoUrl.WebBase(new Uri("https://git.example.com/g/p.git")));
    }

    /// <summary>Ελέγχει ότι αναγνωρίζεται το προφίλ χρήστη GitHub, ώστε να δοθεί σωστό μήνυμα λάθους.</summary>
    [Fact]
    public void IsGitHubProfile_DetectsProfiles()
    {
        Assert.True(RepoUrl.IsGitHubProfile(new Uri("https://github.com/fkalfopoulos")));
        Assert.True(RepoUrl.IsGitHubProfile(new Uri("https://github.com/fkalfopoulos/")));
        Assert.False(RepoUrl.IsGitHubProfile(new Uri("https://github.com/fkalfopoulos/repo")));
        Assert.False(RepoUrl.IsGitHubProfile(new Uri("https://gitlab.com/someone")));
    }
}
