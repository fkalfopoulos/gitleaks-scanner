using Microsoft.Data.Sqlite;

namespace GitleaksScanner;

/// <summary>
/// Αποθήκευση των scans, των ευρημάτων και του triage σε SQLite.
/// </summary>
/// <param name="dbPath">Η διαδρομή του αρχείου SQLite.</param>
public class Store(string dbPath)
{
    /// <summary>Οι επιτρεπτές τιμές για το status του triage.</summary>
    public static readonly string[] TriageStatuses =
        ["pending", "confirmed", "false_positive", "ignored", "fixed", "risk_accepted"];

    readonly string _cs = new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString();

    /// <summary>Ανοίγει νέα σύνδεση με ενεργά foreign keys.</summary>
    /// <returns>Μια ανοιχτή σύνδεση. Ο caller την κλείνει με <c>using</c>.</returns>
    SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        Exec(c, "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
        return c;
    }

    /// <summary>Εκτελεί μια SQL εντολή που δεν επιστρέφει δεδομένα.</summary>
    /// <param name="c">Η σύνδεση.</param>
    /// <param name="sql">Το SQL.</param>
    /// <param name="ps">Οι παράμετροι.</param>
    static void Exec(SqliteConnection c, string sql, params (string, object?)[] ps)
    {
        using var cmd = Cmd(c, sql, ps);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Φτιάχνει SQL εντολή με παραμέτρους (ποτέ με string concatenation, για αποφυγή SQL injection).</summary>
    /// <param name="c">Η σύνδεση.</param>
    /// <param name="sql">Το SQL, με παραμέτρους της μορφής <c>$όνομα</c>.</param>
    /// <param name="ps">Ζεύγη (όνομα, τιμή) για τις παραμέτρους.</param>
    /// <returns>Η εντολή, έτοιμη για εκτέλεση.</returns>
    static SqliteCommand Cmd(SqliteConnection c, string sql, params (string, object?)[] ps)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return cmd;
    }

    /// <summary>Δημιουργεί τους πίνακες αν δεν υπάρχουν και προσθέτει στήλες που μπήκαν σε νεότερες εκδόσεις.</summary>
    public void Init()
    {
        using var c = Open();
        Exec(c, "PRAGMA journal_mode = WAL;");
        Exec(c, """
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                source       TEXT NOT NULL,
                mode         TEXT NOT NULL,
                full_history INTEGER NOT NULL,
                mask_mode    TEXT NOT NULL,
                started_at   TEXT NOT NULL,
                duration_ms  INTEGER NOT NULL,
                count        INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_source ON scans(source, mode, full_history, id);

            CREATE TABLE IF NOT EXISTS findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                key           TEXT NOT NULL,
                rule_id       TEXT, description TEXT, file TEXT,
                start_line    INTEGER, end_line INTEGER,
                commit_sha    TEXT, author TEXT, email TEXT, date TEXT, message TEXT,
                entropy       REAL,
                secret_masked TEXT, match_masked TEXT, link TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            -- secret_enc / match_enc: κρυπτογραφημένα για το unmask (στήλες που μπήκαν αργότερα, βλ. AddColumn).

            -- Το triage ανήκει στο (repo, κλειδί) και όχι σε ένα scan: ένα false positive
            -- μένει μαρκαρισμένο σε όλα τα επόμενα scans του ίδιου repo.
            CREATE TABLE IF NOT EXISTS triage (
                source     TEXT NOT NULL,
                key        TEXT NOT NULL,
                status     TEXT NOT NULL,
                note       TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                PRIMARY KEY (source, key)
            );
            """);
        AddColumn(c, "findings", "secret_enc", "BLOB");
        AddColumn(c, "findings", "match_enc", "BLOB");
        AddColumn(c, "findings", "context_enc", "BLOB");
    }

    /// <summary>
    /// Προσθέτει μια στήλη σε πίνακα, αν δεν υπάρχει ήδη (η SQLite δεν έχει "ADD COLUMN IF NOT EXISTS").
    /// Έτσι μια παλιά βάση αναβαθμίζεται χωρίς να χαθούν δεδομένα.
    /// </summary>
    /// <param name="c">Η σύνδεση.</param>
    /// <param name="table">Ο πίνακας (σταθερό όνομα από τον κώδικα, όχι από τον χρήστη).</param>
    /// <param name="column">Η στήλη.</param>
    /// <param name="type">Ο τύπος της στήλης.</param>
    static void AddColumn(SqliteConnection c, string table, string column, string type)
    {
        using var cmd = Cmd(c, $"SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = $n", ("$n", column));
        if ((long)cmd.ExecuteScalar()! == 0) Exec(c, $"ALTER TABLE {table} ADD COLUMN {column} {type}");
    }

    /// <summary>Επιστρέφει τα κρυπτογραφημένα secret, match και κώδικα ενός ευρήματος (μόνο για το unmask).</summary>
    /// <param name="findingId">Το id του ευρήματος.</param>
    /// <returns>Τα κρυπτογραφημένα δεδομένα, ή <c>null</c> αν δεν υπάρχει το εύρημα.</returns>
    public (byte[]? Secret, byte[]? Match, byte[]? Context)? GetEncrypted(long findingId)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT secret_enc, match_enc, context_enc FROM findings WHERE id = $id", ("$id", findingId));
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        byte[]? B(int i) => r.IsDBNull(i) ? null : (byte[])r[i];
        return (B(0), B(1), B(2));
    }

    /// <summary>Αποθηκεύει ένα scan και όλα τα ευρήματά του σε μία transaction (ή όλα ή τίποτα).</summary>
    /// <param name="source">Το κανονικοποιημένο όνομα της πηγής.</param>
    /// <param name="mode">"git" ή "dir".</param>
    /// <param name="fullHistory">Αν σκαναρίστηκε όλο το ιστορικό.</param>
    /// <param name="maskMode">"partial" ή "full".</param>
    /// <param name="startedAt">Πότε ξεκίνησε.</param>
    /// <param name="durationMs">Πόσο κράτησε.</param>
    /// <param name="findings">Τα ευρήματα.</param>
    /// <returns>Το id του νέου scan.</returns>
    public long SaveScan(string source, string mode, bool fullHistory, string maskMode,
        DateTime startedAt, long durationMs, IReadOnlyList<StoredFinding> findings)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        using var ins = Cmd(c, """
            INSERT INTO scans (source, mode, full_history, mask_mode, started_at, duration_ms, count)
            VALUES ($s, $m, $f, $mm, $t, $d, $n) RETURNING id
            """, ("$s", source), ("$m", mode), ("$f", fullHistory ? 1 : 0), ("$mm", maskMode),
            ("$t", startedAt.ToString("O")), ("$d", durationMs), ("$n", findings.Count));
        ins.Transaction = tx;
        var scanId = (long)ins.ExecuteScalar()!;

        using var fc = Cmd(c, """
            INSERT INTO findings (scan_id, key, rule_id, description, file, start_line, end_line,
              commit_sha, author, email, date, message, entropy, secret_masked, match_masked, link,
              secret_enc, match_enc, context_enc)
            VALUES ($scan, $key, $rule, $desc, $file, $sl, $el, $commit, $author, $email, $date,
              $msg, $ent, $sec, $match, $link, $senc, $menc, $cenc)
            """);
        fc.Transaction = tx;
        foreach (var n in new[] { "$scan", "$key", "$rule", "$desc", "$file", "$sl", "$el", "$commit",
                     "$author", "$email", "$date", "$msg", "$ent", "$sec", "$match", "$link", "$senc", "$menc", "$cenc" })
            fc.Parameters.Add(new SqliteParameter(n, null));

        foreach (var f in findings)
        {
            object?[] vals = [scanId, f.Key, f.RuleId, f.Description, f.File, f.StartLine, f.EndLine,
                f.Commit, f.Author, f.Email, f.Date, f.Message, f.Entropy, f.SecretMasked, f.MatchMasked, f.Link,
                f.SecretEnc, f.MatchEnc, f.ContextEnc];
            for (var i = 0; i < vals.Length; i++) fc.Parameters[i].Value = vals[i] ?? DBNull.Value;
            fc.ExecuteNonQuery();
        }
        tx.Commit();
        return scanId;
    }

    /// <summary>Επιστρέφει τα πιο πρόσφατα scans.</summary>
    /// <param name="limit">Το μέγιστο πλήθος.</param>
    /// <returns>Τα scans, από το νεότερο στο παλαιότερο.</returns>
    public List<ScanInfo> ListScans(int limit = 200)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT * FROM scans ORDER BY id DESC LIMIT $l", ("$l", limit));
        using var r = cmd.ExecuteReader();
        var list = new List<ScanInfo>();
        while (r.Read()) list.Add(ReadScan(r));
        return list;
    }

    /// <summary>Επιστρέφει τα στοιχεία ενός scan.</summary>
    /// <param name="id">Το id του scan.</param>
    /// <returns>Το scan, ή <c>null</c> αν δεν υπάρχει.</returns>
    public ScanInfo? GetScan(long id)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT * FROM scans WHERE id = $id", ("$id", id));
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadScan(r) : null;
    }

    /// <summary>Βρίσκει το προηγούμενο scan του ίδιου repo με τις ίδιες ρυθμίσεις, για σύγκριση.</summary>
    /// <remarks>
    /// Οι ρυθμίσεις πρέπει να είναι ίδιες: αν συγκρίνεις ένα full-history scan με ένα dir scan,
    /// τα μισά ευρήματα θα φαίνονταν ψευδώς "διορθωμένα".
    /// </remarks>
    /// <param name="s">Το scan.</param>
    /// <returns>Το id του προηγούμενου scan, ή <c>null</c> αν είναι το πρώτο.</returns>
    public long? PreviousScanId(ScanInfo s)
    {
        using var c = Open();
        using var cmd = Cmd(c, """
            SELECT id FROM scans WHERE source = $s AND mode = $m AND full_history = $f AND id < $id
            ORDER BY id DESC LIMIT 1
            """, ("$s", s.Source), ("$m", s.Mode), ("$f", s.FullHistory ? 1 : 0), ("$id", s.Id));
        return cmd.ExecuteScalar() is long v ? v : null;
    }

    /// <summary>Διαγράφει ένα scan και τα ευρήματά του (όχι το triage, που ανήκει στο repo).</summary>
    /// <param name="id">Το id του scan.</param>
    /// <returns><c>true</c> αν βρέθηκε και διαγράφηκε.</returns>
    public bool DeleteScan(long id)
    {
        using var c = Open();
        using var cmd = Cmd(c, "DELETE FROM scans WHERE id = $id", ("$id", id));
        return cmd.ExecuteNonQuery() > 0;
    }

    /// <summary>Επιστρέφει τα ευρήματα ενός scan, χωρίς τα κρυπτογραφημένα δεδομένα.</summary>
    /// <param name="scanId">Το id του scan.</param>
    /// <returns>Τα ευρήματα.</returns>
    public List<StoredFinding> GetFindings(long scanId)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT * FROM findings WHERE scan_id = $id ORDER BY id", ("$id", scanId));
        using var r = cmd.ExecuteReader();
        var list = new List<StoredFinding>();
        while (r.Read())
            list.Add(new StoredFinding
            {
                Id = r.GetInt64(r.GetOrdinal("id")),
                CanUnmask = !r.IsDBNull(r.GetOrdinal("match_enc")),
                Key = r.GetString(r.GetOrdinal("key")),
                RuleId = Str(r, "rule_id"), Description = Str(r, "description"), File = Str(r, "file"),
                StartLine = r.GetInt32(r.GetOrdinal("start_line")), EndLine = r.GetInt32(r.GetOrdinal("end_line")),
                Commit = Str(r, "commit_sha"), Author = Str(r, "author"), Email = Str(r, "email"),
                Date = Str(r, "date"), Message = Str(r, "message"), Entropy = r.GetDouble(r.GetOrdinal("entropy")),
                SecretMasked = Str(r, "secret_masked"), MatchMasked = Str(r, "match_masked"), Link = Str(r, "link")
            });
        return list;
    }

    /// <summary>Επιστρέφει το triage όλων των ευρημάτων ενός repo.</summary>
    /// <param name="source">Το repo.</param>
    /// <returns>Λεξικό κλειδί ευρήματος → (status, σημείωση).</returns>
    public Dictionary<string, (string Status, string Note)> GetTriage(string source)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT key, status, note FROM triage WHERE source = $s", ("$s", source));
        using var r = cmd.ExecuteReader();
        var map = new Dictionary<string, (string, string)>();
        while (r.Read()) map[r.GetString(0)] = (r.GetString(1), r.GetString(2));
        return map;
    }

    /// <summary>
    /// Ορίζει το triage ενός ευρήματος. Αν επιστρέψει σε "pending" χωρίς σημείωση, η εγγραφή σβήνεται.
    /// </summary>
    /// <param name="source">Το repo.</param>
    /// <param name="key">Το κλειδί του ευρήματος.</param>
    /// <param name="status">Το νέο status.</param>
    /// <param name="note">Η σημείωση.</param>
    public void SetTriage(string source, string key, string status, string note)
    {
        using var c = Open();
        if (status == "pending" && note.Length == 0)
        {
            Exec(c, "DELETE FROM triage WHERE source = $s AND key = $k", ("$s", source), ("$k", key));
            return;
        }
        Exec(c, """
            INSERT INTO triage (source, key, status, note, updated_at) VALUES ($s, $k, $st, $n, $t)
            ON CONFLICT (source, key) DO UPDATE SET status = $st, note = $n, updated_at = $t
            """, ("$s", source), ("$k", key), ("$st", status), ("$n", note), ("$t", DateTime.UtcNow.ToString("O")));
    }

    /// <summary>Διαβάζει μια στήλη κειμένου που μπορεί να είναι NULL.</summary>
    /// <param name="r">Ο reader.</param>
    /// <param name="col">Το όνομα της στήλης.</param>
    /// <returns>Η τιμή, ή <c>null</c>.</returns>
    static string? Str(SqliteDataReader r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : r.GetString(i);
    }

    /// <summary>Μετατρέπει την τρέχουσα γραμμή του πίνακα scans σε <see cref="ScanInfo"/>.</summary>
    /// <param name="r">Ο reader, τοποθετημένος σε μια γραμμή.</param>
    /// <returns>Το scan.</returns>
    static ScanInfo ReadScan(SqliteDataReader r) => new(
        r.GetInt64(r.GetOrdinal("id")), r.GetString(r.GetOrdinal("source")), r.GetString(r.GetOrdinal("mode")),
        r.GetInt32(r.GetOrdinal("full_history")) == 1, r.GetString(r.GetOrdinal("mask_mode")),
        r.GetString(r.GetOrdinal("started_at")), r.GetInt64(r.GetOrdinal("duration_ms")), r.GetInt32(r.GetOrdinal("count")));
}

/// <summary>Τα στοιχεία ενός scan.</summary>
/// <param name="Id">Το id.</param>
/// <param name="Source">Το repo ή ο φάκελος.</param>
/// <param name="Mode">"git" ή "dir".</param>
/// <param name="FullHistory">Αν σκαναρίστηκε όλο το ιστορικό.</param>
/// <param name="MaskMode">"partial" ή "full".</param>
/// <param name="StartedAt">Πότε ξεκίνησε (ISO 8601, UTC).</param>
/// <param name="DurationMs">Πόσο κράτησε.</param>
/// <param name="Count">Πόσα ευρήματα βρέθηκαν.</param>
public record ScanInfo(long Id, string Source, string Mode, bool FullHistory, string MaskMode,
    string StartedAt, long DurationMs, int Count);

/// <summary>Ένα εύρημα όπως αποθηκεύεται στη βάση. Δεν περιέχει ποτέ το raw secret σε αναγνώσιμη μορφή.</summary>
public class StoredFinding
{
    /// <summary>Το id στη βάση.</summary>
    public long Id { get; set; }
    /// <summary>Αν υπάρχουν κρυπτογραφημένα δεδομένα για unmask (όχι σε scans πριν από αυτή τη λειτουργία).</summary>
    public bool CanUnmask { get; set; }
    /// <summary>Το secret, κρυπτογραφημένο. Μόνο κατά την αποθήκευση· δεν διαβάζεται μαζί με τη λίστα.</summary>
    public byte[]? SecretEnc { get; set; }
    /// <summary>Το match, κρυπτογραφημένο. Μόνο κατά την αποθήκευση.</summary>
    public byte[]? MatchEnc { get; set; }
    /// <summary>Ο κώδικας γύρω από το εύρημα, κρυπτογραφημένος. Μόνο κατά την αποθήκευση.</summary>
    public byte[]? ContextEnc { get; set; }
    /// <summary>Το σταθερό κλειδί (βλ. <see cref="Secrets.Key"/>), κοινό για το ίδιο leak σε όλα τα scans.</summary>
    public string Key { get; set; } = "";
    /// <summary>Ο κανόνας του gitleaks.</summary>
    public string? RuleId { get; set; }
    /// <summary>Η περιγραφή του κανόνα.</summary>
    public string? Description { get; set; }
    /// <summary>Το σχετικό path του αρχείου.</summary>
    public string? File { get; set; }
    /// <summary>Η πρώτη γραμμή.</summary>
    public int StartLine { get; set; }
    /// <summary>Η τελευταία γραμμή.</summary>
    public int EndLine { get; set; }
    /// <summary>Το commit (μόνο σε git mode).</summary>
    public string? Commit { get; set; }
    /// <summary>Ο συγγραφέας του commit.</summary>
    public string? Author { get; set; }
    /// <summary>Το email του συγγραφέα.</summary>
    public string? Email { get; set; }
    /// <summary>Η ημερομηνία του commit.</summary>
    public string? Date { get; set; }
    /// <summary>Το μήνυμα του commit.</summary>
    public string? Message { get; set; }
    /// <summary>Η εντροπία του secret.</summary>
    public double Entropy { get; set; }
    /// <summary>Το secret με μερική ή πλήρη απόκρυψη.</summary>
    public string? SecretMasked { get; set; }
    /// <summary>Το match με κρυμμένο το secret.</summary>
    public string? MatchMasked { get; set; }
    /// <summary>Link προς το αρχείο στο GitHub/GitLab/Bitbucket, αν υπάρχει.</summary>
    public string? Link { get; set; }
}
