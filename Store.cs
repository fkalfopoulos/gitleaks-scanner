using Microsoft.Data.Sqlite;

/// Αποθήκευση scans, ευρημάτων και triage σε SQLite.
class Store(string dbPath)
{
    public static readonly string[] TriageStatuses =
        ["pending", "confirmed", "false_positive", "ignored", "fixed", "risk_accepted"];

    readonly string _cs = new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString();

    SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        Exec(c, "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
        return c;
    }

    static void Exec(SqliteConnection c, string sql, params (string, object?)[] ps)
    {
        using var cmd = Cmd(c, sql, ps);
        cmd.ExecuteNonQuery();
    }

    static SqliteCommand Cmd(SqliteConnection c, string sql, params (string, object?)[] ps)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return cmd;
    }

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

    // Η SQLite δεν έχει "ADD COLUMN IF NOT EXISTS": ελέγχουμε πρώτα αν υπάρχει η στήλη.
    static void AddColumn(SqliteConnection c, string table, string column, string type)
    {
        using var cmd = Cmd(c, $"SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = $n", ("$n", column));
        if ((long)cmd.ExecuteScalar()! == 0) Exec(c, $"ALTER TABLE {table} ADD COLUMN {column} {type}");
    }

    /// Τα κρυπτογραφημένα secret/match ενός ευρήματος (μόνο για το unmask).
    public (byte[]? Secret, byte[]? Match, byte[]? Context)? GetEncrypted(long findingId)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT secret_enc, match_enc, context_enc FROM findings WHERE id = $id", ("$id", findingId));
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        byte[]? B(int i) => r.IsDBNull(i) ? null : (byte[])r[i];
        return (B(0), B(1), B(2));
    }

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

    public List<ScanInfo> ListScans(int limit = 200)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT * FROM scans ORDER BY id DESC LIMIT $l", ("$l", limit));
        using var r = cmd.ExecuteReader();
        var list = new List<ScanInfo>();
        while (r.Read()) list.Add(ReadScan(r));
        return list;
    }

    public ScanInfo? GetScan(long id)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT * FROM scans WHERE id = $id", ("$id", id));
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadScan(r) : null;
    }

    /// Το προηγούμενο scan του ίδιου repo με τις ΙΔΙΕΣ ρυθμίσεις: αν συγκρίνεις ένα full-history
    /// scan με ένα dir scan, τα μισά ευρήματα θα φαίνονταν ψευδώς "διορθωμένα".
    public long? PreviousScanId(ScanInfo s)
    {
        using var c = Open();
        using var cmd = Cmd(c, """
            SELECT id FROM scans WHERE source = $s AND mode = $m AND full_history = $f AND id < $id
            ORDER BY id DESC LIMIT 1
            """, ("$s", s.Source), ("$m", s.Mode), ("$f", s.FullHistory ? 1 : 0), ("$id", s.Id));
        return cmd.ExecuteScalar() is long v ? v : null;
    }

    public bool DeleteScan(long id)
    {
        using var c = Open();
        using var cmd = Cmd(c, "DELETE FROM scans WHERE id = $id", ("$id", id));
        return cmd.ExecuteNonQuery() > 0;
    }

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

    public Dictionary<string, (string Status, string Note)> GetTriage(string source)
    {
        using var c = Open();
        using var cmd = Cmd(c, "SELECT key, status, note FROM triage WHERE source = $s", ("$s", source));
        using var r = cmd.ExecuteReader();
        var map = new Dictionary<string, (string, string)>();
        while (r.Read()) map[r.GetString(0)] = (r.GetString(1), r.GetString(2));
        return map;
    }

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

    static string? Str(SqliteDataReader r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : r.GetString(i);
    }

    static ScanInfo ReadScan(SqliteDataReader r) => new(
        r.GetInt64(r.GetOrdinal("id")), r.GetString(r.GetOrdinal("source")), r.GetString(r.GetOrdinal("mode")),
        r.GetInt32(r.GetOrdinal("full_history")) == 1, r.GetString(r.GetOrdinal("mask_mode")),
        r.GetString(r.GetOrdinal("started_at")), r.GetInt64(r.GetOrdinal("duration_ms")), r.GetInt32(r.GetOrdinal("count")));
}

record ScanInfo(long Id, string Source, string Mode, bool FullHistory, string MaskMode,
    string StartedAt, long DurationMs, int Count);

class StoredFinding
{
    public long Id { get; set; }
    public bool CanUnmask { get; set; }
    // Μόνο κατά την αποθήκευση· δεν διαβάζονται ποτέ μαζί με τη λίστα.
    public byte[]? SecretEnc { get; set; }
    public byte[]? MatchEnc { get; set; }
    public byte[]? ContextEnc { get; set; }
    public string Key { get; set; } = "";
    public string? RuleId { get; set; }
    public string? Description { get; set; }
    public string? File { get; set; }
    public int StartLine { get; set; }
    public int EndLine { get; set; }
    public string? Commit { get; set; }
    public string? Author { get; set; }
    public string? Email { get; set; }
    public string? Date { get; set; }
    public string? Message { get; set; }
    public double Entropy { get; set; }
    public string? SecretMasked { get; set; }
    public string? MatchMasked { get; set; }
    public string? Link { get; set; }
}
