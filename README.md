# 🔐 Gitleaks Scanner

[![CI](https://github.com/fkalfopoulos/gitleaks-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/fkalfopoulos/gitleaks-scanner/actions/workflows/ci.yml)

Τοπικό web app (ASP.NET Core / C#) που σκανάρει Git repositories για secrets (API keys, tokens,
κωδικούς) με το [gitleaks](https://github.com/gitleaks/gitleaks), κρατά ιστορικό και δείχνει τι
άλλαξε από scan σε scan.

## Δυνατότητες

- **Scan** ενός repo (https URL ή τοπικός φάκελος), είτε σε όλο το ιστορικό commits είτε μόνο
  στα τρέχοντα αρχεία.
- **Όλα τα repos ενός χρήστη GitHub**: δίνεις `https://github.com/<user>`, διαλέγεις repos και
  σκανάρονται ένα-ένα.
- **Ιστορικό και triage**: κάθε εύρημα μαρκάρεται ως confirmed, false positive, ignored, fixed ή
  risk accepted, με σημείωση. Το triage ισχύει και στα επόμενα scans του ίδιου repo.
- **Σύγκριση**: το rescan δείχνει τα **νέα** και τα **διορθωμένα** ευρήματα σε σχέση με το
  προηγούμενο scan με τις ίδιες ρυθμίσεις.
- **Μερική απόκρυψη**: τα secrets εμφανίζονται ως `••••••ab12`.
- **Unmask**: με ένα κλικ βλέπεις το secret και τον κώδικα γύρω του, όπως ήταν στο commit.

## Εγκατάσταση

Χρειάζεσαι [.NET 11 SDK](https://dotnet.microsoft.com/download), `git` και `gitleaks`:

```bash
brew install --cask dotnet-sdk
brew install gitleaks
```

## Εκτέλεση

```bash
dotnet run
```

Άνοιξε το http://localhost:5080.

## Ασφάλεια

Το app τρέχει εντολές (`git`, `gitleaks`) στο μηχάνημά σου και κρατά secrets, γι' αυτό:

- Ακούει **μόνο στο localhost** και απορρίπτει αιτήματα με άλλο `Host` header (προστασία από
  DNS rebinding).
- Δέχεται μόνο `https://` URLs (όχι `file://`, `ext::` κ.λπ.) και τρέχει τις εντολές χωρίς shell.
- **Αγνοεί το `.gitleaks.toml` των ξένων repos**, γιατί ένα repo μπορεί να το χρησιμοποιήσει για
  να κρύψει τα secrets του. Υπάρχει επιλογή για να το ενεργοποιήσεις.
- Τα secrets και ο κώδικας αποθηκεύονται **κρυπτογραφημένα** (AES-256-GCM). Αποκρυπτογραφούνται
  μόνο όταν πατάς Unmask σε ένα εύρημα. Η ταυτοποίηση γίνεται με HMAC, όχι με απλό hash.
- Τα clones σβήνονται αμέσως μετά το scan.

Ο φάκελος `data/` περιέχει τη βάση (`scanner.db`) και τα κλειδιά (`enc.key`, `hmac.key`). Είναι
στο `.gitignore` και **δεν πρέπει να ανέβει ποτέ** σε repo. Αν σβήσεις το `enc.key`, τα παλιά
scans δεν θα έχουν πια unmask.

## Δομή

| Αρχείο | Περιεχόμενο |
| --- | --- |
| `Program.cs` | Ρυθμίσεις και εκκίνηση |
| `Api.cs` | Τα HTTP endpoints |
| `ScanService.cs` | Η διαδικασία ενός scan: clone, gitleaks, masking, αποθήκευση |
| `ScanView.cs` | Προβολή scan: triage και σύγκριση με το προηγούμενο |
| `Store.cs` | SQLite: scans, ευρήματα, triage |
| `Secrets.cs` | Masking, HMAC, κρυπτογράφηση |
| `CodeContext.cs` | Ανάγνωση του κώδικα γύρω από κάθε εύρημα |
| `RepoUrl.cs`, `ProcessRunner.cs`, `Models.cs` | Βοηθητικά |
| `wwwroot/index.html` | Το UI |
| `tests/` | Unit tests (xUnit) |

Κάθε method έχει XML documentation στα ελληνικά.

## Tests

```bash
dotnet test tests/GitleaksScanner.Tests
```

Τα tests καλύπτουν το masking, την κρυπτογράφηση (λάθος κλειδί, αλλοιωμένα δεδομένα), την
κανονικοποίηση URLs, την προστασία από path traversal και τη σύγκριση scans. Τρέχουν
αυτόματα σε κάθε push μέσω GitHub Actions.

## Άδεια

[MIT](LICENSE)
