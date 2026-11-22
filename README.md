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
dotnet run --project src/GitleaksScanner.Api
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

Ο φάκελος `src/GitleaksScanner.Api/appdata/` περιέχει τη βάση (`scanner.db`) και τα κλειδιά (`enc.key`, `hmac.key`). Είναι
στο `.gitignore` και **δεν πρέπει να ανέβει ποτέ** σε repo. Εκεί είναι και τα logs. Αν σβήσεις το `enc.key`, τα παλιά
scans δεν θα έχουν πια unmask.

## Αρχιτεκτονική

Clean Architecture: κάθε layer είναι ξεχωριστό project, οπότε ο compiler δεν επιτρέπει λάθος
εξαρτήσεις (π.χ. η Application δεν μπορεί να χρησιμοποιήσει απευθείας SQLite ή `git`).

```
GitleaksScanner.Api  ──►  GitleaksScanner.Application  ──►  GitleaksScanner.Domain
        │                          ▲
        └──►  GitleaksScanner.Infrastructure (υλοποιεί τα interfaces της Application)
```

| Project | Περιεχόμενο |
| --- | --- |
| `src/GitleaksScanner.Domain` | Entities (`ScanInfo`, `StoredFinding`), κανόνες masking, σύγκριση scans, URLs: καθαρή λογική χωρίς εξαρτήσεις |
| `src/GitleaksScanner.Application` | Use cases (`ScanService`, `ScanQueryService`, `FindingService`), interfaces, DTOs, `Result<T>` |
| `src/GitleaksScanner.Infrastructure` | SQLite, AES-GCM/HMAC, `git clone`, εκτέλεση `gitleaks`, GitHub API |
| `src/GitleaksScanner.Api` | HTTP endpoints, UI (`wwwroot/`), logging, ρυθμίσεις ασφαλείας |
| `tests/GitleaksScanner.Tests` | Unit tests (xUnit) |

Κάθε method έχει XML documentation στα ελληνικά.

## Logging

[Serilog](https://serilog.net) με έξοδο στην κονσόλα και σε αρχείο ανά ημέρα στο
`src/GitleaksScanner.Api/appdata/logs/` (κρατιούνται 14 ημέρες). Καταγράφονται τα HTTP αιτήματα,
η αρχή και το τέλος κάθε scan, οι αλλαγές triage και κάθε **unmask (audit)**. **Τα secrets δεν
γράφονται ποτέ στα logs.** Το επίπεδο αλλάζει από το `appsettings.json` (`Serilog:MinimumLevel`).

## Tests

```bash
dotnet test GitleaksScanner.slnx
```

Τα tests καλύπτουν το masking, την κρυπτογράφηση (λάθος κλειδί, αλλοιωμένα δεδομένα), την
κανονικοποίηση URLs, την προστασία από path traversal και τη σύγκριση scans. Τρέχουν
αυτόματα σε κάθε push μέσω GitHub Actions.

## Άδεια

[MIT](LICENSE)
