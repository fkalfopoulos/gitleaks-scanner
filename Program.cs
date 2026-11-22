using GitleaksScanner;

var builder = WebApplication.CreateBuilder(args);

// Ακούμε ΜΟΝΟ στο localhost: το app τρέχει εντολές στο μηχάνημά σου,
// δεν πρέπει να είναι προσβάσιμο από το δίκτυο.
builder.WebHost.UseUrls("http://localhost:5080");

// Δεχόμαστε αιτήματα μόνο με Host "localhost": μια κακόβουλη ιστοσελίδα μπορεί με DNS rebinding
// να κάνει το domain της να δείχνει στο 127.0.0.1 και να διαβάσει το API (π.χ. το unmask).
builder.Configuration["AllowedHosts"] = "localhost";

var dataDir = Path.Combine(builder.Environment.ContentRootPath, "data");
Directory.CreateDirectory(dataDir);
var store = new Store(Path.Combine(dataDir, "scanner.db"));
store.Init();
builder.Services.AddSingleton(store);
builder.Services.AddSingleton(new ScannerKeys(
    Hmac: Secrets.LoadOrCreateKey(Path.Combine(dataDir, "hmac.key")),
    Encryption: Secrets.LoadOrCreateKey(Path.Combine(dataDir, "enc.key"))));
builder.Services.AddSingleton<ScanService>();

builder.Services.AddHttpClient("github", c =>
{
    c.BaseAddress = new Uri("https://api.github.com/");
    c.DefaultRequestHeaders.UserAgent.ParseAdd("gitleaks-scanner/1.0");
    c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
    c.Timeout = TimeSpan.FromSeconds(30);
});

var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapApi();
app.Run();
