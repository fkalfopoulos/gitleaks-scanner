using GitleaksScanner.Api;
using GitleaksScanner.Application;
using GitleaksScanner.Infrastructure;
using Serilog;
using Serilog.Events;

var builder = WebApplication.CreateBuilder(args);

// Τα δεδομένα (βάση, κλειδιά, logs) μένουν στο appdata/, που ΔΕΝ μπαίνει ποτέ στο git.
var dataDir = Path.Combine(builder.Environment.ContentRootPath, "appdata");

// ---------- Logging (Serilog) ----------
// Κονσόλα για την ανάπτυξη και αρχείο ανά ημέρα (κρατιούνται 14) για ό,τι χρειαστεί αργότερα.
// Ο υπόλοιπος κώδικας γράφει μέσω ILogger<T> και δεν ξέρει ότι από πίσω είναι το Serilog.
// ΠΟΤΕ δεν γράφουμε secrets στα logs: μόνο ids, πηγές και πλήθη.
builder.Host.UseSerilog((ctx, cfg) => cfg
    .ReadFrom.Configuration(ctx.Configuration)
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .MinimumLevel.Override("System.Net.Http.HttpClient", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(Path.Combine(dataDir, "logs", "gitleaks-scanner-.log"),
        rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"));

// ---------- Ασφάλεια ----------
// Ακούμε ΜΟΝΟ στο localhost: το app τρέχει εντολές στο μηχάνημά σου.
builder.WebHost.UseUrls("http://localhost:5080");
// Μόνο Host "localhost": αλλιώς μια κακόβουλη ιστοσελίδα θα μπορούσε, με DNS rebinding, να
// διαβάσει το API (π.χ. το unmask).
builder.Configuration["AllowedHosts"] = "localhost";

// ---------- Layers ----------
builder.Services.AddApplication();
builder.Services.AddInfrastructure(dataDir);
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseExceptionHandler();   // απρόβλεπτα σφάλματα → 500 χωρίς λεπτομέρειες προς τον browser (καταγράφονται στο log)
app.UseSerilogRequestLogging(o => o.MessageTemplate = "HTTP {RequestMethod} {RequestPath} → {StatusCode} σε {Elapsed:0} ms");
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapEndpoints();

try
{
    Log.Information("Το Gitleaks Scanner ξεκινά στο http://localhost:5080 (δεδομένα: {DataDir})", dataDir);
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Το Gitleaks Scanner σταμάτησε απρόσμενα");
    throw;
}
finally
{
    Log.CloseAndFlush();
}
