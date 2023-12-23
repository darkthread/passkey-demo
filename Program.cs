using Fido2NetLib;
using Fido2NetLib.Development;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);

var config = builder.Configuration;

builder.Services.AddSingleton<DevelopmentFileStore>();
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    // Set a short timeout for easy testing.
    options.IdleTimeout = TimeSpan.FromMinutes(2);
    options.Cookie.HttpOnly = true;
    // Strict SameSite mode is required because the default mode used
    // by ASP.NET Core 3 isn't understood by the Conformance Tool
    // and breaks conformance testing
    options.Cookie.SameSite = SameSiteMode.Unspecified;
});
builder.Services.AddFido2(options =>
{
    options.ServerDomain = config["fido2:serverDomain"];
    options.ServerName = "FIDO2 Test";
    options.Origins = config.GetSection("fido2:origins").Get<HashSet<string>>();
    options.TimestampDriftTolerance = config.GetValue<int>("fido2:timestampDriftTolerance");
    options.MDSCacheDirPath = config["fido2:MDSCacheDirPath"];
    options.BackupEligibleCredentialPolicy = config.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backupEligibleCredentialPolicy");
    options.BackedUpCredentialPolicy = config.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backedUpCredentialPolicy");

}).AddCachedMetadataService(config =>
{
    config.AddFidoMetadataRepository(httpClientBuilder =>
    {
        //TODO: any specific config you want for accessing the MDS
    });
});

builder.Services.AddMvc();

var app = builder.Build();

app.UseHsts();
app.UseDefaultFiles();
app.UseFileServer();
app.UseSession(); //Fido2Controller requires session middleware
app.MapControllers();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
