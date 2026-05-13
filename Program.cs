using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RemoteAdminMCPSharp.Configuration;
using RemoteAdminMCPSharp.Hosting;
using RemoteAdminMCPSharp.Services;
using Serilog;

namespace RemoteAdminMCPSharp;

public static class Program
{
    public static int Main(string[] args)
    {
        // When running as a Windows Service the working directory is
        // C:\Windows\System32, so resolve config and logs relative to the exe.
        var contentRoot = GetContentRoot();
        var isService = WindowsServiceHelpers.IsWindowsService();
        if (!isService)
        {
            McpSharpIcon.ApplyConsoleWindowIcon();
        }

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console()
            .WriteTo.File(
                Path.Combine(contentRoot, "logs", "remoteadminmcp-bootstrap-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                shared: true)
            .CreateBootstrapLogger();

        try
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = args,
                ContentRootPath = contentRoot,
            });

            builder.Configuration
                .SetBasePath(contentRoot)
                .AddJsonFile(ResolveConfigFile(contentRoot, "appsettings.json"), optional: true, reloadOnChange: true)
                .AddJsonFile(ResolveConfigFile(contentRoot, $"appsettings.{builder.Environment.EnvironmentName}.json"), optional: true, reloadOnChange: true)
                .AddJsonFile(ResolveConfigFile(contentRoot, "appsettings.Local.json"), optional: true, reloadOnChange: true)
                .AddJsonFile(ResolveConfigFile(contentRoot, "RemoteAdminMCPSharp.json"), optional: true, reloadOnChange: true)
                .AddJsonFile(ResolveConfigFile(contentRoot, $"RemoteAdminMCPSharp.{builder.Environment.EnvironmentName}.json"), optional: true, reloadOnChange: true)
                .AddJsonFile(ResolveConfigFile(contentRoot, "RemoteAdminMCPSharp.Local.json"), optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .AddEnvironmentVariables(prefix: "REMOTEADMINMCP_")
                .AddCommandLine(args);

            if (isService)
            {
                var svcOptions = builder.Configuration.GetSection(ServerOptions.SectionName).Get<ServerOptions>() ?? new ServerOptions();
                builder.Host.UseWindowsService(o => o.ServiceName = svcOptions.WindowsServiceName);
            }

            builder.Host.UseSerilog((ctx, services, cfg) => cfg
                .ReadFrom.Configuration(ctx.Configuration)

                .ReadFrom.Services(services)
                .Enrich.FromLogContext());

            builder.Services.Configure<RemoteAdminOptions>(
                builder.Configuration.GetSection(RemoteAdminOptions.SectionName));
            builder.Services.Configure<ServerOptions>(
                builder.Configuration.GetSection(ServerOptions.SectionName));

            builder.Services.AddSingleton<RemoteAdminService>();

            // Cross-platform AES-GCM keyfile protector is always available.
            builder.Services.AddSingleton<ICredentialProtector>(sp =>
            {
                var opts = sp.GetRequiredService<IOptions<RemoteAdminOptions>>().Value;
                var keyPath = Path.IsPathRooted(opts.KeyFilePath)
                    ? opts.KeyFilePath
                    : Path.Combine(contentRoot, opts.KeyFilePath);
                var logger = sp.GetRequiredService<ILogger<AesGcmKeyFileCredentialProtector>>();
                return new AesGcmKeyFileCredentialProtector(keyPath, logger);
            });

            // DPAPI protectors are Windows-only.
            if (OperatingSystem.IsWindows())
            {
                builder.Services.AddSingleton<ICredentialProtector, DpapiCurrentUserCredentialProtector>();
                builder.Services.AddSingleton<ICredentialProtector, DpapiLocalMachineCredentialProtector>();
            }

            builder.Services.AddSingleton<CredentialProtectionService>(sp =>
            {
                var opts = sp.GetRequiredService<IOptions<RemoteAdminOptions>>().Value;
                var protectors = sp.GetServices<ICredentialProtector>();
                var scheme = opts.CredentialProtection;
                if (string.IsNullOrWhiteSpace(scheme) || string.Equals(scheme, "auto", StringComparison.OrdinalIgnoreCase))
                {
                    scheme = OperatingSystem.IsWindows() ? "dpapi-user" : "aesgcm-keyfile";
                }
                return new CredentialProtectionService(protectors, scheme);
            });

            builder.Services.AddSingleton<ServerInventoryService>();
            builder.Services.AddSingleton<ConcurrencyGate>();
            builder.Services.AddSingleton<PowerShellRemoteExecutor>();
            builder.Services.AddSingleton<SshRemoteExecutor>();

            builder.Services
                .AddMcpServer()
                .WithHttpTransport()
                .WithToolsFromAssembly();

            var server = builder.Configuration.GetSection(ServerOptions.SectionName).Get<ServerOptions>() ?? new ServerOptions();
            builder.WebHost.ConfigureKestrel(k =>
            {
                if (string.Equals(server.Host, "localhost", StringComparison.OrdinalIgnoreCase))
                {
                    k.ListenLocalhost(server.Port);
                }
                else if (IPAddress.TryParse(server.Host, out var ip))
                {
                    k.Listen(ip, server.Port);
                }
                else
                {
                    k.ListenAnyIP(server.Port);
                }
            });

            var app = builder.Build();

            app.UseSerilogRequestLogging();

            // Surface any swallowed exceptions from the host as fatal log entries.
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                Log.Fatal(e.ExceptionObject as Exception, "Unhandled exception in AppDomain");
            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                Log.Error(e.Exception, "Unobserved task exception");
                e.SetObserved();
            };

            var admin = app.Services.GetRequiredService<RemoteAdminService>();
            var inventory = app.Services.GetRequiredService<ServerInventoryService>();
            LogStartup(
                "RemoteAdminMCPSharp",
                $"http://{server.Host}:{server.Port}{server.Path}",
                "HTTP",
                isService ? "WindowsService" : "Console",
                contentRoot,
                $"Read-only: {admin.IsReadOnly}",
                $"Arbitrary exec: {admin.ArbitraryCommandsEnabled}",
                $"Inventory servers: {inventory.Servers.Count}");

            app.UseMiddleware<McpPasswordMiddleware>();

            app.MapFavicon();
            app.MapGet("/healthz", () => new
            {
                status = "ok",
                server = "RemoteAdminMCPSharp",
                path = server.Path,
                readOnly = admin.IsReadOnly,
                timeUtc = DateTimeOffset.UtcNow,
            });
            app.MapMcp(server.Path);

            app.Run();
            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Server terminated unexpectedly");
            return 1;
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }

    private static void LogStartup(string serviceName, string endpoint, string transport, string mode, string contentRoot, params string[] details)
    {
        var startupLog = Log.ForContext("SourceContext", serviceName + ".Startup");
        startupLog.Information("{ServiceName} startup", serviceName);
        startupLog.Information("  Endpoint: {Endpoint}", endpoint);
        startupLog.Information("  Transport: {Transport}", transport);
        startupLog.Information("  Mode: {Mode}", mode);
        foreach (var detail in details)
        {
            startupLog.Information("  {Detail}", detail);
        }
        startupLog.Information("  Content root: {ContentRoot}", contentRoot);
    }
    private static string GetContentRoot() =>
        Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;

    private static string ResolveConfigFile(string contentRoot, string fileName)
    {
        if (File.Exists(Path.Combine(contentRoot, fileName)))
        {
            return fileName;
        }

        try
        {
            var match = Directory.EnumerateFiles(contentRoot, "*", SearchOption.TopDirectoryOnly)
                .FirstOrDefault(path => string.Equals(Path.GetFileName(path), fileName, StringComparison.OrdinalIgnoreCase));

            return match is null ? fileName : Path.GetFileName(match);
        }
        catch (DirectoryNotFoundException)
        {
            return fileName;
        }
    }
}
