using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Read-only Linux diagnostics over SSH. Never gated by ReadOnly — these cannot mutate the
/// target. Each tool runs a small, portable shell command and parses its output into JSON.
/// </summary>
[McpServerToolType]
public static class LinuxDiagnosticsTools
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    [McpServerTool(Name = "linux_list_services"),
     Description("List systemd units of type=service on a remote Linux machine. Filters applied locally after fetch.")]
    public static string ListServices(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Optional case-insensitive substring filter on unit name or description")] string? nameContains = null,
        [Description("Optional active-state filter, e.g. 'active', 'inactive', 'failed'")] string? state = null)
    {
        var target = inventory.GetRequired(server);
        // --plain strips the tree drawing chars, --no-legend strips the summary footer,
        // --no-pager prevents `less` from buffering, --all includes loaded-but-inactive units.
        var result = exec.InvokeRemote(target,
            "systemctl list-units --type=service --all --no-pager --no-legend --plain");

        var rows = new List<object>();
        foreach (var line in result.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = SplitColumns(line.TrimEnd('\r'), 5);
            if (parts.Length < 5) continue;
            var unit = parts[0];
            var load = parts[1];
            var active = parts[2];
            var sub = parts[3];
            var description = parts[4];

            if (!string.IsNullOrWhiteSpace(state) &&
                !string.Equals(active, state, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!string.IsNullOrWhiteSpace(nameContains) &&
                !unit.Contains(nameContains, StringComparison.OrdinalIgnoreCase) &&
                !description.Contains(nameContains, StringComparison.OrdinalIgnoreCase))
                continue;

            rows.Add(new
            {
                Unit = unit,
                Load = load,
                Active = active,
                Sub = sub,
                Description = description,
            });
        }
        return JsonSerializer.Serialize(rows, JsonOpts);
    }

    [McpServerTool(Name = "linux_list_processes"),
     Description("List running processes on a remote Linux machine, ordered by RSS descending.")]
    public static string ListProcesses(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Optional case-insensitive substring filter on command")] string? nameContains = null,
        [Description("Max rows (default 200)")] int top = 200)
    {
        var target = inventory.GetRequired(server);
        // pid/user/rss(kb)/vsz(kb)/stat/cmd. RSS column for the "memory hogs first" sort.
        var result = exec.InvokeRemote(target,
            "ps -eo pid,user,rss,vsz,stat,cmd --no-headers --sort=-rss");

        var rows = new List<object>();
        foreach (var line in result.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = SplitColumns(line.TrimEnd('\r'), 6);
            if (parts.Length < 6) continue;
            if (!int.TryParse(parts[0], out var pid)) continue;
            var user = parts[1];
            _ = long.TryParse(parts[2], out var rssKb);
            _ = long.TryParse(parts[3], out var vszKb);
            var stat = parts[4];
            var cmd = parts[5];

            if (!string.IsNullOrWhiteSpace(nameContains) &&
                !cmd.Contains(nameContains, StringComparison.OrdinalIgnoreCase))
                continue;

            rows.Add(new
            {
                Pid = pid,
                User = user,
                RssBytes = rssKb * 1024L,
                VszBytes = vszKb * 1024L,
                Stat = stat,
                Command = cmd,
            });
            if (rows.Count >= Math.Max(1, top)) break;
        }
        return JsonSerializer.Serialize(rows, JsonOpts);
    }

    [McpServerTool(Name = "linux_list_storage"),
     Description("List mounted filesystems on a remote Linux machine with size / free / percent-free. By default only local filesystems are listed — `df` on an unresponsive NFS/CIFS mount can hang for minutes (kernel NFS timeout), and `-l` filters those out before any stat() happens.")]
    public static string ListStorage(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Include network mounts (NFS, CIFS, sshfs, etc). Off by default — these can hang `df` for minutes if the remote server is unresponsive.")] bool includeNetworkMounts = false)
    {
        var target = inventory.GetRequired(server);
        // -P  POSIX-format (one line per filesystem); -T  include fstype; -B1  size in bytes;
        // -l  local filesystems only (skip NFS/CIFS/etc. — these can stall df indefinitely).
        var dfFlags = includeNetworkMounts ? "-PT -B1" : "-PT -B1 -l";
        var result = exec.InvokeRemote(target, $"df {dfFlags}");

        var rows = new List<object>();
        var lines = result.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        // skip header (first line)
        foreach (var raw in lines.Skip(1))
        {
            var parts = SplitColumns(raw.TrimEnd('\r'), 7);
            if (parts.Length < 7) continue;
            var source = parts[0];
            var fsType = parts[1];
            _ = long.TryParse(parts[2], out var size);
            _ = long.TryParse(parts[3], out var used);
            _ = long.TryParse(parts[4], out var avail);
            // parts[5] = capacity like "19%"; recompute for consistency
            var mount = parts[6];

            rows.Add(new
            {
                Source = source,
                FsType = fsType,
                SizeBytes = size,
                UsedBytes = used,
                FreeBytes = avail,
                MountPoint = mount,
                PercentFree = size == 0 ? 0d : Math.Round((double)avail / size * 100, 2),
            });
        }
        return JsonSerializer.Serialize(rows, JsonOpts);
    }

    [McpServerTool(Name = "linux_cpu_usage"),
     Description("Sample current CPU load on a remote Linux machine using vmstat (1s sample).")]
    public static string CpuUsage(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        // `vmstat 1 2` prints two samples; the 2nd line reflects the actual measured rate.
        // Columns 13..16 are us, sy, id, wa (procps-ng layout).
        var result = exec.InvokeRemote(target,
            "vmstat 1 2 | awk 'NR==4 {print $13, $14, $15, $16}'",
            timeout: TimeSpan.FromSeconds(15));

        var tokens = result.StdOut.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        int us = 0, sy = 0, id = 100, wa = 0;
        if (tokens.Length >= 4)
        {
            _ = int.TryParse(tokens[0], out us);
            _ = int.TryParse(tokens[1], out sy);
            _ = int.TryParse(tokens[2], out id);
            _ = int.TryParse(tokens[3], out wa);
        }
        return JsonSerializer.Serialize(new
        {
            PercentUser = us,
            PercentSystem = sy,
            PercentIdle = id,
            PercentIoWait = wa,
            PercentBusy = 100 - id,
        }, JsonOpts);
    }

    [McpServerTool(Name = "linux_ram_usage"),
     Description("Get total / free / available memory and swap on a remote Linux machine from /proc/meminfo.")]
    public static string RamUsage(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        var result = exec.InvokeRemote(target, "cat /proc/meminfo");

        // /proc/meminfo reports kilobytes ("Key: NNNN kB"). Convert to bytes.
        var kb = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in result.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.TrimEnd('\r');
            var colon = line.IndexOf(':');
            if (colon < 0) continue;
            var key = line[..colon].Trim();
            var rest = line[(colon + 1)..].Trim();
            var firstSpace = rest.IndexOf(' ');
            var number = firstSpace > 0 ? rest[..firstSpace] : rest;
            if (long.TryParse(number, out var value))
                kb[key] = value;
        }

        long Bytes(string key) => kb.TryGetValue(key, out var v) ? v * 1024L : 0L;

        var totalPhys = Bytes("MemTotal");
        var freePhys = Bytes("MemFree");
        var availPhys = Bytes("MemAvailable");
        var totalSwap = Bytes("SwapTotal");
        var freeSwap = Bytes("SwapFree");

        return JsonSerializer.Serialize(new
        {
            TotalPhysicalBytes = totalPhys,
            FreePhysicalBytes = freePhys,
            AvailablePhysicalBytes = availPhys,
            UsedPhysicalBytes = totalPhys - availPhys,
            PercentPhysicalFree = totalPhys == 0 ? 0d : Math.Round((double)availPhys / totalPhys * 100, 2),
            TotalSwapBytes = totalSwap,
            FreeSwapBytes = freeSwap,
            UsedSwapBytes = totalSwap - freeSwap,
        }, JsonOpts);
    }

    [McpServerTool(Name = "linux_list_active_users"),
     Description("List users with active terminal sessions (SSH, console, tty) on a remote Linux machine. Uses `who` — universal across distros.")]
    public static string ListActiveUsers(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        var result = exec.InvokeRemote(target, "who");

        var rows = new List<object>();
        foreach (var raw in result.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = raw.TrimEnd('\r').Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) continue;
            // Layout: user  tty  YYYY-MM-DD  HH:MM  [(source-ip-or-host)]
            var loginTime = parts[2] + " " + parts[3];
            string? source = null;
            if (parts.Length > 4)
            {
                var rest = string.Join(' ', parts.Skip(4));
                if (rest.StartsWith('(') && rest.EndsWith(')'))
                    source = rest[1..^1];
                else
                    source = rest;
            }
            rows.Add(new
            {
                User = parts[0],
                Tty = parts[1],
                LoginTime = loginTime,
                Source = source,
            });
        }
        return JsonSerializer.Serialize(rows, JsonOpts);
    }

    [McpServerTool(Name = "linux_os_version"),
     Description("Get the most granular Linux OS version available — distro id, version id (e.g. 22.04), version codename (e.g. jammy), pretty name, build id, plus kernel release/version/machine from uname. Single SSH round-trip reading /etc/os-release and calling uname; no external tools required.")]
    public static string OsVersion(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        // Single command, several light reads, sentinel-separated for easy splitting on this side.
        const string script =
            "echo '__OSREL__'; cat /etc/os-release 2>/dev/null || true; " +
            "echo '__UNAME_R__'; uname -r; " +
            "echo '__UNAME_M__'; uname -m; " +
            "echo '__UNAME_V__'; uname -v; " +
            "echo '__END__'";
        var result = exec.InvokeRemote(target, script);
        var sections = ParseSentinels(result.StdOut,
            new[] { "__OSREL__", "__UNAME_R__", "__UNAME_M__", "__UNAME_V__", "__END__" });

        var osrel = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in (sections.GetValueOrDefault("__OSREL__") ?? "").Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            var eq = trimmed.IndexOf('=');
            if (eq < 1) continue;
            var key = trimmed[..eq];
            var value = trimmed[(eq + 1)..].Trim().Trim('"');
            osrel[key] = value;
        }

        return JsonSerializer.Serialize(new
        {
            Id = osrel.GetValueOrDefault("ID"),
            Name = osrel.GetValueOrDefault("NAME"),
            PrettyName = osrel.GetValueOrDefault("PRETTY_NAME"),
            VersionId = osrel.GetValueOrDefault("VERSION_ID"),
            Version = osrel.GetValueOrDefault("VERSION"),
            VersionCodename = osrel.GetValueOrDefault("VERSION_CODENAME"),
            BuildId = osrel.GetValueOrDefault("BUILD_ID"),
            VariantId = osrel.GetValueOrDefault("VARIANT_ID"),
            IdLike = osrel.GetValueOrDefault("ID_LIKE"),
            Kernel = new
            {
                Release = (sections.GetValueOrDefault("__UNAME_R__") ?? "").Trim(),
                Version = (sections.GetValueOrDefault("__UNAME_V__") ?? "").Trim(),
                Machine = (sections.GetValueOrDefault("__UNAME_M__") ?? "").Trim(),
            },
        }, JsonOpts);
    }

    [McpServerTool(Name = "linux_system_info"),
     Description("Get distro / kernel / hostname / uptime from a remote Linux machine.")]
    public static string SystemInfo(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        // Bundle several light commands into one round-trip, separated by sentinels we can split on.
        const string script =
            "echo '__KERNEL__'; uname -a; " +
            "echo '__OSREL__'; cat /etc/os-release 2>/dev/null || true; " +
            "echo '__HOST__'; hostname; " +
            "echo '__UPTIME__'; uptime -p 2>/dev/null || uptime; " +
            "echo '__CPUS__'; nproc; " +
            "echo '__END__'";
        var result = exec.InvokeRemote(target, script);
        var sections = ParseSentinels(result.StdOut,
            new[] { "__KERNEL__", "__OSREL__", "__HOST__", "__UPTIME__", "__CPUS__", "__END__" });

        var osrel = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in (sections.GetValueOrDefault("__OSREL__") ?? "").Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            var eq = trimmed.IndexOf('=');
            if (eq < 1) continue;
            var key = trimmed[..eq];
            var value = trimmed[(eq + 1)..].Trim().Trim('"');
            osrel[key] = value;
        }

        _ = int.TryParse((sections.GetValueOrDefault("__CPUS__") ?? "0").Trim(), out var logicalCpus);

        return JsonSerializer.Serialize(new
        {
            Kernel = (sections.GetValueOrDefault("__KERNEL__") ?? "").Trim(),
            Hostname = (sections.GetValueOrDefault("__HOST__") ?? "").Trim(),
            Uptime = (sections.GetValueOrDefault("__UPTIME__") ?? "").Trim(),
            LogicalCpus = logicalCpus,
            Distro = new
            {
                Id = osrel.GetValueOrDefault("ID"),
                Name = osrel.GetValueOrDefault("NAME"),
                PrettyName = osrel.GetValueOrDefault("PRETTY_NAME"),
                VersionId = osrel.GetValueOrDefault("VERSION_ID"),
                Version = osrel.GetValueOrDefault("VERSION"),
            },
        }, JsonOpts);
    }

    // ---- helpers ----

    private static Dictionary<string, string> ParseSentinels(string text, string[] sentinels)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var lines = text.Split('\n');
        string? current = null;
        var buf = new System.Text.StringBuilder();
        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');
            if (sentinels.Contains(line.Trim()))
            {
                if (current is not null)
                    result[current] = buf.ToString();
                current = line.Trim();
                buf.Clear();
                continue;
            }
            if (current is not null)
                buf.AppendLine(raw);
        }
        if (current is not null)
            result[current] = buf.ToString();
        return result;
    }

    /// <summary>
    /// Split a whitespace-separated line into at most <paramref name="columnCount"/> columns. The
    /// last column captures the rest of the line (preserves embedded spaces), which is essential
    /// for fields like service descriptions and process command lines.
    /// </summary>
    private static string[] SplitColumns(string line, int columnCount)
    {
        var parts = new List<string>(columnCount);
        var i = 0;
        while (parts.Count < columnCount - 1 && i < line.Length)
        {
            while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
            if (i >= line.Length) break;
            var start = i;
            while (i < line.Length && !char.IsWhiteSpace(line[i])) i++;
            parts.Add(line[start..i]);
        }
        while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
        if (i < line.Length || parts.Count < columnCount)
            parts.Add(i < line.Length ? line[i..] : string.Empty);
        return parts.ToArray();
    }
}
