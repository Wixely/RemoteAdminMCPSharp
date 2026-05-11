using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

[McpServerToolType]
public static class InventoryTools
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    [McpServerTool(Name = "list_servers"),
     Description("List all servers known to this MCP server (loaded from servers.json plus any imported .rdg files). Credentials are not returned.")]
    public static string ListServers(
        ServerInventoryService inventory,
        [Description("Optional case-insensitive name substring filter")] string? nameContains = null,
        [Description("Optional tag filter — server must have this tag")] string? tag = null,
        [Description("Optional OS filter, e.g. 'windows' or 'linux'")] string? os = null)
    {
        var query = inventory.Servers.AsEnumerable();
        if (!string.IsNullOrWhiteSpace(nameContains))
            query = query.Where(s => s.Name.Contains(nameContains, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(tag))
            query = query.Where(s => s.Tags.Contains(tag, StringComparer.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(os))
            query = query.Where(s => string.Equals(s.Os, os, StringComparison.OrdinalIgnoreCase));

        var projected = query
            .OrderBy(s => string.Join("/", s.GroupPath), StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .Select(s => new
            {
                s.Name,
                s.Host,
                s.Os,
                s.Description,
                s.Tags,
                Group = string.Join("/", s.GroupPath),
                HasCredentials = s.Credentials is not null,
            })
            .ToList();

        return JsonSerializer.Serialize(projected, JsonOpts);
    }
}
