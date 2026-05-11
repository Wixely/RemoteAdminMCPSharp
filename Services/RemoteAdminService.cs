using Microsoft.Extensions.Options;
using ModelContextProtocol;
using RemoteAdminMCPSharp.Configuration;

namespace RemoteAdminMCPSharp.Services;

/// <summary>
/// Aggregates the runtime options for the server and provides the read-only / arbitrary-command
/// gate that every mutating tool must call before doing work.
/// </summary>
public sealed class RemoteAdminService
{
    private readonly RemoteAdminOptions _options;

    public RemoteAdminService(IOptions<RemoteAdminOptions> options)
    {
        _options = options.Value;
    }

    public RemoteAdminOptions Options => _options;
    public bool IsReadOnly => _options.ReadOnly;
    public bool ArbitraryCommandsEnabled => _options.AllowArbitraryCommands;
    public TimeSpan RemoteTimeout => TimeSpan.FromSeconds(_options.RemoteOperationTimeoutSeconds);

    /// <summary>
    /// Gate every mutating tool: checks the global <see cref="RemoteAdminOptions.ReadOnly"/>
    /// switch AND the per-operation flag under <see cref="RemoteAdminOptions.Operations"/>.
    /// Both must be permissive — turning ReadOnly off does NOT auto-enable any individual tool.
    /// </summary>
    /// <summary>
    /// Gate every mutating tool. Throws <see cref="McpException"/> (which the MCP framework
    /// passes back to the agent with the message intact) when blocked, naming the exact config
    /// key the operator needs to flip.
    /// </summary>
    public void EnsureOperationAllowed(Operation op)
    {
        if (_options.ReadOnly)
        {
            throw new McpException(
                $"MCP tool blocked by server configuration: the MCP server is running in read-only mode " +
                $"(RemoteAdmin:ReadOnly=true in appsettings.json). All mutating tools — including '{op}' — " +
                "are disabled. The operator must set RemoteAdmin:ReadOnly=false AND enable the per-tool " +
                $"switch RemoteAdmin:Operations:{op} for this tool to work.");
        }
        if (!_options.Operations.IsEnabled(op))
        {
            throw new McpException(
                $"MCP tool '{op}' is disabled by server configuration: the per-tool switch " +
                $"RemoteAdmin:Operations:{op} is set to false in appsettings.json (this is the default). " +
                "The operator must explicitly set this specific switch to true to enable this tool. " +
                "Other mutating tools may also be disabled by their own per-tool switches.");
        }
    }

    public void EnsureArbitraryAllowed()
    {
        if (!_options.AllowArbitraryCommands)
        {
            throw new McpException(
                "Arbitrary command execution is disabled by MCP server configuration: " +
                "RemoteAdmin:AllowArbitraryCommands=false in appsettings.json (this is the default). " +
                "The operator must set this to true AND enable the per-tool switch " +
                "(RemoteAdmin:Operations:WinRunCommand or RemoteAdmin:Operations:LinuxRunCommand) " +
                "for the *_run_command tools to be usable.");
        }
    }
}
