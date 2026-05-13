# RemoteAdminMCPSharp

MCP (Model Context Protocol) server that exposes a strict, curated set of
remote-administration commands against Windows hosts (over WinRM) and Linux hosts (over SSH).
It exposes an MCP endpoint over Streamable HTTP.

## Tools at a glance

**Windows (WinRM via PowerShell SDK)**
- Diagnostics: `win_list_services`, `win_service_details`, `win_list_processes`, `win_list_storage`, `win_list_active_users`, `win_cpu_usage`, `win_ram_usage`, `win_os_version`, `win_system_info`
- IIS (read): `win_iis_list_sites`, `win_iis_list_app_pools`
- Files (read): `win_list_files`, `win_read_file`, `win_file_properties`
- Management *(gated by `ReadOnly`)*: `win_start_service`, `win_stop_service`, `win_restart_service`, `win_set_service_startup_type`, `win_create_service`, `win_delete_service`, `win_kill_process`
- IIS management *(gated by `ReadOnly`)*: `win_iis_start_site`, `win_iis_stop_site`, `win_iis_delete_site`, `win_iis_start_app_pool`, `win_iis_stop_app_pool`, `win_iis_recycle_app_pool`, `win_iis_delete_app_pool`, `win_iis_reset`
- File management *(gated by `ReadOnly`)*: `win_write_file`, `win_append_to_file`, `win_create_folder`, `win_delete_file`, `win_delete_folder`, `win_copy_path`, `win_move_path`
- Arbitrary *(gated by `ReadOnly` AND `AllowArbitraryCommands`)*: `win_run_command`

**Linux (SSH via SSH.NET)**
- Diagnostics: `linux_list_services` (systemd), `linux_list_processes`, `linux_list_storage`, `linux_list_active_users`, `linux_cpu_usage`, `linux_ram_usage`, `linux_os_version`, `linux_system_info`
- Files (read): `linux_list_files`, `linux_read_file`, `linux_file_properties`
- Management *(gated by `ReadOnly`)*: `linux_start_service`, `linux_stop_service`, `linux_restart_service`, `linux_kill_process`
- File management *(gated by `ReadOnly`)*: `linux_write_file`, `linux_append_to_file`, `linux_create_folder`, `linux_delete_file`, `linux_delete_folder`, `linux_copy_path`, `linux_move_path`
- Arbitrary *(gated by `ReadOnly` AND `AllowArbitraryCommands`)*: `linux_run_command`

**Common**
- `list_servers` — what's in the inventory.

---

## Quick start

```sh
# 1. Clone, then create your live inventory files from the templates
cp remote_admin_windows_servers.example.json remote_admin_windows_servers.json
cp remote_admin_linux_servers.example.json   remote_admin_linux_servers.json

# 2. Edit the *.json files (NOT the .example.json) and fill in real hostnames + plaintext passwords.

# 3. Run
dotnet run
```

On first start the service encrypts the plaintext passwords in those files, rewrites them with
ciphertext, and prints how many secrets it rotated. From then on the on-disk files contain only
ciphertext — see [Credentials & encryption](#credentials--encryption) below.

Point your MCP client at `http://localhost:5706/mcp`.

## Docker

```sh
docker run --rm -p 5706:5706 \
  -v $(pwd)/config:/config \
  -v $(pwd)/logs:/app/logs \
  -e REMOTEADMINMCP_RemoteAdmin__WindowsInventoryPath=/config/remote_admin_windows_servers.json \
  -e REMOTEADMINMCP_RemoteAdmin__LinuxInventoryPath=/config/remote_admin_linux_servers.json \
  -e REMOTEADMINMCP_RemoteAdmin__CredentialProtection=aesgcm-keyfile \
  -e REMOTEADMINMCP_RemoteAdmin__KeyFilePath=/config/master.key \
  -e REMOTEADMINMCP_RemoteAdmin__AllowedServers__0=web01 \
  -e REMOTEADMINMCP_Server__Password=change-me \
  ghcr.io/wixely/remoteadminmcpsharp:latest
```

Environment variables override `RemoteAdminMCPSharp.json`. Use the `REMOTEADMINMCP_` prefix and `__` for nested keys; arrays use numeric indexes such as `REMOTEADMINMCP_RemoteAdmin__AllowedServers__0=web01`, and booleans use `true` or `false`.

---

## Credentials & encryption

This is the bit operators care about most. The short version:

1. **You write plaintext** in `remote_admin_windows_servers.json` / `remote_admin_linux_servers.json` whenever you want
   to add or update a password.
2. **The service encrypts it** the next time it starts, swaps the plaintext field for an
   encrypted equivalent, and writes the file back atomically.
3. **To rotate a password**, just put a new plaintext value in the `password` field and
   restart. Plaintext always wins over the encrypted version, so the next encrypt pass
   overwrites the old ciphertext.

### What the JSON shape looks like

What you write:

```json
{
  "credentials": {
    "username": "svc-remoteadmin",
    "password": "MyNewPassword123!"
  }
}
```

What the service writes after first start:

```json
{
  "credentials": {
    "username": "svc-remoteadmin",
    "passwordProtected": "AQAAANCMnd8B...",
    "protectionScheme": "dpapi-user"
  }
}
```

Same lifecycle applies to `privateKeyPassphrase` → `privateKeyPassphraseProtected`.

### Where the encryption key lives

The service picks a scheme automatically based on the OS it's running on. You can override with
the `RemoteAdmin:CredentialProtection` setting.

| Scheme | Platform | Where the key lives | Who can decrypt |
|---|---|---|---|
| `dpapi-user` *(default on Windows)* | Windows | Windows DPAPI master key for the **service account's** Windows profile (`%APPDATA%\Microsoft\Protect\<SID>\`) | Only the same Windows account on this machine |
| `dpapi-machine` | Windows | Windows DPAPI master key under `C:\ProgramData\Microsoft\Crypto\Protect\` | Any process on this machine |
| `aesgcm-keyfile` *(default on Linux/macOS)* | All | A 32-byte file at `master.key` next to the executable (configurable via `RemoteAdmin:KeyFilePath`), permissions `0600` on Unix | Anyone who can read the key file |
| `none` | All | _(no encryption — leaves plaintext in the inventory file)_ | Anyone who can read the file |

**Windows hosting tip**: if you're going to run this as a Windows Service, make sure the
service account is the one that encrypts the secrets. The simplest pattern: install the service
to run as e.g. `NT SERVICE\RemoteAdminMCPSharp` or your own service account, then start it
**once interactively as that account** so the first encrypt pass happens under its identity.
Future starts will be able to decrypt.

**Linux hosting tip**: the AES-GCM `master.key` file is your trust boundary. If a user can
read it, they can decrypt the inventory. So:
- It's created with `0600` perms by default.
- Make sure it's owned by the service user, not root.
- **Back it up separately from the inventory files.** Losing the key means losing every
  protected credential — you'd have to re-enter every password.

### Things to know

- The plaintext lives on disk in the window between when you save the file and when the service
  restarts. That window is intentional (it's how you enter passwords). For the rest of the
  lifecycle, only ciphertext sits on disk.
- The `.gitignore` excludes `remote_admin_windows_servers.json`, `remote_admin_linux_servers.json`, and `master.key`.
  Only the `*.example.json` templates are tracked.
- The atomic rewrite is `write → rename`; a service crash mid-write leaves the original file
  untouched.
- If the service can't decrypt (wrong user, missing key file, scheme not available on this
  platform), it logs an error per server and that server's `password` resolves to `null`. The
  fix is always the same: put plaintext back in the file and restart.
- Imported RDCMan `.rdg` credentials are passed through verbatim and **not** re-encrypted —
  the `.rdg` file is the source of truth; rewriting would just race the next import.

### Disabling encryption

```json
"RemoteAdmin": {
  "CredentialProtection": "none",
  "AutoProtectCredentials": false
}
```

Useful for testing, air-gapped lab setups, or when you have a separate secret manager.

---

## Per-operation switches (defence in depth)

`RemoteAdmin:ReadOnly` is the master kill-switch — when `true` (the default) every mutating
tool is blocked.

In addition, **every individual mutating tool has its own switch under `RemoteAdmin:Operations`,
all defaulting to `false`.** Both gates must be permissive for a tool to run: flipping
`ReadOnly` off does NOT auto-enable any individual tool.

Workflow to enable a single tool — e.g. just `linux_restart_service`:

```json
"RemoteAdmin": {
  "ReadOnly": false,
  "Operations": {
    "LinuxRestartService": true
  }
}
```

Every other write tool stays blocked because its switch is still at the default of `false`.

The full list of switches (matches the C# `Operation` enum):

| Group | Switches |
|---|---|
| Windows services / processes | `WinStartService`, `WinStopService`, `WinRestartService`, `WinSetServiceStartupType`, `WinCreateService`, `WinDeleteService`, `WinKillProcess` |
| Windows IIS | `WinIisStartSite`, `WinIisStopSite`, `WinIisDeleteSite`, `WinIisStartAppPool`, `WinIisStopAppPool`, `WinIisRecycleAppPool`, `WinIisDeleteAppPool`, `WinIisReset` |
| Windows files | `WinWriteFile`, `WinAppendToFile`, `WinCreateFolder`, `WinDeleteFile`, `WinDeleteFolder`, `WinCopyPath`, `WinMovePath` |
| Windows arbitrary | `WinRunCommand` (also requires `AllowArbitraryCommands=true`) |
| Linux services / processes | `LinuxStartService`, `LinuxStopService`, `LinuxRestartService`, `LinuxKillProcess` |
| Linux files | `LinuxWriteFile`, `LinuxAppendToFile`, `LinuxCreateFolder`, `LinuxDeleteFile`, `LinuxDeleteFolder`, `LinuxCopyPath`, `LinuxMovePath` |
| Linux arbitrary | `LinuxRunCommand` (also requires `AllowArbitraryCommands=true`) |

When a blocked tool is called, the server returns an error naming the exact config key that needs to be changed.

## Concurrency limits

Two limits, both under `RemoteAdmin:Concurrency`:

- **`MaxConcurrentPerServer`** (default `1`) — how many tool calls can be in-flight against the
  same box simultaneously. Default of 1 means five `win_list_processes` calls at
  the same host queues them strictly in order. Stops parallel hammering and avoids WinRM session
  contention.
- **`MaxConcurrentGlobal`** (default `16`) — total in-flight across the whole inventory. Caps the
  load from large fan-out requests across many servers.

Slots are queued up to `AcquireTimeoutSeconds` (default `30`) before the call fails — the
operation itself has its own (longer) timeout; this is just how long the request waits in
line.

Concurrency limits parallelism, not frequency. If you want to floor the *interval* between
operations against the same server (e.g. "no more than one CPU sample every 5 seconds per host")
set `MinIntervalPerServerMs` to that interval in milliseconds. It's off by default.

## Prerequisites — Windows targets

- **WinRM enabled**: `Enable-PSRemoting -Force` (already on by default on Windows Server).
- **Reachability**: TCP 5985 (HTTP) or 5986 (HTTPS) open from this server to the target.
- **Auth**:
  - **Domain-joined target + domain-joined caller**: Kerberos just works; populate
    `domain`/`username`/`password` in `remote_admin_windows_servers.json` (or omit and run under the caller's
    identity).
  - **Non-domain / cross-forest**: configure HTTPS WinRM **or** add the target to TrustedHosts on
    this machine: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'host1,host2'`.

## Prerequisites — Linux targets

- **SSH server reachable** on the configured port (default 22).
- **Auth** (one of these):
  - Password — set `password` in the credentials block.
  - Private key — set `privateKeyPath` (absolute path on the host running this server) and
    optionally `privateKeyPassphrase`. Preferred over password when both are set.
- **Mutating ops (`linux_*_service`, `linux_kill_process`) need root**:
  - Either point at a root SSH user, or
  - Configure passwordless sudo for the SSH user (e.g. a sudoers drop-in granting NOPASSWD on
    `/bin/systemctl` and `/bin/kill`) and set `"useSudo": true` in the credentials block.
- The `linux_run_command` tool runs the command verbatim — it does **not** auto-prefix sudo;
  the operator is in charge.

---

## Configuration reference

Defaults live in `RemoteAdminMCPSharp.json`, with optional local overrides in `RemoteAdminMCPSharp.Local.json`. Environment variables and command-line arguments can override both.

| Setting | Default | Description |
| --- | --- | --- |
| `RemoteAdmin:ReadOnly` | `true` | Blocks every non-diagnostic operation. |
| `RemoteAdmin:AllowArbitraryCommands` | `false` | Master switch for the per-OS `*_run_command` tools. |
| `RemoteAdmin:WindowsInventoryPath` | `remote_admin_windows_servers.json` | Windows inventory file. |
| `RemoteAdmin:LinuxInventoryPath` | `remote_admin_linux_servers.json` | Linux inventory file. |
| `RemoteAdmin:RdgImportPath` | _(none)_ | Folder containing `.rdg` files to merge into the Windows inventory at startup. |
| `RemoteAdmin:CredentialProtection` | `auto` | `auto` / `dpapi-user` / `dpapi-machine` / `aesgcm-keyfile` / `none`. |
| `RemoteAdmin:AutoProtectCredentials` | `true` | Encrypt-and-rewrite plaintexts on startup. |
| `RemoteAdmin:KeyFilePath` | `master.key` | AES-GCM master key file (used by `aesgcm-keyfile` scheme). |
| `RemoteAdmin:RemoteOperationTimeoutSeconds` | `60` | Per-call timeout for WinRM/SSH operations. |
| `RemoteAdmin:AllowedServers` / `BlockedServers` | `[]` | Inventory allow/deny lists by server name. |
| `RemoteAdmin:Concurrency:MaxConcurrentPerServer` | `1` | Max parallel operations against any single server. |
| `RemoteAdmin:Concurrency:MaxConcurrentGlobal` | `16` | Max parallel operations across the whole inventory. |
| `RemoteAdmin:Concurrency:AcquireTimeoutSeconds` | `30` | How long to wait for a slot before failing the call. |
| `RemoteAdmin:Concurrency:MinIntervalPerServerMs` | `0` | Optional floor on time between operations against the same server (rate-limit). 0 disables. |
| `Server:Port` | `5706` | HTTP port. |
| `Server:Password` | blank | Optional MCP endpoint password; blank disables password auth. |
| `Server:WindowsServiceName` | `RemoteAdminMCPSharp` | Used when launched by the Service Control Manager. |

When `Server:Password` is set, MCP requests must provide the password as `Authorization: Bearer <password>`, the Basic auth password, or `X-MCP-Password`.

---

## Windows Service

The host detects when it's launched by the Service Control Manager and switches to service mode
automatically (config and logs resolve from the executable directory, not `C:\Windows\System32`).

```powershell
dotnet publish -c Release -r win-x64 --self-contained false -o C:\Services\RemoteAdminMCPSharp

sc.exe create RemoteAdminMCPSharp `
    binPath= "C:\Services\RemoteAdminMCPSharp\RemoteAdminMCPSharp.exe" `
    start= auto `
    DisplayName= "Remote Admin MCP Server"
sc.exe start RemoteAdminMCPSharp
```

Put the service account's plaintext passwords in `remote_admin_windows_servers.json` and `remote_admin_linux_servers.json`
**before** the first start, then start the service as that account. The first start encrypts them
under DPAPI for that account.

---

## RDCMan import (Windows-only)

Set `RemoteAdmin:RdgImportPath` to a folder containing `.rdg` files. The service walks the folder
recursively, parses each XML, and merges any `<group>`/`<server>` entries into the Windows
inventory. Group hierarchy and credential cascade are preserved.

RDCMan stores its own passwords as DPAPI blobs under the encrypting user's profile. Those blobs
are passed through verbatim — they'll only work if the service runs under that same Windows
account on that same machine. The pragmatic path: import the `.rdg` once, then enter credentials
in `remote_admin_windows_servers.json` for the servers you actually need to act on (entries there override
any duplicate from the `.rdg`).
