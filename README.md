# mssql-mcp

Read-only SQL Server MCP server (stdio) for Claude Code on client workstations, deployed through NinjaOne.

It connects with Windows auth as the signed-in user, then switches the connection to a SQL **application role**. The
role's permissions are the whole gate: the user's own SQL rights (even `db_owner`) don't apply. Before every query it
checks `USER_NAME()` is the role and refuses otherwise.

- `mssql-mcp.exe`: MCP server (Claude Code starts it from `managed-mcp.json`)
- `mssql-mcp.exe --set-secret`: read the role password from stdin, store it DPAPI-encrypted (machine scope)
- `mssql-mcp.exe --selftest`: connect as the current user, activate the role, print the identity

Config lives in `C:\ProgramData\CCI\mssql-mcp\` (or `%MSSQL_MCP_HOME%`): `config.json`
`{server, database, appRole, instructions, trustServerCertificate}` and `approle.dat`.

Tools: `query` (SELECT / WITH / DECLARE, tab-separated, row cap), `list_tables`, `describe_table` (marks hidden columns).

Build (any OS with the .NET 10 SDK): `dotnet publish src -c Release -o out` → `out/mssql-mcp.exe` and
`out/Microsoft.Data.SqlClient.SNI.dll`, which must stay side by side.

## Deploying with NinjaOne

`deploy/Install-MssqlMcp.ps1` installs or updates it machine-wide (run as SYSTEM, safe to re-run). It downloads the
pinned release from this public repo, checks its SHA-256, writes the config and the DPAPI-encrypted role password, and
registers the server in `C:\Program Files\ClaudeCode\managed-mcp.json`. That file gives **exclusive** MCP control on the
machine, so list any computer with its own MCP setup in the config's `deployExclude`.

Ninja custom fields (device, inheriting from organization):

| Field | Type | |
|---|---|---|
| `mssqlMcpConfig` | multi-line text | `config.json` for the client, plus optional `deployExclude: ["PC-NAME", ...]` |
| `mssqlMcpRolePassword` | secure | the SQL application role password |
| `mssqlMcpStatus` | text | written by the script: version, exe SHA-256, server/database, selftest result |

## SQL side

The gate lives in the database: an application role with `SELECT` on the database, and column/object `DENY`s for
sensitive data (card, bank, SSN, tax id, passwords), including columns re-exposed by views under other names. Client
specific setup scripts and rules are kept with each client's private documentation, not in this repo.
