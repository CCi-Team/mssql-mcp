// Read-only SQL Server MCP for Claude Code (stdio). Connects with Windows auth as the signed-in user, then switches the
// connection to a SQL application role whose permissions are the whole gate.
//
//   mssql-mcp.exe                 run the MCP server (Claude Code starts this)
//   mssql-mcp.exe --set-secret    read the app role password from stdin, store it DPAPI-encrypted (run as admin/SYSTEM)
//   mssql-mcp.exe --selftest      connect as the current user, activate the role, print who we are
//
// Config: %MSSQL_MCP_HOME% or C:\ProgramData\CCI\mssql-mcp\ — config.json {server, database, appRole, instructions,
// trustServerCertificate (opt-in for servers with a self-signed certificate)}
// and approle.dat (the DPAPI-encrypted password).
using System.ComponentModel;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

var home = Environment.GetEnvironmentVariable("MSSQL_MCP_HOME") ?? @"C:\ProgramData\CCI\mssql-mcp";

if (args.Contains("--set-secret"))
{
    // Windows PowerShell piping with a UTF-8 console encoding sends a BOM first; .NET's Trim() keeps U+FEFF.
    var pwd = Console.In.ReadLine()?.Trim().Trim('﻿').Trim();
    if (string.IsNullOrEmpty(pwd)) { Console.Error.WriteLine("no password on stdin"); return 1; }
    Directory.CreateDirectory(home);
    File.WriteAllBytes(Path.Combine(home, "approle.dat"),
        ProtectedData.Protect(Encoding.UTF8.GetBytes(pwd), Db.Entropy, DataProtectionScope.LocalMachine));
    Console.WriteLine("secret stored");
    return 0;
}

var db = new Db(Config.Load(home), home);

if (args.Contains("--selftest"))
{
    try
    {
        Console.WriteLine(await db.Run(c => Db.Scalar(c, "SELECT USER_NAME() + ' as ' + SUSER_SNAME() + ' on ' + @@SERVERNAME + '/' + DB_NAME()"), default));
        return 0;
    }
    catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }
}

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);   // stdout belongs to MCP
builder.Services.AddSingleton(db);
builder.Services
    .AddMcpServer(o => o.ServerInstructions = db.Cfg.Instructions)
    .WithStdioServerTransport()
    .WithTools<SqlTools>();
await builder.Build().RunAsync();
return 0;

sealed record Config(string Server, string Database, string AppRole, string? Instructions, bool TrustServerCertificate = false)
{
    public static Config Load(string home) =>
        JsonSerializer.Deserialize<Config>(File.ReadAllText(Path.Combine(home, "config.json")),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
        ?? throw new InvalidOperationException("config.json is empty");
}

sealed class Db(Config cfg, string home)
{
    public static readonly byte[] Entropy = Encoding.UTF8.GetBytes("cci-mssql-mcp");
    public Config Cfg => cfg;
    SqlConnection? conn;
    readonly SemaphoreSlim gate = new(1, 1);

    // One connection, used by one call at a time. The app role applies only to the connection it was set on, so every
    // call first proves the connection is still under the role and refuses otherwise (fail closed).
    public async Task<T> Run<T>(Func<SqlConnection, Task<T>> work, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    if (conn is not { State: ConnectionState.Open }) await Connect(ct);
                    if (await Scalar(conn!, "SELECT USER_NAME()") != cfg.AppRole)
                    {
                        Reset();
                        throw new InvalidOperationException($"Refusing to run: connection is not under app role '{cfg.AppRole}'.");
                    }
                    break;
                }
                catch (SqlException) when (attempt == 0) { Reset(); }   // stale connection: reconnect once
            }
            return await work(conn!);
        }
        catch (SqlException) when (conn is not { State: ConnectionState.Open }) { Reset(); throw; }
        finally { gate.Release(); }
    }

    async Task Connect(CancellationToken ct)
    {
        Reset();
        var csb = new SqlConnectionStringBuilder
        {
            DataSource = cfg.Server, InitialCatalog = cfg.Database, IntegratedSecurity = true,
            Pooling = false, Encrypt = true, TrustServerCertificate = cfg.TrustServerCertificate,
            ApplicationName = "claude-mssql-mcp", ConnectTimeout = 30,
        };
        var c = new SqlConnection(csb.ConnectionString);
        await c.OpenAsync(ct);
        var pwd = Encoding.UTF8.GetString(ProtectedData.Unprotect(
            File.ReadAllBytes(Path.Combine(home, "approle.dat")), Entropy, DataProtectionScope.LocalMachine));
        using (var cmd = new SqlCommand("sys.sp_setapprole", c) { CommandType = CommandType.StoredProcedure })
        {
            cmd.Parameters.AddWithValue("@rolename", cfg.AppRole);
            cmd.Parameters.AddWithValue("@password", pwd);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        conn = c;
    }

    void Reset()
    {
        conn?.Dispose();
        conn = null;
    }

    public static async Task<string?> Scalar(SqlConnection c, string sql)
    {
        using var cmd = new SqlCommand(sql, c);
        return (await cmd.ExecuteScalarAsync())?.ToString();
    }
}

[McpServerToolType]
sealed class SqlTools(Db db)
{
    static readonly Regex FirstWord = new(@"^\s*(?:(?:--[^\n]*\n|/\*.*?\*/)\s*)*(\w+)", RegexOptions.Singleline);

    [McpServerTool(Name = "query", ReadOnly = true), Description(
        "Run a read-only T-SQL query (SELECT, WITH or DECLARE batch) and get tab-separated results. " +
        "Some sensitive tables and columns are hidden; SELECT * fails on a table with a hidden column, so list columns " +
        "explicitly (describe_table shows which are readable). Text values are right-trimmed.")]
    public Task<string> Query(
        [Description("The T-SQL to run")] string sql,
        [Description("Max rows per result set (default 200, max 5000)")] int maxRows = 200,
        CancellationToken ct = default)
    {
        var word = FirstWord.Match(sql ?? "").Groups[1].Value.ToUpperInvariant();
        if (word is not ("SELECT" or "WITH" or "DECLARE"))
            return Task.FromResult("Error: only read queries are allowed (start with SELECT, WITH or DECLARE).");
        maxRows = Math.Clamp(maxRows, 1, 5000);
        return Safe(() => db.Run(async c =>
        {
            using var cmd = new SqlCommand(sql, c) { CommandTimeout = 120 };
            using var r = await cmd.ExecuteReaderAsync(ct);
            var sb = new StringBuilder();
            do
            {
                if (r.FieldCount == 0) continue;
                if (sb.Length > 0) sb.AppendLine();
                sb.AppendLine(string.Join('\t', Enumerable.Range(0, r.FieldCount).Select(r.GetName)));
                var n = 0;
                while (await r.ReadAsync(ct))
                {
                    if (n++ == maxRows) { sb.AppendLine($"... more rows not shown (maxRows={maxRows})"); break; }
                    sb.AppendLine(string.Join('\t', Enumerable.Range(0, r.FieldCount).Select(i => Cell(r.GetValue(i)))));
                }
                if (n == 0) sb.AppendLine("(no rows)");
            } while (await r.NextResultAsync(ct));
            return sb.Length == 0 ? "(no result set)" : sb.ToString();
        }, ct));
    }

    [McpServerTool(Name = "list_tables", ReadOnly = true), Description(
        "List readable tables and views, optionally filtered by a SQL LIKE pattern on the name (e.g. 'SOP%'). " +
        "Some may have hidden columns; see describe_table.")]
    public Task<string> ListTables(
        [Description("LIKE pattern on the table/view name; omit for all")] string? pattern = null,
        CancellationToken ct = default) =>
        Safe(() => db.Run(async c =>
        {
            using var cmd = new SqlCommand("""
                SELECT s.name + '.' + o.name, CASE o.type WHEN 'U' THEN 'table' ELSE 'view' END
                FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id
                WHERE o.type IN ('U','V') AND o.is_ms_shipped = 0 AND (@p IS NULL OR o.name LIKE @p)
                ORDER BY o.name
                """, c);
            cmd.Parameters.AddWithValue("@p", (object?)pattern ?? DBNull.Value);
            using var r = await cmd.ExecuteReaderAsync(ct);
            var sb = new StringBuilder();
            while (await r.ReadAsync(ct)) sb.Append(r.GetString(0)).Append('\t').AppendLine(r.GetString(1));
            return sb.Length == 0 ? "(none)" : sb.ToString();
        }, ct));

    [McpServerTool(Name = "describe_table", ReadOnly = true), Description(
        "Columns of a table or view with type, and whether each column is readable.")]
    public Task<string> DescribeTable(
        [Description("Table or view name, e.g. SOP30200 or dbo.SOP30200")] string table,
        CancellationToken ct = default) =>
        Safe(() => db.Run(async c =>
        {
            using var cmd = new SqlCommand("""
                SELECT c.name, TYPE_NAME(c.user_type_id) +
                         CASE WHEN TYPE_NAME(c.user_type_id) IN ('char','varchar','nchar','nvarchar')
                              THEN '(' + CAST(c.max_length AS varchar(10)) + ')' ELSE '' END,
                       CASE HAS_PERMS_BY_NAME(QUOTENAME(OBJECT_SCHEMA_NAME(c.object_id)) + '.' + QUOTENAME(OBJECT_NAME(c.object_id)),
                                              'OBJECT', 'SELECT', c.name, 'COLUMN') WHEN 1 THEN 'yes' ELSE 'HIDDEN' END
                FROM sys.columns c WHERE c.object_id = OBJECT_ID(@t) ORDER BY c.column_id
                """, c);
            cmd.Parameters.AddWithValue("@t", table);
            using var r = await cmd.ExecuteReaderAsync(ct);
            var sb = new StringBuilder("column\ttype\treadable\n");
            var any = false;
            while (await r.ReadAsync(ct)) { any = true; sb.AppendLine($"{r.GetString(0)}\t{r.GetString(1)}\t{r.GetString(2)}"); }
            return any ? sb.ToString() : $"No readable table or view named '{table}'.";
        }, ct));

    static string Cell(object v) => v switch
    {
        DBNull => "NULL",
        string s => s.TrimEnd().Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' '),
        DateTime d => d.TimeOfDay == TimeSpan.Zero ? d.ToString("yyyy-MM-dd") : d.ToString("yyyy-MM-dd HH:mm:ss"),
        byte[] b => "0x" + Convert.ToHexString(b.Length > 32 ? b[..32] : b) + (b.Length > 32 ? "..." : ""),
        _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "",
    };

    static async Task<string> Safe(Func<Task<string>> f)
    {
        try { return await f(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return "Error: " + ex.Message; }
    }
}
