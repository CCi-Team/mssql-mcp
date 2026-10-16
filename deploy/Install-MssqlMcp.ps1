<#
Install or update mssql-mcp for Claude Code on a Windows workstation. Run by NinjaOne as SYSTEM. Safe to re-run.

Reads Ninja custom fields (org scope, device can override):
  mssqlMcpConfig         multi-line text: config.json for the client {server, database, appRole, instructions,
                         trustServerCertificate}, plus optional deployExclude: computer names this must never run on
  mssqlMcpRolePassword   secure: SQL app role password
Writes (if the field exists):
  mssqlMcpStatus         device text: version, exe SHA-256 (for allow entries), server/database, selftest result

Then: release zip (SHA-256 checked) -> C:\Program Files\CCI\mssql-mcp, config + DPAPI secret -> C:\ProgramData\CCI\mssql-mcp,
registers the server in C:\Program Files\ClaudeCode\managed-mcp.json (exclusive MCP control) and merges
allowAllClaudeAiMcps + permissions.allow mcp__mssql__* into managed-settings.json. Last, runs --selftest as the
signed-in user (if any).

Exit codes: 1 bad fields/config/download or --set-secret failed, 2 computer in deployExclude, 3 Claude Code missing or
not runnable by standard users, 4 files unreadable (application control), 5 selftest as the user failed.
#>
$ErrorActionPreference = 'Stop'

$Version   = 'v0.1.0'
$ZipName   = "mssql-mcp-$Version-win-x64.zip"
$ZipSha256 = '672d0a175883f481fbf82125ab44cd9c37af333bbd09e33c39a9e99ee9b568f0'
$ZipUrl    = "https://github.com/CCi-Team/mssql-mcp/releases/download/$Version/$ZipName"

$AppDir    = Join-Path $env:ProgramFiles 'CCI\mssql-mcp'
$DataDir   = Join-Path $env:ProgramData 'CCI\mssql-mcp'
$ClaudeDir = Join-Path $env:ProgramFiles 'ClaudeCode'

function Log($m) { Write-Output "$(Get-Date -Format s) $m" }
# Windows PowerShell's -Encoding UTF8 adds a BOM, which JSON readers can reject
function Write-Text($p, $t) { [IO.File]::WriteAllText($p, $t, (New-Object System.Text.UTF8Encoding $false)) }

$config   = Ninja-Property-Get mssqlMcpConfig
$rolePwd  = Ninja-Property-Get mssqlMcpRolePassword
if (-not $config -or -not $rolePwd) { Log 'FAILED: mssqlMcpConfig or mssqlMcpRolePassword is empty'; exit 1 }
$cfg = $config | ConvertFrom-Json   # fail early on bad JSON
# managed-mcp.json is exclusive: machines with their own MCP setup must never get it
if (@($cfg.deployExclude) -contains $env:COMPUTERNAME) { Log "REFUSED: $env:COMPUTERNAME is in deployExclude"; exit 2 }
foreach ($k in 'server', 'database', 'appRole') { if (-not $cfg.$k) { Log "FAILED: config has no '$k'"; exit 1 } }
Log "config: $($cfg.server)/$($cfg.database) as $($cfg.appRole)"

# 0. Claude Code must be installed and runnable by standard users (winget can leave claude.exe admin-only)
# (resolve the package folder first: Windows PowerShell's -Recurse -Filter finds nothing under a wildcard path)
$claudeExe = Get-ChildItem (Join-Path $env:ProgramFiles 'WinGet\Packages\Anthropic.ClaudeCode_*'), (Join-Path $env:ProgramFiles 'Microsoft\WinGet\Packages\Anthropic.ClaudeCode_*') -Directory -ErrorAction SilentlyContinue |
    Get-ChildItem -Filter 'claude.exe' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $claudeExe) { Log 'FAILED: Claude Code is not installed machine-wide; run the Claude Code install script first'; exit 3 }
$usersCanRun = (Get-Acl $claudeExe.FullName).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
    Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -in 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0' -and
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile) }
if (-not $usersCanRun) { Log "FAILED: standard users cannot run $($claudeExe.FullName); re-run the Claude Code install script (it resets the ACL)"; exit 3 }

# 1. Binaries
$versionFile = Join-Path $AppDir 'version.txt'
$exe = Join-Path $AppDir 'mssql-mcp.exe'
if ((Test-Path $exe) -and (Test-Path $versionFile) -and (Get-Content $versionFile -Raw).Trim() -eq $Version) {
    Log "binaries $Version already installed"
} else {
    $tmp = Join-Path $env:TEMP "mssql-mcp-$([guid]::NewGuid()).zip"
    Invoke-WebRequest $ZipUrl -OutFile $tmp -UseBasicParsing
    $got = (Get-FileHash $tmp -Algorithm SHA256).Hash
    if ($got -ne $ZipSha256) { Remove-Item $tmp -Force; Log "FAILED: zip SHA-256 $got does not match"; exit 1 }
    New-Item -ItemType Directory -Force $AppDir | Out-Null
    Expand-Archive $tmp -DestinationPath $AppDir -Force
    Remove-Item $tmp -Force
    Write-Text $versionFile $Version
    Log "installed $Version to $AppDir"
}
# Application control (e.g. ThreatLocker) shows up as "Access is denied" on reading the files, even for SYSTEM
foreach ($f in $exe, (Join-Path $AppDir 'Microsoft.Data.SqlClient.SNI.dll')) {
    try { Log "$(Split-Path $f -Leaf) SHA-256 $((Get-FileHash $f -Algorithm SHA256 -ErrorAction Stop).Hash)" }
    catch { Log "FAILED: cannot read $f ($($_.Exception.Message)); allow it in application control (ThreatLocker)"; exit 4 }
}

# 2. Config and secret. Standard users can create folders under ProgramData, so a pre-existing folder (or a link planted
# in its place) is not trusted: anything not owned by SYSTEM/Administrators is removed and recreated. Owner Administrators;
# SYSTEM and Administrators full, Users read only.
function New-TrustedDir($path) {
    if (Test-Path $path) {
        $item = Get-Item $path -Force
        $owner = (Get-Acl $path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $owner -notin 'S-1-5-18', 'S-1-5-32-544') {
            Log "removing untrusted $path (owner $owner)"
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $item.Delete() } else { Remove-Item $path -Recurse -Force }
        }
    }
    New-Item -ItemType Directory -Force $path | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($id in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier $id), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl $path $acl
}
New-TrustedDir (Split-Path $DataDir)   # C:\ProgramData\CCI
New-TrustedDir $DataDir
Get-ChildItem $DataDir -Force | Where-Object { $_.Name -notin 'config.json', 'approle.dat' } | Remove-Item -Recurse -Force
Write-Text (Join-Path $DataDir 'config.json') $config
# Piping to the exe, or Process.StandardInput, writes a BOM first when the console input encoding is UTF-8 (cp 65001),
# which ends up in the stored password. Use UTF-8 without BOM for the child's stdin.
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding $false
$psi = New-Object System.Diagnostics.ProcessStartInfo $exe, '--set-secret'
$psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true
$p = [System.Diagnostics.Process]::Start($psi)
$p.StandardInput.WriteLine($rolePwd.Trim()); $p.StandardInput.Close(); $p.WaitForExit()
if ($p.ExitCode -ne 0) { Log 'FAILED: --set-secret'; exit 1 }
Log "config and secret written to $DataDir"

# 3. Claude Code registration (machine-wide)
New-Item -ItemType Directory -Force $ClaudeDir | Out-Null
function Read-Json($p) { if (Test-Path $p) { Get-Content $p -Raw | ConvertFrom-Json } else { [pscustomobject]@{} } }
function Set-Prop($o, $n, $v) { if ($o.PSObject.Properties[$n]) { $o.$n = $v } else { $o | Add-Member -NotePropertyName $n -NotePropertyValue $v } }

$mcpPath = Join-Path $ClaudeDir 'managed-mcp.json'
$mcp = Read-Json $mcpPath
if (-not $mcp.PSObject.Properties['mcpServers']) { Set-Prop $mcp 'mcpServers' ([pscustomobject]@{}) }
Set-Prop $mcp.mcpServers 'mssql' ([pscustomobject]@{ type = 'stdio'; command = $exe; args = @() })
Write-Text $mcpPath ($mcp | ConvertTo-Json -Depth 10)

$setPath = Join-Path $ClaudeDir 'managed-settings.json'
$set = Read-Json $setPath
Set-Prop $set 'allowAllClaudeAiMcps' $true
if (-not $set.PSObject.Properties['permissions']) { Set-Prop $set 'permissions' ([pscustomobject]@{}) }
$allow = @($set.permissions.allow | Where-Object { $_ }) + 'mcp__mssql__*' | Select-Object -Unique
Set-Prop $set.permissions 'allow' @($allow)
Write-Text $setPath ($set | ConvertTo-Json -Depth 10)
Log "registered in $mcpPath and $setPath"

# 4. Selftest as the signed-in console user (SYSTEM has no SQL login): a one-off interactive scheduled task, which runs
# in their session without a password, then is removed
$user = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $user) {
    $selftest = 'selftest pending (no user signed in; re-run to verify)'; $short = 'selftest pending'
} else {
    $out  = Join-Path $env:SystemRoot "Temp\mssql-mcp-selftest-$([guid]::NewGuid()).txt"   # users can create, not read others'
    $task = "CCI mssql-mcp selftest $([guid]::NewGuid())"
    # conhost --headless: no console window flashes up in the user's session. It breaks cmd's nested quotes, so run
    # from $AppDir and keep the command line free of quotes ($out has no spaces).
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" -Argument "--headless $env:ComSpec /c mssql-mcp.exe --selftest > $out 2>&1" -WorkingDirectory $AppDir
    Register-ScheduledTask -TaskName $task -Action $action -Principal (New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive) | Out-Null
    try {
        Start-ScheduledTask -TaskName $task
        $deadline = (Get-Date).AddSeconds(90)
        do { Start-Sleep 2 } while (((-not (Test-Path $out)) -or (Get-ScheduledTask -TaskName $task).State -ne 'Ready') -and (Get-Date) -lt $deadline)
        $result = if (Test-Path $out) { "$(Get-Content $out -Raw)".Trim() } else { 'no output (timed out)' }
    } finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
        Remove-Item $out -Force -ErrorAction SilentlyContinue
    }
    $ok = $result -match "^$([regex]::Escape($cfg.appRole)) as "
    $selftest = if ($ok) { "selftest OK: $result" } else { "selftest FAILED as ${user}: $result" }
    $short = if ($ok) { "selftest OK as $user" } else { "selftest FAILED as $user (see run log)" }   # field length limit
}
Log $selftest

# 5. Report
$exeHash = (Get-FileHash $exe -Algorithm SHA256).Hash
try { Ninja-Property-Set mssqlMcpStatus "$Version exe=$exeHash $($cfg.server)/$($cfg.database) $short $(Get-Date -Format s)" } catch { Log "mssqlMcpStatus not set: $($_.Exception.Message)" }
if ($selftest -like 'selftest FAILED*') { exit 5 }
Log 'done'
