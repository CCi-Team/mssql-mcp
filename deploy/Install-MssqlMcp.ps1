<#
Install or update mssql-mcp for Claude Code on a Windows workstation. Run by NinjaOne as SYSTEM. Safe to re-run.

Reads Ninja custom fields (org scope, device can override):
  mssqlMcpConfig         multi-line text: config.json for the client {server, database, appRole, instructions,
                         trustServerCertificate}, plus optional deployExclude: computer names this must never run on
  mssqlMcpRolePassword   secure: SQL app role password
Writes (if the field exists):
  mssqlMcpStatus         device text: installed version and exe SHA-256 (for the SentinelOne allow entry)

Then: release zip (SHA-256 checked) -> C:\Program Files\CCI\mssql-mcp, config + DPAPI secret -> C:\ProgramData\CCI\mssql-mcp,
registers the server in C:\Program Files\ClaudeCode\managed-mcp.json (exclusive MCP control) and merges
allowAllClaudeAiMcps + permissions.allow mcp__mssql__* into managed-settings.json.
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
$rolePwd | & $exe --set-secret
if ($LASTEXITCODE -ne 0) { Log 'FAILED: --set-secret'; exit 1 }
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

# 4. Report
$exeHash = (Get-FileHash $exe -Algorithm SHA256).Hash
Log "mssql-mcp.exe SHA-256 $exeHash"
try { Ninja-Property-Set mssqlMcpStatus "$Version exe=$exeHash $(Get-Date -Format s)" } catch { Log "mssqlMcpStatus not set: $($_.Exception.Message)" }
Log 'done. Identity test must run as the user: & "C:\Program Files\CCI\mssql-mcp\mssql-mcp.exe" --selftest'
