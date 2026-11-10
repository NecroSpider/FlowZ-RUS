<#
.SYNOPSIS
  Guides a FlowZ and OpenVPN test and saves a local ZIP with network snapshots.
.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\collect-flowz-windows.ps1 -WorkHost portal.example.org
.NOTES
  Compatible with Windows PowerShell 5.1. Run as your usual Windows user.
  Network state is read only. Use FlowZ's diagnostic export for its redacted logs.
#>
[CmdletBinding()]
param(
  [ValidatePattern('^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$')]
  [string]$WorkHost,
  [string]$OutputRoot = [Environment]::GetFolderPath('MyDocuments'),
  [switch]$SnapshotOnly
)

$ErrorActionPreference = 'Stop'
if (-not $OutputRoot) { $OutputRoot = $env:USERPROFILE }
$name = 'FlowZ-Diagnostics-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$directory = New-Item -ItemType Directory -Path (Join-Path $OutputRoot $name)

function Save-Json([string]$Name, $Value) {
  $Value | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $directory.FullName $Name) -Encoding UTF8
}

function Read-Section([scriptblock]$Read) {
  try {
    @{ rows = @(& $Read) }
  } catch {
    @{ rows = @(); errorType = $_.Exception.GetType().Name; errorId = $_.FullyQualifiedErrorId }
  }
}

function Test-Endpoint([string]$HostName, [int]$Port, [string]$Path) {
  $dns = Read-Section {
    Resolve-DnsName -Name $HostName -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
      Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
  }
  $routes = Read-Section {
    foreach ($address in $dns.rows) {
      Find-NetRoute -RemoteIPAddress $address -ErrorAction Stop |
        Select-Object InterfaceAlias, InterfaceIndex, IPAddress, DestinationPrefix, NextHop, RouteMetric
    }
  }
  $http = @{ available = $false }
  $curl = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($curl) {
    $url = 'https://{0}:{1}{2}' -f $HostName, $Port, $Path
    $status = & $curl.Source -q --noproxy '*' --silent --head --output NUL --write-out '%{http_code}' --connect-timeout 4 --max-time 8 $url
    $http = @{ available = $true; status = $status; exitCode = $LASTEXITCODE }
  }
  @{ host = $HostName; dns = $dns; routes = $routes; https = $http }
}

function Read-OpenVpnSummary {
  $paths = @()
  if ($env:APPDATA) {
    $paths += Join-Path $env:APPDATA 'OpenVPN Connect\log\openvpn.log'
    $paths += Join-Path $env:APPDATA 'OpenVPN Connect\log\ovpn.log'
  }
  if ($env:USERPROFILE) {
    $paths += @(Get-ChildItem -LiteralPath (Join-Path $env:USERPROFILE 'OpenVPN\log') -Filter '*.log' -File -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 2 -ExpandProperty FullName)
  }
  # Keep only selected network options and event names. PUSH_REPLY can also contain auth tokens.
  $networkOption = '^(?:route(?:-ipv6|-gateway|-metric)?|dhcp-option (?:DNS|DNS6|DOMAIN|DOMAIN-SEARCH|DOMAIN-ROUTE)|redirect-gateway|block-outside-dns)(?: [A-Za-z0-9.:/_ -]+)?$'
  $trimChars = [char[]]@(32, 34, 39)
  foreach ($file in $paths) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { continue }
    $entries = foreach ($line in (Get-Content -LiteralPath $file -Tail 450 -ErrorAction Stop)) {
      $timestamp = [regex]::Match($line, '^\[?(?:\d{4}[-/]\d{2}[-/]\d{2}|\w{3} \w{3} +\d{1,2})[ T]+\d{2}:\d{2}:\d{2}').Value
      if ($line -match 'PUSH_REPLY(?:,(.*))?') {
        $options = @(([string]$Matches[1]) -split ',' | ForEach-Object { $_.Trim($trimChars) } | Where-Object { $_ -match $networkOption })
        @{ time = $timestamp; event = 'PUSH_REPLY'; options = $options }
      } elseif ($line -match '(?:^|\s)(\[(?:route(?:-ipv6|-gateway|-metric)?|dhcp-option|redirect-gateway|block-outside-dns)\].*)') {
        $option = ([regex]::Matches($Matches[1], '\[([A-Za-z0-9.:/_ -]+)\]') | ForEach-Object { $_.Groups[1].Value }) -join ' '
        if ($option -match $networkOption) { @{ time = $timestamp; event = 'OPTION'; options = @($option) } }
      } elseif ($line -match '\b(EVENT:\s*(?:CONNECTED|DISCONNECTED|AUTH_FAILED|TLS_ERROR|TUN_SETUP_FAILED)|Initialization Sequence Completed|AUTH_FAILED|TLS Error)\b') {
        @{ time = $timestamp; event = $Matches[1] }
      }
    }
    @{
      source = if ($file -like '*OpenVPN Connect*') { 'OpenVPN Connect' } else { 'OpenVPN GUI' }
      modifiedUtc = (Get-Item -LiteralPath $file).LastWriteTimeUtc.ToString('o')
      tail = @($entries | Select-Object -Last 100)
    }
  }
}

function Save-Snapshot([string]$Stage, [switch]$Vpn) {
  Write-Host ('Collecting {0}...' -f $Stage)
  $snapshot = [ordered]@{
    stage = $Stage
    startedUtc = [DateTime]::UtcNow.ToString('o')
    osVersion = [Environment]::OSVersion.Version.ToString()
    processes = Read-Section { Get-Process -Name 'FlowZ', 'sing-box', 'openvpn*', 'ovpn*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique }
    adapters = Read-Section { Get-NetAdapter -IncludeHidden | Select-Object Name, InterfaceDescription, ifIndex, Status }
    addresses = Read-Section { Get-NetIPAddress | Select-Object InterfaceAlias, InterfaceIndex, IPAddress, PrefixLength, AddressState }
    interfaces = Read-Section { Get-NetIPInterface | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, InterfaceMetric, ConnectionState }
    routes = Read-Section { Get-NetRoute -PolicyStore ActiveStore | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, DestinationPrefix, NextHop, RouteMetric }
    dns = Read-Section { Get-DnsClientServerAddress | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses }
    suffixes = Read-Section { Get-DnsClient | Select-Object InterfaceAlias, InterfaceIndex, ConnectionSpecificSuffix }
    nrpt = Read-Section { Get-DnsClientNrptPolicy -Effective | Select-Object Namespace, NameServers, DirectAccessDnsServers }
    publicProbe = Test-Endpoint 'www.gstatic.com' 443 '/generate_204'
  }
  if ($Vpn) {
    $snapshot.openvpn = Read-Section { Read-OpenVpnSummary }
    if ($WorkHost) { $snapshot.workProbe = Test-Endpoint $WorkHost 443 '/' }
  }
  $snapshot.finishedUtc = [DateTime]::UtcNow.ToString('o')
  Save-Json "$Stage.json" $snapshot
}

function Wait-Step([string]$Message) {
  Write-Host ''
  Write-Host $Message
  [void](Read-Host 'Press Enter when ready, even if the connection failed')
}

if ($SnapshotOnly) {
  Save-Snapshot 'snapshot' -Vpn
} else {
  Wait-Step 'Disconnect FlowZ and OpenVPN. In FlowZ open Settings > Advanced > Diagnostics and start diagnostic capture.'
  Save-Snapshot '01-baseline'
  Wait-Step 'Connect the usual OpenVPN profile with FlowZ still disconnected. Check the work site.'
  Save-Snapshot '02-openvpn-only' -Vpn
  Wait-Step 'Disconnect OpenVPN. Update Shadow, connect FlowZ in TUN mode, apply pending node changes if shown and run the Shadow group test. Wait for its result.'
  Save-Snapshot '03-flowz-shadow'
  Wait-Step 'Keep FlowZ connected and connect OpenVPN again. Return here as soon as OpenVPN reports a result.'
  Save-Snapshot '04-combined'
  Write-Host 'Waiting 35 seconds for Windows and FlowZ to reconcile routes and DNS...'
  Start-Sleep -Seconds 35
  Save-Snapshot '05-combined-settled' -Vpn
  $reportPath = Join-Path $directory.FullName 'flowz-report.md'
  Write-Host ('In FlowZ export the diagnostic report to {0}' -f $reportPath)
  [void](Read-Host 'Press Enter after exporting, or leave it out and send the report separately')
  if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
    Write-Warning 'The ZIP will contain network snapshots only. Export the FlowZ diagnostic report separately.'
  }
  Write-Host 'You can now stop diagnostic capture in FlowZ.'
}

$archive = "$($directory.FullName).zip"
Compress-Archive -Path (Join-Path $directory.FullName '*') -DestinationPath $archive
Write-Host ('Review and share this ZIP in the private diagnostic chat: {0}' -f $archive)
