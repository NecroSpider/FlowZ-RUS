<#
.SYNOPSIS
  Takes a snapshot of the Windows network state, or compares two snapshots.
  Written to find out what an app (e.g. MyPublicWiFi) changes the moment it is launched
  while FlowZ is connected and the internet dies.

.DESCRIPTION
  Run from an ELEVATED Windows PowerShell (5.1 is enough, nothing to install).

  1. Connect FlowZ to a node (TUN mode) and make sure the internet works.
  2. powershell -ExecutionPolicy Bypass -File .\win-net-snapshot.ps1 -Label before
  3. Launch the app (for MyPublicWiFi: do NOT press Start). Wait ~15 seconds.
     The internet should now be dead - do not fix it yet.
  4. powershell -ExecutionPolicy Bypass -File .\win-net-snapshot.ps1 -Label after
  5. powershell -ExecutionPolicy Bypass -File .\win-net-snapshot.ps1 -CompareFrom before -CompareTo after

  Result: <OutDir>\compare.txt and <OutDir>.zip (send the zip).
  Default OutDir: %USERPROFILE%\flowz-net-snapshots

  What is collected: adapters (incl. hidden) and their protocol/filter bindings, IPs, routes, DNS,
  proxy settings, firewall profiles + rule names, Windows Filtering Platform filters, services,
  loaded drivers, running process NAMES (no command lines), recent System event-log entries and a few
  connectivity probes. No passwords, no subscription links, no FlowZ config. It does contain local
  network details (adapter names, IPs, process/service names) - look at the files before sending.

  The script only reads system state. It changes nothing.
#>
[CmdletBinding(DefaultParameterSetName = 'Snapshot')]
param(
  [Parameter(ParameterSetName = 'Snapshot', Mandatory = $true)][string]$Label,
  [Parameter(ParameterSetName = 'Compare', Mandatory = $true)][string]$CompareFrom,
  [Parameter(ParameterSetName = 'Compare', Mandatory = $true)][string]$CompareTo,
  [string]$OutDir = (Join-Path $env:USERPROFILE 'flowz-net-snapshots')
)

$ErrorActionPreference = 'Continue'
$Utf8Bom = New-Object System.Text.UTF8Encoding($true)
$script:Problems = New-Object System.Collections.Generic.List[string]

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Runs a block, never throws. Always call as @(Safe { ... } 'what') so a single result stays an array.
function Safe([scriptblock]$Block, [string]$What) {
  try { return @(& $Block) }
  catch { $script:Problems.Add(('{0}: {1}' -f $What, $_.Exception.Message)); return @() }
}

# Runs a block in a separate process and gives up after $Seconds (DNS / HTTP can hang for a long time).
function Invoke-Bounded([scriptblock]$Script, [int]$Seconds) {
  $job = Start-Job -ScriptBlock $Script
  try {
    if (Wait-Job -Job $job -Timeout $Seconds) { return ((Receive-Job -Job $job) -join ' ') }
    return ('TIMEOUT after {0}s' -f $Seconds)
  }
  finally {
    Stop-Job -Job $job -ErrorAction SilentlyContinue
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
  }
}

function Get-XmlText($Node, [string]$XPath) {
  $n = $Node.SelectSingleNode($XPath)
  if ($null -ne $n) { return $n.InnerText }
  return ''
}

function Test-Tcp([string]$HostName, [int]$Port, [int]$Ms) {
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $t = $c.ConnectAsync($HostName, $Port)
    if ($t.Wait($Ms) -and $c.Connected) { return 'open' }
    return 'timeout'
  }
  catch { return ('error: ' + $_.Exception.Message) }
  finally { $c.Close() }
}

# ---------------------------------------------------------------------------------------------
# Snapshot mode
# ---------------------------------------------------------------------------------------------
function New-Snapshot([string]$Name) {
  if (-not (Test-Admin)) { throw 'Run this from an elevated (Administrator) PowerShell.' }
  if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

  $out = New-Object System.Collections.Generic.List[string]
  function Add-Section([string]$Title, $Lines, [bool]$Sort = $true) {
    $clean = @(@($Lines) | Where-Object { $null -ne $_ -and ([string]$_).Trim() -ne '' } | ForEach-Object { [string]$_ })
    if ($Sort) { $clean = @($clean | Sort-Object) }
    $out.Add('### ' + $Title)
    foreach ($l in $clean) { $out.Add($l) }
  }

  $startLocal = Get-Date
  Write-Host ('[{0}] collecting snapshot "{1}" - this takes about a minute' -f $startLocal.ToString('T'), $Name)

  Write-Host '  environment...'
  $os = $null
  try { $os = Get-CimInstance Win32_OperatingSystem } catch { }
  $env_ = @(
    ('label={0}' -f $Name),
    ('takenAtLocal={0}' -f $startLocal.ToString('s')),
    ('takenAtUtc={0}' -f $startLocal.ToUniversalTime().ToString('o')),
    ('computer={0}' -f $env:COMPUTERNAME),
    ('os={0} build {1}' -f $os.Caption, $os.BuildNumber),
    ('powershell={0}' -f $PSVersionTable.PSVersion),
    'admin=True'
  )
  Add-Section 'meta' $env_ $false

  Write-Host '  connectivity probes (up to ~25 s if the network is dead)...'
  $tests = @(
    ('tcp 1.1.1.1:443 = {0}' -f (Test-Tcp '1.1.1.1' 443 4000)),
    ('dns system example.com = {0}' -f (Invoke-Bounded {
          try {
            $r = Resolve-DnsName -Name example.com -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
            if ($r) { $r.IPAddress } else { 'no A record' }
          } catch { 'ERROR: ' + $_.Exception.Message }
        } 8)),
    ('dns via 1.1.1.1 example.com = {0}' -f (Invoke-Bounded {
          try {
            $r = Resolve-DnsName -Name example.com -Type A -Server 1.1.1.1 -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
            if ($r) { $r.IPAddress } else { 'no A record' }
          } catch { 'ERROR: ' + $_.Exception.Message }
        } 8)),
    ('http generate_204 = {0}' -f (Invoke-Bounded {
          try {
            $r = [System.Net.WebRequest]::Create('http://connectivitycheck.gstatic.com/generate_204')
            $r.Timeout = 5000
            $resp = $r.GetResponse()
            [string][int]$resp.StatusCode
            $resp.Close()
          } catch { 'ERROR: ' + $_.Exception.Message }
        } 9))
  )
  Add-Section 'tests' $tests $false

  Write-Host '  processes, drivers, services...'
  Add-Section 'keyProcesses' @(Safe {
      Get-Process | Where-Object { $_.Name -match 'mypublic|sing-box|flowz|npcap|winpcap|openvpn|wintun' } |
        ForEach-Object { '{0} | {1}' -f $_.Name, $_.Path }
    } 'keyProcesses')
  Add-Section 'processes' @(Safe { Get-Process | Select-Object -ExpandProperty Name -Unique } 'processes')
  Add-Section 'drivers' @(Safe {
      Get-CimInstance Win32_SystemDriver | ForEach-Object { '{0} | {1} | {2} | {3}' -f $_.Name, $_.State, $_.StartMode, $_.PathName }
    } 'drivers')
  Add-Section 'services' @(Safe {
      Get-Service | ForEach-Object { '{0} | {1} | {2}' -f $_.Name, $_.Status, $_.StartType }
    } 'services')

  Write-Host '  adapters and bindings...'
  Add-Section 'adapters' @(Safe {
      Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object {
        '{0} | {1} | status={2} | virtual={3} | hidden={4} | driver={5} | component={6}' -f $_.Name, $_.InterfaceDescription, $_.Status, $_.Virtual, $_.Hidden, $_.DriverFileName, $_.ComponentID
      }
    } 'adapters')
  Add-Section 'bindings' @(Safe {
      Get-NetAdapterBinding -AllBindings -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object {
        '{0} | {1} | {2} | enabled={3}' -f $_.Name, $_.ComponentID, $_.DisplayName, $_.Enabled
      }
    } 'bindings')

  Write-Host '  IPs, routes, DNS, proxy...'
  Add-Section 'interfaces' @(Safe {
      Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object {
        '{0} | {1} | metric={2} | forwarding={3} | dhcp={4} | state={5}' -f $_.InterfaceAlias, $_.AddressFamily, $_.InterfaceMetric, $_.Forwarding, $_.Dhcp, $_.ConnectionState
      }
    } 'interfaces')
  Add-Section 'ips' @(Safe {
      Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object {
        '{0} | {1}/{2} | {3} | {4}' -f $_.InterfaceAlias, $_.IPAddress, $_.PrefixLength, $_.AddressFamily, $_.AddressState
      }
    } 'ips')
  Add-Section 'routes' @(Safe {
      Get-NetRoute -ErrorAction SilentlyContinue | ForEach-Object {
        '{0} | {1} | via {2} | metric={3}' -f $_.InterfaceAlias, $_.DestinationPrefix, $_.NextHop, $_.RouteMetric
      }
    } 'routes')
  Add-Section 'dns' @(Safe {
      Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object {
        '{0} | {1} | {2}' -f $_.InterfaceAlias, $_.AddressFamily, (@($_.ServerAddresses) -join ',')
      }
    } 'dns')
  Add-Section 'nrpt' @(Safe {
      Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | ForEach-Object {
        '{0} -> {1}' -f (@($_.Namespace) -join ','), (@($_.NameServers) -join ',')
      }
    } 'nrpt')
  $proxy = @()
  $inet = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  foreach ($n in 'ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect') {
    $v = $null
    try { $v = (Get-ItemProperty -Path $inet -Name $n -ErrorAction SilentlyContinue).$n } catch { }
    $proxy += ('wininet.{0} = {1}' -f $n, $v)
  }
  $proxy += @(Safe { & netsh winhttp show proxy | ForEach-Object { if ($_.Trim()) { 'winhttp: ' + $_.Trim() } } } 'winhttp')
  Add-Section 'proxy' $proxy
  Add-Section 'hostedNetwork' @(Safe {
      & netsh wlan show hostednetwork | ForEach-Object { if ($_.Trim()) { $_.Trim() } }
    } 'hostednetwork')

  Write-Host '  firewall...'
  Add-Section 'firewallProfiles' @(Safe {
      Get-NetFirewallProfile | ForEach-Object { '{0} | enabled={1} | in={2} | out={3}' -f $_.Name, $_.Enabled, $_.DefaultInboundAction, $_.DefaultOutboundAction }
    } 'firewallProfiles')
  Add-Section 'firewallRules' @(Safe {
      Get-NetFirewallRule | ForEach-Object { '{0} | {1} | enabled={2} | {3} | {4}' -f $_.Name, $_.DisplayName, $_.Enabled, $_.Direction, $_.Action }
    } 'firewallRules')

  Write-Host '  Windows Filtering Platform (netsh wfp)...'
  $wfpFile = Join-Path $OutDir ($Name + '-wfp-filters.xml')
  $wfpProv = @(); $wfpSub = @(); $wfpFil = @()
  try {
    if (Test-Path -LiteralPath $wfpFile) { Remove-Item -LiteralPath $wfpFile -Force }
    Start-Process -FilePath 'netsh.exe' -ArgumentList ('wfp show filters file="{0}"' -f $wfpFile) -Wait -WindowStyle Hidden
    if (Test-Path -LiteralPath $wfpFile) {
      $xml = New-Object System.Xml.XmlDocument
      $xml.Load($wfpFile)
      # XPath instead of dotted access: a child element called "name" would clash with XmlElement.Name.
      foreach ($i in @($xml.SelectNodes('//providers/item'))) {
        $wfpProv += ('{0} | {1}' -f (Get-XmlText $i 'providerKey'), (Get-XmlText $i 'displayData/name'))
      }
      foreach ($i in @($xml.SelectNodes('//subLayers/item'))) {
        $wfpSub += ('{0} | {1} | weight={2}' -f (Get-XmlText $i 'subLayerKey'), (Get-XmlText $i 'displayData/name'), (Get-XmlText $i 'weight'))
      }
      foreach ($i in @($xml.SelectNodes('//filters/item'))) {
        $wfpFil += ('{0} | {1} | provider={2} | layer={3} | {4}' -f (Get-XmlText $i 'filterKey'), (Get-XmlText $i 'displayData/name'), (Get-XmlText $i 'providerKey'), (Get-XmlText $i 'layerKey'), (Get-XmlText $i 'action/type'))
      }
    } else { $script:Problems.Add('wfp: netsh produced no file') }
  } catch { $script:Problems.Add(('wfp: {0}' -f $_.Exception.Message)) }
  Add-Section 'wfpProviders' $wfpProv
  Add-Section 'wfpSubLayers' $wfpSub
  Add-Section 'wfpFilters' $wfpFil

  Write-Host '  System event log (last 60 min)...'
  Add-Section 'events' @(Safe {
      Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-60) } -MaxEvents 800 -ErrorAction SilentlyContinue | ForEach-Object {
        $m = ([string]$_.Message) -replace '\s+', ' '
        if ($m.Length -gt 240) { $m = $m.Substring(0, 240) }
        '{0} | {1} | {2} | {3}' -f $_.TimeCreated.ToString('s'), $_.Id, $_.ProviderName, $m
      }
    } 'events') $false

  Add-Section 'problems' @($script:Problems.ToArray()) $false

  $path = Join-Path $OutDir ($Name + '.snapshot.txt')
  [System.IO.File]::WriteAllLines($path, $out.ToArray(), $Utf8Bom)
  Write-Host ''
  Write-Host ('Saved: {0}' -f $path)
  if ($script:Problems.Count -gt 0) { Write-Host ('Note: {0} item(s) could not be collected (see the "problems" section).' -f $script:Problems.Count) }
}

# ---------------------------------------------------------------------------------------------
# Compare mode
# ---------------------------------------------------------------------------------------------
function Read-Snapshot([string]$Name) {
  $path = Join-Path $OutDir ($Name + '.snapshot.txt')
  if (-not (Test-Path -LiteralPath $path)) { throw ('Snapshot not found: ' + $path) }
  $map = @{}
  $cur = $null
  foreach ($line in [System.IO.File]::ReadAllLines($path, [System.Text.Encoding]::UTF8)) {
    if ($line.StartsWith('### ')) {
      $cur = $line.Substring(4)
      $map[$cur] = New-Object System.Collections.Generic.List[string]
    }
    elseif ($null -ne $cur) { $map[$cur].Add($line) }
  }
  return $map
}

function Get-Lines($Map, [string]$Key) {
  if ($Map.ContainsKey($Key)) { return @($Map[$Key].ToArray()) }
  return @()
}

function Get-Diff([string[]]$A, [string[]]$B) {
  $sa = New-Object 'System.Collections.Generic.HashSet[string]'
  $sb = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($x in $A) { [void]$sa.Add($x) }
  foreach ($x in $B) { [void]$sb.Add($x) }
  $removed = New-Object System.Collections.Generic.List[string]
  $added = New-Object System.Collections.Generic.List[string]
  foreach ($x in $A) { if (-not $sb.Contains($x)) { $removed.Add($x) } }
  foreach ($x in $B) { if (-not $sa.Contains($x)) { $added.Add($x) } }
  return @{ Removed = $removed; Added = $added }
}

function Compare-Snapshots([string]$From, [string]$To) {
  $a = Read-Snapshot $From
  $b = Read-Snapshot $To
  $cap = 200
  $rep = New-Object System.Collections.Generic.List[string]
  $rep.Add(('Network snapshot comparison: "{0}" -> "{1}"' -f $From, $To))
  $rep.Add('  "-" = present before, gone after;  "+" = new after.')
  $rep.Add('')

  $rep.Add('=== Connectivity probes ===')
  $rep.Add('--- before')
  foreach ($l in (Get-Lines $a 'tests')) { $rep.Add('  ' + $l) }
  $rep.Add('--- after')
  foreach ($l in (Get-Lines $b 'tests')) { $rep.Add('  ' + $l) }
  $rep.Add('')

  $order = @('keyProcesses', 'processes', 'drivers', 'services', 'bindings', 'adapters', 'interfaces', 'ips', 'routes',
    'dns', 'nrpt', 'proxy', 'hostedNetwork', 'firewallProfiles', 'wfpProviders', 'wfpSubLayers', 'wfpFilters', 'firewallRules')
  $unchanged = New-Object System.Collections.Generic.List[string]
  foreach ($sec in $order) {
    $d = Get-Diff (Get-Lines $a $sec) (Get-Lines $b $sec)
    if ($d.Removed.Count -eq 0 -and $d.Added.Count -eq 0) { $unchanged.Add($sec); continue }
    $rep.Add(('=== {0}  (-{1} / +{2}) ===' -f $sec, $d.Removed.Count, $d.Added.Count))
    $n = 0
    foreach ($l in $d.Removed) { if ($n -ge $cap) { $rep.Add('  ... more removed lines omitted'); break }; $rep.Add('- ' + $l); $n++ }
    $n = 0
    foreach ($l in $d.Added) { if ($n -ge $cap) { $rep.Add('  ... more added lines omitted'); break }; $rep.Add('+ ' + $l); $n++ }
    $rep.Add('')
  }

  $beforeAt = ''
  foreach ($l in (Get-Lines $a 'meta')) { if ($l.StartsWith('takenAtLocal=')) { $beforeAt = $l.Substring(13) } }
  $rep.Add(('=== System events since the "{0}" snapshot ({1}) ===' -f $From, $beforeAt))
  $n = 0
  foreach ($l in (Get-Lines $b 'events')) {
    if ($l.Length -ge 19 -and [string]::CompareOrdinal($l.Substring(0, 19), $beforeAt) -ge 0) {
      if ($n -ge $cap) { $rep.Add('  ... more events omitted'); break }
      $rep.Add($l); $n++
    }
  }
  if ($n -eq 0) { $rep.Add('  (none)') }
  $rep.Add('')

  foreach ($tag in @($From, $To)) {
    $m = if ($tag -eq $From) { $a } else { $b }
    $p = Get-Lines $m 'problems'
    if ($p.Count -gt 0) {
      $rep.Add(('=== Collection problems in "{0}" ===' -f $tag))
      foreach ($l in $p) { $rep.Add('  ' + $l) }
      $rep.Add('')
    }
  }
  $rep.Add('Sections with no differences: ' + ($unchanged -join ', '))

  $reportPath = Join-Path $OutDir 'compare.txt'
  [System.IO.File]::WriteAllLines($reportPath, $rep.ToArray(), $Utf8Bom)
  $zip = $OutDir.TrimEnd('\') + '.zip'
  try {
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zip -Force
    Write-Host ('Zip to send: {0}' -f $zip)
  } catch { Write-Host ('Could not create the zip ({0}); send the folder {1} instead.' -f $_.Exception.Message, $OutDir) }
  Write-Host ('Report: {0}' -f $reportPath)
  Write-Host ''
  # Short console preview; the full report is in compare.txt.
  foreach ($l in @($rep | Select-Object -First 60)) { Write-Host $l }
  if ($rep.Count -gt 60) { Write-Host ('... ({0} more lines in compare.txt)' -f ($rep.Count - 60)) }
}

if ($PSCmdlet.ParameterSetName -eq 'Compare') { Compare-Snapshots $CompareFrom $CompareTo }
else { New-Snapshot $Label }
