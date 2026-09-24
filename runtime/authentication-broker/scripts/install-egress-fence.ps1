[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$ChromiumPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CanonicalExecutablePath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '[*?"<>|;]' -or $Value -notmatch '^[A-Za-z]:\\.*\.exe$') {
        throw 'ChromiumPath must be one exact absolute Windows .exe path.'
    }
    return [IO.Path]::GetFullPath($Value)
}

function Convert-ProtocolName($Value) {
    switch ([string]$Value) {
        '6' { return 'TCP' }
        '17' { return 'UDP' }
        '256' { return 'Any' }
        default { return ([string]$Value).ToUpperInvariant() }
    }
}

function Test-ExistingRuleMatches($Rule, $Spec, [string]$ProgramPath) {
    $addressFilter = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule)
    $portFilter = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule)
    $appFilter = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule)
    if ($addressFilter.Count -ne 1 -or $portFilter.Count -ne 1 -or $appFilter.Count -ne 1) { return $false }
    $remoteAddress = (@($addressFilter[0].RemoteAddress | ForEach-Object { [string]$_ }) -join ',')
    $remotePort = (@($portFilter[0].RemotePort | ForEach-Object { [string]$_ }) -join ',')
    $profile = (@($Rule.Profile | ForEach-Object { [string]$_ }) -join ',')
    $protocol = Convert-ProtocolName $portFilter[0].Protocol
    return ([string]$Rule.Enabled -eq 'True' -and [string]$Rule.Direction -eq $Spec.Direction -and
        [string]$Rule.Action -eq $Spec.Action -and [string]$appFilter[0].Program -ieq $ProgramPath -and
        $remoteAddress -eq $Spec.RemoteAddress -and $remotePort -eq $Spec.RemotePort -and
        $protocol -eq $Spec.Protocol -and $profile -eq 'Any')
}

$resolvedPath = Get-CanonicalExecutablePath $ChromiumPath
if (-not $WhatIfPreference -and -not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
    throw 'ChromiumPath does not name an existing executable.'
}
if (-not $WhatIfPreference) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run the explicit firewall setup from an elevated PowerShell session.'
    }
}
Import-Module NetSecurity -ErrorAction Stop

$ruleSpecs = @(
    [pscustomobject]@{ Name = 'BHS-AB-Chromium-Block-v4-low'; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = '0.0.0.0-127.0.0.0'; RemotePort = 'Any'; Protocol = 'Any' },
    [pscustomobject]@{ Name = 'BHS-AB-Chromium-Block-v4-high'; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = '127.0.0.2-255.255.255.255'; RemotePort = 'Any'; Protocol = 'Any' },
    [pscustomobject]@{ Name = 'BHS-AB-Chromium-Block-v6-unspecified'; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = '::'; RemotePort = 'Any'; Protocol = 'Any' },
    [pscustomobject]@{ Name = 'BHS-AB-Chromium-Block-v6-nonloopback'; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'; RemotePort = 'Any'; Protocol = 'Any' },
    [pscustomobject]@{ Name = 'BHS-AB-Chromium-Block-v6-loopback'; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = '::1'; RemotePort = 'Any'; Protocol = 'Any' },
    [pscustomobject]@{ Name = 'BHS-AB-Chromium-Block-local-low'; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = '127.0.0.1'; RemotePort = '1-8765'; Protocol = 'TCP' },
    [pscustomobject]@{ Name = 'BHS-AB-Chromium-Block-local-high'; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = '127.0.0.1'; RemotePort = '8767-65535'; Protocol = 'TCP' },
    [pscustomobject]@{ Name = 'BHS-AB-Chromium-Block-local-udp'; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = '127.0.0.1'; RemotePort = 'Any'; Protocol = 'UDP' }
)

foreach ($spec in $ruleSpecs) {
    $persistent = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -ErrorAction SilentlyContinue)
    $active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $spec.Name -ErrorAction SilentlyContinue)
    if ($persistent.Count -gt 1 -or $active.Count -gt 1) { throw "Multiple firewall rules use broker rule name $($spec.Name)." }
    if ($persistent.Count -eq 0 -and $active.Count -gt 0) {
        throw "An external active firewall rule uses broker rule name $($spec.Name); no changes were made."
    }
    if ($persistent.Count -eq 1) {
        if ($active.Count -ne 1 -or -not (Test-ExistingRuleMatches $persistent[0] $spec $resolvedPath) -or
            -not (Test-ExistingRuleMatches $active[0] $spec $resolvedPath)) {
            throw "Existing broker rule $($spec.Name) differs from the approved configuration; no changes were made."
        }
        Write-Output "Already present and exact: $($spec.Name)"
        continue
    }

    Write-Output "Broker rule: $($spec.Name)"
    if (-not $PSCmdlet.ShouldProcess($spec.Name, "Create outbound Chromium block rule for $resolvedPath")) { continue }
    $parameters = @{
        Name = $spec.Name
        DisplayName = $spec.Name
        Group = 'BugHuntSkills Authentication Broker'
        Description = 'Exact-path browser egress fence. Managed target traffic may reach only the local broker proxy.'
        Direction = $spec.Direction
        Action = $spec.Action
        Program = $resolvedPath
        RemoteAddress = $spec.RemoteAddress
        Protocol = $spec.Protocol
        Profile = 'Any'
        Enabled = 'True'
        ErrorAction = 'Stop'
    }
    if ($spec.RemotePort -ne 'Any') { $parameters.RemotePort = $spec.RemotePort }
    New-NetFirewallRule @parameters | Out-Null
}
