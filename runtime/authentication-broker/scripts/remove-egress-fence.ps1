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
if (-not $WhatIfPreference) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run the explicit firewall removal from an elevated PowerShell session.'
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
    if ($persistent.Count -eq 0 -and $active.Count -eq 0) {
        Write-Output "Not present: $($spec.Name)"
        continue
    }
    if ($persistent.Count -ne 1 -or $active.Count -ne 1 -or
        -not (Test-ExistingRuleMatches $persistent[0] $spec $resolvedPath) -or
        -not (Test-ExistingRuleMatches $active[0] $spec $resolvedPath)) {
        throw "Existing rule $($spec.Name) does not match this exact broker installation; no rule was removed."
    }
    if ($PSCmdlet.ShouldProcess($spec.Name, "Remove exact broker-owned firewall rule for $resolvedPath")) {
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -ErrorAction Stop
    }
}
