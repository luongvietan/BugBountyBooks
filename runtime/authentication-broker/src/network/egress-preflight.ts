import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { release as osRelease } from 'node:os';

export const BROKER_PROXY_HOST = '127.0.0.1';
export const BROKER_PROXY_PORT = 8766;
export const BROKER_PROXY_URL = `http://${BROKER_PROXY_HOST}:${BROKER_PROXY_PORT}`;

export interface FirewallRuleSnapshot {
  name: string;
  enabled: boolean;
  direction: 'Inbound' | 'Outbound';
  action: 'Block' | 'Allow';
  program: string;
  remoteAddress: string;
  remotePort: string;
  protocol: 'Any' | 'TCP' | 'UDP';
  profile: string;
}

export interface EgressSnapshot {
  platform: string;
  windowsBuild: number;
  proxy: { listening: boolean; host: string; port: number };
  browserExecutablePath: string;
  launchOptions: { proxy: { server: string; bypass: string }; args: readonly string[] };
  firewallRules: readonly FirewallRuleSnapshot[];
  activePolicyReadComplete: boolean;
  firewallProfilesEnabled: boolean;
  effectivePolicyComplete: boolean;
  conflictingRules: boolean;
}

interface RuleTemplate extends Omit<FirewallRuleSnapshot, 'program' | 'enabled'> {
  enabled: true;
}

export const REQUIRED_EGRESS_RULES: readonly RuleTemplate[] = Object.freeze([
  Object.freeze({ name: 'BHS-AB-Chromium-Block-v4-low', enabled: true, direction: 'Outbound', action: 'Block', remoteAddress: '0.0.0.0-127.0.0.0', remotePort: 'Any', protocol: 'Any', profile: 'Any' }),
  Object.freeze({ name: 'BHS-AB-Chromium-Block-v4-high', enabled: true, direction: 'Outbound', action: 'Block', remoteAddress: '127.0.0.2-255.255.255.255', remotePort: 'Any', protocol: 'Any', profile: 'Any' }),
  Object.freeze({ name: 'BHS-AB-Chromium-Block-v6-unspecified', enabled: true, direction: 'Outbound', action: 'Block', remoteAddress: '::', remotePort: 'Any', protocol: 'Any', profile: 'Any' }),
  Object.freeze({ name: 'BHS-AB-Chromium-Block-v6-nonloopback', enabled: true, direction: 'Outbound', action: 'Block', remoteAddress: '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', remotePort: 'Any', protocol: 'Any', profile: 'Any' }),
  Object.freeze({ name: 'BHS-AB-Chromium-Block-v6-loopback', enabled: true, direction: 'Outbound', action: 'Block', remoteAddress: '::1', remotePort: 'Any', protocol: 'Any', profile: 'Any' }),
  Object.freeze({ name: 'BHS-AB-Chromium-Block-local-low', enabled: true, direction: 'Outbound', action: 'Block', remoteAddress: '127.0.0.1', remotePort: '1-8765', protocol: 'TCP', profile: 'Any' }),
  Object.freeze({ name: 'BHS-AB-Chromium-Block-local-high', enabled: true, direction: 'Outbound', action: 'Block', remoteAddress: '127.0.0.1', remotePort: '8767-65535', protocol: 'TCP', profile: 'Any' }),
  Object.freeze({ name: 'BHS-AB-Chromium-Block-local-udp', enabled: true, direction: 'Outbound', action: 'Block', remoteAddress: '127.0.0.1', remotePort: 'Any', protocol: 'UDP', profile: 'Any' })
]);

export function managedBrowserNetworkOptions(proxyPort = BROKER_PROXY_PORT): EgressSnapshot['launchOptions'] {
  if (proxyPort !== BROKER_PROXY_PORT) throw new Error('Managed proxy port is fixed by the egress fence');
  return Object.freeze({
    proxy: Object.freeze({ server: BROKER_PROXY_URL, bypass: '<-loopback>' }),
    args: Object.freeze(['--disable-quic'])
  });
}

export function egressPreflight(snapshot: unknown): { status: 'verified' | 'unverified'; reason: string } {
  if (!isRecord(snapshot)) return unverified('host state unavailable');
  const candidate = snapshot as Partial<EgressSnapshot>;
  if (candidate.platform !== 'win32' || !Number.isInteger(candidate.windowsBuild) || (candidate.windowsBuild ?? 0) < 22000) return unverified('unsupported host');
  if (!isRecord(candidate.proxy) || candidate.proxy.listening !== true || candidate.proxy.host !== BROKER_PROXY_HOST || candidate.proxy.port !== BROKER_PROXY_PORT) return unverified('proxy listener mismatch');
  if (!isExactWindowsExecutable(candidate.browserExecutablePath ?? '')) return unverified('browser path invalid');
  if (!isRecord(candidate.launchOptions) || !isRecord(candidate.launchOptions.proxy) || !Array.isArray(candidate.launchOptions.args)) return unverified('browser network options unavailable');
  if (!Array.isArray(candidate.firewallRules)) return unverified('required firewall rules unavailable');
  let expectedOptions: EgressSnapshot['launchOptions'];
  try { expectedOptions = managedBrowserNetworkOptions(); } catch { return unverified('browser network options unavailable'); }
  const launchOptions = candidate.launchOptions as EgressSnapshot['launchOptions'];
  if (launchOptions.proxy.server !== expectedOptions.proxy.server || launchOptions.proxy.bypass !== expectedOptions.proxy.bypass ||
      launchOptions.args.length !== expectedOptions.args.length || launchOptions.args.some((argument, index) => argument !== expectedOptions.args[index])) {
    return unverified('browser proxy configuration mismatch');
  }
  if (candidate.activePolicyReadComplete !== true || candidate.firewallProfilesEnabled !== true ||
      candidate.effectivePolicyComplete !== true || candidate.conflictingRules !== false) return unverified('effective firewall state unavailable or conflicting');
  if (candidate.firewallRules.length !== REQUIRED_EGRESS_RULES.length) return unverified('required firewall rules unavailable');
  const actualByName = new Map<string, FirewallRuleSnapshot>();
  for (const rawActual of candidate.firewallRules) {
    if (!isRecord(rawActual) || typeof rawActual.name !== 'string') return unverified('firewall rule data is malformed');
    const actual = rawActual as unknown as FirewallRuleSnapshot;
    if (actualByName.has(actual.name)) return unverified('duplicate firewall rule');
    actualByName.set(actual.name, actual);
  }
  for (const expected of REQUIRED_EGRESS_RULES) {
    const actual = actualByName.get(expected.name);
    if (!actual || actual.enabled !== true || actual.direction !== expected.direction || actual.action !== expected.action ||
        !sameWindowsPath(actual.program, candidate.browserExecutablePath ?? '') || actual.remoteAddress !== expected.remoteAddress ||
        actual.remotePort !== expected.remotePort || actual.protocol !== expected.protocol || actual.profile !== expected.profile) {
      return unverified('firewall rule mismatch');
    }
  }
  return { status: 'verified', reason: 'verified' };
}

export interface FirewallSnapshotOptions {
  browserExecutablePath: string;
  /** Replace only in tests; production runs the built-in read-only query. */
  runPowerShell?: (encodedCommand: string) => Promise<string>;
}

/** Read-only ActiveStore query. Any PowerShell, permission, or schema error returns no snapshot. */
export async function readWindowsFirewallSnapshot(options: FirewallSnapshotOptions): Promise<{
  firewallRules: readonly FirewallRuleSnapshot[];
  activePolicyReadComplete: boolean;
  firewallProfilesEnabled: boolean;
  conflictingRules: boolean;
  effectivePolicyComplete: boolean;
} | undefined> {
  if (process.platform !== 'win32' || !isExactWindowsExecutable(options.browserExecutablePath)) return undefined;
  try {
    const script = buildFirewallReadScript(options.browserExecutablePath);
    const output = await (options.runPowerShell ?? runPowerShell)(script);
    const parsed: unknown = JSON.parse(output);
    if (!isRecord(parsed) || !Array.isArray(parsed.firewallRules) || typeof parsed.firewallProfilesEnabled !== 'boolean' ||
        typeof parsed.conflictingRules !== 'boolean' || parsed.activePolicyReadComplete !== true) return undefined;
    const rules = parsed.firewallRules.map((value) => {
      if (!isRecord(value)) throw new Error('Malformed firewall snapshot');
      return value as unknown as FirewallRuleSnapshot;
    });
    return Object.freeze({
      firewallRules: Object.freeze(rules),
      activePolicyReadComplete: true,
      firewallProfilesEnabled: parsed.firewallProfilesEnabled,
      conflictingRules: parsed.conflictingRules,
      effectivePolicyComplete: true
    });
  } catch {
    return undefined;
  }
}

export async function createCurrentEgressSnapshot(input: {
  proxy: EgressSnapshot['proxy'];
  browserExecutablePath: string;
  launchOptions: EgressSnapshot['launchOptions'];
}): Promise<EgressSnapshot | undefined> {
  if (process.platform !== 'win32') return undefined;
  const build = Number(osRelease().split('.').at(-1));
  if (!Number.isInteger(build)) return undefined;
  const firewall = await readWindowsFirewallSnapshot({ browserExecutablePath: input.browserExecutablePath });
  if (!firewall) return undefined;
  return {
    platform: process.platform,
    windowsBuild: build,
    proxy: input.proxy,
    browserExecutablePath: input.browserExecutablePath,
    launchOptions: input.launchOptions,
    ...firewall
  };
}

function isExactWindowsExecutable(value: string): boolean {
  if (typeof value !== 'string' || !path.win32.isAbsolute(value) || !/^[a-z]:\\/i.test(value) || /[*?"<>|;]/.test(value)) return false;
  return /\.exe$/i.test(path.win32.normalize(value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function buildFirewallReadScript(browserExecutablePath: string): string {
  const path64 = Buffer.from(browserExecutablePath, 'utf8').toString('base64');
  const ruleNames = REQUIRED_EGRESS_RULES.map((rule) => `'${rule.name}'`).join(',');
  return `$ErrorActionPreference='Stop'
Import-Module NetSecurity -ErrorAction Stop
$program=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${path64}'))
$names=@(${ruleNames})
$rules=@()
foreach($name in $names){
  $matches=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction SilentlyContinue)
  foreach($rule in $matches){
    $addresses=@(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $ports=@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    $apps=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
    if($addresses.Count -ne 1 -or $ports.Count -ne 1 -or $apps.Count -ne 1){ throw 'Incomplete rule filter' }
    $protocol=switch([string]$ports[0].Protocol){ '6' {'TCP'} '17' {'UDP'} '256' {'Any'} default {[string]$ports[0].Protocol} }
    $rules+=,[pscustomobject]@{
      name=[string]$rule.Name; enabled=([string]$rule.Enabled -eq 'True'); direction=[string]$rule.Direction
      action=[string]$rule.Action; program=[string]$apps[0].Program
      remoteAddress=(@($addresses[0].RemoteAddress | ForEach-Object {[string]$_}) -join ',')
      remotePort=(@($ports[0].RemotePort | ForEach-Object {[string]$_}) -join ',')
      protocol=$protocol; profile=(@($rule.Profile | ForEach-Object {[string]$_}) -join ',')
    }
  }
}
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
$profilesEnabled=($profiles.Count -ge 3 -and @($profiles | Where-Object { [string]$_.Enabled -ne 'True' }).Count -eq 0)
$nameSet=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($name in $names){[void]$nameSet.Add($name)}
$conflict=$false
$active=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop)
foreach($rule in $active){
  if($nameSet.Contains([string]$rule.Name)){continue}
  $apps=@(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
  if($apps.Count -eq 1 -and [string]$apps[0].Program -and [string]$apps[0].Program -ieq $program){$conflict=$true;break}
}
[pscustomobject]@{firewallRules=@($rules);activePolicyReadComplete=$true;firewallProfilesEnabled=[bool]$profilesEnabled;conflictingRules=[bool]$conflict} | ConvertTo-Json -Depth 5 -Compress`;
}

const execFileAsync = promisify(execFile);

async function runPowerShell(script: string): Promise<string> {
  const encodedCommand = Buffer.from(script, 'utf16le').toString('base64');
  const result = await execFileAsync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodedCommand], {
    windowsHide: true,
    timeout: 8000,
    maxBuffer: 1_048_576,
    encoding: 'utf8'
  });
  return result.stdout;
}

function sameWindowsPath(left: string, right: string): boolean {
  if (!isExactWindowsExecutable(left) || !isExactWindowsExecutable(right)) return false;
  return path.win32.normalize(left).toLowerCase() === path.win32.normalize(right).toLowerCase();
}

function unverified(reason: string): { status: 'unverified'; reason: string } {
  return { status: 'unverified', reason };
}
