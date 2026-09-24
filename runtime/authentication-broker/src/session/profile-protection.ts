import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';

export interface ProfileProtectionEvidence {
  readonly volumeEncrypted: boolean;
  readonly protectionOn: boolean;
  readonly encryptionPercent: number;
  readonly userOnlyAcl: boolean;
}

export interface ProfileProtectionDecision {
  readonly mode: 'persistent' | 'memory';
  readonly reason: 'protection-verified' | 'protection-unverified';
}

export interface ProfileProtectionOptions {
  platform?: string;
  /** Test seam. Production uses the read-only Windows BitLocker and ACL probe. */
  inspect?: (directory: string) => Promise<unknown>;
}

const runFile = promisify(execFile);

export async function selectProfileMode(directory: string, options: ProfileProtectionOptions = {}): Promise<ProfileProtectionDecision> {
  const platform = options.platform ?? process.platform;
  if (platform !== 'win32' || typeof directory !== 'string' || !/^[A-Za-z]:\\/.test(directory) || !path.win32.isAbsolute(directory)) return memoryOnly();

  let raw: unknown;
  try {
    raw = await (options.inspect ?? inspectWindowsProfileProtection)(directory);
  } catch {
    return memoryOnly();
  }
  if (!isEvidence(raw) || raw.volumeEncrypted !== true || raw.protectionOn !== true || raw.encryptionPercent !== 100 || raw.userOnlyAcl !== true) {
    return memoryOnly();
  }
  return Object.freeze({ mode: 'persistent', reason: 'protection-verified' });
}

async function inspectWindowsProfileProtection(directory: string): Promise<unknown> {
  try {
    const path64 = Buffer.from(directory, 'utf8').toString('base64');
    const script = `$ErrorActionPreference='Stop'
$profilePath=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${path64}'))
$mountPoint=[IO.Path]::GetPathRoot($profilePath)
$volume=Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid=$identity.User.Value
$acl=Get-Acl -LiteralPath $profilePath -ErrorAction Stop
$ownerSid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
$rules=@($acl.Access)
$exclusive=($ownerSid -eq $currentSid) -and ($rules.Count -gt 0)
foreach($rule in $rules){
  $ruleSid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  if($ruleSid -ne $currentSid -or $rule.IsInherited -or $rule.AccessControlType -ne 'Allow'){$exclusive=$false}
}
$full=@($rules | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $currentSid -and $_.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl }).Count -gt 0
@{volumeEncrypted=([string]$volume.VolumeStatus -eq 'FullyEncrypted');protectionOn=([string]$volume.ProtectionStatus -eq 'On');encryptionPercent=[int]$volume.EncryptionPercentage;userOnlyAcl=($exclusive -and $full)} | ConvertTo-Json -Compress`;
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    const result = await runFile('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
      windowsHide: true,
      timeout: 8_000,
      maxBuffer: 16_384,
      encoding: 'utf8'
    });
    try { return JSON.parse(result.stdout) as unknown; } catch { return undefined; }
  } catch {
    return undefined;
  }
}

function isEvidence(value: unknown): value is ProfileProtectionEvidence {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Partial<ProfileProtectionEvidence>;
  return typeof candidate.volumeEncrypted === 'boolean' && typeof candidate.protectionOn === 'boolean' &&
    typeof candidate.encryptionPercent === 'number' && Number.isFinite(candidate.encryptionPercent) &&
    typeof candidate.userOnlyAcl === 'boolean';
}

function memoryOnly(): ProfileProtectionDecision {
  return Object.freeze({ mode: 'memory', reason: 'protection-unverified' });
}
