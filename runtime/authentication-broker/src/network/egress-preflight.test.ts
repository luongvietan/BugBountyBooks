import assert from 'node:assert/strict';
import test from 'node:test';

type FirewallRule = {
  name: string; enabled: boolean; direction: 'Inbound' | 'Outbound'; action: 'Block' | 'Allow';
  program: string; remoteAddress: string; remotePort: string; protocol: 'Any' | 'TCP' | 'UDP';
  profile: string;
};
type Snapshot = {
  platform: string; windowsBuild: number; proxy: { listening: boolean; host: string; port: number };
  browserExecutablePath: string;
  launchOptions: { proxy: { server: string; bypass: string }; args: string[] };
  firewallRules: FirewallRule[]; effectivePolicyComplete: boolean; conflictingRules: boolean;
  activePolicyReadComplete: boolean; firewallProfilesEnabled: boolean;
};
type PreflightApi = {
  egressPreflight: (snapshot: Snapshot | undefined) => { status: 'verified' | 'unverified'; reason: string };
  managedBrowserNetworkOptions: (proxyPort?: number) => Snapshot['launchOptions'];
  readWindowsFirewallSnapshot: (options: { browserExecutablePath: string; runPowerShell?: (script: string) => Promise<string> }) => Promise<{
    firewallRules: readonly FirewallRule[]; activePolicyReadComplete: boolean; firewallProfilesEnabled: boolean; conflictingRules: boolean; effectivePolicyComplete: boolean;
  } | undefined>;
};

async function getPreflightApi(): Promise<PreflightApi> {
  let module: PreflightApi | undefined;
  try { module = await import('./egress-preflight.js') as unknown as PreflightApi; } catch { module = undefined; }
  assert.equal(typeof module?.egressPreflight, 'function', 'egress preflight must be implemented');
  assert.equal(typeof module?.managedBrowserNetworkOptions, 'function', 'managed browser network options must be implemented');
  return module!;
}

const chromium = 'C:\\Synthetic\\chrome.exe';
const requiredRules: FirewallRule[] = [
  { name: 'BHS-AB-Chromium-Block-v4-low', enabled: true, direction: 'Outbound', action: 'Block', program: chromium, remoteAddress: '0.0.0.0-127.0.0.0', remotePort: 'Any', protocol: 'Any', profile: 'Any' },
  { name: 'BHS-AB-Chromium-Block-v4-high', enabled: true, direction: 'Outbound', action: 'Block', program: chromium, remoteAddress: '127.0.0.2-255.255.255.255', remotePort: 'Any', protocol: 'Any', profile: 'Any' },
  { name: 'BHS-AB-Chromium-Block-v6-unspecified', enabled: true, direction: 'Outbound', action: 'Block', program: chromium, remoteAddress: '::', remotePort: 'Any', protocol: 'Any', profile: 'Any' },
  { name: 'BHS-AB-Chromium-Block-v6-nonloopback', enabled: true, direction: 'Outbound', action: 'Block', program: chromium, remoteAddress: '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', remotePort: 'Any', protocol: 'Any', profile: 'Any' },
  { name: 'BHS-AB-Chromium-Block-v6-loopback', enabled: true, direction: 'Outbound', action: 'Block', program: chromium, remoteAddress: '::1', remotePort: 'Any', protocol: 'Any', profile: 'Any' },
  { name: 'BHS-AB-Chromium-Block-local-low', enabled: true, direction: 'Outbound', action: 'Block', program: chromium, remoteAddress: '127.0.0.1', remotePort: '1-8765', protocol: 'TCP', profile: 'Any' },
  { name: 'BHS-AB-Chromium-Block-local-high', enabled: true, direction: 'Outbound', action: 'Block', program: chromium, remoteAddress: '127.0.0.1', remotePort: '8767-65535', protocol: 'TCP', profile: 'Any' },
  { name: 'BHS-AB-Chromium-Block-local-udp', enabled: true, direction: 'Outbound', action: 'Block', program: chromium, remoteAddress: '127.0.0.1', remotePort: 'Any', protocol: 'UDP', profile: 'Any' }
];

function goodSnapshot(): Snapshot {
  return {
    platform: 'win32',
    windowsBuild: 26100,
    proxy: { listening: true, host: '127.0.0.1', port: 8766 },
    browserExecutablePath: chromium,
    launchOptions: { proxy: { server: 'http://127.0.0.1:8766', bypass: '<-loopback>' }, args: ['--disable-quic'] },
    firewallRules: requiredRules.map((rule) => ({ ...rule })),
    effectivePolicyComplete: true,
    conflictingRules: false,
    activePolicyReadComplete: true,
    firewallProfilesEnabled: true
  };
}

test('verifies only an exact loopback proxy and complete per-executable egress fence', async () => {
  const { egressPreflight, managedBrowserNetworkOptions } = await getPreflightApi();
  const snapshot = goodSnapshot();
  snapshot.launchOptions = managedBrowserNetworkOptions();
  assert.deepEqual(snapshot.launchOptions, { proxy: { server: 'http://127.0.0.1:8766', bypass: '<-loopback>' }, args: ['--disable-quic'] });
  assert.deepEqual(egressPreflight(snapshot), { status: 'verified', reason: 'verified' });
});

test('fails closed on unsupported, absent, ambiguous, or altered egress state', async (t) => {
  const { egressPreflight } = await getPreflightApi();
  const cases: Array<[string, (snapshot: Snapshot) => void]> = [
    ['unknown snapshot', () => {}],
    ['unsupported host', (snapshot) => { snapshot.platform = 'linux'; }],
    ['old Windows build', (snapshot) => { snapshot.windowsBuild = 19045; }],
    ['proxy not listening', (snapshot) => { snapshot.proxy.listening = false; }],
    ['proxy bound to all interfaces', (snapshot) => { snapshot.proxy.host = '0.0.0.0'; }],
    ['wrong proxy port', (snapshot) => { snapshot.proxy.port = 9999; }],
    ['browser bypass setting changed', (snapshot) => { snapshot.launchOptions.proxy.bypass = 'localhost'; }],
    ['QUIC not disabled', (snapshot) => { snapshot.launchOptions.args = []; }],
    ['incomplete effective policy', (snapshot) => { snapshot.effectivePolicyComplete = false; }],
    ['active firewall read incomplete', (snapshot) => { snapshot.activePolicyReadComplete = false; }],
    ['firewall profile disabled', (snapshot) => { snapshot.firewallProfilesEnabled = false; }],
    ['conflicting policy rules', (snapshot) => { snapshot.conflictingRules = true; }],
    ['missing firewall rule', (snapshot) => { snapshot.firewallRules.pop(); }],
    ['altered firewall program', (snapshot) => { snapshot.firewallRules[0]!.program = 'C:\\Other\\chrome.exe'; }],
    ['altered firewall direction', (snapshot) => { snapshot.firewallRules[1]!.direction = 'Inbound'; }],
    ['altered firewall action', (snapshot) => { snapshot.firewallRules[2]!.action = 'Allow'; }],
    ['altered firewall address', (snapshot) => { snapshot.firewallRules[3]!.remoteAddress = 'Any'; }],
    ['duplicate firewall rule name', (snapshot) => { snapshot.firewallRules.push({ ...snapshot.firewallRules[0]! }); }]
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, () => {
      const snapshot = goodSnapshot();
      if (name !== 'unknown snapshot') mutate(snapshot);
      const result = egressPreflight(name === 'unknown snapshot' ? undefined : snapshot);
      assert.equal(result.status, 'unverified');
      assert.notEqual(result.reason, 'verified');
    });
  }
});

test('rejects a browser path that is not an exact absolute executable path', async (t) => {
  const { egressPreflight } = await getPreflightApi();
  for (const path of ['chrome.exe', 'C:\\Browser\\*.exe', 'C:\\Browser\\chrome.exe;other.exe']) {
    await t.test(path, () => {
      const snapshot = goodSnapshot();
      snapshot.browserExecutablePath = path;
      snapshot.firewallRules = requiredRules.map((rule) => ({ ...rule, program: path }));
      assert.equal(egressPreflight(snapshot).status, 'unverified');
    });
  }
});

test('returns unverified rather than throwing on malformed host snapshots', async () => {
  const { egressPreflight } = await getPreflightApi();
  assert.equal(egressPreflight({ platform: 'win32' } as unknown as Snapshot).status, 'unverified');
  assert.equal(egressPreflight({ platform: 'win32', windowsBuild: 26100 } as unknown as Snapshot).status, 'unverified');
  assert.equal(egressPreflight(null as unknown as Snapshot).status, 'unverified');
});

test('reads firewall state through an injected read-only PowerShell adapter and fails closed on query errors', async (t) => {
  const { readWindowsFirewallSnapshot } = await getPreflightApi();
  if (process.platform !== 'win32') { t.skip('Windows firewall snapshot adapter'); return; }
  const fixture = goodSnapshot();
  let query = '';
  const result = await readWindowsFirewallSnapshot({
    browserExecutablePath: chromium,
    runPowerShell: async (script) => {
      query = script;
      return JSON.stringify({
        firewallRules: fixture.firewallRules,
        activePolicyReadComplete: true,
        firewallProfilesEnabled: true,
        conflictingRules: false
      });
    }
  });
  assert.equal(result?.firewallRules.length, requiredRules.length);
  assert.equal(result?.effectivePolicyComplete, true);
  assert.match(query, /Get-NetFirewallRule/);
  assert.match(query, /ActiveStore/);
  assert.equal(query.includes(chromium), false);
  const unavailable = await readWindowsFirewallSnapshot({ browserExecutablePath: chromium, runPowerShell: async () => { throw new Error('mock query failed'); } });
  assert.equal(unavailable, undefined);
});
