import assert from 'node:assert/strict';
import test from 'node:test';

type RawElement = {
  domIndex: number; tag: string; type: string; name: string; role: string; text: string; href: string;
  target: string; download: boolean; hasOnclick: boolean; disabled: boolean; readOnly: boolean; autoComplete: string;
  visible: boolean;
};
type PageSurface = {
  url: () => string;
  title: () => Promise<string>;
  navigate: (url: string) => Promise<void>;
  inspectElements: () => Promise<RawElement[]>;
  inspectElement: (domIndex: number) => Promise<RawElement | undefined>;
  fillElement: (domIndex: number, value: string) => Promise<void>;
};
type PageToolsApi = {
  createPageTools: (page: PageSurface, options: { targetOrigins: readonly string[]; isTargetActive: () => boolean; sanitizeText?: (value: string) => string }) => {
    navigate: (url: string) => Promise<{ navigated: boolean }>;
    observe: () => Promise<{ title: string; url: string; elements: Array<{ id: string; tag: string; role: string; text: string; href?: string; inputType?: string }> }>;
    clickObservedLink: (id: string) => Promise<{ navigated: boolean }>;
    fillResearcherControlledField: (id: string, value: string) => Promise<{ filled: boolean }>;
  };
};

async function getApi(): Promise<PageToolsApi> {
  let module: PageToolsApi | undefined;
  try { module = await import('./page-tools.js') as unknown as PageToolsApi; } catch { module = undefined; }
  assert.equal(typeof module?.createPageTools, 'function', 'bounded page tools must be implemented');
  return module!;
}

function fakePage(elements: RawElement[]) {
  let currentUrl = 'https://app.example:443/';
  const navigations: string[] = [];
  const fills: Array<{ index: number; value: string }> = [];
  const surface: PageSurface = {
    url: () => currentUrl,
    title: async () => 'Synthetic <title>',
    navigate: async (url) => { currentUrl = url; navigations.push(url); },
    inspectElements: async () => elements.map((element) => ({ ...element })),
    inspectElement: async (domIndex) => elements.find((element) => element.domIndex === domIndex),
    fillElement: async (domIndex, value) => { fills.push({ index: domIndex, value }); }
  };
  return { surface, navigations, fills };
}

const elements: RawElement[] = [
  { domIndex: 0, tag: 'a', type: '', name: '', role: 'link', text: 'Profile researcher@example.test', href: '/profile', target: '', download: false, hasOnclick: false, disabled: false, readOnly: false, autoComplete: '', visible: true },
  { domIndex: 1, tag: 'button', type: 'submit', name: '', role: 'button', text: 'Save', href: '', target: '', download: false, hasOnclick: true, disabled: false, readOnly: false, autoComplete: '', visible: true },
  { domIndex: 2, tag: 'input', type: 'text', name: 'display-name', role: 'textbox', text: 'Display name', href: '', target: '', download: false, hasOnclick: false, disabled: false, readOnly: false, autoComplete: 'nickname', visible: true },
  { domIndex: 3, tag: 'input', type: 'password', name: 'password', role: 'textbox', text: 'Password', href: '', target: '', download: false, hasOnclick: false, disabled: false, readOnly: false, autoComplete: 'current-password', visible: true },
  { domIndex: 4, tag: 'a', type: '', name: '', role: 'link', text: 'External', href: 'https://evil.example/path', target: '', download: false, hasOnclick: false, disabled: false, readOnly: false, autoComplete: '', visible: true },
  { domIndex: 5, tag: 'a', type: '', name: '', role: 'link', text: 'Download', href: '/export', target: '', download: true, hasOnclick: false, disabled: false, readOnly: false, autoComplete: '', visible: true }
];

test('navigates and observes only exact target origins using sanitized visible descriptions', async () => {
  const { createPageTools } = await getApi();
  const page = fakePage(elements);
  const tools = createPageTools(page.surface, {
    targetOrigins: ['https://app.example:443'], isTargetActive: () => true,
    sanitizeText: (value) => value.replace('researcher@example.test', '[email redacted]')
  });
  assert.deepEqual(await tools.navigate('https://app.example:443/map'), { navigated: true });
  await assert.rejects(tools.navigate('https://app.example.evil.test:443/'), /outside the target policy/i);
  const observed = await tools.observe();
  assert.equal(observed.title, 'Synthetic <title>');
  assert.equal(observed.url, 'https://app.example/map');
  assert.equal(observed.elements.some((element) => element.text.includes('researcher@example.test')), false);
  assert.equal(observed.elements.some((element) => element.inputType === 'password'), false);
  assert.equal(observed.elements.some((element) => element.tag === 'button'), true);
  assert.equal(Object.keys(tools).some((key) => /evaluate|cookie|storage|cdp|shell/i.test(key)), false);
});

test('permits only observed ordinary links and researcher-controlled non-secret field filling', async () => {
  const { createPageTools } = await getApi();
  const page = fakePage(elements);
  const tools = createPageTools(page.surface, { targetOrigins: ['https://app.example:443'], isTargetActive: () => true });
  const observed = await tools.observe();
  const profileLink = observed.elements.find((item) => item.text.startsWith('Profile'))!;
  await tools.clickObservedLink(profileLink.id);
  assert.equal(page.navigations.at(-1), 'https://app.example/profile');
  const afterNavigation = await tools.observe();
  const submitButton = afterNavigation.elements.find((item) => item.tag === 'button')!;
  const textField = afterNavigation.elements.find((item) => item.inputType === 'text')!;
  const externalLink = afterNavigation.elements.find((item) => item.text === 'External')!;
  const downloadLink = afterNavigation.elements.find((item) => item.text === 'Download')!;
  await assert.rejects(tools.clickObservedLink(submitButton.id), /ordinary link/i);
  await assert.rejects(tools.clickObservedLink(externalLink.id), /outside the target policy/i);
  await assert.rejects(tools.clickObservedLink(downloadLink.id), /ordinary link/i);
  assert.deepEqual(await tools.fillResearcherControlledField(textField.id, 'synthetic value'), { filled: true });
  assert.deepEqual(page.fills, [{ index: 2, value: 'synthetic value' }]);
  assert.equal(JSON.stringify(await tools.observe()).includes('synthetic value'), false);
});

test('blocks navigation and actions whenever the target session is paused', async () => {
  const { createPageTools } = await getApi();
  const page = fakePage(elements);
  const tools = createPageTools(page.surface, { targetOrigins: ['https://app.example:443'], isTargetActive: () => false });
  await assert.rejects(tools.navigate('https://app.example:443/'), /session is not active/i);
  await assert.rejects(tools.observe(), /session is not active/i);
  await assert.rejects(tools.clickObservedLink('unknown-observation-id'), /session is not active/i);
  assert.deepEqual(page.navigations, []);
});
