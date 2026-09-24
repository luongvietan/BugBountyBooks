import { randomUUID } from 'node:crypto';
import { normalizeOrigin } from '../policy/origin.js';

export interface RawObservedElement {
  readonly domIndex: number;
  readonly tag: string;
  readonly type: string;
  readonly name: string;
  readonly role: string;
  readonly text: string;
  readonly href: string;
  readonly target: string;
  readonly download: boolean;
  readonly hasOnclick: boolean;
  readonly disabled: boolean;
  readonly readOnly: boolean;
  readonly autoComplete: string;
  readonly visible: boolean;
}

export interface PageAutomationSurface {
  url(): string;
  title(): Promise<string>;
  navigate(url: string): Promise<void>;
  inspectElements(): Promise<RawObservedElement[]>;
  inspectElement(domIndex: number): Promise<RawObservedElement | undefined>;
  fillElement(domIndex: number, value: string): Promise<void>;
}

export interface PageToolsOptions {
  readonly targetOrigins: readonly string[];
  readonly isTargetActive: () => boolean;
  readonly sanitizeText?: (value: string) => string;
}

export interface ObservedElement {
  readonly id: string;
  readonly tag: string;
  readonly role: string;
  readonly text: string;
  readonly href?: string;
  readonly inputType?: string;
}

export interface PageObservation {
  readonly title: string;
  readonly url: string;
  readonly elements: readonly ObservedElement[];
}

interface StoredObservation {
  readonly raw: RawObservedElement;
  readonly href?: string;
}

export function createPageTools(page: PageAutomationSurface, options: PageToolsOptions): {
  setAllowedOrigins(origins: readonly string[]): void;
  navigate(url: string): Promise<{ navigated: boolean }>;
  observe(): Promise<PageObservation>;
  clickObservedLink(id: string): Promise<{ navigated: boolean }>;
  fillResearcherControlledField(id: string, value: string): Promise<{ filled: boolean }>;
} {
  const policyOrigins = new Set(options.targetOrigins.map((origin) => {
    try {
      const normalized = normalizeOrigin(origin);
      if (normalized !== origin) throw new Error('non-canonical');
      return normalized;
    } catch { throw new Error('Page target-origin policy is invalid'); }
  }));
  if (!policyOrigins.size) throw new Error('Page target-origin policy is empty');
  let allowedOrigins = new Set(policyOrigins);
  const sanitize = options.sanitizeText ?? defaultSanitize;
  let observations = new Map<string, StoredObservation>();

  function requireActive(): void {
    let active = false;
    try { active = options.isTargetActive() === true; } catch { active = false; }
    if (!active) throw new Error('Target session is not active');
  }

  function setAllowedOrigins(origins: readonly string[]): void {
    if (!Array.isArray(origins)) throw new Error('Page capability origins are invalid');
    const next = new Set<string>();
    for (const origin of origins) {
      let normalized: string;
      try { normalized = normalizeOrigin(origin); } catch { throw new Error('Page capability origin is invalid'); }
      if (normalized !== origin || !policyOrigins.has(origin)) throw new Error('Page capability origin exceeds target policy');
      next.add(origin);
    }
    if (next.size !== allowedOrigins.size || [...next].some((origin) => !allowedOrigins.has(origin))) observations = new Map();
    allowedOrigins = next;
  }

  function parseAllowedTarget(value: string): URL {
    let url: URL;
    try {
      url = new URL(value);
      if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password || url.hash ||
          !allowedOrigins.has(normalizeOrigin(url.origin))) throw new Error('outside');
    } catch {
      throw new Error('Navigation is outside the target policy');
    }
    return url;
  }

  async function navigate(url: string): Promise<{ navigated: boolean }> {
    requireActive();
    const target = parseAllowedTarget(url);
    try { await page.navigate(target.toString()); } catch { throw new Error('Target navigation was blocked or failed'); }
    observations = new Map();
    return Object.freeze({ navigated: true });
  }

  async function observe(): Promise<PageObservation> {
    requireActive();
    let pageUrl: string;
    let title: string;
    let rawElements: RawObservedElement[];
    try {
      pageUrl = page.url();
      parseAllowedTarget(pageUrl);
      title = await page.title();
      rawElements = await page.inspectElements();
    } catch {
      throw new Error('Page observation is unavailable for this session');
    }
    const next = new Map<string, StoredObservation>();
    const elements: ObservedElement[] = [];
    for (const raw of rawElements.slice(0, 500)) {
      if (!validRawElement(raw) || !raw.visible || !['a', 'button', 'input', 'textarea', 'select'].includes(raw.tag.toLowerCase())) continue;
      if (raw.tag.toLowerCase() === 'input' && ['password', 'hidden', 'file', 'submit', 'button', 'image', 'reset'].includes(raw.type.toLowerCase())) continue;
      if (raw.tag.toLowerCase() === 'input' && isCredentialField(raw)) continue;
      const id = randomUUID();
      const item: ObservedElement = Object.freeze({
        id,
        tag: raw.tag.toLowerCase(),
        role: safeText(sanitize, raw.role),
        text: safeText(sanitize, raw.text),
        ...(raw.tag.toLowerCase() === 'a' && raw.href ? { href: safeText(sanitize, raw.href) } : {}),
        ...isFillableField(raw) ? { inputType: raw.tag.toLowerCase() === 'textarea' ? 'textarea' : raw.type.toLowerCase() || 'text' } : {}
      });
      next.set(id, { raw, ...(raw.tag.toLowerCase() === 'a' && raw.href ? { href: raw.href } : {}) });
      elements.push(item);
    }
    observations = next;
    return Object.freeze({ title: safeText(sanitize, title), url: safeText(sanitize, pageUrl), elements: Object.freeze(elements) });
  }

  async function clickObservedLink(id: string): Promise<{ navigated: boolean }> {
    requireActive();
    const observed = observations.get(id);
    if (!observed || observed.raw.tag.toLowerCase() !== 'a' || !observed.href || observed.raw.target && observed.raw.target !== '_self' ||
        observed.raw.download || observed.raw.hasOnclick) throw new Error('Action is limited to an observed ordinary link');
    const target = parseAllowedTarget(new URL(observed.href, page.url()).toString());
    return navigate(target.toString());
  }

  async function fillResearcherControlledField(id: string, value: string): Promise<{ filled: boolean }> {
    requireActive();
    const observed = observations.get(id);
    if (!observed || !isFillableField(observed.raw)) throw new Error('Field is not an observed researcher-controlled input');
    if (typeof value !== 'string' || Buffer.byteLength(value) > 4096 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) {
      throw new Error('Researcher-controlled field value is invalid');
    }
    let current: RawObservedElement | undefined;
    try { current = await page.inspectElement(observed.raw.domIndex); } catch { current = undefined; }
    if (!current || !isFillableField(current) || current.domIndex !== observed.raw.domIndex ||
        current.tag.toLowerCase() !== observed.raw.tag.toLowerCase() || current.type.toLowerCase() !== observed.raw.type.toLowerCase() ||
        current.name !== observed.raw.name || current.autoComplete.toLowerCase() !== observed.raw.autoComplete.toLowerCase()) {
      throw new Error('Observed field changed or is no longer safe');
    }
    try { await page.fillElement(current.domIndex, value); } catch { throw new Error('Researcher-controlled field could not be filled'); }
    return Object.freeze({ filled: true });
  }

  return Object.freeze({ setAllowedOrigins, navigate, observe, clickObservedLink, fillResearcherControlledField });
}

function isFillableField(raw: RawObservedElement): boolean {
  const tag = raw.tag.toLowerCase();
  const type = raw.type.toLowerCase();
  if (!raw.visible || raw.disabled || raw.readOnly || isCredentialField(raw)) return false;
  if (tag === 'textarea') return true;
  return tag === 'input' && ['', 'text', 'search', 'email', 'number', 'tel', 'url'].includes(type);
}

function isCredentialField(raw: RawObservedElement): boolean {
  const hints = `${raw.type} ${raw.name} ${raw.autoComplete} ${raw.role} ${raw.text}`.toLowerCase();
  return /password|passcode|secret|token|authorization|credential|one[- ]time|\botp\b|\bmfa\b|credit.?card|cvv|security.?code/.test(hints) ||
    /current-password|new-password|one-time-code|cc-number|cc-csc/.test(raw.autoComplete.toLowerCase());
}

function validRawElement(value: unknown): value is RawObservedElement {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const raw = value as Partial<RawObservedElement>;
  return Number.isInteger(raw.domIndex) && (raw.domIndex ?? -1) >= 0 && typeof raw.tag === 'string' && typeof raw.type === 'string' &&
    typeof raw.name === 'string' && typeof raw.role === 'string' && typeof raw.text === 'string' && typeof raw.href === 'string' &&
    typeof raw.target === 'string' && typeof raw.download === 'boolean' && typeof raw.hasOnclick === 'boolean' &&
    typeof raw.disabled === 'boolean' && typeof raw.readOnly === 'boolean' && typeof raw.autoComplete === 'string' && typeof raw.visible === 'boolean';
}

function safeText(sanitize: (value: string) => string, value: string): string {
  try {
    const result = sanitize(value);
    return typeof result === 'string' ? result.slice(0, 2048) : '';
  } catch { return ''; }
}

function defaultSanitize(value: string): string {
  return value
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[email redacted]')
    .replace(/\bBearer\s+[A-Z0-9._~+/-]+=*/gi, 'Bearer [redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[token redacted]')
    .replace(/([?&](?:token|key|secret|password|code|session|auth)=)[^&#\s]+/gi, '$1[redacted]');
}
