export interface OutputSanitizerOptions {
  readonly secrets?: readonly string[];
  readonly maxStringChars?: number;
  readonly maxDepth?: number;
}

const SECRET_FIELD = /(?:pass(?:word|code)?|secret|token|authorization|cookie|api[-_]?key|session(?:id)?|credential|refresh)/i;
const SECRET_HEADER = /^(?:authorization|proxy-authorization|cookie|set-cookie|www-authenticate|proxy-authenticate|x-api-key)$/i;
const SECRET_QUERY = /([?&](?:access[_-]?token|refresh[_-]?token|token|key|secret|password|code|session(?:id)?|auth|authorization)=)[^&#\s]*/gi;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g;
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

export function createOutputSanitizer(options: OutputSanitizerOptions = {}): {
  sanitize(value: unknown): unknown;
  sanitizeText(value: string): string;
} {
  const maxStringChars = boundedInteger(options.maxStringChars, 16_384, 32, 1_048_576);
  const maxDepth = boundedInteger(options.maxDepth, 8, 1, 32);
  const secrets = (options.secrets ?? []).filter((value) => typeof value === 'string' && value.length >= 3).slice(0, 256);
  const escapedSecrets = secrets.map((secret) => new RegExp(escapeRegExp(secret), 'gi'));

  function sanitizeText(value: string): string {
    if (typeof value !== 'string') return '';
    let safe = value.replace(BEARER, 'Bearer [redacted]').replace(JWT, '[token redacted]').replace(SECRET_QUERY, '$1[redacted]').replace(EMAIL, '[email redacted]');
    safe = safe.replace(/\b(password|passcode|secret|token|authorization|cookie|api[-_]?key)\s*[:=]\s*([^\s,;&]+)/gi, '$1=[redacted]');
    for (const pattern of escapedSecrets) safe = safe.replace(pattern, '[redacted]');
    return safe.length > maxStringChars ? `${safe.slice(0, maxStringChars - 1)}…` : safe;
  }

  function sanitize(value: unknown): unknown {
    const visited = new WeakSet<object>();
    let nodes = 0;

    function visit(input: unknown, depth: number, parentKey = ''): unknown {
      nodes += 1;
      if (nodes > 20_000 || depth > maxDepth) return '[omitted]';
      if (input === null || typeof input === 'boolean' || typeof input === 'number') return input;
      if (typeof input === 'string') {
        if (parentKey.toLowerCase() === 'body') {
          const trimmed = input.trim();
          if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            try { return visit(JSON.parse(trimmed) as unknown, depth + 1, 'body'); } catch { /* text response */ }
          }
        }
        return sanitizeText(input);
      }
      if (typeof input !== 'object' || input === undefined) return '[omitted]';
      if (visited.has(input)) return '[cycle omitted]';
      visited.add(input);
      if (Array.isArray(input)) return input.slice(0, 1000).map((item) => visit(item, depth + 1, parentKey));

      const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      let descriptors: PropertyDescriptorMap;
      try { descriptors = Object.getOwnPropertyDescriptors(input); } catch { return '[omitted]'; }
      for (const [key, descriptor] of Object.entries(descriptors).slice(0, 500)) {
        if (!descriptor.enumerable || !('value' in descriptor)) continue;
        if (SECRET_FIELD.test(key) || SECRET_HEADER.test(key)) continue;
        output[sanitizeText(key)] = visit(descriptor.value, depth + 1, key);
      }
      return output;
    }

    try { return visit(value, 0); } catch { return '[omitted]'; }
  }

  return Object.freeze({ sanitize, sanitizeText });
}

function boundedInteger(value: number | undefined, fallback: number, min: number, max: number): number {
  return Number.isInteger(value) && (value as number) >= min && (value as number) <= max ? value! : fallback;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
