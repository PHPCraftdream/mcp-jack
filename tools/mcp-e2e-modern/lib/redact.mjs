function secretEntries(secrets) {
  if (!secrets) return [];
  if (secrets instanceof Map) return [...secrets].map(([label, value]) => [String(label), String(value)]);
  if (secrets instanceof Set || Array.isArray(secrets)) {
    return [...secrets].map((item, index) => {
      if (item && typeof item === 'object') return [String(item.label ?? `secret-${index}`), String(item.value ?? '')];
      return [`secret-${index}`, String(item)];
    });
  }
  if (typeof secrets === 'object') return Object.entries(secrets).map(([label, value]) => [label, String(value)]);
  return [];
}

export function redactText(text, secrets = []) {
  let result = String(text)
    .replace(/((?:jack[-_]?auth|authorization)\s*:\s*)([^\r\n,;]+)/gi, '$1[redacted:credential]')
    .replace(/\b(?:bearer|basic)\s+[^\r\n,;\s]+/gi, '[redacted:credential]');
  for (const [label, value] of secretEntries(secrets).sort((a, b) => b[1].length - a[1].length)) {
    if (value) result = result.split(value).join(`[redacted:${label}]`);
  }
  return result;
}

export function fingerprint(text) {
  return String(text).replace(/\s+/g, ' ').trim().slice(0, 80);
}

const sensitiveHeader = /^(?:jack[-_]auth|authorization|mcp-(?=.*(?:auth|token|key|credential|secret)))/i;
const sensitiveKey = /(?:private.?key|public.?key|sign(?:ing)?.?secret|credential|auth(?:orization)?|token)/i;

export function redactRecord(obj, secretSet = []) {
  const entries = secretEntries(secretSet);
  const clone = (value, key = '') => {
    if (typeof value === 'string') {
      if (sensitiveHeader.test(key)) return '[redacted]';
      return redactText(value, entries);
    }
    if (Array.isArray(value)) return value.map((item) => clone(item));
    if (value && typeof value === 'object') {
      const out = {};
      for (const [childKey, child] of Object.entries(value)) {
        out[childKey] = sensitiveHeader.test(childKey) || sensitiveKey.test(childKey)
          ? '[redacted]' : clone(child, childKey);
      }
      return out;
    }
    return value;
  };
  return clone(obj);
}

export function bound(text, maxBytes) {
  const input = String(text);
  if (!Number.isInteger(maxBytes) || maxBytes < 0) throw new TypeError('maxBytes must be a non-negative integer');
  const bytes = Buffer.from(input, 'utf8');
  if (bytes.length <= maxBytes) return input;
  const marker = '[truncated]';
  const budget = Math.max(0, maxBytes - Buffer.byteLength(marker));
  let prefix = bytes.subarray(0, budget).toString('utf8');
  while (Buffer.byteLength(prefix) > budget) prefix = prefix.slice(0, -1);
  return prefix + marker;
}
