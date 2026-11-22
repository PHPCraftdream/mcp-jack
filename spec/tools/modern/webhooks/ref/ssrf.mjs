// Reference implementation of spec/06-webhooks.md section 6 (R6.1-R6.11) and R5.11; pure, deterministic,
// no I/O, no resolver. Literals are hand-parsed: no URL, no net.isIP, no dns.

// R6.5: IPv4 special registry, snake_case reason names. `reachable` is the registry's "Globally Reachable"
// column; the longest matching row decides. Rows overlap on purpose (192.0.0.0/24 contains the /29 and /32 rows,
// and 0.0.0.0/8 contains the registry's own 0.0.0.0/32 "This host on this network" row).
// Not a registry row: 224.0.0.0/4 is the multicast block of the address architecture; every registry row inside
// it is also not globally reachable, so the decision is the same.
export const IPV4_BLOCKS = [
  { block: '0.0.0.0/8', name: 'this_network', reachable: false },
  { block: '0.0.0.0/32', name: 'this_host_on_this_network', reachable: false },
  { block: '10.0.0.0/8', name: 'private_use', reachable: false },
  { block: '100.64.0.0/10', name: 'shared_address_space', reachable: false },
  { block: '127.0.0.0/8', name: 'loopback', reachable: false },
  { block: '169.254.0.0/16', name: 'link_local', reachable: false },
  { block: '172.16.0.0/12', name: 'private_use', reachable: false },
  { block: '192.0.0.0/24', name: 'ietf_protocol_assignments', reachable: false },
  { block: '192.0.0.0/29', name: 'ipv4_service_continuity_prefix', reachable: false },
  { block: '192.0.0.8/32', name: 'ipv4_dummy_address', reachable: false },
  { block: '192.0.0.9/32', name: 'pcp_anycast', reachable: true },
  { block: '192.0.0.10/32', name: 'turn_anycast', reachable: true },
  { block: '192.0.0.170/32', name: 'nat64_dns64_discovery', reachable: false },
  { block: '192.0.0.171/32', name: 'nat64_dns64_discovery', reachable: false },
  { block: '192.0.2.0/24', name: 'documentation', reachable: false },
  { block: '192.31.196.0/24', name: 'as112_v4', reachable: true },
  { block: '192.52.193.0/24', name: 'amt', reachable: true },
  { block: '192.88.99.0/24', name: 'deprecated_6to4_relay_anycast', reachable: false },
  { block: '192.168.0.0/16', name: 'private_use', reachable: false },
  { block: '192.175.48.0/24', name: 'as112_direct_delegation', reachable: true },
  { block: '198.18.0.0/15', name: 'benchmarking', reachable: false },
  { block: '198.51.100.0/24', name: 'documentation', reachable: false },
  { block: '203.0.113.0/24', name: 'documentation', reachable: false },
  { block: '224.0.0.0/4', name: 'multicast', reachable: false },
  { block: '240.0.0.0/4', name: 'reserved', reachable: false },
  { block: '255.255.255.255/32', name: 'limited_broadcast', reachable: false },
];

// R6.6, R6.7: IPv6 special registry. `reachable` is the registry's "Globally Reachable" column; the longest
// matching row decides. Rows overlap on purpose (2001::/23 contains the more specific 2001::/32 rows).
// Not registry rows: ff00::/8 is the multicast block of the address architecture, and ::/96 is the Jack addition
// the spec documents (the registry's mapped row ::ffff:0:0/96 is a different block). 100:0:0:1::/64 is the
// registry's "Dummy IPv6 Prefix"; it sits next to 100::/64 rather than inside it (group 4 is 1 against 0), so
// neither row shadows the other.
export const IPV6_BLOCKS = [
  { block: '::/128', name: 'unspecified', reachable: false },
  { block: '::1/128', name: 'loopback', reachable: false },
  // No chain reorder needed: ::ffff:0:0/96 is not inside ::/96 (byte 10 differs), ::/128 and ::1/128 match with longer prefixes, and the mapped/NAT64 chains run before the table.
  { block: '::/96', name: 'ipv4_compatible_deprecated', reachable: false },
  { block: '::ffff:0:0/96', name: 'ipv4_mapped', reachable: false },
  { block: '64:ff9b::/96', name: 'nat64_well_known', reachable: true },
  { block: '64:ff9b:1::/48', name: 'nat64_local_use', reachable: false },
  { block: '100::/64', name: 'discard_only', reachable: false },
  { block: '100:0:0:1::/64', name: 'dummy_ipv6_prefix', reachable: false },
  { block: '2001::/23', name: 'ietf_protocol_assignments', reachable: false },
  { block: '2001::/32', name: 'teredo', reachable: false },
  { block: '2001:1::1/128', name: 'pcp_anycast', reachable: true },
  { block: '2001:1::2/128', name: 'turn_anycast', reachable: true },
  { block: '2001:2::/48', name: 'benchmarking', reachable: false },
  { block: '2001:3::/32', name: 'amt', reachable: true },
  { block: '2001:4:112::/48', name: 'as112_v6', reachable: true },
  { block: '2001:10::/28', name: 'orchid', reachable: false },
  { block: '2001:20::/28', name: 'orchidv2', reachable: false },
  { block: '2001:30::/28', name: 'drone_remote_id', reachable: false },
  { block: '2001:db8::/32', name: 'documentation', reachable: false },
  { block: '2002::/16', name: 'six_to_four', reachable: false },
  { block: '2620:4f:8000::/48', name: 'as112_direct_delegation', reachable: true },
  { block: '3fff::/20', name: 'documentation', reachable: false },
  { block: '5f00::/16', name: 'srv6_sid', reachable: false },
  { block: 'fc00::/7', name: 'unique_local', reachable: false },
  { block: 'fe80::/10', name: 'link_local', reachable: false },
  { block: 'ff00::/8', name: 'multicast', reachable: false },
];

const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;
const DECIMAL_GROUP = /^(0|[1-9][0-9]{0,2})$/;
const PREFIX_TEXT = /^(0|[1-9][0-9]{0,2})$/;
const PORT_TEXT = /^[0-9]+$/;
const LDH_LABEL = /^[A-Za-z0-9-]{1,63}$/;
const NAT64_WKN = Uint8Array.from([0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

// R6.3, R6.4: canonical dotted-quad only; no leading zeros, no sign, no whitespace, no short form.
export function parseIPv4(text) {
  if (typeof text !== 'string') return { ok: false };
  const parts = text.split('.');
  if (parts.length !== 4) return { ok: false };
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!DECIMAL_GROUP.test(parts[i])) return { ok: false };
    const value = Number(parts[i]);
    if (value > 255) return { ok: false };
    bytes[i] = value;
  }
  return { ok: true, bytes };
}

// R6.7: 1-8 hex groups, one :: compression, at most one embedded IPv4 in the final group, no zone id.
export function parseIPv6(text) {
  if (typeof text !== 'string') return { ok: false };
  if (text.includes('%') || text.includes('[') || text.includes(']')) return { ok: false };
  const gap = text.indexOf('::');
  if (gap !== -1 && text.indexOf('::', gap + 2) !== -1) return { ok: false };
  const compressed = gap !== -1;
  const head = compressed ? (gap === 0 ? [] : text.slice(0, gap).split(':')) : text.split(':');
  const tailText = compressed ? text.slice(gap + 2) : '';
  const tail = compressed ? (tailText === '' ? [] : tailText.split(':')) : [];
  const headValues = parseHexGroups(head, !compressed);
  if (!headValues) return { ok: false };
  const tailValues = parseHexGroups(tail, compressed);
  if (!tailValues) return { ok: false };
  const total = headValues.length + tailValues.length;
  if (compressed ? total > 7 : total !== 8) return { ok: false };
  const values = compressed
    ? [headValues, new Array(8 - total).fill(0), tailValues].flat()
    : headValues;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = values[i] >> 8;
    bytes[i * 2 + 1] = values[i] & 0xff;
  }
  return { ok: true, bytes };
}

// R6.4: dotted quad from four bytes.
export function formatIPv4(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

// R6.6: RFC 5952 compressed lowercase form; the ipv4-mapped shape keeps its dotted quad.
export function formatIPv6(bytes) {
  if (isMapped(bytes)) return `::ffff:${formatIPv4(bytes.subarray(12, 16))}`;
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i] << 8) | bytes[i + 1]);
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] !== 0) continue;
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((group) => group.toString(16));
  if (bestLen < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

// R6.11: <literal>/<prefix> with decimal prefix and zero host bits beyond the prefix.
export function parseCidr(text) {
  if (typeof text !== 'string') return { ok: false };
  const slash = text.indexOf('/');
  if (slash === -1 || text.indexOf('/', slash + 1) !== -1) return { ok: false };
  const literal = text.slice(0, slash);
  if (!PREFIX_TEXT.test(text.slice(slash + 1))) return { ok: false };
  const prefix = Number(text.slice(slash + 1));
  const family = literal.includes(':') ? 'ipv6' : 'ipv4';
  if (prefix > (family === 'ipv6' ? 128 : 32)) return { ok: false };
  const parsed = family === 'ipv4' ? parseIPv4(literal) : parseIPv6(literal);
  if (!parsed.ok || !hostBitsZero(parsed.bytes, prefix)) return { ok: false };
  return { ok: true, family, bytes: parsed.bytes, prefix };
}

// R6.11: containment test of an address literal inside a parsed range.
export function cidrContains(cidr, addressText) {
  if (!cidr || cidr.ok !== true) return false;
  const parsed = parsedAddress(addressText);
  if (!parsed || parsed.family !== cidr.family) return false;
  return matchPrefix(parsed.bytes, cidr.bytes, cidr.prefix);
}

// R6.3: two or more LDH labels, 1-63 chars each, no edge hyphen, at most 253 chars, last label not numeric.
export function isLdhName(name) {
  if (typeof name !== 'string' || name.length > 253) return false;
  const labels = name.split('.');
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (!LDH_LABEL.test(label)) return false;
    if (label[0] === '-' || label[label.length - 1] === '-') return false;
  }
  return !/^[0-9]+$/.test(labels[labels.length - 1]);
}

// R6.3: canonical dotted-quad, bracketed IPv6 or LDH name; every other spelling is never reinterpreted.
export function parseHost(host) {
  if (typeof host !== 'string' || host === '') return { ok: false, reason: 'not_a_hostname' };
  if (host[0] === '[') {
    if (host[host.length - 1] !== ']') return { ok: false, reason: 'host' };
    const inner = host.slice(1, -1);
    if (inner.includes('[') || inner.includes(']') || inner.includes('%')) return { ok: false, reason: 'host' };
    const parsed = parseIPv6(inner);
    if (!parsed.ok) return { ok: false, reason: 'host' };
    const address = formatIPv6(parsed.bytes);
    return { ok: true, kind: 'ipv6', address, normalized: `[${address}]` };
  }
  if (host.includes('[') || host.includes(']')) return { ok: false, reason: 'host' };
  const quad = parseIPv4(host);
  if (quad.ok) {
    const address = formatIPv4(quad.bytes);
    return { ok: true, kind: 'ipv4', address, normalized: address };
  }
  const name = (host.endsWith('.') ? host.slice(0, -1) : host).toLowerCase();
  if (!isLdhName(name)) return { ok: false, reason: 'not_a_hostname' };
  return { ok: true, kind: 'name', name, normalized: name };
}

// R6.5, R6.4: the longest matching registry row decides; its reachability column picks the decision and its
// name is the reason either way. No matching row is globally routable.
export function classifyIPv4(bytes) {
  let best = null;
  for (const range of V4_RANGES) {
    if (best && range.prefix <= best.prefix) continue;
    if (matchPrefix(bytes, range.bytes, range.prefix)) best = range;
  }
  if (!best) return { decision: 'allow', reason: 'global' };
  return { decision: best.reachable ? 'allow' : 'reject', reason: best.name };
}

// R6.7, R6.6: translation chains first, then the longest matching registry row.
export function classifyIPv6(bytes) {
  if (isMapped(bytes)) {
    const v4 = classifyIPv4(bytes.subarray(12, 16));
    return {
      decision: v4.decision,
      reason: v4.decision === 'allow' ? 'ipv4_mapped' : `ipv4_mapped/${v4.reason}`,
    };
  }
  if (matchPrefix(bytes, NAT64_WKN, 96)) {
    const v4 = classifyIPv4(bytes.subarray(12, 16));
    return {
      decision: v4.decision,
      reason: v4.decision === 'allow' ? 'nat64_well_known' : `nat64_well_known/${v4.reason}`,
    };
  }
  // R6.7: 2002::/16 and 2001::/32 block on their own; the embedded address is no longer consulted.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return { decision: 'reject', reason: 'six_to_four' };
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0 && bytes[3] === 0) {
    return { decision: 'reject', reason: 'teredo' };
  }
  let best = null;
  for (const range of V6_RANGES) {
    if (best && range.prefix <= best.prefix) continue;
    if (matchPrefix(bytes, range.bytes, range.prefix)) best = range;
  }
  if (!best) return { decision: 'allow', reason: 'global' };
  return { decision: best.reachable ? 'allow' : 'reject', reason: best.name };
}

// R6.4, R6.7: classify one address literal and report its normalized spelling.
export function classifyAddress(text) {
  const parsed = parsedAddress(text);
  if (!parsed) return { decision: 'reject', reason: 'not_a_hostname' };
  const verdict = classifyParsed(parsed);
  return { decision: verdict.decision, reason: verdict.reason, family: parsed.family, address: parsed.address };
}

// R6.11: the operator override runs after the registry tables and never rescues an unparsable spelling.
export function classifyWithRanges(text, allowedRanges) {
  const parsed = parsedAddress(text);
  if (!parsed) return { decision: 'reject', reason: 'not_a_hostname', address: null };
  const verdict = classifyParsed(parsed);
  if (verdict.decision === 'allow') return { decision: 'allow', reason: verdict.reason, address: parsed.address };
  const ranges = Array.isArray(allowedRanges) ? allowedRanges : [];
  const hit = ranges.some((entry) => {
    const range = parseCidr(entry);
    return range.ok === true && range.family === parsed.family && matchPrefix(parsed.bytes, range.bytes, range.prefix);
  });
  if (hit) return { decision: 'allow', reason: 'allowed_range', address: parsed.address };
  return { decision: 'reject', reason: verdict.reason, address: parsed.address };
}

// R6.1, R6.2, R5.11: parse and validate a callback url into its canonical form.
export function checkUrl(urlText) {
  const text = typeof urlText === 'string' ? urlText : '';
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x21 || code === 0x7f || code > 0x7e) return urlBad('character');
  }
  const marker = text.indexOf('://');
  if (marker === -1) return { ok: false, code: 'scheme_not_https' };
  if (text.slice(0, marker).toLowerCase() !== 'https') return { ok: false, code: 'scheme_not_https' };
  const rest = text.slice(marker + 3);
  let end = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const char = rest[i];
    if (char === '/' || char === '?' || char === '#') {
      end = i;
      break;
    }
  }
  const authority = rest.slice(0, end);
  const tail = rest.slice(end);
  if (authority.includes('@')) return urlBad('userinfo');
  if (tail.includes('#')) return urlBad('fragment');
  if (authority === '') return urlBad('empty_host');
  const split = splitAuthority(authority);
  if (!split) return urlBad('host');
  const port = readPort(split.portText);
  if (port === null) return urlBad('port');
  const host = parseHost(split.hostText);
  // R6.3: a numeric spelling (decimal, octal, hex, short, over-long-dotted, empty label) is not_a_hostname;
  // only a malformed bracketed literal or unparsable authority stays invalid_callback_url with reason host.
  if (!host.ok) {
    if (host.reason === 'not_a_hostname') return { ok: false, code: 'not_a_hostname', reason: 'not_a_hostname' };
    return urlBad('host');
  }
  let path = '/';
  let query = '';
  if (tail !== '') {
    if (tail[0] === '?') {
      query = tail.slice(1);
    } else if (tail[0] === '/') {
      const mark = tail.indexOf('?');
      path = mark === -1 ? tail : tail.slice(0, mark);
      query = mark === -1 ? '' : tail.slice(mark + 1);
    } else {
      return urlBad('path');
    }
  }
  if (!path.startsWith('/')) return urlBad('path');
  for (const segment of path.split('/')) {
    const decoded = segment.replace(/%2e/gi, '.');
    if (decoded === '.' || decoded === '..') return urlBad('dot_segment');
  }
  const suffix = port === 443 ? '' : `:${port}`;
  const canonical = `https://${host.normalized}${suffix}${path}${query === '' ? '' : `?${query}`}`;
  return {
    ok: true,
    scheme: 'https',
    host: host.normalized,
    port,
    path,
    query,
    canonical,
    host_kind: host.kind,
    host_value: host.kind === 'name' ? host.name : host.address,
  };
}

// R6.1-R6.11: one delivery decision from the url, the resolver answers, the recheck and the override ranges.
export function checkDelivery(options) {
  if (!options || typeof options !== 'object' || options.url === undefined) {
    throw new Error('checkDelivery requires { url }');
  }
  const { url, answers = [], recheck = [], allowedRanges = [], redirect = null } = options;
  const checked = checkUrl(url);
  if (!checked.ok) return { decision: 'reject', code: checked.code, reason: checked.reason };
  if (redirect !== null) return { decision: 'reject', code: 'redirect_refused', reason: `status_${redirect}` };
  const literal = checked.host_kind !== 'name';
  const candidates = literal ? [checked.host_value] : answers;
  if (candidates.length === 0) return { decision: 'reject', code: 'no_answer', reason: 'no_records' };
  let address = null;
  let reason = null;
  for (const candidate of candidates) {
    const verdict = classifyWithRanges(candidate, allowedRanges);
    if (verdict.decision !== 'allow') return { decision: 'reject', code: 'blocked_address', reason: verdict.reason };
    if (address === null) {
      address = verdict.address;
      reason = verdict.reason;
    }
  }
  if (recheck.length > 0) {
    const next = parsedAddress(recheck[0]);
    if (!next || next.address !== address) {
      return { decision: 'reject', code: 'dns_rebinding', reason: 'address_changed' };
    }
  }
  const suffix = checked.port === 443 ? '' : `:${checked.port}`;
  return {
    decision: 'allow',
    reason,
    connect: { address, host_header: `${checked.host}${suffix}`, sni: literal ? null : checked.host_value },
  };
}

const urlBad = (reason) => ({ ok: false, code: 'invalid_callback_url', reason });

const parseHexGroups = (parts, allowDottedLast) => {
  const out = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (allowDottedLast && i === parts.length - 1 && part.includes('.')) {
      const quad = parseIPv4(part);
      if (!quad.ok) return null;
      out.push((quad.bytes[0] << 8) | quad.bytes[1], (quad.bytes[2] << 8) | quad.bytes[3]);
      continue;
    }
    if (!HEX_GROUP.test(part)) return null;
    out.push(parseInt(part, 16));
  }
  return out;
};

const hostBitsZero = (bytes, prefix) => {
  const whole = prefix >> 3;
  const restBits = prefix & 7;
  const from = restBits === 0 ? whole : whole + 1;
  for (let i = from; i < bytes.length; i++) if (bytes[i] !== 0) return false;
  if (restBits === 0) return true;
  const mask = (0xff << (8 - restBits)) & 0xff;
  return (bytes[whole] & (~mask & 0xff)) === 0;
};

const matchPrefix = (bytes, network, prefix) => {
  if (!bytes || !network || bytes.length !== network.length) return false;
  const whole = prefix >> 3;
  for (let i = 0; i < whole; i++) if (bytes[i] !== network[i]) return false;
  const restBits = prefix & 7;
  if (restBits === 0) return true;
  const mask = (0xff << (8 - restBits)) & 0xff;
  return (bytes[whole] & mask) === (network[whole] & mask);
};

const isMapped = (bytes) => {
  for (let i = 0; i < 10; i++) if (bytes[i] !== 0) return false;
  return bytes[10] === 0xff && bytes[11] === 0xff;
};

const parsedAddress = (text) => {
  let input = typeof text === 'string' ? text : '';
  if (input.startsWith('[') && input.endsWith(']')) input = input.slice(1, -1);
  const quad = parseIPv4(input);
  if (quad.ok) return { family: 'ipv4', bytes: quad.bytes, address: formatIPv4(quad.bytes) };
  const v6 = parseIPv6(input);
  if (v6.ok) return { family: 'ipv6', bytes: v6.bytes, address: formatIPv6(v6.bytes) };
  return null;
};

const classifyParsed = (parsed) => (parsed.family === 'ipv4' ? classifyIPv4(parsed.bytes) : classifyIPv6(parsed.bytes));

const splitAuthority = (authority) => {
  if (authority[0] === '[') {
    const close = authority.indexOf(']');
    if (close === -1) return { hostText: authority, portText: null };
    const after = authority.slice(close + 1);
    if (after === '') return { hostText: authority.slice(0, close + 1), portText: null };
    if (after[0] !== ':') return null;
    return { hostText: authority.slice(0, close + 1), portText: after.slice(1) };
  }
  const first = authority.indexOf(':');
  if (first === -1) return { hostText: authority, portText: null };
  if (authority.indexOf(':', first + 1) !== -1) return null;
  return { hostText: authority.slice(0, first), portText: authority.slice(first + 1) };
};

const readPort = (text) => {
  if (text === null) return 443;
  if (!PORT_TEXT.test(text) || (text.length > 1 && text[0] === '0')) return null;
  const value = Number(text);
  return value >= 1 && value <= 65535 ? value : null;
};

// Module-load invariant: every row must parse as a CIDR with zero host bits, so containment math is exact.
const V4_RANGES = IPV4_BLOCKS.map((entry) => ({ name: entry.name, reachable: entry.reachable, ...parseCidr(entry.block) }));
const V6_RANGES = IPV6_BLOCKS.map((entry) => ({ name: entry.name, reachable: entry.reachable, ...parseCidr(entry.block) }));
