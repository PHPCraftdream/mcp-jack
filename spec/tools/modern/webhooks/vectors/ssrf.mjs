// Vectors for spec/06-webhooks.md section 6 (R6.1-R6.11), the delivery-time network rules.
import { checkDelivery, checkUrl, cidrContains, classifyAddress, parseCidr, parseHost } from '../reference.mjs';

export const file = 'ssrf-vectors.json';

const HOOK = 'https://hooks.example.test/hooks/x';
const PUBLIC_V4 = '93.184.216.34';

export const cases = [
  { id: 'ssrf-url-http-scheme', rule: 'R6.1', description: 'an http callback url is not https', kind: 'url', input: { url: 'http://hooks.example.test/x' }, expect: { result: 'reject', code: 'scheme_not_https' } },
  { id: 'ssrf-url-ftp-scheme', rule: 'R6.1', description: 'an ftp callback url is not https', kind: 'url', input: { url: 'ftp://hooks.example.test/x' }, expect: { result: 'reject', code: 'scheme_not_https' } },
  { id: 'ssrf-url-no-scheme', rule: 'R6.1', description: 'a bare authority and path carries no scheme', kind: 'url', input: { url: 'hooks.example.test/x' }, expect: { result: 'reject', code: 'scheme_not_https' } },
  { id: 'ssrf-url-scheme-uppercase', rule: 'R6.1', description: 'an uppercase HTTPS scheme is accepted and the canonical url is lowercase', kind: 'url', input: { url: 'HTTPS://hooks.example.test/x' }, expect: { result: 'accept', canonical: 'https://hooks.example.test/x', host: 'hooks.example.test', port: 443, path: '/x', query: '' } },

  { id: 'ssrf-url-userinfo', rule: 'R6.2', description: 'userinfo in the authority is refused', kind: 'url', input: { url: 'https://user:pass@hooks.example.test/x' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'userinfo' } },
  { id: 'ssrf-url-fragment', rule: 'R6.2', description: 'a fragment is refused', kind: 'url', input: { url: 'https://hooks.example.test/x#frag' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'fragment' } },
  { id: 'ssrf-url-empty-host', rule: 'R6.2', description: 'three slashes leave an empty authority', kind: 'url', input: { url: 'https:///x' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'empty_host' } },
  { id: 'ssrf-url-port-zero', rule: 'R6.2', description: 'port 0 is outside 1-65535', kind: 'url', input: { url: 'https://hooks.example.test:0/x' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'port' } },
  { id: 'ssrf-url-port-high', rule: 'R6.2', description: 'port 65536 is one above the range', kind: 'url', input: { url: 'https://hooks.example.test:65536/x' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'port' } },
  { id: 'ssrf-url-space', rule: 'R6.2', description: 'a space inside the url is a forbidden byte', kind: 'url', input: { url: 'https://hooks.example.test/a b' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'character' } },
  { id: 'ssrf-url-bracket-open', rule: 'R6.2', description: 'an unterminated bracketed literal is a host failure', kind: 'url', input: { url: 'https://[::1' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'host' } },
  { id: 'ssrf-url-zone-id', rule: 'R6.2', description: 'a zone id inside a bracketed literal is a host failure', kind: 'url', input: { url: 'https://[fe80::1%25eth0]/x' }, expect: { result: 'reject', code: 'invalid_callback_url', reason: 'host' } },
  { id: 'ssrf-url-query-only', rule: 'R6.2', description: 'a url with only a query keeps the root path', kind: 'url', input: { url: 'https://hooks.example.test?x=1' }, expect: { result: 'accept', canonical: 'https://hooks.example.test/?x=1', host: 'hooks.example.test', port: 443, path: '/', query: 'x=1' } },
  { id: 'ssrf-url-port-443', rule: 'R6.2', description: 'an explicit 443 is dropped from the canonical url', kind: 'url', input: { url: 'https://hooks.example.test:443/x' }, expect: { result: 'accept', canonical: 'https://hooks.example.test/x', host: 'hooks.example.test', port: 443, path: '/x', query: '' } },

  { id: 'ssrf-host-name', rule: 'R6.3', description: 'an LDH name is accepted unchanged', kind: 'host', input: { host: 'hooks.example.test' }, expect: { result: 'accept', kind: 'name', normalized: 'hooks.example.test' } },
  { id: 'ssrf-host-trailing-dot', rule: 'R6.3', description: 'exactly one trailing dot is stripped', kind: 'host', input: { host: 'hooks.example.test.' }, expect: { result: 'accept', kind: 'name', normalized: 'hooks.example.test' } },
  { id: 'ssrf-host-uppercase', rule: 'R6.3', description: 'an uppercase name is lowercased', kind: 'host', input: { host: 'HOOKS.Example.Test' }, expect: { result: 'accept', kind: 'name', normalized: 'hooks.example.test' } },
  { id: 'ssrf-host-ipv6-literal', rule: 'R6.3', description: 'a bracketed IPv6 literal is accepted in compressed form', kind: 'host', input: { host: '[2606:4700:4700::1111]' }, expect: { result: 'accept', kind: 'ipv6', normalized: '[2606:4700:4700::1111]' } },
  { id: 'ssrf-host-double-dot', rule: 'R6.3', description: 'two trailing dots leave an empty label', kind: 'host', input: { host: 'hooks.example.test..' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-short', rule: 'R6.3', description: 'a short dotted form is never reinterpreted', kind: 'host', input: { host: '127.1' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-int', rule: 'R6.3', description: 'a single integer spelling is not a hostname', kind: 'host', input: { host: '2130706433' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-hex', rule: 'R6.3', description: 'a hexadecimal octet is not an address or a name', kind: 'host', input: { host: '0x7f.0.0.1' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-octal', rule: 'R6.3', description: 'a leading zero octet is rejected rather than read as octal', kind: 'host', input: { host: '0177.0.0.1' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-five-octets', rule: 'R6.3', description: 'five dotted parts are not a dotted quad', kind: 'host', input: { host: '1.2.3.4.5' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-empty-label', rule: 'R6.3', description: 'an empty label is not LDH', kind: 'host', input: { host: 'a..b' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-leading-hyphen', rule: 'R6.3', description: 'a label may not start with a hyphen', kind: 'host', input: { host: '-bad.example.test' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-trailing-hyphen', rule: 'R6.3', description: 'a label may not end with a hyphen', kind: 'host', input: { host: 'bad-.example.test' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-single-label', rule: 'R6.3', description: 'a single label is not an LDH name', kind: 'host', input: { host: 'localhost' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-numeric-tld', rule: 'R6.3', description: 'an all-numeric last label is rejected', kind: 'host', input: { host: 'example.123' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-idn', rule: 'R6.3', description: 'a raw non-ASCII label is not_a_hostname', kind: 'host', input: { host: 'exämple.test' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-host-stray-bracket', rule: 'R6.3', description: 'a bracket outside a bracketed literal is a host failure', kind: 'host', input: { host: 'bad[host' }, expect: { result: 'reject', reason: 'host' } },

  { id: 'ssrf-addr-global', rule: 'R6.4', description: 'a public dotted quad is globally routable', kind: 'address', input: { address: '8.8.8.8' }, expect: { result: 'accept', reason: 'global', family: 'ipv4' } },
  { id: 'ssrf-addr-loopback', rule: 'R6.4', description: 'a loopback dotted quad is classified without a resolver', kind: 'address', input: { address: '127.0.0.1' }, expect: { result: 'reject', reason: 'loopback', family: 'ipv4' } },
  { id: 'ssrf-addr-leading-zero', rule: 'R6.4', description: 'a leading zero octet is not a canonical dotted quad', kind: 'address', input: { address: '127.0.0.01' }, expect: { result: 'reject', reason: 'not_a_hostname' } },
  { id: 'ssrf-addr-bracketed-loopback', rule: 'R6.4', description: 'a bracketed ::1 is a literal and classifies as loopback', kind: 'address', input: { address: '[::1]' }, expect: { result: 'reject', reason: 'loopback', family: 'ipv6' } },

  // R6.5: the longest matching registry row decides and its name is the reason, so every reason below is a row name.
  { id: 'ssrf-v4-this-network', rule: 'R6.5', description: '0.0.0.0 is inside 0.0.0.0/8 this_network', kind: 'address', input: { address: '0.0.0.0' }, expect: { result: 'reject', reason: 'this_network', family: 'ipv4' } },
  { id: 'ssrf-v4-private-10', rule: 'R6.5', description: '10.1.2.3 is inside 10.0.0.0/8 private_use', kind: 'address', input: { address: '10.1.2.3' }, expect: { result: 'reject', reason: 'private_use', family: 'ipv4' } },
  { id: 'ssrf-v4-shared', rule: 'R6.5', description: '100.64.0.1 is inside 100.64.0.0/10 shared_address_space', kind: 'address', input: { address: '100.64.0.1' }, expect: { result: 'reject', reason: 'shared_address_space', family: 'ipv4' } },
  { id: 'ssrf-v4-loopback', rule: 'R6.5', description: '127.0.0.1 is inside 127.0.0.0/8 loopback', kind: 'address', input: { address: '127.0.0.1' }, expect: { result: 'reject', reason: 'loopback', family: 'ipv4' } },
  { id: 'ssrf-v4-link-local', rule: 'R6.5', description: '169.254.1.1 is inside 169.254.0.0/16 link_local', kind: 'address', input: { address: '169.254.1.1' }, expect: { result: 'reject', reason: 'link_local', family: 'ipv4' } },
  { id: 'ssrf-v4-private-172', rule: 'R6.5', description: '172.16.0.1 is inside 172.16.0.0/12 private_use', kind: 'address', input: { address: '172.16.0.1' }, expect: { result: 'reject', reason: 'private_use', family: 'ipv4' } },
  { id: 'ssrf-v4-ietf', rule: 'R6.5', description: '192.0.0.11 is inside 192.0.0.0/24 and in none of the more specific rows of that /24, so ietf_protocol_assignments', kind: 'address', input: { address: '192.0.0.11' }, expect: { result: 'reject', reason: 'ietf_protocol_assignments', family: 'ipv4' } },
  { id: 'ssrf-v4-service-continuity', rule: 'R6.5', description: '192.0.0.4 is inside 192.0.0.0/29 ipv4_service_continuity_prefix', kind: 'address', input: { address: '192.0.0.4' }, expect: { result: 'reject', reason: 'ipv4_service_continuity_prefix', family: 'ipv4' } },
  { id: 'ssrf-v4-service-continuity-longest', rule: 'R6.5', description: '192.0.0.1 is in the /24 and the /29 rows, and the longer prefix names it ipv4_service_continuity_prefix', kind: 'address', input: { address: '192.0.0.1' }, expect: { result: 'reject', reason: 'ipv4_service_continuity_prefix', family: 'ipv4' } },
  { id: 'ssrf-v4-dummy', rule: 'R6.5', description: '192.0.0.8 is inside 192.0.0.8/32 ipv4_dummy_address', kind: 'address', input: { address: '192.0.0.8' }, expect: { result: 'reject', reason: 'ipv4_dummy_address', family: 'ipv4' } },
  { id: 'ssrf-v4-nat64-discovery-170', rule: 'R6.5', description: '192.0.0.170 is inside 192.0.0.170/32 nat64_dns64_discovery', kind: 'address', input: { address: '192.0.0.170' }, expect: { result: 'reject', reason: 'nat64_dns64_discovery', family: 'ipv4' } },
  { id: 'ssrf-v4-nat64-discovery-171', rule: 'R6.5', description: '192.0.0.171 is inside 192.0.0.171/32 nat64_dns64_discovery', kind: 'address', input: { address: '192.0.0.171' }, expect: { result: 'reject', reason: 'nat64_dns64_discovery', family: 'ipv4' } },
  { id: 'ssrf-v4-doc-192-0-2', rule: 'R6.5', description: '192.0.2.1 is inside 192.0.2.0/24 documentation', kind: 'address', input: { address: '192.0.2.1' }, expect: { result: 'reject', reason: 'documentation', family: 'ipv4' } },
  { id: 'ssrf-v4-6to4-relay', rule: 'R6.5', description: '192.88.99.1 is inside 192.88.99.0/24 deprecated_6to4_relay_anycast', kind: 'address', input: { address: '192.88.99.1' }, expect: { result: 'reject', reason: 'deprecated_6to4_relay_anycast', family: 'ipv4' } },
  { id: 'ssrf-v4-private-192', rule: 'R6.5', description: '192.168.1.1 is inside 192.168.0.0/16 private_use', kind: 'address', input: { address: '192.168.1.1' }, expect: { result: 'reject', reason: 'private_use', family: 'ipv4' } },
  { id: 'ssrf-v4-benchmark', rule: 'R6.5', description: '198.18.0.1 is inside 198.18.0.0/15 benchmarking', kind: 'address', input: { address: '198.18.0.1' }, expect: { result: 'reject', reason: 'benchmarking', family: 'ipv4' } },
  { id: 'ssrf-v4-doc-198-51-100', rule: 'R6.5', description: '198.51.100.1 is inside 198.51.100.0/24 documentation', kind: 'address', input: { address: '198.51.100.1' }, expect: { result: 'reject', reason: 'documentation', family: 'ipv4' } },
  { id: 'ssrf-v4-doc-203-0-113', rule: 'R6.5', description: '203.0.113.1 is inside 203.0.113.0/24 documentation', kind: 'address', input: { address: '203.0.113.1' }, expect: { result: 'reject', reason: 'documentation', family: 'ipv4' } },
  { id: 'ssrf-v4-multicast', rule: 'R6.5', description: '224.0.0.1 is inside 224.0.0.0/4 multicast', kind: 'address', input: { address: '224.0.0.1' }, expect: { result: 'reject', reason: 'multicast', family: 'ipv4' } },
  { id: 'ssrf-v4-reserved', rule: 'R6.5', description: '240.0.0.1 is inside 240.0.0.0/4 reserved', kind: 'address', input: { address: '240.0.0.1' }, expect: { result: 'reject', reason: 'reserved', family: 'ipv4' } },
  { id: 'ssrf-v4-limited-broadcast', rule: 'R6.5', description: '255.255.255.255 is inside 255.255.255.255/32 limited_broadcast, which wins over the shorter 240.0.0.0/4 row', kind: 'address', input: { address: '255.255.255.255' }, expect: { result: 'reject', reason: 'limited_broadcast', family: 'ipv4' } },
  { id: 'ssrf-v4-pcp-anycast', rule: 'R6.5', description: '192.0.0.9 is inside 192.0.0.9/32 pcp_anycast, which is globally reachable', kind: 'address', input: { address: '192.0.0.9' }, expect: { result: 'accept', reason: 'pcp_anycast', family: 'ipv4' } },
  { id: 'ssrf-v4-turn-anycast', rule: 'R6.5', description: '192.0.0.10 is inside 192.0.0.10/32 turn_anycast, which is globally reachable', kind: 'address', input: { address: '192.0.0.10' }, expect: { result: 'accept', reason: 'turn_anycast', family: 'ipv4' } },
  { id: 'ssrf-v4-as112', rule: 'R6.5', description: '192.31.196.1 is inside 192.31.196.0/24 as112_v4, which is globally reachable', kind: 'address', input: { address: '192.31.196.1' }, expect: { result: 'accept', reason: 'as112_v4', family: 'ipv4' } },
  { id: 'ssrf-v4-amt', rule: 'R6.5', description: '192.52.193.1 is inside 192.52.193.0/24 amt, which is globally reachable', kind: 'address', input: { address: '192.52.193.1' }, expect: { result: 'accept', reason: 'amt', family: 'ipv4' } },
  { id: 'ssrf-v4-as112-direct', rule: 'R6.5', description: '192.175.48.1 is inside 192.175.48.0/24 as112_direct_delegation, which is globally reachable', kind: 'address', input: { address: '192.175.48.1' }, expect: { result: 'accept', reason: 'as112_direct_delegation', family: 'ipv4' } },
  { id: 'ssrf-v4-global-google', rule: 'R6.5', description: '8.8.8.8 matches no IPv4 row and is globally routable', kind: 'address', input: { address: '8.8.8.8' }, expect: { result: 'accept', reason: 'global', family: 'ipv4' } },
  { id: 'ssrf-v4-global-example', rule: 'R6.5', description: '93.184.216.34 matches no IPv4 row and is globally routable', kind: 'address', input: { address: '93.184.216.34' }, expect: { result: 'accept', reason: 'global', family: 'ipv4' } },

  // R6.6: the same longest-match rule on the IPv6 table; the teredo, benchmarking and as112 rows outrank 2001::/23.
  { id: 'ssrf-v6-unspecified', rule: 'R6.6', description: ':: is inside ::/128 unspecified', kind: 'address', input: { address: '::' }, expect: { result: 'reject', reason: 'unspecified', family: 'ipv6' } },
  { id: 'ssrf-v6-loopback', rule: 'R6.6', description: '::1 is inside ::1/128 loopback', kind: 'address', input: { address: '::1' }, expect: { result: 'reject', reason: 'loopback', family: 'ipv6' } },
  { id: 'ssrf-v6-compat', rule: 'R6.6', description: '::8.8.8.8 is inside ::/96 ipv4_compatible_deprecated', kind: 'address', input: { address: '::8.8.8.8' }, expect: { result: 'reject', reason: 'ipv4_compatible_deprecated', family: 'ipv6' } },
  { id: 'ssrf-v6-discard', rule: 'R6.6', description: '100::1 is inside 100::/64 discard_only', kind: 'address', input: { address: '100::1' }, expect: { result: 'reject', reason: 'discard_only', family: 'ipv6' } },
  { id: 'ssrf-v6-ietf', rule: 'R6.6', description: '2001:8::1 is inside 2001::/23 and in none of its more specific rows, so ietf_protocol_assignments', kind: 'address', input: { address: '2001:8::1' }, expect: { result: 'reject', reason: 'ietf_protocol_assignments', family: 'ipv6' } },
  { id: 'ssrf-v6-teredo-prefix', rule: 'R6.6', description: '2001::1 is inside 2001::/32 teredo, the narrowest row under 2001::/23', kind: 'address', input: { address: '2001::1' }, expect: { result: 'reject', reason: 'teredo', family: 'ipv6' } },
  { id: 'ssrf-v6-teredo', rule: 'R6.6', description: '2001:0:4136:e378:: is inside 2001::/32 teredo', kind: 'address', input: { address: '2001:0:4136:e378::' }, expect: { result: 'reject', reason: 'teredo', family: 'ipv6' } },
  { id: 'ssrf-v6-benchmark', rule: 'R6.6', description: '2001:2::1 is inside 2001:2::/48 benchmarking', kind: 'address', input: { address: '2001:2::1' }, expect: { result: 'reject', reason: 'benchmarking', family: 'ipv6' } },
  { id: 'ssrf-v6-orchid', rule: 'R6.6', description: '2001:10::1 is inside 2001:10::/28 orchid', kind: 'address', input: { address: '2001:10::1' }, expect: { result: 'reject', reason: 'orchid', family: 'ipv6' } },
  { id: 'ssrf-v6-orchidv2', rule: 'R6.6', description: '2001:20::1 is inside 2001:20::/28 orchidv2', kind: 'address', input: { address: '2001:20::1' }, expect: { result: 'reject', reason: 'orchidv2', family: 'ipv6' } },
  { id: 'ssrf-v6-drone', rule: 'R6.6', description: '2001:30::1 is inside 2001:30::/28 drone_remote_id', kind: 'address', input: { address: '2001:30::1' }, expect: { result: 'reject', reason: 'drone_remote_id', family: 'ipv6' } },
  { id: 'ssrf-v6-doc', rule: 'R6.6', description: '2001:db8::1 is inside 2001:db8::/32 documentation', kind: 'address', input: { address: '2001:db8::1' }, expect: { result: 'reject', reason: 'documentation', family: 'ipv6' } },
  { id: 'ssrf-v6-6to4', rule: 'R6.6', description: '2002:7f00:1:: is inside 2002::/16 six_to_four', kind: 'address', input: { address: '2002:7f00:1::' }, expect: { result: 'reject', reason: 'six_to_four', family: 'ipv6' } },
  { id: 'ssrf-v6-doc-3fff', rule: 'R6.6', description: '3fff::1 is inside 3fff::/20 documentation', kind: 'address', input: { address: '3fff::1' }, expect: { result: 'reject', reason: 'documentation', family: 'ipv6' } },
  { id: 'ssrf-v6-srv6', rule: 'R6.6', description: '5f00::1 is inside 5f00::/16 srv6_sid', kind: 'address', input: { address: '5f00::1' }, expect: { result: 'reject', reason: 'srv6_sid', family: 'ipv6' } },
  { id: 'ssrf-v6-ula', rule: 'R6.6', description: 'fc00::1 is inside fc00::/7 unique_local', kind: 'address', input: { address: 'fc00::1' }, expect: { result: 'reject', reason: 'unique_local', family: 'ipv6' } },
  { id: 'ssrf-v6-link-local', rule: 'R6.6', description: 'fe80::1 is inside fe80::/10 link_local', kind: 'address', input: { address: 'fe80::1' }, expect: { result: 'reject', reason: 'link_local', family: 'ipv6' } },
  { id: 'ssrf-v6-multicast', rule: 'R6.6', description: 'ff02::1 is inside ff00::/8 multicast', kind: 'address', input: { address: 'ff02::1' }, expect: { result: 'reject', reason: 'multicast', family: 'ipv6' } },
  { id: 'ssrf-v6-pcp-anycast', rule: 'R6.6', description: '2001:1::1 is inside 2001:1::1/128 pcp_anycast, which is globally reachable', kind: 'address', input: { address: '2001:1::1' }, expect: { result: 'accept', reason: 'pcp_anycast', family: 'ipv6' } },
  { id: 'ssrf-v6-turn-anycast', rule: 'R6.6', description: '2001:1::2 is inside 2001:1::2/128 turn_anycast, which is globally reachable', kind: 'address', input: { address: '2001:1::2' }, expect: { result: 'accept', reason: 'turn_anycast', family: 'ipv6' } },
  { id: 'ssrf-v6-amt', rule: 'R6.6', description: '2001:3::1 is inside 2001:3::/32 amt, which is globally reachable', kind: 'address', input: { address: '2001:3::1' }, expect: { result: 'accept', reason: 'amt', family: 'ipv6' } },
  { id: 'ssrf-v6-as112', rule: 'R6.6', description: '2001:4:112::1 is inside 2001:4:112::/48 as112_v6, which is globally reachable', kind: 'address', input: { address: '2001:4:112::1' }, expect: { result: 'accept', reason: 'as112_v6', family: 'ipv6' } },
  { id: 'ssrf-v6-as112-direct', rule: 'R6.6', description: '2620:4f:8000::1 is inside 2620:4f:8000::/48 as112_direct_delegation, which is globally reachable', kind: 'address', input: { address: '2620:4f:8000::1' }, expect: { result: 'accept', reason: 'as112_direct_delegation', family: 'ipv6' } },
  { id: 'ssrf-v6-global-cloudflare', rule: 'R6.6', description: '2606:4700:4700::1111 matches no IPv6 row', kind: 'address', input: { address: '2606:4700:4700::1111' }, expect: { result: 'accept', reason: 'global', family: 'ipv6' } },
  { id: 'ssrf-v6-global-google', rule: 'R6.6', description: '2a00:1450:4001:80f::200e matches no IPv6 row', kind: 'address', input: { address: '2a00:1450:4001:80f::200e' }, expect: { result: 'accept', reason: 'global', family: 'ipv6' } },

  // R6.7: mapped and NAT64 inherit the embedded decision; 6to4 and teredo never decode the embedded address.
  { id: 'ssrf-chain-mapped-loopback', rule: 'R6.7', description: 'an ipv4-mapped loopback address names both chain and reason', kind: 'address', input: { address: '::ffff:127.0.0.1' }, expect: { result: 'reject', reason: 'ipv4_mapped/loopback', family: 'ipv6' } },
  { id: 'ssrf-chain-mapped-private', rule: 'R6.7', description: 'an ipv4-mapped private address names both chain and reason', kind: 'address', input: { address: '::ffff:10.0.0.1' }, expect: { result: 'reject', reason: 'ipv4_mapped/private_use', family: 'ipv6' } },
  { id: 'ssrf-chain-mapped-global', rule: 'R6.7', description: 'an ipv4-mapped public address is allowed with the chain label alone', kind: 'address', input: { address: '::ffff:8.8.8.8' }, expect: { result: 'accept', reason: 'ipv4_mapped', family: 'ipv6' } },
  { id: 'ssrf-chain-nat64-private', rule: 'R6.7', description: 'a NAT64 private address names both chain and reason', kind: 'address', input: { address: '64:ff9b::a00:1' }, expect: { result: 'reject', reason: 'nat64_well_known/private_use', family: 'ipv6' } },
  { id: 'ssrf-chain-nat64-global', rule: 'R6.7', description: 'a NAT64 address with a public embedded address is allowed', kind: 'address', input: { address: '64:ff9b::808:808' }, expect: { result: 'accept', reason: 'nat64_well_known', family: 'ipv6' } },
  { id: 'ssrf-chain-nat64-local', rule: 'R6.7', description: 'the local-use NAT64 prefix has no fixed embedding and is blocked whole as nat64_local_use', kind: 'address', input: { address: '64:ff9b:1::1' }, expect: { result: 'reject', reason: 'nat64_local_use', family: 'ipv6' } },
  { id: 'ssrf-chain-6to4-public', rule: 'R6.7', description: '6to4 is blocked as six_to_four even when the embedded address is public', kind: 'address', input: { address: '2002:808:808::' }, expect: { result: 'reject', reason: 'six_to_four', family: 'ipv6' } },
  { id: 'ssrf-chain-teredo-private', rule: 'R6.7', description: 'teredo is blocked as teredo whether the embedded address is public or private', kind: 'address', input: { address: '2001:0:a00:1::' }, expect: { result: 'reject', reason: 'teredo', family: 'ipv6' } },

  { id: 'ssrf-deliver-name', rule: 'R6.8', description: 'a public answer is connected to, with the name in Host and SNI', kind: 'delivery', input: { url: HOOK, answers: [PUBLIC_V4] }, expect: { result: 'accept', address: PUBLIC_V4, reason: 'global', host_header: 'hooks.example.test', sni: 'hooks.example.test' } },
  { id: 'ssrf-deliver-port', rule: 'R6.8', description: 'a non-default port is appended to the Host header', kind: 'delivery', input: { url: 'https://hooks.example.test:8443/hooks/x', answers: [PUBLIC_V4] }, expect: { result: 'accept', address: PUBLIC_V4, reason: 'global', host_header: 'hooks.example.test:8443', sni: 'hooks.example.test' } },
  { id: 'ssrf-deliver-no-answer', rule: 'R6.8', description: 'an empty resolver answer set is no_answer', kind: 'delivery', input: { url: HOOK, answers: [] }, expect: { result: 'reject', code: 'no_answer', reason: 'no_records' } },
  { id: 'ssrf-deliver-second-blocked', rule: 'R6.8', description: 'a private answer after a public one refuses the attempt in resolver order', kind: 'delivery', input: { url: HOOK, answers: [PUBLIC_V4, '10.0.0.5'] }, expect: { result: 'reject', code: 'blocked_address', reason: 'private_use' } },
  { id: 'ssrf-deliver-ipv6-literal', rule: 'R6.8', description: 'an IPv6 literal is its own name and sends no SNI', kind: 'delivery', input: { url: 'https://[2606:4700:4700::1111]/x' }, expect: { result: 'accept', address: '2606:4700:4700::1111', reason: 'global', host_header: '[2606:4700:4700::1111]', sni: null } },

  { id: 'ssrf-deliver-rebind', rule: 'R6.9', description: 'a different address on recheck is dns_rebinding', kind: 'delivery', input: { url: HOOK, answers: [PUBLIC_V4], recheck: ['10.0.0.5'] }, expect: { result: 'reject', code: 'dns_rebinding', reason: 'address_changed' } },
  { id: 'ssrf-deliver-recheck-same', rule: 'R6.9', description: 'a recheck matching the validated address is accepted', kind: 'delivery', input: { url: HOOK, answers: [PUBLIC_V4], recheck: [PUBLIC_V4] }, expect: { result: 'accept', address: PUBLIC_V4, reason: 'global', host_header: 'hooks.example.test', sni: 'hooks.example.test' } },

  { id: 'ssrf-deliver-redirect', rule: 'R6.10', description: 'a 302 is redirect_refused and final', kind: 'delivery', input: { url: HOOK, answers: [PUBLIC_V4], redirect: 302 }, expect: { result: 'reject', code: 'redirect_refused', reason: 'status_302' } },
  { id: 'ssrf-deliver-no-redirect', rule: 'R6.10', description: 'the same delivery without a redirect status succeeds', kind: 'delivery', input: { url: HOOK, answers: [PUBLIC_V4] }, expect: { result: 'accept', address: PUBLIC_V4, reason: 'global', host_header: 'hooks.example.test', sni: 'hooks.example.test' } },

  { id: 'ssrf-allowed-range-hit', rule: 'R6.11', description: 'an allowed range overrides the private table and reports allowed_range', kind: 'delivery', input: { url: 'https://10.1.2.3/x', allowedRanges: ['10.0.0.0/8'] }, expect: { result: 'accept', address: '10.1.2.3', reason: 'allowed_range', host_header: '10.1.2.3', sni: null } },
  { id: 'ssrf-allowed-range-miss', rule: 'R6.11', description: 'an address outside the allowed ranges stays blocked', kind: 'delivery', input: { url: 'https://192.168.1.1/x', allowedRanges: ['10.0.0.0/8'] }, expect: { result: 'reject', code: 'blocked_address', reason: 'private_use' } },
  { id: 'ssrf-allowed-range-malformed', rule: 'R6.11', description: 'a malformed range entry is ignored, so the table decides', kind: 'delivery', input: { url: 'https://10.1.2.3/x', allowedRanges: ['10.0.0.0/33'] }, expect: { result: 'reject', code: 'blocked_address', reason: 'private_use' } },
  { id: 'ssrf-allowed-range-http', rule: 'R6.11', description: 'the override never rescues a non-https scheme', kind: 'delivery', input: { url: 'http://10.1.2.3/x', allowedRanges: ['10.0.0.0/8'] }, expect: { result: 'reject', code: 'scheme_not_https' } },

  { id: 'ssrf-cidr-v4-contains', rule: 'R6.11', description: '10.1.2.3 is contained in 10.0.0.0/8', kind: 'cidr', input: { cidr: '10.0.0.0/8', address: '10.1.2.3' }, expect: { result: 'accept', contains: true } },
  { id: 'ssrf-cidr-v4-outside', rule: 'R6.11', description: '192.169.0.1 is outside 192.168.0.0/16', kind: 'cidr', input: { cidr: '192.168.0.0/16', address: '192.169.0.1' }, expect: { result: 'accept', contains: false } },
  { id: 'ssrf-cidr-v6-contains', rule: 'R6.11', description: '64:ff9b::1 is contained in 64:ff9b::/96', kind: 'cidr', input: { cidr: '64:ff9b::/96', address: '64:ff9b::1' }, expect: { result: 'accept', contains: true } },
  { id: 'ssrf-cidr-malformed', rule: 'R6.11', description: 'an IPv4 prefix of 33 is malformed', kind: 'cidr', input: { cidr: '10.0.0.0/33', address: '10.1.2.3' }, expect: { result: 'reject' } },
];

export function run(c) {
  const input = c.input;
  switch (c.kind) {
    case 'address': {
      const verdict = classifyAddress(input.address);
      return verdict.family === undefined
        ? { result: 'reject', reason: verdict.reason }
        : { result: resultOf(verdict.decision), reason: verdict.reason, family: verdict.family };
    }
    case 'host': {
      const verdict = parseHost(input.host);
      return verdict.ok
        ? { result: 'accept', kind: verdict.kind, normalized: verdict.normalized }
        : { result: 'reject', reason: verdict.reason };
    }
    case 'url': {
      const verdict = checkUrl(input.url);
      if (!verdict.ok) return refusal(verdict.code, verdict.reason);
      return {
        result: 'accept',
        canonical: verdict.canonical,
        host: verdict.host,
        port: verdict.port,
        path: verdict.path,
        query: verdict.query,
      };
    }
    case 'delivery': {
      const verdict = checkDelivery(input);
      if (verdict.decision !== 'allow') return refusal(verdict.code, verdict.reason);
      return {
        result: 'accept',
        address: verdict.connect.address,
        reason: verdict.reason,
        host_header: verdict.connect.host_header,
        sni: verdict.connect.sni,
      };
    }
    case 'cidr': {
      const range = parseCidr(input.cidr);
      if (!range.ok) return { result: 'reject' };
      return { result: 'accept', contains: cidrContains(range, input.address) };
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

const resultOf = (decision) => (decision === 'allow' ? 'accept' : 'reject');

const refusal = (code, reason) =>
  reason === undefined ? { result: 'reject', code } : { result: 'reject', code, reason };
