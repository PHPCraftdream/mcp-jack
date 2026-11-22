// C1-C4 vectors of spec 04 sections 4 and 6. Data only: no build, no I/O, no
// clock, no randomness. Every expected header value is a literal written by
// hand from the encoding rules of section 4, never produced by the encoder
// under test; the generator asserts the reference reproduces each literal.
import { MODERN_MIN, META_VERSION_KEY } from '../spec-data.mjs';

const V = MODERN_MIN;

// The four documented sentinel values of spec 04 section 4, transcribed. The
// literals are written by hand from the encoding rules; the generator asserts
// the reference reproduces them.
const B64_HELLO_WORLD = '=?base64?SGVsbG8sIOS4lueVjA==?=';
const B64_PADDED = '=?base64?IHBhZGRlZCA=?=';
const B64_LINE = '=?base64?bGluZTEKbGluZTI=?=';
const B64_LITERAL = '=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=';

export const ENCODING_CASES = [
  // C1 and C2: the `_meta` and the mirror headers of one request.
  {
    id: 'enc-build-tools-call', rule: 'C1', kind: 'build',
    description: 'a tools/call request mirrors the version, the method and the tool name',
    version: V, method: 'tools/call', params: { name: 'get_weather' },
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', 'get_weather']],
    },
  },
  {
    id: 'enc-build-tools-call-nonascii', rule: 'C2', kind: 'build',
    description: 'a non-ASCII tool name is sent as a sentinel',
    version: V, method: 'tools/call', params: { name: 'get weather/日本' },
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '=?base64?Z2V0IHdlYXRoZXIv5pel5pys?=']],
    },
  },
  {
    id: 'enc-build-tools-call-empty-name', rule: 'C2', kind: 'build',
    description: 'an empty tool name produces an empty Mcp-Name value',
    version: V, method: 'tools/call', params: { name: '' },
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', '']],
    },
  },
  {
    id: 'enc-build-tools-call-sentinel-name', rule: 'C2', kind: 'build',
    description: 'a sentinel-shaped tool name is sent as a sentinel',
    version: V, method: 'tools/call', params: { name: '=?base64?literal?=' },
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'tools/call'], ['Mcp-Name', B64_LITERAL]],
    },
  },
  {
    id: 'enc-build-resources-read', rule: 'C2', kind: 'build',
    description: 'resources/read mirrors params.uri, encoded by the same rule',
    version: V, method: 'resources/read', params: { uri: 'file:///a b.json' },
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'resources/read'], ['Mcp-Name', 'file:///a b.json']],
    },
  },
  {
    id: 'enc-build-prompts-get', rule: 'C2', kind: 'build',
    description: 'prompts/get mirrors params.name',
    version: V, method: 'prompts/get', params: { name: 'summarize' },
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'prompts/get'], ['Mcp-Name', 'summarize']],
    },
  },
  {
    id: 'enc-build-server-discover', rule: 'C2', kind: 'build',
    description: 'server/discover has no source field, so no Mcp-Name is sent',
    version: V, method: 'server/discover', params: {},
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'server/discover']],
    },
  },
  {
    id: 'enc-build-events-list', rule: 'C2', kind: 'build',
    description: 'events/list carries no Mcp-Name even with a name argument',
    version: V, method: 'events/list', params: { name: 'incident.created' },
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/list']],
    },
  },
  {
    id: 'enc-build-events-subscribe', rule: 'C2', kind: 'build',
    description: 'events/subscribe has a name source field and mirrors it',
    version: V, method: 'events/subscribe', params: { name: 'incident.created' },
    expect: {
      meta: { [META_VERSION_KEY]: V, 'io.modelcontextprotocol/clientCapabilities': {} },
      headers: [['MCP-Protocol-Version', V], ['Mcp-Method', 'events/subscribe'], ['Mcp-Name', 'incident.created']],
    },
  },

  // C3: type to text, then the sentinel only when section 4 requires it.
  {
    id: 'enc-plain-tool-name', rule: 'C3', kind: 'encode',
    description: 'a plain ASCII string needs no sentinel',
    value: 'us-west1', type: 'string',
    expect: { header_value: 'us-west1' },
  },
  {
    id: 'enc-plain-uri', rule: 'C3', kind: 'encode',
    description: 'a URI without edge space or non-ASCII stays plain',
    value: 'file:///projects/myapp/config.json', type: 'string',
    expect: { header_value: 'file:///projects/myapp/config.json' },
  },
  {
    id: 'enc-plain-interior-space', rule: 'C3', kind: 'encode',
    description: 'an interior SP is legal in a field-value, so it stays plain',
    value: 'Seattle WA', type: 'string',
    expect: { header_value: 'Seattle WA' },
  },
  {
    id: 'enc-plain-empty', rule: 'C3', kind: 'encode',
    description: 'the empty string is never encoded',
    value: '', type: 'string',
    expect: { header_value: '' },
  },
  {
    id: 'enc-nonascii', rule: 'C3', kind: 'encode',
    description: 'a non-ASCII string is sent as a sentinel',
    value: 'Hello, 世界', type: 'string',
    expect: { header_value: B64_HELLO_WORLD },
  },
  {
    id: 'enc-padded', rule: 'C3', kind: 'encode',
    description: 'a leading and trailing SP force the sentinel',
    value: ' padded ', type: 'string',
    expect: { header_value: B64_PADDED },
  },
  {
    id: 'enc-leading-space', rule: 'C3', kind: 'encode',
    description: 'a leading SP alone forces the sentinel',
    value: ' leading', type: 'string',
    expect: { header_value: '=?base64?IGxlYWRpbmc=?=' },
  },
  {
    id: 'enc-trailing-space', rule: 'C3', kind: 'encode',
    description: 'a trailing SP alone forces the sentinel, as it would be removed as OWS',
    value: 'trailing ', type: 'string',
    expect: { header_value: '=?base64?dHJhaWxpbmcg?=' },
  },
  {
    id: 'enc-newline', rule: 'C3', kind: 'encode',
    description: 'an LF is outside 0x20-0x7E and forces the sentinel',
    value: 'line1\nline2', type: 'string',
    expect: { header_value: B64_LINE },
  },
  {
    id: 'enc-carriage-return', rule: 'C3', kind: 'encode',
    description: 'a CR is outside 0x20-0x7E and forces the sentinel',
    value: 'a\rb', type: 'string',
    expect: { header_value: '=?base64?YQ1i?=' },
  },
  {
    id: 'enc-nul', rule: 'C3', kind: 'encode',
    description: 'a NUL is outside 0x20-0x7E and forces the sentinel',
    value: 'a\u0000b', type: 'string',
    expect: { header_value: '=?base64?YQBi?=' },
  },
  {
    id: 'enc-del', rule: 'C3', kind: 'encode',
    description: 'DEL is outside 0x20-0x7E and forces the sentinel',
    value: 'a\u007fb', type: 'string',
    expect: { header_value: '=?base64?YX9i?=' },
  },
  {
    id: 'enc-interior-tab', rule: 'C3', kind: 'encode',
    description: 'an interior HTAB is a control character, so it is encoded',
    value: 'a\tb', type: 'string',
    expect: { header_value: '=?base64?YQli?=' },
  },
  {
    id: 'enc-sentinel-literal', rule: 'C3', kind: 'encode',
    description: 'a value that already looks like a sentinel is encoded',
    value: '=?base64?literal?=', type: 'string',
    expect: { header_value: B64_LITERAL },
  },
  {
    id: 'enc-sentinel-prefix-only', rule: 'C3', kind: 'encode',
    description: 'a value with only the opening marker is not a sentinel',
    value: '=?base64?abc', type: 'string',
    expect: { header_value: '=?base64?abc' },
  },
  {
    id: 'enc-sentinel-suffix-only', rule: 'C3', kind: 'encode',
    description: 'a value with only the closing marker is not a sentinel',
    value: 'abc?=', type: 'string',
    expect: { header_value: 'abc?=' },
  },
  {
    id: 'enc-marker-case', rule: 'C3', kind: 'encode',
    description: 'the markers are case-sensitive, so an upper-case marker stays plain',
    value: '=?Base64?SGVsbG8=?=', type: 'string',
    expect: { header_value: '=?Base64?SGVsbG8=?=' },
  },
  {
    id: 'enc-emoji', rule: 'C3', kind: 'encode',
    description: 'an astral non-ASCII character is encoded as its UTF-8 bytes',
    value: '\u{1F680}', type: 'string',
    expect: { header_value: '=?base64?8J+agA==?=' },
  },
  {
    id: 'enc-integer-42', rule: 'C3', kind: 'encode',
    description: 'an integer is decimal without sign or leading zeros',
    value: 42, type: 'integer',
    expect: { header_value: '42' },
  },
  {
    id: 'enc-integer-negative', rule: 'C3', kind: 'encode',
    description: 'a negative integer keeps its minus sign',
    value: -7, type: 'integer',
    expect: { header_value: '-7' },
  },
  {
    id: 'enc-integer-zero', rule: 'C3', kind: 'encode',
    description: 'zero is a single digit',
    value: 0, type: 'integer',
    expect: { header_value: '0' },
  },
  {
    id: 'enc-integer-safe-max', rule: 'C3', kind: 'encode',
    description: 'the safe integer maximum is representable',
    value: 9007199254740991, type: 'integer',
    expect: { header_value: '9007199254740991' },
  },
  {
    id: 'enc-boolean-true', rule: 'C3', kind: 'encode',
    description: 'true is the lowercase word',
    value: true, type: 'boolean',
    expect: { header_value: 'true' },
  },
  {
    id: 'enc-boolean-false', rule: 'C3', kind: 'encode',
    description: 'false is the lowercase word',
    value: false, type: 'boolean',
    expect: { header_value: 'false' },
  },

  // C4: a non-sentinel is plain; a sentinel must be canonical base64 of UTF-8.
  {
    id: 'dec-plain', rule: 'C4', kind: 'decode',
    description: 'a plain value decodes to itself',
    header_value: 'us-west1',
    expect: { ok: true, text: 'us-west1' },
  },
  {
    id: 'dec-plain-empty', rule: 'C4', kind: 'decode',
    description: 'the empty value is plain and decodes to the empty string',
    header_value: '',
    expect: { ok: true, text: '' },
  },
  {
    id: 'dec-sentinel-nonascii', rule: 'C4', kind: 'decode',
    description: 'an encoded non-ASCII text decodes back to it',
    header_value: B64_HELLO_WORLD,
    expect: { ok: true, text: 'Hello, 世界' },
  },
  {
    id: 'dec-sentinel-padded', rule: 'C4', kind: 'decode',
    description: 'encoded edge spaces survive decoding',
    header_value: B64_PADDED,
    expect: { ok: true, text: ' padded ' },
  },
  {
    id: 'dec-sentinel-newline', rule: 'C4', kind: 'decode',
    description: 'an encoded newline decodes back to it',
    header_value: B64_LINE,
    expect: { ok: true, text: 'line1\nline2' },
  },
  {
    id: 'dec-sentinel-literal', rule: 'C4', kind: 'decode',
    description: 'the encoded sentinel-shaped text decodes to that text',
    header_value: B64_LITERAL,
    expect: { ok: true, text: '=?base64?literal?=' },
  },
  {
    id: 'dec-empty-inner', rule: 'C4', kind: 'decode',
    description: 'an empty inner text decodes to the empty string',
    header_value: '=?base64??=',
    expect: { ok: true, text: '' },
  },
  {
    id: 'dec-marker-case', rule: 'C4', kind: 'decode',
    description: 'an upper-case marker is not a sentinel, so the value is plain text',
    header_value: '=?BASE64?SGVsbG8=?=',
    expect: { ok: true, text: '=?BASE64?SGVsbG8=?=' },
  },
  {
    id: 'dec-bad-alphabet', rule: 'C4', kind: 'decode',
    description: 'characters outside the base64 alphabet make the sentinel undecodable',
    header_value: '=?base64?@@@@?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-missing-padding', rule: 'C4', kind: 'decode',
    description: 'an inner text that is not a multiple of four is undecodable',
    header_value: '=?base64?SGVsbG8?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-noncanonical', rule: 'C4', kind: 'decode',
    description: 'non-zero unused trailing bits make the base64 non-canonical',
    header_value: '=?base64?SGVsbG9=?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-space-inside', rule: 'C4', kind: 'decode',
    description: 'a space inside the inner text is outside the base64 alphabet',
    header_value: '=?base64?SGVs bG8=?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-tab-inside', rule: 'C4', kind: 'decode',
    description: 'a HTAB inside the inner text is outside the base64 alphabet',
    header_value: '=?base64?SGVs\tbG8=?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-base64url-alphabet', rule: 'C4', kind: 'decode',
    description: 'the base64url alphabet is not the standard one, so an underscore is undecodable',
    header_value: '=?base64?SGVsbG8_?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-invalid-utf8-byte', rule: 'C4', kind: 'decode',
    description: 'a lone 0xFF byte is not valid UTF-8',
    header_value: '=?base64?' + Buffer.from([0xff]).toString('base64') + '?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-overlong-utf8', rule: 'C4', kind: 'decode',
    description: 'an overlong two-byte form is not valid UTF-8',
    header_value: '=?base64?' + Buffer.from([0xc0, 0x80]).toString('base64') + '?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-utf8-surrogate', rule: 'C4', kind: 'decode',
    description: 'an encoded surrogate is not valid UTF-8',
    header_value: '=?base64?' + Buffer.from([0xed, 0xa0, 0x80]).toString('base64') + '?=',
    expect: { ok: false, reason: 'bad_encoding' },
  },
  {
    id: 'dec-cross-check-plain-sentinel', rule: 'C4', kind: 'decode',
    description: 'the encoded form of the sentinel-shaped plain text decodes back to it',
    header_value: '=?base64?' + Buffer.from('=?base64?literal?=', 'utf8').toString('base64') + '?=',
    expect: { ok: true, text: '=?base64?literal?=' },
  },
];
