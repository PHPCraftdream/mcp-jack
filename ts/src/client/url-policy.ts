/** Client destination-URL policy (spec 01 section 1; docs/design/interop.md section 9; table: spec/fixtures/client-url-policy.json). */
import { DestinationRefusedError } from "./errors.js";

const HOST_CHARS = /^[A-Za-z0-9._-]+$/;
const IPV6_CHARS = /^[0-9A-Fa-f:.]+$/;
const PORT_DIGITS = /^[0-9]{1,5}$/;
const DECIMAL = /^[0-9]+$/;

/** A port after ":" is 1 to 5 ASCII digits with value 1..65535. */
function checkPort(port: string): void {
  if (!PORT_DIGITS.test(port)) {
    throw new DestinationRefusedError("invalid port");
  }
  const n = Number(port);
  if (n < 1 || n > 65535) {
    throw new DestinationRefusedError("port out of range");
  }
}

/** Whether host is canonical dotted-decimal IPv4 in 127.0.0.0/8: four octets 0..255, no leading zeros. */
function isLoopbackIPv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const values: number[] = [];
  for (const part of parts) {
    if (!DECIMAL.test(part) || part.length > 3 || (part.length > 1 && part.startsWith("0"))) {
      return false;
    }
    const n = Number(part);
    if (n > 255) {
      return false;
    }
    values.push(n);
  }
  return values[0] === 127;
}

/**
 * checkDestination applies the client URL policy to the RAW destination
 * string and throws DestinationRefusedError when it is refused. It is a pure
 * function of the string: no URL parser, no DNS, no rewriting.
 *
 * https is accepted for any well-formed host; http only for a literal
 * canonical 127.x.y.z or [::1]. Userinfo, percent escapes in the authority
 * (which also refuses zone IDs), backslashes, whitespace/control/non-ASCII
 * bytes, `localhost` aliases and every non-canonical IP spelling are refused.
 * Path, query and fragment are not inspected beyond the byte rule, so
 * percent-encoded path/query bytes stay accepted and are signed as given.
 */
export function checkDestination(raw: string): void {
  if (typeof raw !== "string" || raw === "") {
    throw new DestinationRefusedError("empty url");
  }
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f || c >= 0x80) {
      throw new DestinationRefusedError("url contains a control, space or non-ASCII byte");
    }
    if (c === 0x5c) {
      throw new DestinationRefusedError("url contains a backslash");
    }
  }
  const m = /^(https?):\/\//i.exec(raw);
  if (m === null) {
    throw new DestinationRefusedError("scheme must be http or https");
  }
  const scheme = (m[1] ?? "").toLowerCase();
  const rest = raw.slice(m[0].length);
  let end = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest.charAt(i);
    if (ch === "/" || ch === "?" || ch === "#") {
      end = i;
      break;
    }
  }
  const authority = rest.slice(0, end);
  if (authority === "") {
    throw new DestinationRefusedError("empty host");
  }
  if (authority.includes("@")) {
    throw new DestinationRefusedError("userinfo is not allowed");
  }
  if (authority.includes("%")) {
    throw new DestinationRefusedError("percent escapes are not allowed in the host");
  }

  let loopback: boolean;
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close < 0 || authority.indexOf("]", close + 1) >= 0) {
      throw new DestinationRefusedError("malformed IPv6 literal");
    }
    const inner = authority.slice(1, close);
    if (inner === "" || !IPV6_CHARS.test(inner)) {
      throw new DestinationRefusedError("malformed IPv6 literal");
    }
    const after = authority.slice(close + 1);
    if (after !== "") {
      if (!after.startsWith(":")) {
        throw new DestinationRefusedError("malformed host");
      }
      checkPort(after.slice(1));
    }
    loopback = inner.toLowerCase() === "::1";
  } else {
    if (authority.includes("[") || authority.includes("]")) {
      throw new DestinationRefusedError("malformed host");
    }
    const colon = authority.indexOf(":");
    let host = authority;
    if (colon >= 0) {
      if (authority.indexOf(":", colon + 1) >= 0) {
        throw new DestinationRefusedError("unbracketed IPv6 literal");
      }
      host = authority.slice(0, colon);
      checkPort(authority.slice(colon + 1));
    }
    if (host === "" || !HOST_CHARS.test(host)) {
      throw new DestinationRefusedError("invalid host");
    }
    loopback = isLoopbackIPv4(host);
  }

  if (scheme === "https") {
    return;
  }
  if (!loopback) {
    throw new DestinationRefusedError("http is only allowed for a literal loopback address (127.x.y.z or [::1]); use https");
  }
}
