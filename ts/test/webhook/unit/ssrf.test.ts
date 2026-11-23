import assert from "node:assert/strict";
import { test } from "node:test";
import {
  classifyAddress,
  classifyWithRanges,
  formatIPv4,
  formatIPv6,
  parseHost,
} from "../../../src/webhook/ssrf/address.js";
import { HardenedTransport } from "../../../src/webhook/ssrf/client.js";
import type { HardenedDialTarget, HardenedRequest } from "../../../src/webhook/ssrf/client.js";
import { checkDelivery } from "../../../src/webhook/ssrf/delivery.js";
import { cidrContains, IPV4_BLOCKS, IPV6_BLOCKS, parseCidr } from "../../../src/webhook/ssrf/tables.js";
import type { IpBlock, ParsedCidr } from "../../../src/webhook/ssrf/tables.js";

function parseRows(blocks: readonly IpBlock[]) {
  return blocks.map((row) => {
    const range = parseCidr(row.block);
    if (!range.ok) throw new Error(`Invalid table CIDR: ${row.block}`);
    return { ...row, range };
  }).sort((a, b) => b.range.prefix - a.range.prefix);
}

function edgeBytes(range: ParsedCidr): readonly [Uint8Array, Uint8Array] {
  const last = range.bytes.map((byte, index) => {
    const hostBits = Math.max(0, Math.min(8, (index + 1) * 8 - range.prefix));
    return byte | ((1 << hostBits) - 1);
  });
  return [range.bytes, last];
}

test("all registry block edges follow longest-match reachability and chain precedence", () => {
  const ipv4 = parseRows(IPV4_BLOCKS);
  const ipv6 = parseRows(IPV6_BLOCKS);
  for (const table of [ipv4, ipv6]) {
    for (const { block, range } of table) {
      for (const bytes of edgeBytes(range)) {
        const address = range.family === "ipv4" ? formatIPv4(bytes) : formatIPv6(bytes);
        const label = `${block} edge ${address}`;
        const row = table.find(({ range: candidate }) => cidrContains(candidate, address));
        if (row === undefined) throw new Error(`No registry row for ${label}`);

        let reachable = row.reachable;
        let reason = row.name;
        if (range.family === "ipv6") {
          switch (row.name) {
            case "ipv4_mapped":
            case "nat64_well_known": {
              const embedded = formatIPv4(bytes.subarray(12));
              const embeddedRow = ipv4.find(({ range: candidate }) => cidrContains(candidate, embedded));
              reachable = embeddedRow?.reachable ?? true;
              if (embeddedRow !== undefined) reason += `/${embeddedRow.name}`;
              break;
            }
            case "six_to_four":
            case "teredo":
              reachable = false;
              break;
          }
        }
        const expected = { decision: reachable ? "allow" : "reject", reason };
        for (const classify of [classifyAddress, classifyWithRanges]) {
          const actual = classify(address);
          assert.deepEqual({ decision: actual.decision, reason: actual.reason }, expected, `${classify.name}: ${label}`);
        }
      }
    }
  }
});

test("translation, tunneling and special anycast addresses have exact decisions and reasons", () => {
  const cases = [
    ["::ffff:127.0.0.1", "reject", "ipv4_mapped/loopback"],
    ["64:ff9b::10.0.0.1", "reject", "nat64_well_known/private_use"],
    ["2002:7f00:1::", "reject", "six_to_four"],
    ["2001:0:4136:e378::", "reject", "teredo"],
    ["64:ff9b:1::1", "reject", "nat64_local_use"],
    ["192.0.0.9", "allow", "pcp_anycast"],
    ["2620:4f:8000::1", "allow", "as112_direct_delegation"],
  ] as const;
  for (const [address, decision, reason] of cases) {
    const actual = classifyAddress(address);
    assert.deepEqual({ decision: actual.decision, reason: actual.reason }, { decision, reason }, address);
  }
});

test("parseHost refuses noncanonical hosts and accepts the documented literal and name forms", () => {
  for (const host of ["127.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "1.2.3.4.5", "a..b", "hóoks.example.test"]) {
    assert.deepEqual(parseHost(host), { ok: false, reason: "not_a_hostname" }, host);
  }
  assert.deepEqual(parseHost("hooks.example.test."), {
    ok: true, kind: "name", name: "hooks.example.test", normalized: "hooks.example.test",
  });
  assert.deepEqual(parseHost("[::1]"), { ok: true, kind: "ipv6", address: "::1", normalized: "[::1]" });
});

const CALLBACK = "https://hooks.example.test/x";
const PUBLIC_ADDRESS = "93.184.216.34";
const PRIVATE_ADDRESS = "10.0.0.5";
const REQUEST: HardenedRequest = { method: "POST", path: "/x", headers: {} };

test("checkDelivery mirrors the presence of a URL refusal reason", () => {
  assert.deepEqual(checkDelivery({ url: "http://hooks.example.test/x" }), {
    decision: "reject", code: "scheme_not_https",
  });
  assert.deepEqual(checkDelivery({ url: `${CALLBACK}#fragment` }), {
    decision: "reject", code: "invalid_callback_url", reason: "fragment",
  });
});

test("checkDelivery rejects an address that changes during recheck", () => {
  const result = checkDelivery({ url: CALLBACK, answers: [PUBLIC_ADDRESS], recheck: [PRIVATE_ADDRESS] });
  assert.deepEqual(result, { decision: "reject", code: "dns_rebinding", reason: "address_changed" });
});

test("HardenedTransport resolves once and dials only the validated address", async () => {
  const resolved: string[] = [];
  const targets: HardenedDialTarget[] = [];
  const response = { status: 200, headers: {}, body: new Uint8Array() };
  const transport = new HardenedTransport({
    resolver: {
      async resolve(host) {
        resolved.push(host);
        return [resolved.length === 1 ? PUBLIC_ADDRESS : PRIVATE_ADDRESS];
      },
    },
    async dialer(target) {
      targets.push(target);
      return response;
    },
  });
  assert.deepEqual(await transport.request(CALLBACK, REQUEST), { ok: true, response });
  assert.deepEqual(resolved, ["hooks.example.test"]);
  assert.deepEqual(targets.map(({ address }) => address), [PUBLIC_ADDRESS]);
});

test("HardenedTransport never dials a blocked resolver answer", async () => {
  let dials = 0;
  const transport = new HardenedTransport({
    resolver: { async resolve() { return [PRIVATE_ADDRESS]; } },
    async dialer() {
      dials++;
      return { status: 200, headers: {}, body: new Uint8Array() };
    },
  });
  assert.deepEqual(await transport.request(CALLBACK, REQUEST), { ok: false, code: "blocked_address" });
  assert.equal(dials, 0);
});

test("checkDelivery refuses redirects with the status reason", () => {
  const result = checkDelivery({ url: CALLBACK, answers: [PUBLIC_ADDRESS], redirect: 302 });
  assert.deepEqual(result, { decision: "reject", code: "redirect_refused", reason: "status_302" });
});
