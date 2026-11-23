import { test } from "node:test";
import { classifyAddress, parseHost } from "../../../src/webhook/ssrf/address.js";
import { checkDelivery } from "../../../src/webhook/ssrf/delivery.js";
import type { DeliveryCheckInput } from "../../../src/webhook/ssrf/delivery.js";
import { cidrContains, parseCidr } from "../../../src/webhook/ssrf/tables.js";
import { checkCallbackUrl } from "../../../src/webhook/ssrf/url.js";
import { refusal, runCorpus } from "../support/vectors.js";
import type { VectorCase } from "../support/vectors.js";

function run(c: VectorCase): unknown {
  const { input } = c;
  switch (c.kind) {
    case "url": {
      const checked = checkCallbackUrl(input.url);
      if (!checked.ok) return refusal(checked.code, checked.reason);
      const { canonical, host, port, path, query } = checked;
      return { result: "accept", canonical, host, port, path, query };
    }
    case "host": {
      const host = parseHost(input.host);
      return host.ok
        ? { result: "accept", kind: host.kind, normalized: host.normalized }
        : { result: "reject", reason: host.reason };
    }
    case "address": {
      const { decision, reason, family } = classifyAddress(input.address as string);
      const result = decision === "allow" ? "accept" : "reject";
      return family === null ? { result, reason } : { result, reason, family };
    }
    case "delivery": {
      const checked = checkDelivery(input as typeof input & DeliveryCheckInput);
      if (checked.decision !== "allow") return refusal(checked.code, checked.reason);
      const { address, hostHeader, sni } = checked.connect;
      return { result: "accept", address, reason: checked.reason, host_header: hostHeader, sni };
    }
    case "cidr": {
      const range = parseCidr(input.cidr);
      return range.ok
        ? { result: "accept", contains: cidrContains(range, input.address as string) }
        : { result: "reject" };
    }
    default:
      throw new Error(`${c.id}: unknown kind ${c.kind}`);
  }
}

test("ssrf: every case", async () => {
  await runCorpus({ corpus: "ssrf", file: "ssrf-vectors.json", expectedCases: 120, run });
});
