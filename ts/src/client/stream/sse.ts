/**
 * Re-emission of verified stream messages to an official MCP client (spec 05
 * section 6.1): exactly one `message` event per verified `message` frame, LF
 * line endings, one `data:` line per LF-separated piece of the data value and
 * one blank line. The output carries no `jack:` field, no `jack-end` event, no
 * unverified comment and never a 2.18 transport signal: callers pass verified
 * data values only, so this is a pure byte transformation of signed bytes.
 */

const ENCODER = new TextEncoder();

/**
 * The 6.1 bytes of one verified data value: `event: message`, one
 * `data: <piece>` line per piece (an empty piece is `data:` alone, so "" yields
 * one `data:` line), then the blank line that ends the event.
 */
export function reemitSseMessage(data: string): Uint8Array {
  let out = "event: message\n";
  for (const piece of data.split("\n")) {
    out += piece === "" ? "data:\n" : `data: ${piece}\n`;
  }
  return ENCODER.encode(out + "\n");
}
