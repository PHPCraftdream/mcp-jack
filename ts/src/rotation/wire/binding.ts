import type { RotationBinding } from "./record.js";

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Internal scalar/size guard only; does not normalize endpoint or audience. */
export function rotationBindingError(binding: RotationBinding): "binding_size" | "utf8" | undefined {
  for (const [text, maximum] of [[binding.endpoint, 2048], [binding.aud, 1024]] as const) {
    const bytes = Buffer.from(text, "utf8");
    if (bytes.length < 1 || bytes.length > maximum) return "binding_size";
    if (utf8.decode(bytes) !== text) return "utf8";
  }
  return undefined;
}
