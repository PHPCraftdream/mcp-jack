/**
 * Server signer of signed streams (spec 05 sections 2.5, 2.15, 2.16 and 3.1).
 *
 * One key signs the open header (2.5) and every frame (2.15), so `kid` is taken
 * from that key once and never changes (3.1). The end frame (2.16) is an
 * ordinary frame with the empty data value. `seq` starts at 0 and `prev` starts
 * at the open signature, so the frames form one hash chain rooted in the open
 * header; both live in private fields, so a caller cannot break the chain.
 *
 * Every signature a caller-supplied key callback returns is re-verified against
 * that key before it is used, mirroring `writeAuthorized` in
 * `src/server/http/fetch.ts`: a provider callback is never trusted.
 */
import { BadBase64UrlError, decodeBase64URLFixed, encodeBase64URL, keyId } from "../core/encoding.js";
import { validatePublicKey, verify } from "../core/ed25519.js";
import type { StreamClientCode } from "./codes.js";
import { STREAM_SIGNAL_CODES } from "./codes.js";
import {
  formatStreamOpenAuth,
  serializeStreamFrame,
  STREAM_SIGNAL_METHOD,
  streamDataHash,
  streamFrameSigningString,
  streamOpenSigningString,
} from "./wire.js";

const ENCODER = new TextEncoder();

// 2.2: a canonical ts is unsigned decimal of at most 12 digits.
const MAX_TS = 999999999999;
// 2.18: the signalled limit is at most 2^53 - 1.
const LIMIT_MAX = 9007199254740991;
// 2.18: the template up to the code, then the canonical limit.
const SIGNAL_PREFIX = '{"jsonrpc":"2.0","method":"' + STREAM_SIGNAL_METHOD + '","params":{"code":"';
const SIGNAL_LIMIT = '","limit":';
const SIGNAL_SUFFIX = "}}";

/**
 * The signing half of a stream key. Structurally satisfied by the client
 * `InMemorySigner` and by a pinned rotation signer; `sign` returns the 64-byte
 * Ed25519 signature of the message bytes and `publicKey` the raw 32-byte key.
 */
export interface StreamSigningKey {
  readonly sign: (message: Uint8Array) => Uint8Array;
  readonly publicKey: () => Uint8Array;
}

/** Everything one signed stream needs besides the frames themselves (2.4, 2.5, 2.1). */
export interface StreamSignerOptions {
  readonly key: StreamSigningKey;
  /** The `sig` parameter of the v1 request that opened the stream (2.5). */
  readonly requestSig: string;
  /** 16 random bytes as canonical unpadded base64url (2.4). */
  readonly sid: string;
  /** Unix seconds for the open header. */
  readonly openerTs: number;
  /** Response status; only 200 opens a stream (2.1). */
  readonly status?: number;
}

/** One signed frame: the 2.15 chain inputs, the signature and the exact 2.6 wire bytes. */
export interface SignedStreamFrame {
  readonly seq: number;
  readonly ts: number;
  readonly sig: string;
  /** The chained predecessor: the open sig for seq 0, else the previous frame's sig. */
  readonly prev: string;
  readonly dataHash: string;
  readonly signingString: string;
  /** The exact 2.6 wire bytes including the terminating blank line. */
  readonly bytes: Uint8Array;
}

/** Signs the open header and every frame of one stream, chained (spec 05 sections 2.5, 2.15, 2.16, 3.1). */
export class StreamSigner {
  private readonly key: StreamSigningKey;
  private readonly pub: Uint8Array;
  private readonly streamKid: string;
  private readonly streamSid: string;
  private readonly openTs: number;
  private readonly openSigning: string;
  private readonly openSig: string;
  private nextSeq = 0;
  private prev: string;

  /**
   * Validates the key, `sid`, `openerTs` and `status` up front, then signs the
   * open signing string so `openAuthValue()` and the chain root are fixed.
   */
  constructor(options: StreamSignerOptions) {
    const key = options.key;
    if (key === undefined || key === null) {
      throw new Error("server: StreamSignerOptions.key must be set");
    }
    const publicKey = key.publicKey();
    // Length, canonical form, curve membership and the prime-order subgroup (01 section 2).
    if (!(publicKey instanceof Uint8Array) || validatePublicKey(publicKey) !== null) {
      throw new Error("server: stream signing key must be a valid 32-byte Ed25519 public key");
    }
    try {
      decodeBase64URLFixed(options.sid, 16);
    } catch (err) {
      if (err instanceof BadBase64UrlError) {
        throw new Error("server: stream sid must be 16 bytes of canonical unpadded base64url");
      }
      throw err;
    }
    if (!isCanonicalTs(options.openerTs)) {
      throw new Error("server: stream opener ts must be canonical unix seconds with at most 12 digits");
    }
    const status = options.status ?? 200;
    if (status !== 200) {
      throw new Error("server: a signed stream response must have status 200");
    }
    this.key = key;
    this.pub = publicKey;
    this.streamKid = keyId(publicKey);
    this.streamSid = options.sid;
    this.openTs = options.openerTs;
    this.openSigning = streamOpenSigningString({
      status,
      requestSig: options.requestSig,
      kid: this.streamKid,
      ts: options.openerTs,
      sid: options.sid,
    });
    this.openSig = this.signMessage(this.openSigning);
    this.prev = this.openSig;
  }

  /** `keyId(key.publicKey())`: the one kid the open header and every frame are bound to (3.1). */
  get kid(): string {
    return this.streamKid;
  }

  /** The stream identifier the open header carries (2.4). */
  get sid(): string {
    return this.streamSid;
  }

  /** The next seq to sign; starts at 0 and grows by one per frame (2.15). */
  get seq(): number {
    return this.nextSeq;
  }

  /** The six-line open signing string of 2.5. */
  openSigningString(): string {
    return this.openSigning;
  }

  /** The 2.1 `Jack-Auth` open value, carrying the open signature. */
  openAuthValue(): string {
    return formatStreamOpenAuth({ kid: this.streamKid, ts: this.openTs, sid: this.streamSid, sig: this.openSig });
  }

  /** Signs one `message` frame; the data value must be non-empty (2.9). */
  frame(data: string, ts: number): SignedStreamFrame {
    if (data === "") {
      throw new Error("server: a stream message frame must have a non-empty data value");
    }
    // 2.10: a raw CR would become a line terminator on the client.
    if (data.includes("\r")) {
      throw new Error("server: a stream data value must not contain a raw CR");
    }
    checkTs(ts);
    return this.signFrame("message", data, ts);
  }

  /** Signs the 2.18 transport signal with a canonical limit. */
  signal(code: StreamClientCode, limit: number, ts: number): SignedStreamFrame {
    if (!STREAM_SIGNAL_CODES.includes(code)) {
      throw new Error("server: the code is not a signalled stream code");
    }
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > LIMIT_MAX) {
      throw new Error("server: a stream signal limit must be a safe integer in 0..9007199254740991");
    }
    checkTs(ts);
    const data = SIGNAL_PREFIX + code + SIGNAL_LIMIT + String(limit) + SIGNAL_SUFFIX;
    return this.signFrame("message", data, ts);
  }

  /** Signs the 2.16 end frame: empty data, its own seq and ts, chained over the previous sig. */
  end(ts: number): SignedStreamFrame {
    checkTs(ts);
    return this.signFrame("jack-end", "", ts);
  }

  /** Signs one message over the exact bytes and re-verifies it against the pinned key. */
  private signMessage(message: string): string {
    const bytes = ENCODER.encode(message);
    const supplied = this.key.sign(bytes);
    // Provider callback output is never trusted: length plus an independent verification.
    if (!(supplied instanceof Uint8Array) || supplied.length !== 64 || !verify(this.pub, bytes, supplied)) {
      throw new Error("server: stream signer returned an invalid signature");
    }
    return encodeBase64URL(supplied);
  }

  /** Builds, signs, chains and serializes one frame; the chain state advances only on success. */
  private signFrame(kind: "message" | "jack-end", data: string, ts: number): SignedStreamFrame {
    const seq = this.nextSeq;
    const prev = this.prev;
    const dataHash = streamDataHash(data);
    const signingString = streamFrameSigningString({ sid: this.streamSid, seq, ts, prev, dataHash });
    const sig = this.signMessage(signingString);
    const bytes = serializeStreamFrame({ kind, data, seq, ts, sig });
    this.nextSeq = seq + 1;
    this.prev = sig;
    return { seq, ts, sig, prev, dataHash, signingString, bytes };
  }
}

/** 2.2: canonical unsigned decimal of at most 12 digits, for both the open header and every frame. */
function isCanonicalTs(ts: number): boolean {
  return Number.isSafeInteger(ts) && ts >= 0 && ts <= MAX_TS;
}

/** Refuses a frame the client would reject under 2.2/2.7 rather than put it on the wire. */
function checkTs(ts: number): void {
  if (!isCanonicalTs(ts)) {
    throw new Error("server: a stream frame ts must be canonical unix seconds with at most 12 digits");
  }
}
