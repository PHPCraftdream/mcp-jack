/** Typed MCP tool calls of the jack protocol (spec 03; port of Go client/tools.go). */
import { encodeBase64URL } from "../encoding.js";
import { rotateProofString } from "../signing.js";
import type { Client, JsonValue } from "./rpc.js";
import type { Signer } from "./signer.js";

/** Protocol-native tool names (spec 03). */
export const TOOL_ENROLL = "jack.enroll";
export const TOOL_WHOAMI = "jack.whoami";
export const TOOL_ROTATE_KEY = "jack.key.rotate";
export const TOOL_ADMIN_USER_LIST = "jack.admin.user.list";
export const TOOL_ADMIN_USER_GET = "jack.admin.user.get";
export const TOOL_ADMIN_USER_CREATE = "jack.admin.user.create";
export const TOOL_ADMIN_USER_SET_ADMIN = "jack.admin.user.set_admin";
export const TOOL_ADMIN_USER_REVOKE = "jack.admin.user.revoke";
export const TOOL_ADMIN_INVITE_CREATE = "jack.admin.invite.create";
export const TOOL_ADMIN_INVITE_LIST = "jack.admin.invite.list";
export const TOOL_ADMIN_INVITE_REVOKE = "jack.admin.invite.revoke";

/** One registry key entry (spec 03 sections 3.3). */
export interface Entry {
  kid: string;
  publicKey: string;
  name: string;
  admin: boolean;
  notBefore: number | null;
  notAfter: number | null;
}

/** Describes the calling key (spec 03 section 3.3). */
export interface WhoAmIResult {
  kid: string;
  name: string;
  admin: boolean;
  notBefore: number | null;
  notAfter: number | null;
}

/** Describes the key just enrolled via an invite (spec 03 section 3.2). */
export interface EnrollResult {
  kid: string;
  name: string;
  admin: boolean;
}

/** Reports the kid of the affected registry entry. */
export interface KidResult {
  kid: string;
}

/** Carries a freshly minted invite (spec 03 section 3.2). */
export interface InviteCreateResult {
  inviteId: string;
  code: string;
  expiresAt: number;
}

/** One live invite (spec 03 section 3.3). */
export interface InviteListEntry {
  inviteId: string;
  admin: boolean;
  createdBy: string;
  createdAt: number;
  expiresAt: number;
}

/** Confirms a revoked invite. */
export interface InviteRevokeResult {
  inviteId: string;
}

/** Arguments of jack.admin.user.create. */
export interface UserCreateParams {
  name: string;
  publicKey: string;
  admin?: boolean;
  notBefore?: number;
  notAfter?: number;
}

/** Arguments of jack.admin.invite.create. */
export interface InviteCreateParams {
  admin?: boolean;
  ttlSeconds?: number;
  keyTtlSeconds?: number;
}

/** Decodes a JSON string field, throwing on any other type (mirrors Go's strict unmarshal into string). */
function asString(v: JsonValue | undefined, field: string): string {
  if (typeof v !== "string") {
    throw new Error(`jack client: field ${field} must be a string`);
  }
  return v;
}

/** Decodes a JSON integer field, throwing on non-integers. */
function asInt(v: JsonValue | undefined, field: string): number {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new Error(`jack client: field ${field} must be an integer`);
  }
  return v;
}

/** Decodes a JSON boolean field, throwing on any other type. */
function asBool(v: JsonValue | undefined, field: string): boolean {
  if (typeof v !== "boolean") {
    throw new Error(`jack client: field ${field} must be a boolean`);
  }
  return v;
}

/** Decodes an optional integer field: absent or null -> null, else asInt. */
function nullableInt(v: JsonValue | undefined, field: string): number | null {
  if (v === null || v === undefined) {
    return null;
  }
  return asInt(v, field);
}

/** Decodes the common kid/name/admin/validity entry fields. */
function decodeEntryFields(v: { readonly [key: string]: JsonValue }): { kid: string; name: string; admin: boolean; notBefore: number | null; notAfter: number | null } {
  return {
    kid: asString(v["kid"], "kid"),
    name: asString(v["name"], "name"),
    admin: asBool(v["admin"], "admin"),
    notBefore: nullableInt(v["not_before"], "not_before"),
    notAfter: nullableInt(v["not_after"], "not_after"),
  };
}

/** Enroll enrolls a NEW key with an invite code; the WHOLE request is signed by the new key (spec 03 section 3.2). */
export function enroll(client: Client, code: string, name: string, newSigner: Signer): Promise<EnrollResult> {
  const args = { code, name, public_key: encodeBase64URL(newSigner.publicKey()) };
  return client.callWith(TOOL_ENROLL, args, newSigner).then((v) => {
    const rec = requireRecord(v);
    return {
      kid: asString(rec["kid"], "kid"),
      name: asString(rec["name"], "name"),
      admin: asBool(rec["admin"], "admin"),
    };
  });
}

/** WhoAmI asks the server to describe the calling key. */
export function whoAmI(client: Client): Promise<WhoAmIResult> {
  return client.callTool(TOOL_WHOAMI).then((v) => {
    const rec = requireRecord(v);
    return { ...decodeEntryFields(rec) };
  });
}

/**
 * RotateKey rotates from the client's current key to newSigner: the new key
 * signs the rotate proof, the CURRENT key signs the request, and the proof ts
 * must equal the header ts, so the signing clock is pinned (spec 03 section 3.1).
 */
export function rotateKey(client: Client, newSigner: Signer): Promise<KidResult> {
  const now = client.clock();
  const proof = newSigner.sign(new TextEncoder().encode(rotateProofString(client.aud, client.signer.kid(), newSigner.kid(), now)));
  const args = { public_key: encodeBase64URL(newSigner.publicKey()), proof: encodeBase64URL(proof) };
  return client.callWith(TOOL_ROTATE_KEY, args, client.signer, now).then((v) => {
    const rec = requireRecord(v);
    return { kid: asString(rec["kid"], "kid") };
  });
}

/** AdminUserList lists all registry entries. */
export function adminUserList(client: Client): Promise<Entry[]> {
  return client.callTool(TOOL_ADMIN_USER_LIST).then((v) => {
    const rec = requireRecord(v);
    return decodeUserList(rec["users"]);
  });
}

/** AdminUserGet returns one registry entry by kid. */
export function adminUserGet(client: Client, kid: string): Promise<Entry> {
  return client.callWith(TOOL_ADMIN_USER_GET, { kid }, client.signer).then(decodeEntryResult);
}

/** AdminUserCreate registers a key directly as an admin operation. */
export function adminUserCreate(client: Client, params: UserCreateParams): Promise<KidResult> {
  // One literal, field order matching the Go struct byte for byte; admin is
  // omitted when unset (Go omitempty), validity bounds when absent.
  const args = {
    name: params.name,
    public_key: params.publicKey,
    ...(params.admin !== undefined ? { admin: params.admin } : {}),
    ...(params.notBefore !== undefined ? { not_before: params.notBefore } : {}),
    ...(params.notAfter !== undefined ? { not_after: params.notAfter } : {}),
  };
  return client.callWith(TOOL_ADMIN_USER_CREATE, args, client.signer).then((v) => {
    const rec = requireRecord(v);
    return { kid: asString(rec["kid"], "kid") };
  });
}

/** AdminUserSetAdmin replaces one entry's admin flag. */
export function adminUserSetAdmin(client: Client, kid: string, admin: boolean): Promise<Entry> {
  return client.callWith(TOOL_ADMIN_USER_SET_ADMIN, { kid, admin }, client.signer).then(decodeEntryResult);
}

/** AdminUserRevoke revokes one registry entry. */
export function adminUserRevoke(client: Client, kid: string): Promise<KidResult> {
  return client.callWith(TOOL_ADMIN_USER_REVOKE, { kid }, client.signer).then((v) => {
    const rec = requireRecord(v);
    return { kid: asString(rec["kid"], "kid") };
  });
}

/** AdminInviteCreate mints an invite. */
export function adminInviteCreate(client: Client, params: InviteCreateParams): Promise<InviteCreateResult> {
  const args = {
    ...(params.admin !== undefined ? { admin: params.admin } : {}),
    ...(params.ttlSeconds !== undefined ? { ttl_seconds: params.ttlSeconds } : {}),
    ...(params.keyTtlSeconds !== undefined ? { key_ttl_seconds: params.keyTtlSeconds } : {}),
  };
  return client.callWith(TOOL_ADMIN_INVITE_CREATE, args, client.signer).then((v) => {
    const rec = requireRecord(v);
    return {
      inviteId: asString(rec["invite_id"], "invite_id"),
      code: asString(rec["code"], "code"),
      expiresAt: asInt(rec["expires_at"], "expires_at"),
    };
  });
}

/** AdminInviteList lists all invites. */
export function adminInviteList(client: Client): Promise<InviteListEntry[]> {
  return client.callTool(TOOL_ADMIN_INVITE_LIST).then((v) => {
    const rec = requireRecord(v);
    const invites = rec["invites"];
    if (!Array.isArray(invites)) {
      throw new Error("jack client: field invites must be an array");
    }
    return invites.map((item) => {
      const rec2 = requireRecord(item);
      return {
        inviteId: asString(rec2["invite_id"], "invite_id"),
        admin: asBool(rec2["admin"], "admin"),
        createdBy: asString(rec2["created_by"], "created_by"),
        createdAt: asInt(rec2["created_at"], "created_at"),
        expiresAt: asInt(rec2["expires_at"], "expires_at"),
      };
    });
  });
}

/** AdminInviteRevoke revokes one invite. */
export function adminInviteRevoke(client: Client, inviteId: string): Promise<InviteRevokeResult> {
  return client.callWith(TOOL_ADMIN_INVITE_REVOKE, { invite_id: inviteId }, client.signer).then((v) => {
    const rec = requireRecord(v);
    return { inviteId: asString(rec["invite_id"], "invite_id") };
  });
}

/** Narrows structuredContent to a JSON object. */
function requireRecord(v: JsonValue): { readonly [key: string]: JsonValue } {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new Error("jack client: structuredContent must be a JSON object");
  }
  return v;
}

/** Decodes a single registry-entry structuredContent. */
function decodeEntryResult(v: JsonValue): Entry {
  const rec = requireRecord(v);
  return { ...decodeEntryFields(rec), publicKey: asString(rec["public_key"], "public_key") };
}

/** Decodes the {"users":[...]} envelope (Go userListWrapper). */
function decodeUserList(v: JsonValue | undefined): Entry[] {
  if (!Array.isArray(v)) {
    throw new Error("jack client: field users must be an array");
  }
  return v.map(decodeEntryResult);
}
