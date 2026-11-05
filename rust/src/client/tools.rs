//! Typed calls for the protocol-native jack.* tools (spec 03 sections
//! 3.1-3.3). Every method assembles the arguments as a struct whose
//! declaration order is the wire order (matching the Go port and the
//! admin-vectors fixtures), signs and verifies via `Client::call_raw`, and
//! decodes the structuredContent into a typed result.

use crate::client::error::ClientError;
use crate::client::rpc::Client;
use crate::client::signer::Signer;
use crate::encoding::encode_b64url;

// Protocol-native tool names (spec 03 sections 3.1-3.3).
pub const TOOL_ENROLL: &str = "jack.enroll";
pub const TOOL_WHOAMI: &str = "jack.whoami";
pub const TOOL_ROTATE_KEY: &str = "jack.key.rotate";
pub const TOOL_ADMIN_USER_LIST: &str = "jack.admin.user.list";
pub const TOOL_ADMIN_USER_GET: &str = "jack.admin.user.get";
pub const TOOL_ADMIN_USER_CREATE: &str = "jack.admin.user.create";
pub const TOOL_ADMIN_USER_SET_SCOPES: &str = "jack.admin.user.set_scopes";
pub const TOOL_ADMIN_USER_REVOKE: &str = "jack.admin.user.revoke";
pub const TOOL_ADMIN_INVITE_CREATE: &str = "jack.admin.invite.create";
pub const TOOL_ADMIN_INVITE_LIST: &str = "jack.admin.invite.list";
pub const TOOL_ADMIN_INVITE_REVOKE: &str = "jack.admin.invite.revoke";

/// One registry key entry (spec 03 section 3.3). Go's nil validity fields map
/// to None; an absent kind maps to "" like Go's zero value.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Entry {
    pub kid: String,
    pub public_key: String,
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub not_before: Option<i64>,
    #[serde(default)]
    pub not_after: Option<i64>,
}

/// Describes the calling key (spec 03 section 3.3).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct WhoAmIResult {
    pub kid: String,
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub not_before: Option<i64>,
    #[serde(default)]
    pub not_after: Option<i64>,
}

/// Describes the key just enrolled via an invite (spec 03 section 3.2).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct EnrollResult {
    pub kid: String,
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Reports the kid of the affected registry entry.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct KidResult {
    pub kid: String,
}

/// Carries a freshly minted invite; the code is returned once (spec 03
/// section 3.2).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct InviteCreateResult {
    pub invite_id: String,
    pub code: String,
    pub expires_at: i64,
}

/// One live invite (spec 03 section 3.3).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct InviteListEntry {
    pub invite_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub kind: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Confirms a revoked invite.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct InviteRevokeResult {
    pub invite_id: String,
}

/// The arguments of jack.admin.user.create. Go's Kind is a string with
/// omitempty (the empty string is dropped from the wire form); the Rust
/// caller passes None for absent, mirroring that.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct UserCreateParams {
    pub name: String,
    pub public_key: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,
}

/// The arguments of jack.admin.invite.create. The ttl bounds are the
/// server's (spec 03 section 3.3).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct InviteCreateParams {
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ttl_seconds: Option<i64>,
}

// Argument structs below: declaration order is wire order (spec 03 sections
// 3.1-3.2; matches the admin-vectors fixtures).

/// Ordered code,name,public_key (spec 03 section 3.2).
#[derive(serde::Serialize)]
struct EnrollArgs {
    code: String,
    name: String,
    public_key: String,
}

/// Ordered public_key,proof (spec 03 section 3.1).
#[derive(serde::Serialize)]
struct RotateArgs {
    public_key: String,
    proof: String,
}

/// One kid argument; Go marshals map[string]string{"kid": ...}, and a
/// one-key struct is byte-identical (used by get and revoke).
#[derive(serde::Serialize)]
struct KidArgs {
    kid: String,
}

/// Go's anonymous struct {kid, scopes}.
#[derive(serde::Serialize)]
struct SetScopesArgs {
    kid: String,
    scopes: Vec<String>,
}

#[derive(serde::Serialize)]
struct InviteRevokeArgs {
    invite_id: String,
}

/// Decodes the {"users":[...]} envelope.
#[derive(serde::Deserialize)]
struct UsersWrapper {
    #[serde(default)]
    users: Vec<Entry>,
}

/// Decodes the {"invites":[...]} envelope.
#[derive(serde::Deserialize)]
struct InvitesWrapper {
    #[serde(default)]
    invites: Vec<InviteListEntry>,
}

fn args_json<T: serde::Serialize>(args: &T) -> Result<String, ClientError> {
    serde_json::to_string(args)
        .map_err(|e| ClientError::Client(format!("jack client: marshal arguments: {e}")))
}

fn decode_out<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, ClientError> {
    serde_json::from_value(v)
        .map_err(|e| ClientError::Client(format!("jack client: decoding structuredContent: {e}")))
}

impl Client {
    /// Enrolls a NEW key with an invite code; the WHOLE request is signed by
    /// the new key (spec 03 section 3.2). Go's nil-signer check is
    /// unrepresentable for `&dyn Signer`.
    pub fn enroll(
        &self,
        code: &str,
        name: &str,
        new_signer: &dyn Signer,
    ) -> Result<EnrollResult, ClientError> {
        let args = EnrollArgs {
            code: code.to_string(),
            name: name.to_string(),
            public_key: encode_b64url(&new_signer.public_key()),
        };
        let out: EnrollResult = decode_out(self.call_raw(
            Some(new_signer),
            None,
            TOOL_ENROLL,
            Some(&args_json(&args)?),
        )?)?;
        Ok(out)
    }

    /// Asks the server to describe the calling key.
    pub fn whoami(&self) -> Result<WhoAmIResult, ClientError> {
        decode_out(self.call_raw(None, None, TOOL_WHOAMI, None)?)
    }

    /// Rotates from the client's current key to `new_signer`: the new key
    /// signs the rotate proof, the CURRENT key signs the request, and the
    /// proof ts must equal the header ts (spec 03 section 3.1), so the clock
    /// is pinned for this one call — the Rust replacement of Go's
    /// withFixedNow + WithRequestSigner context values.
    pub fn rotate_key(&self, new_signer: &dyn Signer) -> Result<KidResult, ClientError> {
        let now = (self.now)();
        let proof_msg = crate::signing::rotate_proof_string(
            &self.aud,
            self.signer.kid(),
            new_signer.kid(),
            now,
        );
        let proof = new_signer
            .sign(proof_msg.as_bytes())
            .map_err(|e| ClientError::Client(format!("jack client: signing rotate proof: {e}")))?;
        let args = RotateArgs {
            public_key: encode_b64url(&new_signer.public_key()),
            proof: encode_b64url(&proof),
        };
        decode_out(self.call_raw(
            Some(self.signer.as_ref()),
            Some(now),
            TOOL_ROTATE_KEY,
            Some(&args_json(&args)?),
        )?)
    }

    /// Lists all registry entries.
    pub fn admin_user_list(&self) -> Result<Vec<Entry>, ClientError> {
        Ok(
            decode_out::<UsersWrapper>(self.call_raw(None, None, TOOL_ADMIN_USER_LIST, None)?)?
                .users,
        )
    }

    /// Returns one registry entry by kid.
    pub fn admin_user_get(&self, kid: &str) -> Result<Entry, ClientError> {
        let args = KidArgs {
            kid: kid.to_string(),
        };
        decode_out(self.call_raw(None, None, TOOL_ADMIN_USER_GET, Some(&args_json(&args)?))?)
    }

    /// Registers a key directly as an admin operation.
    pub fn admin_user_create(&self, params: &UserCreateParams) -> Result<KidResult, ClientError> {
        decode_out(self.call_raw(
            None,
            None,
            TOOL_ADMIN_USER_CREATE,
            Some(&args_json(params)?),
        )?)
    }

    /// Replaces the scopes of one entry.
    pub fn admin_user_set_scopes(
        &self,
        kid: &str,
        scopes: &[String],
    ) -> Result<Entry, ClientError> {
        let args = SetScopesArgs {
            kid: kid.to_string(),
            scopes: scopes.to_vec(),
        };
        decode_out(self.call_raw(
            None,
            None,
            TOOL_ADMIN_USER_SET_SCOPES,
            Some(&args_json(&args)?),
        )?)
    }

    /// Revokes one registry entry.
    pub fn admin_user_revoke(&self, kid: &str) -> Result<KidResult, ClientError> {
        let args = KidArgs {
            kid: kid.to_string(),
        };
        decode_out(self.call_raw(None, None, TOOL_ADMIN_USER_REVOKE, Some(&args_json(&args)?))?)
    }

    /// Mints an invite.
    pub fn admin_invite_create(
        &self,
        params: &InviteCreateParams,
    ) -> Result<InviteCreateResult, ClientError> {
        decode_out(self.call_raw(
            None,
            None,
            TOOL_ADMIN_INVITE_CREATE,
            Some(&args_json(params)?),
        )?)
    }

    /// Lists all invites.
    pub fn admin_invite_list(&self) -> Result<Vec<InviteListEntry>, ClientError> {
        Ok(decode_out::<InvitesWrapper>(self.call_raw(
            None,
            None,
            TOOL_ADMIN_INVITE_LIST,
            None,
        )?)?
        .invites)
    }

    /// Revokes one invite.
    pub fn admin_invite_revoke(&self, invite_id: &str) -> Result<InviteRevokeResult, ClientError> {
        let args = InviteRevokeArgs {
            invite_id: invite_id.to_string(),
        };
        decode_out(self.call_raw(
            None,
            None,
            TOOL_ADMIN_INVITE_REVOKE,
            Some(&args_json(&args)?),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_name_constants() {
        assert_eq!(TOOL_ENROLL, "jack.enroll");
        assert_eq!(TOOL_WHOAMI, "jack.whoami");
        assert_eq!(TOOL_ROTATE_KEY, "jack.key.rotate");
        assert_eq!(TOOL_ADMIN_USER_LIST, "jack.admin.user.list");
        assert_eq!(TOOL_ADMIN_USER_GET, "jack.admin.user.get");
        assert_eq!(TOOL_ADMIN_USER_CREATE, "jack.admin.user.create");
        assert_eq!(TOOL_ADMIN_USER_SET_SCOPES, "jack.admin.user.set_scopes");
        assert_eq!(TOOL_ADMIN_USER_REVOKE, "jack.admin.user.revoke");
        assert_eq!(TOOL_ADMIN_INVITE_CREATE, "jack.admin.invite.create");
        assert_eq!(TOOL_ADMIN_INVITE_LIST, "jack.admin.invite.list");
        assert_eq!(TOOL_ADMIN_INVITE_REVOKE, "jack.admin.invite.revoke");
    }

    #[test]
    fn enroll_and_rotate_args_wire_order() {
        let enroll = EnrollArgs {
            code: "c".to_string(),
            name: "newbie".to_string(),
            public_key: "p".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&enroll).expect("serialize"),
            r#"{"code":"c","name":"newbie","public_key":"p"}"#
        );
        let rotate = RotateArgs {
            public_key: "pk".to_string(),
            proof: "pr".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&rotate).expect("serialize"),
            r#"{"public_key":"pk","proof":"pr"}"#
        );
    }

    #[test]
    fn user_create_params_wire_order() {
        let minimal = UserCreateParams {
            name: "n".to_string(),
            public_key: "p".to_string(),
            scopes: vec!["read".to_string()],
            kind: None,
            not_before: None,
            not_after: None,
        };
        assert_eq!(
            serde_json::to_string(&minimal).expect("serialize"),
            r#"{"name":"n","public_key":"p","scopes":["read"]}"#
        );
        let full = UserCreateParams {
            kind: Some("human".to_string()),
            not_before: Some(1),
            not_after: Some(2),
            ..minimal
        };
        assert_eq!(
            serde_json::to_string(&full).expect("serialize"),
            r#"{"name":"n","public_key":"p","scopes":["read"],"kind":"human","not_before":1,"not_after":2}"#
        );
    }

    #[test]
    fn invite_create_params_wire_order() {
        let minimal = InviteCreateParams {
            scopes: vec!["read".to_string()],
            kind: None,
            ttl_seconds: None,
            key_ttl_seconds: None,
        };
        assert_eq!(
            serde_json::to_string(&minimal).expect("serialize"),
            r#"{"scopes":["read"]}"#
        );
        let full = InviteCreateParams {
            kind: Some("human".to_string()),
            ttl_seconds: Some(60),
            key_ttl_seconds: Some(3600),
            ..minimal
        };
        assert_eq!(
            serde_json::to_string(&full).expect("serialize"),
            r#"{"scopes":["read"],"kind":"human","ttl_seconds":60,"key_ttl_seconds":3600}"#
        );
    }

    // Go also tolerates explicit nulls as no-ops; serde errors on null for
    // String/i64 fields, so only the absent forms are tested here.
    #[test]
    fn entry_decodes_absent_and_null_validity() {
        let absent: Entry =
            serde_json::from_str(r#"{"kid":"k","public_key":"p","name":"n","scopes":["read"]}"#)
                .expect("decode");
        assert_eq!(absent.kind, "");
        assert_eq!(absent.not_before, None);
        assert_eq!(absent.not_after, None);

        let with_expiry: Entry = serde_json::from_str(
            r#"{"kid":"k","public_key":"p","name":"n","scopes":["read"],"not_after":1750000000}"#,
        )
        .expect("decode");
        assert_eq!(with_expiry.not_after, Some(1750000000));
    }
}
