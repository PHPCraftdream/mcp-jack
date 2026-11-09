//! The verified caller identity handed to the wrapped MCP handler
//! (spec 02 section 3).

/// The verified caller identity handed to the wrapped MCP handler (spec 02
/// section 3): exactly `{kid, name, admin}` of the caller's registry entry as
/// of verification time.
///
/// Normative invariants (spec 02 section 3):
/// - SERVER-AUTHENTICATED: derived exclusively from signature verification and
///   the registry — never from request headers, query or body.
/// - IMMUTABLE to consumers: there is NO public constructor and no setter, so
///   a handler can only ever hold identities the verifier built. `Clone`
///   exists so a handler may retain the snapshot beyond the request borrow,
///   but construction is `pub(crate)`.
/// - SNAPSHOT LIFECYCLE: the identity is the registry snapshot at verification
///   time. Registry changes affect only subsequent requests; an in-flight
///   handler keeps its snapshot.
/// - AVAILABILITY: ordinary MCP POST and GET traffic is forwarded to the
///   wrapped handler with this identity as a typed request extension; native
///   `jack.*` calls never reach the wrapped handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    kid: String,
    name: String,
    admin: bool,
}

impl VerifiedIdentity {
    /// Crate-only constructor: consumers cannot fabricate an identity (spec
    /// 02 section 3: no public constructor or setter exists).
    pub(crate) fn new(kid: String, name: String, admin: bool) -> Self {
        Self { kid, name, admin }
    }

    /// Kid of the verified caller.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Name of the verified caller.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Admin flag of the verified caller's registry entry.
    pub fn admin(&self) -> bool {
        self.admin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_return_construction_values() {
        let id = VerifiedIdentity::new("k1".to_owned(), "alice".to_owned(), true);
        assert_eq!(id.kid(), "k1");
        assert_eq!(id.name(), "alice");
        assert!(id.admin());
        // Clone retains the snapshot, but no field is publicly writable and
        // there is no public constructor (spec 02 section 3).
        let copy = id.clone();
        assert_eq!(copy, id);
    }
}
