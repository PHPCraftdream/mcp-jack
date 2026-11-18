use super::json_object::Object;
use super::{MAX_ORDINAL, MAX_RETAINED_KEYS};
use serde::de::{self, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::fmt;

#[derive(Serialize)]
#[serde(transparent)]
pub(in crate::rotation) struct Unsigned(pub(in crate::rotation) u64);

fn canonical_unsigned<E: de::Error>(raw: &RawValue) -> Result<u64, E> {
    let text = raw.get();
    if text.is_empty()
        || text.len() > 16
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(E::custom("noncanonical unsigned number"));
    }
    let value = text.parse::<u64>().map_err(E::custom)?;
    if value > MAX_ORDINAL {
        return Err(E::custom("unsigned number outside safe domain"));
    }
    Ok(value)
}

impl<'de> Deserialize<'de> for Unsigned {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        canonical_unsigned(&raw).map(Self)
    }
}

// Not an Option field: known_cutoff must be present but allows explicit null.
#[derive(Serialize)]
#[serde(transparent)]
pub(in crate::rotation) struct Cutoff(pub(in crate::rotation) Option<u64>);

impl<'de> Deserialize<'de> for Cutoff {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        if raw.get() == "null" {
            return Ok(Self(None));
        }
        canonical_unsigned(&raw).map(|value| Self(Some(value)))
    }
}

#[derive(Serialize)]
#[serde(transparent)]
pub(in crate::rotation) struct BoundedVec<T, const LIMIT: usize>(pub(in crate::rotation) Vec<T>);

impl<'de, T: Deserialize<'de>, const LIMIT: usize> Deserialize<'de> for BoundedVec<T, LIMIT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Sequence<T, const LIMIT: usize>(Vec<T>);
        impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for Sequence<T, LIMIT> {
            type Value = BoundedVec<T, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of at most {LIMIT} values")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                mut self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                // size_hint does not determine the allocation; an extra element is not kept.
                while self.0.len() < LIMIT {
                    match sequence.next_element::<T>()? {
                        Some(value) => self.0.push(value),
                        None => return Ok(BoundedVec(self.0)),
                    }
                }
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("array capacity exceeded"));
                }
                Ok(BoundedVec(self.0))
            }
        }
        deserializer.deserialize_seq(Sequence::<T, LIMIT>(Vec::new()))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rotation) struct BindingDocument {
    pub(in crate::rotation) endpoint: String,
    pub(in crate::rotation) aud: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rotation) struct CheckpointDocument {
    pub(in crate::rotation) ordinal: Unsigned,
    pub(in crate::rotation) hash: String,
    pub(in crate::rotation) kid: String,
    pub(in crate::rotation) public_key: String,
    pub(in crate::rotation) published_at: Unsigned,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rotation) struct HeadDocument {
    pub(in crate::rotation) ordinal: Unsigned,
    pub(in crate::rotation) hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rotation) struct KeyDocument {
    pub(in crate::rotation) ordinal: Unsigned,
    pub(in crate::rotation) kid: String,
    pub(in crate::rotation) public_key: String,
    pub(in crate::rotation) not_before: Unsigned,
    pub(in crate::rotation) known_cutoff: Cutoff,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rotation) struct ClockDocument {
    pub(in crate::rotation) binding: Object<BindingDocument>,
    pub(in crate::rotation) window: Unsigned,
    pub(in crate::rotation) high_water: Unsigned,
    pub(in crate::rotation) clock_revision: Unsigned,
    #[serde(rename = "unsafe")]
    pub(in crate::rotation) unsafe_clock: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rotation) struct TrustDocument {
    pub(in crate::rotation) format_version: Unsigned,
    pub(in crate::rotation) binding: Object<BindingDocument>,
    pub(in crate::rotation) window: Unsigned,
    pub(in crate::rotation) checkpoint: Object<CheckpointDocument>,
    pub(in crate::rotation) head: Object<HeadDocument>,
    pub(in crate::rotation) records: BoundedVec<String, { MAX_RETAINED_KEYS - 1 }>,
    pub(in crate::rotation) keys: BoundedVec<Object<KeyDocument>, MAX_RETAINED_KEYS>,
    pub(in crate::rotation) trust_revision: Unsigned,
    pub(in crate::rotation) fenced: bool,
    pub(in crate::rotation) clock: Object<ClockDocument>,
}

#[cfg(test)]
mod tests {
    use super::BoundedVec;

    #[test]
    fn bounded_sequence_accepts_limit_without_decoding_an_extra_owned_element() {
        let positive =
            serde_json::from_str::<BoundedVec<u8, 2>>("[1,2]").expect("inclusive array limit");
        assert_eq!(positive.0, [1, 2]);
        let failure = serde_json::from_str::<BoundedVec<u8, 2>>("[1,2,\"not a byte\"]")
            .err()
            .expect("excess array refused");
        assert!(failure.to_string().contains("array capacity exceeded"));
    }
}
