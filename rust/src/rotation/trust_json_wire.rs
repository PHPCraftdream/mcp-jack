use super::{MAX_ORDINAL, MAX_RETAINED_KEYS};
use serde::de::{self, value::MapAccessDeserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::fmt;
use std::marker::PhantomData;

// serde struct visitor допускает sequence; persisted objects обязаны быть maps.
#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct Object<T>(pub(super) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Map<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for Map<T> {
            type Value = Object<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(Map::<T>(PhantomData))
    }
}

#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct Unsigned(pub(super) u64);

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

// Не Option field: known_cutoff обязан присутствовать, но допускает explicit null.
#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct Cutoff(pub(super) Option<u64>);

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
pub(super) struct BoundedVec<T, const LIMIT: usize>(pub(super) Vec<T>);

impl<'de, T: Deserialize<'de>, const LIMIT: usize> Deserialize<'de> for BoundedVec<T, LIMIT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Sequence<T, const LIMIT: usize>(Vec<T>);
        impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for Sequence<T, LIMIT> {
            type Value = BoundedVec<T, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of at most {LIMIT} values")
            }

            fn visit_seq<A: SeqAccess<'de>>(mut self, mut sequence: A) -> Result<Self::Value, A::Error> {
                // size_hint не определяет allocation; extra element не сохраняется.
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
pub(super) struct BindingDocument {
    pub(super) endpoint: String,
    pub(super) aud: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointDocument {
    pub(super) ordinal: Unsigned,
    pub(super) hash: String,
    pub(super) kid: String,
    pub(super) public_key: String,
    pub(super) published_at: Unsigned,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeadDocument {
    pub(super) ordinal: Unsigned,
    pub(super) hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyDocument {
    pub(super) ordinal: Unsigned,
    pub(super) kid: String,
    pub(super) public_key: String,
    pub(super) not_before: Unsigned,
    pub(super) known_cutoff: Cutoff,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClockDocument {
    pub(super) binding: Object<BindingDocument>,
    pub(super) window: Unsigned,
    pub(super) high_water: Unsigned,
    pub(super) clock_revision: Unsigned,
    #[serde(rename = "unsafe")]
    pub(super) unsafe_clock: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustDocument {
    pub(super) format_version: Unsigned,
    pub(super) binding: Object<BindingDocument>,
    pub(super) window: Unsigned,
    pub(super) checkpoint: Object<CheckpointDocument>,
    pub(super) head: Object<HeadDocument>,
    pub(super) records: BoundedVec<String, { MAX_RETAINED_KEYS - 1 }>,
    pub(super) keys: BoundedVec<Object<KeyDocument>, MAX_RETAINED_KEYS>,
    pub(super) trust_revision: Unsigned,
    pub(super) fenced: bool,
    pub(super) clock: Object<ClockDocument>,
}

#[cfg(test)]
mod tests {
    use super::BoundedVec;

    #[test]
    fn bounded_sequence_accepts_limit_without_decoding_an_extra_owned_element() {
        let positive = serde_json::from_str::<BoundedVec<u8, 2>>("[1,2]")
            .expect("inclusive array limit");
        assert_eq!(positive.0, [1, 2]);
        let failure = serde_json::from_str::<BoundedVec<u8, 2>>("[1,2,\"not a byte\"]")
            .err().expect("excess array refused");
        assert!(failure.to_string().contains("array capacity exceeded"));
    }
}
