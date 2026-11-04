//! Portable processor identities. Source paths belong to local asset catalogs,
//! never to a project file that may have come from another machine.
use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, Visitor},
};

use crate::ProjectError;

pub const MAX_LANGUAGE_ID_BYTES: usize = 512;
pub const MAX_COMPILER_ID_BYTES: usize = 256;
pub const MAX_CONTEXT_FIELDS: usize = 256;
pub const MAX_CONTEXT_NAME_BYTES: usize = 256;
/// Enough characters to display every valid context map as decimal name=value.
pub const MAX_CONTEXT_TEXT_CHARS: usize = MAX_CONTEXT_FIELDS * (MAX_CONTEXT_NAME_BYTES + 22);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanguageIdentity {
    pub id: String,
    pub major: u32,
    pub minor: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessorConfiguration {
    pub language: LanguageIdentity,
    /// Reserved for an explicit ABI choice, not inferred during decoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_id: Option<String>,
    #[serde(deserialize_with = "deserialize_context")]
    pub context: BTreeMap<String, u64>,
}

impl ProcessorConfiguration {
    /// Structural validation; resolving IDs/fields against assets is the
    /// consumer's responsibility. Unknown IDs can be preserved without assets.
    pub fn validate(&self) -> Result<(), ProjectError> {
        let invalid = |message: &str| ProjectError::InvalidMetadata(message.to_owned());
        if self.language.id.trim().is_empty()
            || self.language.id.len() > MAX_LANGUAGE_ID_BYTES
            || self.language.id.chars().any(char::is_control)
        {
            return Err(invalid(
                "processor language ID is empty, too long, or contains control characters",
            ));
        }
        if let Some(id) = &self.compiler_id
            && (id.trim().is_empty()
                || id.len() > MAX_COMPILER_ID_BYTES
                || id.chars().any(char::is_control))
        {
            return Err(invalid(
                "compiler ID is empty, too long, or contains control characters",
            ));
        }
        if self.context.len() > MAX_CONTEXT_FIELDS {
            return Err(invalid("more than 256 processor context fields"));
        }
        for name in self.context.keys() {
            if name.is_empty()
                || name.len() > MAX_CONTEXT_NAME_BYTES
                || name
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == '=' || c == ',')
            {
                return Err(invalid(
                    "processor context field names must be nonempty, at most 256 UTF-8 bytes, and contain no whitespace, control characters, '=' or ','",
                ));
            }
        }
        Ok(())
    }
}

fn deserialize_context<'de, D>(deserializer: D) -> Result<BTreeMap<String, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ContextVisitor;
    impl<'de> Visitor<'de> for ContextVisitor {
        type Value = BTreeMap<String, u64>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 256 unique processor context fields with u64 values")
        }
        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            if access
                .size_hint()
                .is_some_and(|size| size > MAX_CONTEXT_FIELDS)
            {
                return Err(de::Error::custom("more than 256 processor context fields"));
            }
            let mut fields = BTreeMap::new();
            while let Some(name) = access.next_key::<String>()? {
                if fields.len() == MAX_CONTEXT_FIELDS {
                    return Err(de::Error::custom("more than 256 processor context fields"));
                }
                let value = access.next_value::<u64>()?;
                if fields.insert(name, value).is_some() {
                    return Err(de::Error::custom("duplicate processor context field"));
                }
            }
            Ok(fields)
        }
    }
    deserializer.deserialize_map(ContextVisitor)
}
