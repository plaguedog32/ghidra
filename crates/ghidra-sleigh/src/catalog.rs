//! Catalog recipes are applied only to the selected code address space.
use std::collections::BTreeMap;

use ghidra_languages::{LanguageDefinition, ProcessorSpec, ResolvedValue, Severity};
use ghidra_pcode::SpaceKind;
use sleigh::ContextDatabase;

use crate::{Error, SleighLanguage, guard};

pub(super) struct CatalogContext {
    processor: ProcessorSpec,
    code_space: String,
    pub(super) overrides: BTreeMap<String, u64>,
}

impl CatalogContext {
    pub(super) fn at(&self, address: u64) -> Result<BTreeMap<String, u64>, Error> {
        narrow(self.processor.context_at(&self.code_space, address))
    }
}

fn narrow(values: Vec<ResolvedValue>) -> Result<BTreeMap<String, u64>, Error> {
    values
        .into_iter()
        .map(|value| {
            let integer = u64::try_from(value.value).map_err(|_| {
                Error::Context(format!(
                    "{} exceeds the decoder's 64-bit context values",
                    value.name
                ))
            })?;
            Ok((value.name, integer))
        })
        .collect()
}

impl SleighLanguage {
    /// Compile a catalog language and apply its processor decoding context.
    ///
    /// Tracked register initialization and compiler ABI definitions are not
    /// decoding context and are not applied here. Explicit overrides win over
    /// processor defaults, while recorded SLEIGH `globalset` effects retain
    /// their normal precedence at an address.
    pub fn from_language(
        definition: &LanguageDefinition,
        overrides: &BTreeMap<String, u64>,
    ) -> Result<Self, Error> {
        if !definition.truncated_spaces.is_empty() {
            return Err(Error::Unsupported(format!(
                "language {} truncates address spaces; source lowering does not yet model this",
                definition.id
            )));
        }
        let source = definition.source.available_path().ok_or_else(|| {
            Error::Source(format!(
                "language {} has no available SLEIGH source",
                definition.id
            ))
        })?;
        let processor = definition
            .load_processor_spec()
            .map_err(|e| Error::Context(e.to_string()))?;
        if let Some(diagnostic) = processor
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity >= Severity::Warning)
        {
            return Err(Error::Context(format!(
                "processor specification has unresolved diagnostics: {diagnostic}"
            )));
        }
        let mut language = Self::from_spec(source, &BTreeMap::new())?;
        if language.instruction_endianness != definition.instruction_endian {
            return Err(Error::Unsupported(format!(
                "language {} declares {:?} instruction byte order, source declares {:?}",
                definition.id, definition.instruction_endian, language.instruction_endianness
            )));
        }
        let code_space = language
            .spaces
            .iter()
            .find(|space| space.id == language.code_space)
            .expect("validated default space")
            .name
            .clone();
        let mut globals = narrow(processor.context_globals(&code_space))?;
        globals.extend(overrides.clone());
        guard(|| {
            let mut bytes = language.spec.new_context();
            for (name, value) in &globals {
                let field = language
                    .spec
                    .field(name)
                    .ok_or_else(|| Error::Context(format!("unknown field {name}")))?;
                language
                    .spec
                    .set_context_field(&mut bytes, field.id, *value)
                    .map_err(|e| Error::Context(format!("{name}: {e}")))?;
            }
            language
                .spec
                .set_context_bytes(bytes)
                .map_err(|e| Error::Context(e.to_string()))?;
            language.context = ContextDatabase::new(&language.spec);
            Ok(())
        })?;
        // Register alias offsets are lowered according to source byte order.
        // Keep that storage layout; only data LOAD/STORE uses the data order.
        for space in &mut language.spaces {
            if space.kind == SpaceKind::Ram {
                space.endianness = definition.endian;
            }
        }
        language.catalog_context = Some(CatalogContext {
            processor,
            code_space,
            overrides: overrides.clone(),
        });
        Ok(language)
    }
}
