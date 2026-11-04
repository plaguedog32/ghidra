//! Address-keyed store for context values an instruction stream commits.

use std::collections::{BTreeMap, HashMap};

use crate::{
    bitrange::BitRange,
    objects::field::{FieldId, FieldParent},
    runtime::{
        CompiledSpec, ContextBytes, Instruction, effects::ContextScope, walker::update_context,
    },
};

/// What the database needs to know about a context field to write it back.
struct ContextFieldInfo {
    range: BitRange,
    noflow: bool,
}

/// Accumulates [`ContextEffect`](crate::ContextEffect)s and answers "what context decodes the
/// instruction at this address?".
///
/// [`crate::Decoder::decode_one`] is pure: it takes a context and never changes
/// it. A `globalset` therefore has nowhere to write to, and its effect is
/// reported instead. Feeding those effects back is a policy decision — a linear
/// sweep, a recursive-descent disassembler and a caching UI all want something
/// different — so this database is opt-in, and callers with their own context
/// tracking can ignore it.
///
/// Only `globalset` commits land here. A plain assignment in a disassembly
/// action block never leaves its own decode, so it produces no effect and this
/// database never sees it.
///
/// ```no_run
/// # use sleigh::{ContextDatabase, Decoder, CompiledSpec};
/// # fn run(spec: &CompiledSpec, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// let decoder = Decoder::new(spec);
/// let mut db = ContextDatabase::new(spec);
///
/// let mut addr = 0x1000;
/// while (addr as usize) < bytes.len() {
///     let insn = decoder.decode_one(addr, &bytes[addr as usize..], &db.context_at(addr))?;
///     db.apply(&insn);
///     addr = insn.next_address();
/// }
/// # Ok(())
/// # }
/// ```
///
/// Effects are keyed by [`FieldId`], so a database built from one
/// [`CompiledSpec`] must only be fed instructions decoded with that same spec.
pub struct ContextDatabase {
    /// The specification's default context, the baseline every answer starts from.
    default_bytes: Vec<u8>,

    fields: HashMap<FieldId, ContextFieldInfo>,

    /// Per field, the value committed at each address, applying from that
    /// address until the next entry. Ordered so a lookup is a range query.
    flowing: BTreeMap<FieldId, BTreeMap<u64, u64>>,

    /// Per field, values committed for one address only — a `globalset` of a
    /// `noflow` variable.
    points: BTreeMap<FieldId, HashMap<u64, u64>>,
}

impl ContextDatabase {
    /// Creates an empty database over `spec`'s default context.
    ///
    /// Every address answers with the default context until effects are
    /// applied.
    pub fn new(spec: &CompiledSpec) -> Self {
        let fields = spec
            .spec()
            .fields
            .iter()
            .filter(|field| field.parent == FieldParent::Context)
            .map(|field| {
                (
                    field.id,
                    ContextFieldInfo {
                        range: field.range.clone(),
                        noflow: field.noflow,
                    },
                )
            })
            .collect();

        Self {
            default_bytes: spec.new_context().as_bytes().to_vec(),
            fields,
            flowing: BTreeMap::new(),
            points: BTreeMap::new(),
        }
    }

    /// Replaces the baseline context every answer starts from.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidLength`] if the buffer is not this
    /// specification's context length.
    ///
    /// [`ContextError::InvalidLength`]: crate::ContextError::InvalidLength
    pub fn set_default_context(
        &mut self,
        context: ContextBytes,
    ) -> Result<(), crate::ContextError> {
        if context.len() != self.default_bytes.len() {
            return Err(crate::ContextError::InvalidLength {
                expected: self.default_bytes.len(),
                actual: context.len(),
            });
        }
        self.default_bytes = context.as_bytes().to_vec();
        Ok(())
    }

    /// The context to decode the instruction at `addr` with.
    pub fn context_at(&self, addr: u64) -> ContextBytes {
        let mut bytes = self.default_bytes.clone();

        for (field, commits) in &self.flowing {
            // The newest commit at or before `addr` wins; anything committed
            // later has not taken effect yet.
            if let Some((_, &value)) = commits.range(..=addr).next_back() {
                update_context(&mut bytes, &self.fields[field].range, value);
            }
        }

        // Point commits are for exactly one instruction, and override a flowing
        // value at the same address.
        for (field, commits) in &self.points {
            if let Some(&value) = commits.get(&addr) {
                update_context(&mut bytes, &self.fields[field].range, value);
            }
        }

        ContextBytes::from_raw(bytes)
    }

    /// Records everything `instruction` asks to change.
    ///
    /// Every effect names the address it applies at. The *field* decides how
    /// long it lasts: a `noflow` variable applies to that one address, anything
    /// else from that address until a later commit overrides it.
    pub fn apply(&mut self, instruction: &Instruction<'_, '_>) {
        for effect in instruction.context_effects() {
            let Some(info) = self.fields.get(&effect.field) else {
                continue;
            };
            let noflow = info.noflow;
            let ContextScope::At(addr) = effect.scope;

            if noflow {
                self.points
                    .entry(effect.field)
                    .or_default()
                    .insert(addr, effect.value);
            } else {
                self.flowing
                    .entry(effect.field)
                    .or_default()
                    .insert(addr, effect.value);
            }
        }
    }

    /// Forgets every applied effect, keeping the default context.
    pub fn clear(&mut self) {
        self.flowing.clear();
        self.points.clear();
    }
}
