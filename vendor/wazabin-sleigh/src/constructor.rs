use crate::{
    action::Action,
    constraint::ConstraintAst,
    objects::{
        field::{FIELD_INST_NEXT2, Field, FieldId, FieldParent},
        table::TableId,
    },
    pattern::{CompiledCombinedPattern, OperandId, OperandType, TokenPattern},
    pmacro::{PCodeMacro, statement::DelaySlotArg},
    source::Span,
};
use jstd::{
    Identifier,
    registry::{Identified, Registry},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, hash_map};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DisplayElement {
    String(String),
    Table(TableId),
    Field(FieldId),
}

#[derive(Debug, Clone)]
pub(crate) enum PatternOrConstraint {
    Pattern(TokenPattern),
    Constraint(ConstraintAst),
}

impl Default for PatternOrConstraint {
    fn default() -> Self {
        PatternOrConstraint::Pattern(Default::default())
    }
}

impl PatternOrConstraint {
    pub(crate) fn unwrap_pattern(&self) -> &TokenPattern {
        let Self::Pattern(pat) = self else {
            panic!("Attempted to unwrap a pattern from a constraint")
        };
        pat
    }

    pub(crate) fn unwrap_constraint(&self) -> &ConstraintAst {
        let Self::Constraint(constraint) = self else {
            panic!("Attempted to unwrap a constraint from a pattern")
        };
        constraint
    }
}

#[derive(Identifier)]
pub(crate) struct ConstructorId(usize);

/// A mutable constructor reference to a [`ConstructorBuilder`] with its id
pub(crate) type ConstructorMutRef<'b> = Identified<ConstructorId, &'b mut ConstructorBuilder>;

/// The central sleigh object
#[derive(Debug, Clone)]
pub(crate) struct ConstructorBuilder {
    /// The minimum size of this constructor in bytes
    pub min_size: usize,

    /// The pattern this constructor matches on
    /// It is a constraint AST before the the entire sleigh has been parsed
    pub pattern: PatternOrConstraint,

    /// The format for this constructor
    pub display_list: Vec<DisplayElement>,

    /// Disassembly time actions
    pub actions: Vec<Action>,

    /// Physical source span for this definition.
    pub src: Span,

    pub(crate) pmacro: PCodeMacro,
}

/// Where a constructor was written, narrowed to the serialized form's
/// fixed-width integers.
///
/// These are offsets into the *physical* file, not into the preprocessed
/// buffer, so the [`FileId`](crate::FileId) has to travel with them — several
/// specification files are larger than the offsets of constructors in others,
/// and without the file the two are indistinguishable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct ConstructorSrc {
    pub(crate) file: crate::Size,
    pub(crate) start: crate::Size,
    pub(crate) end: crate::Size,
}

/// A map of a constructor's few operands or globals, kept as entries in
/// key order and scanned. The decoder looks one up several times per
/// constructor of every decode, and hashing a key costs more than
/// scanning the handful of entries a constructor has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SmallMap<K, V>(Vec<(K, V)>);

impl<K: Ord + Copy, V> SmallMap<K, V> {
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> + '_ {
        self.0.iter().map(|(k, v)| (k, v))
    }
}

impl<K: Ord + Copy, V> From<HashMap<K, V>> for SmallMap<K, V> {
    fn from(map: HashMap<K, V>) -> Self {
        let mut entries: Vec<(K, V)> = map.into_iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        Self(entries)
    }
}

impl<K: Ord + Copy, V> std::ops::Index<&K> for SmallMap<K, V> {
    type Output = V;

    fn index(&self, key: &K) -> &V {
        self.get(key).expect("a key of the map")
    }
}

/// A compiled constructor definition, used at decode time by the Walker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Constructor {
    min_size: crate::Size,
    pub(crate) src: ConstructorSrc,
    pub(crate) token_pattern: TokenPattern,
    pub(crate) runtime_patterns: Vec<CompiledCombinedPattern>,
    pub(crate) display: Vec<DisplayElement>,
    pub(crate) actions: Vec<Action>,
    pub(crate) field_map: SmallMap<FieldId, OperandId>,
    pub(crate) table_map: SmallMap<TableId, OperandId>,
    pub(crate) global_map: SmallMap<FieldId, crate::Size>,
    pub(crate) pmacro: PCodeMacro,

    /// The `delayslot` directive in this constructor's body, hoisted out of the
    /// p-code so the decoder can find it without walking statements.
    pub(crate) delay_slot: Option<DelaySlotArg>,

    /// Does the body read `inst_next2`? Answering it needs a look-ahead decode,
    /// so the decoder only pays for it where a constructor asks.
    pub(crate) uses_inst_next2: bool,
}

impl Constructor {
    pub(crate) fn min_size(&self) -> usize {
        self.min_size as usize
    }

    pub(crate) fn global_index(&self, field: FieldId) -> usize {
        self.global_map[&field] as usize
    }

    pub(crate) fn try_global_index(&self, field: FieldId) -> Option<usize> {
        self.global_map.get(&field).map(|&idx| idx as usize)
    }

    pub(crate) fn global_pairs(&self) -> impl Iterator<Item = (FieldId, usize)> + '_ {
        self.global_map
            .iter()
            .map(|(&field_id, &idx)| (field_id, idx as usize))
    }
}

impl Constructor {
    pub(crate) fn from_builder(
        fields: &Registry<FieldId, Field>,
        builder: ConstructorBuilder,
    ) -> Self {
        let PatternOrConstraint::Pattern(mut token_pattern) = builder.pattern else {
            unreachable!();
        };

        let mut field_map = HashMap::new();
        let mut table_map = HashMap::new();
        let mut global_map = HashMap::new();

        for (id, op) in token_pattern.operands.iter().enumerate() {
            match op.ty {
                OperandType::Field(field_id) => {
                    field_map.insert(field_id, id as OperandId);
                }
                OperandType::Table(table_id) => {
                    table_map.insert(table_id, id as OperandId);
                }
                _ => (),
            }
        }

        for id in builder.actions.iter().flat_map(|action| action.fields()) {
            let field = &fields[id];
            match field.parent {
                FieldParent::Token(_) => {
                    if let hash_map::Entry::Vacant(e) = field_map.entry(id) {
                        let operand_id = token_pattern.operands.len();
                        token_pattern = token_pattern.with_operand(OperandType::Field(id));
                        e.insert(operand_id as OperandId);
                    }
                }
                FieldParent::Context => (),
                FieldParent::Global => {
                    // Two actions may name the same global — `[ reloc = ...;
                    // globalset(inst_next, X); ]` mentions `inst_next` twice
                    // once the assignment reads it. A plain `insert` would then
                    // hand the field an index equal to the *unchanged* map
                    // length, one past the end of the value vector the walker
                    // sizes from that length.
                    let next = global_map.len() as crate::Size;
                    global_map.entry(id).or_insert(next);
                }
            }
        }

        let runtime_patterns = token_pattern
            .combined_patterns()
            .map(|pattern| pattern.compile_matcher())
            .collect();

        Self {
            src: ConstructorSrc {
                file: builder.src.file.index() as crate::Size,
                start: builder.src.start.0 as crate::Size,
                end: builder.src.end.0 as crate::Size,
            },
            delay_slot: builder.pmacro.delay_slot().cloned(),
            uses_inst_next2: builder
                .pmacro
                .references_field(FIELD_INST_NEXT2, &fields[FIELD_INST_NEXT2].name),
            token_pattern,
            runtime_patterns,
            field_map: SmallMap::from(field_map),
            table_map: SmallMap::from(table_map),
            global_map: SmallMap::from(global_map),
            min_size: builder.min_size as crate::Size,
            display: builder.display_list,
            actions: builder.actions,
            pmacro: builder.pmacro,
        }
    }
}
