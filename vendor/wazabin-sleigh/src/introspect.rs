//! Read-only views over a compiled specification's *symbolic* structures.
//!
//! [`crate::Decoder`] answers "what does this byte string mean?". This module
//! answers the question a *code generator* asks instead: "what shapes can this
//! specification produce at all?" — the decision tree before any bytes are
//! matched against it, and a constructor's p-code before any operand has a
//! value.
//!
//! Nothing here decodes. Every view borrows the [`CompiledSpec`] it came from
//! and copies nothing large.
//!
//! # Stability
//!
//! **Unstable.** Behind the `unstable-introspect` feature and exempt from this
//! crate's semantic versioning: these are the compiler's own internal
//! representations, and they change whenever it does. The intended consumer is
//! `wazabin-metal`, which compiles a specification to synthesizable HDL.
//!
//! # Example
//!
//! ```
//! # use sleigh::{Compiler, SourceDb};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut sources = SourceDb::new();
//! # let root = sources.add_file("tiny.slaspec", "define endian=little;
//! #     define space ram type=ram_space size=4 default;
//! #     define space register type=register_space size=4;
//! #     define register offset=0 size=4 [ r0 ];
//! #     define token instr(8) op=(0,7);
//! #     :inc is op=1 { r0 = r0 + 1; }");
//! # let spec = Compiler::new(&mut sources).compile(root)?;
//! let view = spec.introspect();
//! let instructions = view.instruction_table();
//! assert_eq!(instructions.constructor_count(), 1);
//!
//! // The constructor's body, with operands still symbolic.
//! let body = instructions.constructor(0).body();
//! assert_eq!(body.len(), 1);
//! # Ok(())
//! # }
//! ```

use crate::{
    action::{Action, Atom, Expr},
    action::{BinOp, GlobalSetAddr, UnOp},
    bitrange::BitRange,
    builder::Endian as InternalEndian,
    constructor::{Constructor, ConstructorId, DisplayElement},
    objects::{
        field::{Field, FieldId, FieldParent as InternalFieldParent, FieldType},
        table::TableId,
    },
    pattern::{CompiledPatternBlock, OperandType},
    pmacro::{PCodeMacro, PMacroId},
    runtime::CompiledSpec,
    source::FileId,
    spec::Spec,
    token::TokenId,
    tree::{Tree, TreeId, TreeNode, TreeNodeId},
};
use pcode_types::{Ast, BitRangeFieldId, DelaySlotArg, Expression, PCodeOpId, RegisterId, SpaceId};

impl CompiledSpec {
    /// Opens a read-only view over this specification's symbolic structures.
    ///
    /// See the [module documentation](self) for what that covers and what it
    /// deliberately does not.
    pub fn introspect(&self) -> SpecView<'_> {
        SpecView { spec: self.inner() }
    }
}

/// Byte order of a token or of the specification as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl From<InternalEndian> for Endian {
    fn from(value: InternalEndian) -> Self {
        match value {
            InternalEndian::Little => Self::Little,
            InternalEndian::Big => Self::Big,
        }
    }
}

/// A read-only view over a compiled specification.
#[derive(Clone, Copy)]
pub struct SpecView<'spec> {
    spec: &'spec Spec,
}

impl<'spec> SpecView<'spec> {
    /// The specification's default address space — where code lives.
    pub fn default_space(&self) -> SpaceId {
        self.spec.default_space
    }

    /// The space raw p-code temporaries are allocated in.
    pub fn unique_space(&self) -> SpaceId {
        self.spec.unique_space
    }

    /// The register holding decode context, if the specification defines one.
    pub fn context_register(&self) -> Option<RegisterId> {
        self.spec.context_reg
    }

    /// The root instruction table, which every decode starts from.
    pub fn instruction_table(&self) -> TableView<'spec> {
        self.table(TableId::from(0))
            .expect("every specification has an instruction table")
    }

    /// The table `id` names, or `None` if the specification has no such table.
    pub fn table(&self, id: TableId) -> Option<TableView<'spec>> {
        let tree_id = TreeId::from(id);
        (usize::from(tree_id) < self.spec.trees.len()).then(|| TableView {
            spec: self.spec,
            id,
            tree: &self.spec.trees[tree_id],
        })
    }

    /// Every constructor table, the instruction table first.
    pub fn tables(&self) -> impl Iterator<Item = TableView<'spec>> + 'spec {
        let spec = self.spec;
        (0..spec.trees.len()).map(move |index| {
            let id = TableId::from(index);
            TableView {
                spec,
                id,
                tree: &spec.trees[TreeId::from(id)],
            }
        })
    }

    /// The field `id` names.
    pub fn field(&self, id: FieldId) -> Option<FieldView<'spec>> {
        (usize::from(id) < self.spec.fields.len()).then(|| FieldView {
            spec: self.spec,
            id,
            field: &self.spec.fields[id],
        })
    }

    /// Every field, in id order.
    pub fn fields(&self) -> impl Iterator<Item = FieldView<'spec>> + 'spec {
        let spec = self.spec;
        (0..spec.fields.len()).map(move |index| {
            let id = FieldId::from(index);
            FieldView {
                spec,
                id,
                field: &spec.fields[id],
            }
        })
    }

    /// The p-code macro `id` names — the target of an unexpanded
    /// [`pcode_types::ExpressionTy::MacroCall`].
    pub fn pcode_macro(&self, id: PMacroId) -> Option<MacroView<'spec>> {
        (usize::from(id) < self.spec.pmacros.len()).then(|| MacroView {
            pmacro: &self.spec.pmacros[id],
        })
    }

    /// The name of a `define pcodeop`.
    pub fn pcode_op_name(&self, id: PCodeOpId) -> Option<&'spec str> {
        (usize::from(id) < self.spec.pcode_ops.len()).then(|| &*self.spec.pcode_ops[id])
    }

    /// The register a `define bitrange` name refers to, and its bit window
    /// within that register as `(start_bit, bit_count)`.
    pub fn bitrange(&self, id: BitRangeFieldId) -> Option<(RegisterId, usize, usize)> {
        (usize::from(id) < self.spec.bitranges.len()).then(|| {
            let field = &self.spec.bitranges[id];
            (field.register, field.offset(), field.size())
        })
    }

    /// Size in bits of the token `id` names.
    pub fn token_size(&self, id: TokenId) -> usize {
        use crate::token::TokenContext;
        self.spec.token_size(id)
    }

    /// Byte order of the token `id` names.
    pub fn token_endian(&self, id: TokenId) -> Endian {
        use crate::token::TokenContext;
        self.spec.token_endian(id).into()
    }

    /// Name of the token `id` names.
    pub fn token_name(&self, id: TokenId) -> &'spec str {
        use crate::token::TokenContext;
        self.spec.token_name(id)
    }
}

/// A read-only view over one constructor table and its decision tree.
#[derive(Clone, Copy)]
pub struct TableView<'spec> {
    spec: &'spec Spec,
    id: TableId,
    tree: &'spec Tree,
}

impl<'spec> TableView<'spec> {
    /// The table's id, which doubles as the id of its decision tree.
    pub fn id(&self) -> TableId {
        self.id
    }

    /// The table's name, as written in the specification.
    pub fn name(&self) -> &'spec str {
        &self.tree.name
    }

    /// How many constructors this table holds.
    pub fn constructor_count(&self) -> usize {
        self.tree.constructors.len()
    }

    /// The constructor at `index` within this table.
    ///
    /// The index is the one [`crate::ConstructorMatch::index`] reports.
    pub fn constructor(&self, index: usize) -> ConstructorView<'spec> {
        ConstructorView {
            spec: self.spec,
            table: self.id,
            index,
            constructor: &self.tree.constructors[ConstructorId::from(index)],
        }
    }

    /// Every constructor, in declaration order.
    pub fn constructors(&self) -> impl Iterator<Item = ConstructorView<'spec>> + 'spec {
        let (spec, table, tree) = (self.spec, self.id, self.tree);
        (0..tree.constructors.len()).map(move |index| ConstructorView {
            spec,
            table,
            index,
            constructor: &tree.constructors[ConstructorId::from(index)],
        })
    }

    /// The node a decode of this table starts at.
    pub fn root(&self) -> NodeId {
        NodeId(self.tree.root_id())
    }

    /// The decision node `id` names.
    pub fn node(&self, id: NodeId) -> DecisionNode<'spec> {
        match self.tree.node(id.0) {
            TreeNode::Node { range, children } => DecisionNode::Branch {
                source: match range {
                    crate::pattern::CombinedRange::Context(_) => BitSource::Context,
                    crate::pattern::CombinedRange::Instruction(_) => BitSource::Instruction,
                },
                bits: BitWindow::from(range.bitrange()),
                children: children.iter().map(|id| id.map(NodeId)).collect(),
            },
            TreeNode::Leaf { constructors } => DecisionNode::Leaf {
                constructors: constructors.iter().map(|&id| usize::from(id)).collect(),
            },
        }
    }

    /// Every decision node id, in id order. Walk from [`root`](Self::root)
    /// instead if you want the tree's shape; this is for sizing a generated
    /// node table.
    pub fn nodes(&self) -> impl Iterator<Item = NodeId> + 'spec {
        self.tree.node_ids().map(NodeId)
    }
}

/// Identifies one node of a table's decision tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(TreeNodeId);

impl NodeId {
    /// The node's index, for use as an array subscript in generated code.
    pub fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// Which bits a decision node or pattern tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BitSource {
    /// Bits of the instruction byte stream, LSB-numbered from its first byte.
    Instruction,
    /// Bits of the decode context register.
    Context,
}

/// An inclusive run of bits, LSB-numbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitWindow {
    /// Index of the lowest bit in the run.
    pub start: usize,
    /// Index of the highest bit in the run, inclusive.
    pub end: usize,
}

impl BitWindow {
    /// Number of bits in the run.
    pub fn width(self) -> usize {
        self.end + 1 - self.start
    }
}

impl From<&BitRange> for BitWindow {
    fn from(value: &BitRange) -> Self {
        Self {
            start: value.start(),
            end: value.end(),
        }
    }
}

/// One node of a table's decision tree.
///
/// A generated decoder mirrors this directly: a branch reads `bits` out of
/// `source` and indexes `children` with the value; a leaf tries each listed
/// constructor's [`patterns`](ConstructorView::patterns) in order and takes the
/// first that matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionNode<'spec> {
    /// Dispatch on a small bit field.
    Branch {
        /// Where the bits are read from.
        source: BitSource,
        /// Which bits, LSB-numbered within `source`.
        bits: BitWindow,
        /// One entry per value of `bits`, `None` where no constructor matches.
        children: Vec<Option<NodeId>>,
    },

    /// A short list of candidate constructors, most specific first.
    Leaf {
        /// Indices into the owning [`TableView`], in priority order.
        constructors: Vec<usize>,
    },

    /// Never produced; present so matching stays exhaustive across versions.
    #[doc(hidden)]
    #[allow(dead_code)]
    NonExhaustive(std::marker::PhantomData<&'spec ()>),
}

/// A mask/value test over the instruction stream or the context register.
///
/// A byte matches when `byte & mask == value`. Bytes past the end of `mask`
/// are unconstrained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternTest<'spec> {
    /// Matches anything.
    Always,
    /// Matches nothing.
    Never,
    /// Matches when every masked byte agrees.
    Masked {
        /// Which bits of each byte are constrained.
        mask: &'spec [u8],
        /// What those bits must equal.
        value: &'spec [u8],
    },
}

impl<'spec> From<&'spec CompiledPatternBlock> for PatternTest<'spec> {
    fn from(value: &'spec CompiledPatternBlock) -> Self {
        match value {
            CompiledPatternBlock::AlwaysTrue => Self::Always,
            CompiledPatternBlock::AlwaysFalse => Self::Never,
            CompiledPatternBlock::Masked { masks, values } => Self::Masked {
                mask: masks,
                value: values,
            },
        }
    }
}

/// One alternative of a constructor's `is` pattern.
///
/// A constructor written with `|` has several; it matches when *any* of them
/// does, and every one of them must pass both halves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructorPattern<'spec> {
    /// The test against the instruction byte stream.
    pub instruction: PatternTest<'spec>,
    /// The test against the context register.
    pub context: PatternTest<'spec>,
}

/// What a constructor operand stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandKind {
    /// A token or context field, decoded to an integer.
    Field(FieldId),
    /// A sub-table, decoded by recursing into that table's decision tree.
    Table(TableId),
    /// A register named directly in the bit pattern.
    Register(RegisterId),
}

/// One operand slot of a constructor, in the order the decoder fills them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperandSlot {
    /// What this slot holds.
    pub kind: OperandKind,
    /// Bit offset of the operand's bits within the instruction, for a slot
    /// whose position is fixed. Relative slots add to this; see
    /// [`relative_to`](Self::relative_to).
    pub bit_offset: usize,
    /// For an operand introduced by a `;` concatenation, the slot its position
    /// is measured from and the minimum byte extent of the left-hand pattern.
    ///
    /// `None` means the operand sits at [`bit_offset`](Self::bit_offset)
    /// outright, which is the case a straightforward fixed-width ISA only ever
    /// produces.
    pub relative_to: Option<(usize, usize)>,
}

/// A read-only view over one constructor: its pattern, its operands, and its
/// still-symbolic p-code body.
#[derive(Clone, Copy)]
pub struct ConstructorView<'spec> {
    spec: &'spec Spec,
    table: TableId,
    index: usize,
    constructor: &'spec Constructor,
}

impl<'spec> ConstructorView<'spec> {
    /// The table this constructor belongs to.
    pub fn table(&self) -> TableId {
        self.table
    }

    /// This constructor's index within its table.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Smallest number of instruction bytes this constructor can occupy.
    ///
    /// A constructor with sub-table or relative operands may decode longer;
    /// this is the floor, not the length.
    pub fn min_size(&self) -> usize {
        self.constructor.min_size()
    }

    /// Which file this constructor was written in, and the byte range it
    /// occupies there, for diagnostics that point back at the specification.
    pub fn source_span(&self) -> (FileId, usize, usize) {
        let src = self.constructor.src;
        (
            FileId::from_index(src.file as usize),
            src.start as usize,
            src.end as usize,
        )
    }

    /// The alternatives of this constructor's `is` pattern. It matches when
    /// any one of them does.
    pub fn patterns(&self) -> impl Iterator<Item = ConstructorPattern<'spec>> + 'spec {
        self.constructor
            .runtime_patterns
            .iter()
            .map(|pattern| ConstructorPattern {
                instruction: pattern.instruction_block().into(),
                context: pattern.context_block().into(),
            })
    }

    /// This constructor's operand slots, in decoder fill order.
    pub fn operands(&self) -> Vec<OperandSlot> {
        self.constructor
            .token_pattern
            .operands
            .iter()
            .map(|operand| OperandSlot {
                kind: match operand.ty {
                    OperandType::Field(id) => OperandKind::Field(id),
                    OperandType::Table(id) => OperandKind::Table(id),
                    OperandType::Register(id) => OperandKind::Register(id),
                },
                bit_offset: operand.offset(),
                relative_to: operand.relative(),
            })
            .collect()
    }

    /// Which operand slot holds the decoded value of `field`.
    ///
    /// This is the link a code generator needs to turn a symbolic
    /// [`pcode_types::Ident::Field`] in the body into "operand slot *n* of the
    /// instruction currently being executed".
    pub fn field_operand(&self, field: FieldId) -> Option<usize> {
        self.constructor
            .field_map
            .get(&field)
            .map(|&id| id as usize)
    }

    /// Which operand slot holds the sub-constructor decoded for `table`.
    pub fn table_operand(&self, table: TableId) -> Option<usize> {
        self.constructor
            .table_map
            .get(&table)
            .map(|&id| id as usize)
    }

    /// Which global-value slot holds `field`, for the pseudo-fields
    /// (`inst_start` and friends) and disassembly-action locals.
    pub fn global_index(&self, field: FieldId) -> Option<usize> {
        self.constructor.try_global_index(field)
    }

    /// Every global-value slot, as `(field, index)`.
    pub fn globals(&self) -> impl Iterator<Item = (FieldId, usize)> + '_ {
        self.constructor.global_pairs()
    }

    /// This constructor's display list — the disassembly text, with field and
    /// sub-table references left symbolic.
    pub fn display(&self) -> Vec<DisplayPart<'spec>> {
        self.constructor
            .display
            .iter()
            .map(|element| match element {
                DisplayElement::String(text) => DisplayPart::Text(text),
                DisplayElement::Table(id) => DisplayPart::Table(*id),
                DisplayElement::Field(id) => DisplayPart::Field(*id),
            })
            .collect()
    }

    /// The constructor's semantic body, with operands still symbolic:
    /// a [`pcode_types::Ident::Field`] where the source named a field, a
    /// [`pcode_types::Ident::Table`] where it named a sub-table operand.
    ///
    /// Macro calls are *not* expanded — resolve them through
    /// [`SpecView::pcode_macro`].
    pub fn body(&self) -> Vec<Ast> {
        self.constructor.pmacro.body_stripped().collect()
    }

    /// The value this constructor hands to its parent, for a sub-table
    /// constructor with an `export`.
    pub fn export(&self) -> Option<Expression> {
        self.constructor.pmacro.export_stripped()
    }

    /// How many distinct local variables the body declares. A generator can
    /// use this to size its temporary allocation.
    pub fn local_var_count(&self) -> usize {
        self.constructor.pmacro.local_var_count as usize
    }

    /// Sub-table operands whose semantics SLEIGH auto-builds even though the
    /// body never `build`s them explicitly.
    pub fn auto_built_tables(&self) -> &'spec [TableId] {
        &self.constructor.pmacro.non_build_table_refs
    }

    /// This constructor's disassembly actions, in source order.
    ///
    /// These run at *decode* time, not execution time: they compute the
    /// values of the constructor's global pseudo-fields, which the body then
    /// reads like any other field. A PC-relative branch target is the usual
    /// case — `reloc = inst_next + 2 * simm8;` — so a generated decoder that
    /// skips them cannot resolve a branch destination.
    pub fn actions(&self) -> Vec<DisassemblyAction> {
        self.constructor
            .actions
            .iter()
            .map(|action| match action {
                Action::Assign { field_id, expr } => DisassemblyAction::Assign {
                    field: *field_id,
                    value: ActionExpr::from(expr),
                },
                Action::GlobalSet { addr, field_id } => DisassemblyAction::GlobalSet {
                    address: match addr {
                        GlobalSetAddr::Expr(expr) => GlobalSetTarget::Expr(ActionExpr::from(expr)),
                        GlobalSetAddr::Table(id) => GlobalSetTarget::Operand(*id),
                    },
                    field: *field_id,
                },
            })
            .collect()
    }

    /// The `delayslot` directive in this constructor's body, if it has one.
    pub fn delay_slot(&self) -> Option<&'spec DelaySlotArg> {
        self.constructor.delay_slot.as_ref()
    }

    /// Whether the body reads `inst_next2`, which needs a look-ahead decode.
    pub fn uses_inst_next2(&self) -> bool {
        self.constructor.uses_inst_next2
    }

    /// The specification this constructor came from.
    pub fn spec(&self) -> SpecView<'spec> {
        SpecView { spec: self.spec }
    }
}

/// One element of a constructor's disassembly display list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayPart<'spec> {
    /// Literal text.
    Text(&'spec str),
    /// The rendered form of a sub-table operand.
    Table(TableId),
    /// The rendered form of a field operand.
    Field(FieldId),
}

/// A read-only view over a `macro` definition.
#[derive(Clone, Copy)]
pub struct MacroView<'spec> {
    pmacro: &'spec PCodeMacro,
}

impl<'spec> MacroView<'spec> {
    /// The macro's parameters, as the local-variable ids its body refers to
    /// them by.
    pub fn params(&self) -> &'spec [pcode_types::LocalVarId] {
        &self.pmacro.args
    }

    /// How many distinct local variables the body declares, parameters
    /// included.
    pub fn local_var_count(&self) -> usize {
        self.pmacro.local_var_count as usize
    }

    /// The macro body.
    pub fn body(&self) -> Vec<Ast> {
        self.pmacro.body_stripped().collect()
    }

    /// The value the macro exports, if any.
    pub fn export(&self) -> Option<Expression> {
        self.pmacro.export_stripped()
    }
}

/// What a field's bit range is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldParent {
    /// Bits of a token, so the field is extracted from the instruction stream.
    Token(TokenId),
    /// Bits of the context register.
    Context,
    /// A pseudo-field with no bits behind it — `inst_start`, `inst_next`,
    /// `inst_next2`, or a disassembly-action local.
    Global,
}

/// How a field's raw bits are interpreted, as set by an `attach` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attachment<'spec> {
    /// Unattached: the value is the number read out of the bits.
    Integer,
    /// `attach variables`: the value indexes this register table. A `None`
    /// entry is a `_` placeholder, which no value may select.
    Registers(&'spec [Option<RegisterId>]),
    /// `attach values`: the value indexes this table of integers, read as
    /// signed two's complement.
    Values(&'spec [Option<u64>]),
    /// `attach names`: the value indexes this table of display names, which
    /// carry no semantic meaning.
    Names(&'spec [Option<Box<str>>]),
}

/// A read-only view over one field definition.
#[derive(Clone, Copy)]
pub struct FieldView<'spec> {
    spec: &'spec Spec,
    id: FieldId,
    field: &'spec Field,
}

impl<'spec> FieldView<'spec> {
    /// The field's id.
    pub fn id(&self) -> FieldId {
        self.id
    }

    /// The field's name, as declared.
    pub fn name(&self) -> &'spec str {
        &self.field.name
    }

    /// Which bits of the parent the field occupies, LSB-numbered as SLEIGH
    /// numbers them for that parent.
    pub fn bits(&self) -> BitWindow {
        BitWindow::from(&self.field.range)
    }

    /// Whether the extracted value is sign-extended.
    pub fn signed(&self) -> bool {
        self.field.signed
    }

    /// Whether a context field is marked `noflow`.
    pub fn noflow(&self) -> bool {
        self.field.noflow
    }

    /// What the field's bits are measured against.
    pub fn parent(&self) -> FieldParent {
        match self.field.parent {
            InternalFieldParent::Token(id) => FieldParent::Token(id),
            InternalFieldParent::Context => FieldParent::Context,
            InternalFieldParent::Global => FieldParent::Global,
        }
    }

    /// Width of the field's parent in bits.
    pub fn parent_bits(&self) -> usize {
        self.field.parent_size()
    }

    /// How the raw bits are to be interpreted.
    pub fn attachment(&self) -> Attachment<'spec> {
        match self.field.field_type() {
            FieldType::Integer => Attachment::Integer,
            FieldType::Registers(id) => {
                Attachment::Registers(self.spec.field_tables.register_table(id))
            }
            FieldType::Values(id) => Attachment::Values(self.spec.field_tables.value_table(id)),
            FieldType::String(id) => Attachment::Names(self.spec.field_tables.name_table(id)),
        }
    }

    /// Where bit `field_bit` of this field sits in the instruction byte
    /// stream, LSB-numbered from the first byte of the instruction.
    ///
    /// `operand_bit_offset` is the operand slot's
    /// [`OperandSlot::bit_offset`], which places the field's token within the
    /// instruction. A big-endian token permutes its bytes, so its bits are
    /// *not* a contiguous run in the stream and a generated extractor has to
    /// gather them one at a time — which is what this method is for.
    ///
    /// Returns `None` for a context or global field, which is not in the
    /// instruction stream at all.
    pub fn stream_bit(&self, field_bit: usize, operand_bit_offset: usize) -> Option<usize> {
        use crate::token::{TokenContext, token_stream_bit};
        let InternalFieldParent::Token(token) = self.field.parent else {
            return None;
        };
        let token_bits = self.spec.token_size(token);
        let endian = self.spec.token_endian(token);
        let within_token = self.field.range.start() + field_bit;
        Some(operand_bit_offset + token_stream_bit(token_bits, endian, within_token))
    }
}

/// One statement of a constructor's disassembly-action block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisassemblyAction {
    /// `field = value;` — computes a global pseudo-field for this decode.
    Assign {
        /// The field written.
        field: FieldId,
        /// What it is set to.
        value: ActionExpr,
    },

    /// `globalset(address, field);` — commits `field`'s current value into the
    /// context database, so it applies to later decodes.
    GlobalSet {
        /// Where the committed value takes effect.
        address: GlobalSetTarget,
        /// The context field whose value is committed.
        field: FieldId,
    },
}

/// Where a `globalset` commits its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalSetTarget {
    /// An expression over this decode's fields, overwhelmingly `inst_next`.
    Expr(ActionExpr),
    /// A sub-table operand, whose exported address is the target.
    Operand(TableId),
}

/// An infix operator in a disassembly-action expression.
///
/// Actions compute over whole field values at decode time, so there is one
/// arithmetic per operator: no width, and no signedness to pick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionBinOp {
    /// Bitwise or.
    Or,
    /// Bitwise exclusive-or.
    Xor,
    /// Bitwise and.
    And,
    /// Left shift. A distance that is negative or at least 64 fails the decode.
    Shl,
    /// Right shift, with the same restriction on the distance.
    Shr,
    /// Wrapping addition.
    Add,
    /// Wrapping subtraction.
    Sub,
    /// Wrapping multiplication.
    Mul,
    /// Signed division. A zero divisor fails the decode.
    Div,
}

impl From<BinOp> for ActionBinOp {
    fn from(value: BinOp) -> Self {
        match value {
            BinOp::Or => Self::Or,
            BinOp::Xor => Self::Xor,
            BinOp::And => Self::And,
            BinOp::Shl => Self::Shl,
            BinOp::Shr => Self::Shr,
            BinOp::Add => Self::Add,
            BinOp::Sub => Self::Sub,
            BinOp::Mul => Self::Mul,
            BinOp::Div => Self::Div,
        }
    }
}

/// A prefix operator in a disassembly-action expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionUnOp {
    /// Wrapping negation.
    Neg,
    /// Bitwise complement.
    Not,
}

impl From<UnOp> for ActionUnOp {
    fn from(value: UnOp) -> Self {
        match value {
            UnOp::Neg => Self::Neg,
            UnOp::Not => Self::Not,
        }
    }
}

/// An expression evaluated at decode time over 64-bit field values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionExpr {
    /// A literal.
    Int(i64),
    /// The decoded value of a field, or of a pseudo-field such as `inst_next`.
    Field(FieldId),
    /// An infix operation.
    Binary {
        /// Which operator.
        op: ActionBinOp,
        /// Left operand.
        lhs: Box<ActionExpr>,
        /// Right operand.
        rhs: Box<ActionExpr>,
    },
    /// A prefix operation.
    Unary {
        /// Which operator.
        op: ActionUnOp,
        /// The operand.
        operand: Box<ActionExpr>,
    },
}

impl From<&Expr> for ActionExpr {
    fn from(value: &Expr) -> Self {
        match value {
            Expr::Atom(Atom::Int(value)) => Self::Int(*value),
            Expr::Atom(Atom::Ident(id)) => Self::Field(*id),
            Expr::Binary { op, lhs, rhs } => Self::Binary {
                op: (*op).into(),
                lhs: Box::new(Self::from(&**lhs)),
                rhs: Box::new(Self::from(&**rhs)),
            },
            Expr::Unary { op, expr } => Self::Unary {
                op: (*op).into(),
                operand: Box::new(Self::from(&**expr)),
            },
        }
    }
}
