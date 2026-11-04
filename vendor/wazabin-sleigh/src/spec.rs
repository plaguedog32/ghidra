use crate::{
    builder::Endian,
    builder::{SpecBuilder, SymbolId},
    objects::field::{Field, FieldId, FieldTables},
    objects::table::TableId,
    pattern::OperandType,
    pmacro::{PCodeMacro, PMacroId},
    register_map::RegisterMap,
    runtime::walker::update_context,
    token::{BitRangeField, BitRangeFieldId, TokenContext},
    token::{Token, TokenId},
    tree::{Tree, TreeId},
};
use jstd::registry::{Identified, Registry};
use pcode_types::{PCodeOpId, Register, RegisterId, Space, SpaceId, SymbolicWidth};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Legacy compiled SLEIGH specification.
///
/// `Spec` is the internal runtime representation used by the current decoder
/// and qcode adapter.  New public callers should prefer
/// [`crate::Compiler`] and [`crate::CompiledSpec`], which borrow source text
/// from [`crate::SourceDb`] and report diagnostics instead of panicking on
/// malformed input.
///
/// # Usage
///
/// ```no_run
/// use sleigh::{Compiler, Decoder, SourceDb};
///
/// let text = std::fs::read_to_string("x86-64.slaspec").unwrap();
/// let mut sources = SourceDb::new();
/// let root = sources.add_file("x86-64.slaspec", text);
/// let spec = Compiler::new(&mut sources).compile(root).unwrap();
/// let context = spec.new_context();
/// let decoder = Decoder::new(&spec);
/// let instruction = decoder.decode_one(0, &[0x90], &context).unwrap();
/// println!("{}", instruction.display().unwrap());
/// ```
#[derive(Serialize, Deserialize)]
pub(crate) struct Spec {
    pub(crate) default_space: SpaceId,

    /// The real, spec-owned space used for raw p-code temporaries.
    pub(crate) unique_space: SpaceId,

    pub(crate) context_reg: Option<RegisterId>,

    /// Tables to attach values to fields
    pub(crate) field_tables: FieldTables,

    /// A mapping of symbol names to their corresponding IDs
    pub(crate) symbols: HashMap<Box<str>, SymbolId>,

    // ===== Registries =====
    /// Named additional PCode operations, not part of the official pcode spec
    pub(crate) pcode_ops: Registry<PCodeOpId, Box<str>>,

    /// P-code macro templates used during decoded AST expansion.
    pub(crate) pmacros: Registry<PMacroId, PCodeMacro>,

    /// Trees, build constructors from raw bytes
    pub(crate) trees: Registry<TreeId, Tree>,

    /// Field definitions
    pub(crate) fields: Registry<FieldId, Field>,

    /// Register definitions
    pub(crate) registers: Registry<RegisterId, Register>,

    /// The registers by location, for enclosing-register and overlap queries.
    pub(crate) register_map: RegisterMap,

    /// Space definitions
    pub(crate) spaces: Registry<SpaceId, Space>,

    /// Bitrange definitions
    pub(crate) bitranges: Registry<BitRangeFieldId, BitRangeField>,

    /// Does any constructor in this specification carry a `delayslot`
    /// directive, or read `inst_next2`? Both need a look-ahead decode, and
    /// neither is common — a specification with no delay slots must not pay a
    /// tree walk per instruction to discover that.
    pub(crate) needs_lookahead: bool,

    tokens: Registry<TokenId, Token>,
}

impl Spec {
    /// Parses and compiles a SLEIGH source string into a runtime [`Spec`].
    ///
    /// Prefer [`crate::Compiler`] for new code; it borrows source text from
    /// [`crate::SourceDb`] and returns diagnostics on user input errors.
    ///
    /// # Panics
    ///
    /// Panics if the source contains a parse or concretization error.  A
    /// diagnostic is printed to `stderr` before panicking.
    #[cfg(test)]
    pub(crate) fn from_src(src: &str) -> Self {
        use crate::{
            resolve::resolve,
            source::{PreprocessOptions, SourceDb},
            syntax::parse_to_ast,
        };

        let mut sources = SourceDb::new();
        let root = sources.add_file("test.sla", src);
        let (file, _) = parse_to_ast(&mut sources, root, &PreprocessOptions::default())
            .unwrap_or_else(|diags| panic!("{}", diags[0].message));
        let (mut builder, _warnings) =
            resolve(&file).unwrap_or_else(|diags| panic!("{}", diags[0].message));
        builder.concretize().unwrap();
        Self::from_builder(builder)
    }

    pub(crate) fn from_builder(builder: SpecBuilder) -> Self {
        let tables = builder.tables;

        // Verify every constructor was concretized before we discard the builder.
        #[cfg(debug_assertions)]
        for table in tables.iter() {
            for c in table.inner.constructors.iter() {
                debug_assert!(
                    matches!(
                        c.pattern,
                        crate::constructor::PatternOrConstraint::Pattern(_)
                    ),
                    "Constructor was not concretized at bytes {:?}",
                    c.src
                );
            }
        }

        let trees: Registry<TreeId, Tree> = tables
            .into_iter()
            .map(|table| Tree::from_table(&builder.fields, table.inner))
            .collect();

        // Create a default space if one doesn't exist
        // We should probably emit a warning if this happens, but for now just create one
        let mut spaces = builder.spaces;
        let default_space = builder
            .default_space
            .unwrap_or_else(|| spaces.push(Space::new(None, 8, 8)));
        // Append this only after resolving all source spaces: their stable IDs
        // are part of compiled-spec blobs and must not be renumbered.
        let unique_space = spaces.push(Space::unique(spaces[default_space].addr_size));

        let mut symbols = builder.symbols;
        symbols.insert(Box::from("unique"), SymbolId::Space(unique_space));

        let mut spec = Self {
            trees,
            spaces,
            default_space,
            unique_space,
            fields: builder.fields,
            register_map: RegisterMap::new(&builder.registers),
            registers: builder.registers,
            bitranges: builder.bitranges,
            field_tables: builder.field_tables,
            context_reg: builder.context_reg,
            symbols,
            pcode_ops: builder.pcode_ops,
            pmacros: builder.pmacros,

            tokens: builder.tokens,
            needs_lookahead: false,
        };
        spec.refresh_runtime_metadata();
        spec.resolve_local_widths();
        spec.needs_lookahead = spec.trees.iter().any(|tree| {
            tree.constructors
                .iter()
                .any(|c| c.delay_slot.is_some() || c.uses_inst_next2)
        });
        spec
    }

    /// Resolves every p-code body's local widths once, when the specification
    /// is compiled, so no decode has to rediscover them.
    ///
    /// A width that depends on an operand a decode substitutes is kept
    /// symbolic rather than dropped: dropping it would let a later statement
    /// establish a *different* width than the one the substituted value gives.
    fn resolve_local_widths(&mut self) {
        let widths: Vec<Vec<pcode_types::BodyWidths<SymbolicWidth>>> = {
            let context = crate::runtime::InstructionPcodeContext::new(self);
            self.trees
                .iter()
                .map(|tree| {
                    tree.constructors
                        .iter()
                        .map(|constructor| {
                            pcode_types::resolve_body_widths(&constructor.pmacro.body, &context)
                        })
                        .collect()
                })
                .collect()
        };
        let macro_widths: Vec<pcode_types::BodyWidths<SymbolicWidth>> = {
            let context = crate::runtime::InstructionPcodeContext::new(self);
            self.pmacros
                .iter()
                .map(|pmacro| pcode_types::resolve_body_widths(&pmacro.body, &context))
                .collect()
        };

        for (tree_widths, mut tree) in widths.into_iter().zip(self.trees.iter_mut()) {
            for (widths, mut constructor) in
                tree_widths.into_iter().zip(tree.constructors.iter_mut())
            {
                constructor.pmacro.local_widths = widths.widths;
                constructor.pmacro.unsized_locals = widths.unsized_locals;
            }
        }
        for (widths, mut pmacro) in macro_widths.into_iter().zip(self.pmacros.iter_mut()) {
            pmacro.local_widths = widths.widths;
            pmacro.unsized_locals = widths.unsized_locals;
        }
    }

    fn refresh_runtime_metadata(&mut self) {
        let symbols = &self.symbols;
        for mut pmacro in self.pmacros.iter_mut() {
            pmacro.refresh_runtime_metadata(symbols, &[]);
        }
        for mut tree in self.trees.iter_mut() {
            for mut constructor in tree.constructors.iter_mut() {
                let pattern_tables: Vec<TableId> = constructor
                    .token_pattern
                    .operands
                    .iter()
                    .filter_map(|op| match op.ty {
                        OperandType::Table(id) => Some(id),
                        _ => None,
                    })
                    .collect();
                constructor
                    .pmacro
                    .refresh_runtime_metadata(symbols, &pattern_tables);
            }
        }
    }

    pub(crate) fn context_len(&self) -> usize {
        self.context_reg
            .map(|id| self.registers[id].size)
            .unwrap_or(0)
    }

    /// Assign a [`Field`] in the context
    pub(crate) fn set_context_field(&self, context: &mut [u8], field: FieldId, value: u64) {
        update_context(context, &self.fields[field].range, value);
    }

    /// Attempts to get a field by name
    /// Returns `None` if the field doesn't exist or isn't a field
    /// This is mostly used for testing, since fields are usually accessed through patterns
    pub(crate) fn get_field_by_name(&self, name: &str) -> Option<Identified<FieldId, &Field>> {
        if let Some(&SymbolId::Field(id)) = self.symbols.get(name) {
            Some(Identified::new(id, &self.fields[id]))
        } else {
            None
        }
    }

    /// Attempts to get a token by name.
    /// Returns `None` if the token doesn't exist or isn't a token.
    /// This is mostly used for testing, since tokens are usually accessed through patterns.
    pub(crate) fn get_token_by_name(&self, name: &str) -> Option<Identified<TokenId, &Token>> {
        if let Some(&SymbolId::Token(id)) = self.symbols.get(name) {
            Some(Identified::new(id, &self.tokens[id]))
        } else {
            None
        }
    }

    /// Looks up a register by name.
    pub(crate) fn get_register_by_name(
        &self,
        name: &str,
    ) -> Option<Identified<RegisterId, &Register>> {
        if let Some(&SymbolId::Register(id)) = self.symbols.get(name) {
            Some(Identified::new(id, &self.registers[id]))
        } else {
            None
        }
    }
}

impl TokenContext for Spec {
    fn token_size(&self, id: TokenId) -> usize {
        self.tokens[id].size()
    }

    fn token_endian(&self, id: TokenId) -> Endian {
        self.tokens[id].endian
    }

    fn token_name(&self, id: TokenId) -> &str {
        &self.tokens[id].name
    }
}

#[cfg(test)]
mod tests {
    use crate::objects::field::FieldValue;

    use super::*;

    #[test]
    fn test_parse_register() {
        let spec = Spec::from_src(
            "
        define space register type=register_space size=4;
        define register offset=0x200 size=4 [r1 r2 r3 r4];",
        );

        let r1 = spec.get_register_by_name("r1").unwrap();
        let r2 = spec.get_register_by_name("r2").unwrap();
        let r3 = spec.get_register_by_name("r3").unwrap();
        let r4 = spec.get_register_by_name("r4").unwrap();

        assert_eq!(r1.size, 4);
        assert_eq!(r1.offset, 0x200);

        assert_eq!(r2.size, 4);
        assert_eq!(r2.offset, 0x204);

        assert_eq!(r3.size, 4);
        assert_eq!(r3.offset, 0x208);

        assert_eq!(r4.size, 4);
        assert_eq!(r4.offset, 0x20c);
    }

    #[test]
    fn test_parse_single_token() {
        let spec = Spec::from_src("define token my_token(40);");

        let token = spec.get_token_by_name("my_token").unwrap();

        assert_eq!(token.size(), 40);
        assert_eq!(token.name.as_ref(), "my_token");
    }

    #[test]
    fn test_parse_single_field() {
        let spec = Spec::from_src("define token mytoken (40) foo=(1, 3);");

        let foo = spec.get_field_by_name("foo").unwrap();

        assert_eq!(foo.name.as_ref(), "foo");
        assert_eq!(foo.range.start(), 1);
        assert_eq!(foo.range.end(), 3);
    }

    #[test]
    fn test_eval_field() {
        let spec = Spec::from_src("define token mytoken (40) foo=(1, 3);");

        let foo = spec.get_field_by_name("foo").unwrap();

        assert_eq!(
            foo.value(&spec.field_tables, 0b110),
            Some(FieldValue::UInt(0b110))
        );
    }

    #[test]
    fn test_eval_field_value() {
        let spec = Spec::from_src(
            "
        define token mytoken (40) foo=(1, 3);
        attach values [foo] [0 0 0 0 0 69 0 0];
        ",
        );

        let foo = spec.get_field_by_name("foo").unwrap();

        // `attach values` entries read as signed, matching Ghidra.
        assert_eq!(foo.value(&spec.field_tables, 5), Some(FieldValue::Int(69)));
    }

    #[test]
    fn test_eval_field_name() {
        let spec = Spec::from_src(
            r#"
        define token mytoken (40) foo=(1, 3);
        attach names [foo] [_ _ _ _ _ "Hello" "World" _];
        "#,
        );

        let foo = spec.get_field_by_name("foo").unwrap();

        assert_eq!(
            foo.value(&spec.field_tables, 5),
            Some(FieldValue::String("Hello"))
        );
    }

    #[test]
    fn test_eval_field_register() {
        let spec = Spec::from_src(
            "
            define space register type=register_space size=4;
            define register offset=0 size=4 [r1 r2 r3 r4];

            define token mytoken (40) foo=(1, 3);
            attach variables [foo] [_ r1 _ r2 _ r3 _ r4];",
        );

        let foo = spec.get_field_by_name("foo").unwrap();
        let r3 = spec.get_register_by_name("r3").unwrap();

        assert_eq!(
            foo.value(&spec.field_tables, 5),
            Some(FieldValue::Register(r3.id))
        );
    }
}
