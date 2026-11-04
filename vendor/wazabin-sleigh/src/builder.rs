use crate::bitrange::BitRange;
use crate::pmacro::expression::Builtin;
use crate::{
    action::Action,
    constraint::ConstraintAst,
    constructor::{
        ConstructorBuilder, ConstructorId, ConstructorMutRef, DisplayElement, PatternOrConstraint,
    },
    diagnostic::{BuildResult, Diagnostic, DiagnosticCode},
    objects::{
        field::{
            FIELD_INST_NEXT, FIELD_INST_NEXT2, FIELD_INST_START, Field, FieldId, FieldParent,
            FieldTables,
        },
        table::{Table, TableId, TableMutRef, TableRef},
    },
    pattern::TokenPattern,
    pmacro::{PCodeMacro, PMacroId, statement::AstNode},
    source::Span,
    token::{BitRangeField, BitRangeFieldId, Token, TokenContext, TokenId, TokenMutRef},
};
use jstd::registry::{Identified, Registry};
use pcode_types::{
    PCodeOpId, Register, RegisterId, RegisterMutRef, RegisterRef, SPACE_CONST, Space, SpaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Endian {
    #[default]
    Little,
    Big,
}

pub(crate) enum Symbol<'b> {
    Field(Identified<FieldId, &'b Field>),
    Table(Identified<TableId, &'b Table>),
    Register(RegisterRef<'b>),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SymbolId {
    Register(RegisterId),
    BitRangeField(BitRangeFieldId),
    Space(SpaceId),
    Token(TokenId),
    Field(FieldId),
    Macro(PMacroId),
    Table(TableId),
    PCodeOp(PCodeOpId),

    /// A reserved name with no particular meaning, used for builtins
    Special,
}

#[derive(Default)]
pub(crate) struct SpecBuilder {
    pub(crate) endian: Endian,
    pub(crate) default_space: Option<SpaceId>,
    pub(crate) context_reg: Option<RegisterId>,
    pub(crate) alignment: usize,
    pub(crate) field_tables: FieldTables,
    pub(crate) symbols: HashMap<Box<str>, SymbolId>,
    next_global: usize,
    pub(crate) tables: Registry<TableId, Table>,
    pub(crate) spaces: Registry<SpaceId, Space>,
    pub(crate) tokens: Registry<TokenId, Token>,
    pub(crate) registers: Registry<RegisterId, Register>,
    pub(crate) bitranges: Registry<BitRangeFieldId, BitRangeField>,
    pub(crate) pcode_ops: Registry<PCodeOpId, Box<str>>,
    pub(crate) fields: Registry<FieldId, Field>,
    pub(crate) pmacros: Registry<PMacroId, PCodeMacro>,
}

impl SpecBuilder {
    pub(crate) fn new() -> Self {
        let mut ctx = SpecBuilder {
            alignment: 1,
            ..Default::default()
        };

        ctx.register_table("instruction").unwrap();

        ctx.register_global("inst_start").unwrap();
        debug_assert_eq!(ctx.fields[FIELD_INST_START].name.as_ref(), "inst_start");
        ctx.register_global("inst_next").unwrap();
        debug_assert_eq!(ctx.fields[FIELD_INST_NEXT].name.as_ref(), "inst_next");
        ctx.register_global("inst_next2").unwrap();
        debug_assert_eq!(ctx.fields[FIELD_INST_NEXT2].name.as_ref(), "inst_next2");

        ctx.register_space("const").unwrap();
        debug_assert_eq!(ctx.spaces[SPACE_CONST].name.as_deref(), Some("const"));

        // Seeded from `Builtin::ALL` so that the two cannot disagree: a
        // builtin missing here is not callable from a specification, however
        // well the enum knows it.
        for builtin in Builtin::ALL {
            ctx.register_symbol(builtin.as_str(), SymbolId::Special)
                .unwrap();
        }

        ctx
    }

    fn register_symbol(&mut self, name: &str, symbol: SymbolId) -> BuildResult<()> {
        if self.symbols.insert(name.into(), symbol).is_some() {
            Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!("Redefinition of symbol {name}"),
                Span::sentinel(),
            )))
        } else {
            Ok(())
        }
    }

    pub(crate) fn try_get_field(&self, name: &str) -> Option<Identified<FieldId, &Field>> {
        if let Some(&SymbolId::Field(id)) = self.symbols.get(name) {
            Some(self.fields.get(id))
        } else {
            None
        }
    }

    pub(crate) fn try_get_mut_field(&mut self, name: &str) -> Option<&mut Field> {
        if let Some(&SymbolId::Field(id)) = self.symbols.get(name) {
            Some(&mut self.fields[id])
        } else {
            None
        }
    }

    pub(crate) fn try_get_table(&self, name: &str) -> Option<TableRef<'_>> {
        if let Some(&SymbolId::Table(id)) = self.symbols.get(name) {
            Some(self.tables.get(id))
        } else {
            None
        }
    }

    pub(crate) fn try_get_register(&self, name: &str) -> Option<RegisterRef<'_>> {
        if let Some(&SymbolId::Register(id)) = self.symbols.get(name) {
            Some(self.registers.get(id))
        } else {
            None
        }
    }

    pub(crate) fn try_get_space(&self, name: &str) -> Option<Identified<SpaceId, &Space>> {
        if let Some(&SymbolId::Space(id)) = self.symbols.get(name) {
            Some(self.spaces.get(id))
        } else {
            None
        }
    }

    pub(crate) fn get_symbol<'b>(&'b self, name: &str) -> Symbol<'b> {
        self.symbols
            .get(name)
            .map_or(Symbol::None, |symbol| match *symbol {
                SymbolId::Field(id) => Symbol::Field(self.fields.get(id)),
                SymbolId::Register(id) => Symbol::Register(self.registers.get(id)),
                SymbolId::Table(id) => Symbol::Table(self.tables.get(id)),
                _ => Symbol::None,
            })
    }

    /// Creates a new global field of `size` bits
    pub(crate) fn register_global(
        &mut self,
        field_name: &str,
    ) -> BuildResult<Identified<FieldId, &mut Field>> {
        let start = self.next_global;
        self.next_global += 1;
        self.register_field(field_name, start, start, FieldParent::Global, false)
    }

    /// Mints a global field without claiming its name in the symbol table.
    ///
    /// A disassembly-action local is scoped to its constructor. Modelling one
    /// as a named global is convenient and almost always harmless — but not
    /// when the constructor's own table already owns the name, as Loongarch's
    /// `csr: csr is imm10_14 [csr = ...]` does. The caller keeps the name in a
    /// per-constructor map instead.
    pub(crate) fn register_scoped_global(&mut self, field_name: &str) -> FieldId {
        let start = self.next_global;
        self.next_global += 1;
        self.fields.push(Field::new(
            field_name,
            FieldParent::Global,
            BitRange::new(start, start),
            crate::Size::MAX as usize,
            false,
        ))
    }

    pub(crate) fn register_field(
        &mut self,
        name: &str,
        start: usize,
        end: usize,
        parent: FieldParent,
        signed: bool,
    ) -> BuildResult<Identified<FieldId, &mut Field>> {
        if end < start {
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                "Field has invalid size (end < start)",
                Span::sentinel(),
            )));
        }

        let parent_size: usize = match parent {
            FieldParent::Token(tok) => self.tokens[tok].size(),
            FieldParent::Context => {
                self.registers[self.context_reg.ok_or_else(|| {
                    Diagnostic::error(
                        DiagnosticCode::Compile,
                        "Using context before it has been defined",
                        Span::sentinel(),
                    )
                })?]
                .size
            }
            FieldParent::Global => crate::Size::MAX as usize,
        };

        let id = self.fields.push(Field::new(
            name,
            parent,
            BitRange::new(start, end),
            parent_size,
            signed,
        ));

        self.register_symbol(name, SymbolId::Field(id))?;

        Ok(self.fields.get_mut(id))
    }

    pub(crate) fn register_reg(
        &mut self,
        name: &str,
        space: SpaceId,
        offset: usize,
        size: usize,
    ) -> BuildResult<RegisterMutRef<'_>> {
        let id = self.registers.push(Register {
            name: name.into(),
            space,
            offset,
            size,
        });
        self.register_symbol(name, SymbolId::Register(id))?;
        Ok(self.registers.get_mut(id))
    }

    pub(crate) fn register_space(
        &mut self,
        name: &str,
    ) -> BuildResult<Identified<SpaceId, &mut Space>> {
        let id = self.spaces.push(Space::new(Some(name), 1, 8));
        self.register_symbol(name, SymbolId::Space(id))?;
        Ok(self.spaces.get_mut(id))
    }

    pub(crate) fn register_token(
        &mut self,
        name: &str,
        size: usize,
    ) -> BuildResult<TokenMutRef<'_>> {
        let id = self.tokens.push(Token::new(size, self.endian, name));
        self.register_symbol(name, SymbolId::Token(id))?;
        Ok(self.tokens.get_mut(id))
    }

    pub(crate) fn register_table(&mut self, name: &str) -> BuildResult<TableMutRef<'_>> {
        let id = self.tables.push(Table::new(name.into()));
        self.register_symbol(name, SymbolId::Table(id))?;
        Ok(self.tables.get_mut(id))
    }

    pub(crate) fn register_macro(&mut self, name: &str, macro_def: PCodeMacro) -> BuildResult<()> {
        let id = self.pmacros.push(macro_def);
        self.register_symbol(name, SymbolId::Macro(id))
    }

    pub(crate) fn register_bitrange(
        &mut self,
        name: &str,
        register: RegisterId,
        offset: usize,
        size: usize,
    ) -> BuildResult<&mut BitRangeField> {
        let id = self
            .bitranges
            .push(BitRangeField::new(name, register, offset, size));
        self.register_symbol(name, SymbolId::BitRangeField(id))?;
        Ok(&mut self.bitranges[id])
    }

    pub(crate) fn register_pcodeop(&mut self, name: &str) -> BuildResult<()> {
        let id = self.pcode_ops.push(name.into());
        self.register_symbol(name, SymbolId::PCodeOp(id))
    }

    pub(crate) fn add_constructor(
        &mut self,
        parent: &str,
        constraint: ConstraintAst,
        dl: Vec<DisplayElement>,
        actions: Vec<Action>,
        src: Span,
        pmacro: PCodeMacro,
    ) -> BuildResult<ConstructorMutRef<'_>> {
        let mut table = match self.try_get_table(parent).map(|t| t.id) {
            Some(id) => self.tables.get_mut(id),
            None => self.register_table(parent)?,
        };

        let id = table.constructors.push(ConstructorBuilder {
            min_size: 0,
            pattern: PatternOrConstraint::Constraint(constraint),
            display_list: dl,
            actions,
            src,
            pmacro,
        });

        Ok(table.inner.constructors.get_mut(id))
    }

    /// Concretizes a table by converting the constraint ASTs in its constructors to token patterns.
    /// Then, tries to find a common sub-pattern between all constructors to use as the table pattern.
    pub(crate) fn concretize_table(&mut self, id: TableId) -> BuildResult<TokenPattern> {
        let table = &mut self.tables[id];

        if let Some(pat) = &table.pattern {
            return Ok(pat.clone());
        }

        if table.building {
            // We are recursing. Return a *bare* placeholder: `build_operand` is
            // the only caller that can reach this arm and it adds the operand
            // itself. Adding one here too gave a self-recursive table two
            // operands for a single reference, so every level of a recursive
            // list decoded its own tail twice — 2^depth work for a linear list.
            // ARM's `buildVldmSdList` compiled to
            // `[Sreg, buildVldmSdList, buildVldmSdList]` and made `vldmia` with
            // a long register list undecodable.
            return Ok(TokenPattern::default());
        }

        let constructors = std::mem::take(&mut table.constructors);
        table.building = true;

        self.tables[id].constructors = constructors
            .into_iter()
            .map(|mut constructor| {
                let token_pattern = constructor.pattern.unwrap_constraint();
                let pattern = token_pattern.to_pattern(self)?;
                constructor.min_size = pattern.min_size(self) / 8;
                constructor.pattern = PatternOrConstraint::Pattern(pattern);
                Ok(constructor.clone())
            })
            .collect::<BuildResult<Registry<ConstructorId, _>>>()?;

        let table = &mut self.tables[id];
        table.building = false;

        // Build this table's combined pattern
        let mut pat =
            table
                .constructors
                .iter()
                .try_fold(TokenPattern::impossible(), |acc, c| {
                    acc.common_sub_pattern(c.pattern.unwrap_pattern())
                        .map_err(|err| {
                            Box::new(Diagnostic::error(
                                DiagnosticCode::Compile,
                                err.to_string(),
                                c.src,
                            ))
                        })
                })?;

        // Strip operands from the pattern
        pat.operands.clear();

        table.pattern = Some(pat.clone());

        Ok(pat)
    }

    /// Convert all the constraint ASTs in the constructors by Token patterns
    pub(crate) fn concretize(&mut self) -> BuildResult<()> {
        for id in 0..self.tables.len() {
            self.concretize_table(id.into())?;
        }
        Ok(())
    }

    /// Finalizes the p-code macros by expanding all macro calls.
    /// This should be called after concretization, since macro expansion may depend on the patterns.
    pub(crate) fn finalize_pcode(&mut self) -> crate::pcode_error::PcodeResult<()> {
        let macros = self.pmacros.clone();
        for table in self.tables.iter_mut() {
            for mut constructor in table.inner.constructors.iter_mut() {
                constructor.pmacro.expand_macros(&macros)?;
                // After expansion, so a directive reached through a macro call
                // counts. One instruction has one delay slot; two directives
                // would each want to splice the same following instructions.
                check_single_delay_slot(&constructor.pmacro)?;
            }
        }
        Ok(())
    }
}

/// Rejects a constructor body carrying more than one `delayslot` directive.
fn check_single_delay_slot(pmacro: &PCodeMacro) -> crate::pcode_error::PcodeResult<()> {
    let mut directives = pmacro
        .body
        .iter()
        .filter(|stmt| matches!(stmt.ty, AstNode::DelaySlot(_)));

    if directives.next().is_some()
        && let Some(second) = directives.next()
    {
        return Err(crate::pcode_error::PcodeError::new(
            crate::pcode_error::PcodeErrorTy::Unsupported(
                "a constructor may contain at most one `delayslot` directive".into(),
            ),
            second.span,
        ));
    }
    Ok(())
}

impl TokenContext for SpecBuilder {
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
