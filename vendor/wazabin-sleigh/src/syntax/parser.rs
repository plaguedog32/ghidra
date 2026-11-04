//! Typed SLEIGH AST builder.
//!
//! This layer consumes the already-preprocessed buffer with the raw tooling
//! grammar. It does not parse physical source files before preprocessing.
//!
//! [`build_sleigh_ast`] produces a typed [`SleighFile`] AST from a single Pest
//! parse, without touching any symbol table.

use std::sync::LazyLock;

use crate::raw_parsing::Rule;
use pcode_types::SpaceType;
use pest::{
    iterators::{Pair, Pairs},
    pratt_parser::{Assoc, Op, PrattParser},
};

use crate::{
    action::{BinOp as ActionBinOp, UnOp as ActionUnOp},
    diagnostic::{BuildResult, Diagnostic, DiagnosticCode},
    source::{PreparedSourceId, SourceDb, Span},
    syntax::lower::{constraint::parse_constraint, pcode::parse_pcode_macro},
};

use super::ast::{
    AlignmentDef, AttachStrDef, AttachValDef, AttachVarDef, BitRangeDef, BitRangeItem,
    ConstructorDef, ContextDef, EndiannessDef, FieldDef, MacroDef, PcodeOpDef, RegisterDef,
    SleighFile, SleighItem, SpaceDef, TokenDef, TriviaToken, UnresolvedAction,
    UnresolvedDisplayToken, UnresolvedExpr, WithBlockDef,
};

// ── SleighFile AST builder ────────────────────────────────────────────────────

static AST_ACTION_PRATT: LazyLock<PrattParser<Rule>> = LazyLock::new(|| {
    use Assoc::*;
    PrattParser::new()
        .op(Op::infix(Rule::action_or, Left))
        .op(Op::infix(Rule::action_xor, Left))
        .op(Op::infix(Rule::action_and, Left))
        .op(Op::infix(Rule::action_shl, Left) | Op::infix(Rule::action_shr, Left))
        .op(Op::infix(Rule::action_plus, Left) | Op::infix(Rule::action_sub, Left))
        .op(Op::infix(Rule::action_times, Left) | Op::infix(Rule::action_div, Left))
        .op(Op::prefix(Rule::operator_minus) | Op::prefix(Rule::operator_not))
});

/// Builds a typed [`SleighFile`] AST from a Pest `sleigh_program` pair.
///
/// No symbol tables are touched — all cross-references remain as [`Box<str>`]
/// names. P-code bodies are parsed immediately using a fresh [`SpecBuilder`]
/// so that deferred global name references are preserved for Phase 3.
pub(crate) fn build_sleigh_ast(
    program: Pair<'_, Rule>,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> Result<SleighFile, Vec<Diagnostic>> {
    let (items, errors) = collect_items(program.into_inner(), sources, prepared);
    if errors.is_empty() {
        Ok(SleighFile { items })
    } else {
        Err(errors)
    }
}

fn collect_items<'a>(
    pairs: impl Iterator<Item = Pair<'a, Rule>>,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> (Vec<SleighItem>, Vec<Diagnostic>) {
    let mut items = Vec::new();
    let mut errors = Vec::new();
    let mut pending: Vec<TriviaToken> = Vec::new();

    for pair in pairs {
        match pair.as_rule() {
            Rule::WHITESPACE | Rule::COMMENT => {
                let span = sources.map_preprocessed_bytes(
                    prepared,
                    pair.as_span().start(),
                    pair.as_span().end(),
                );
                pending.push(TriviaToken {
                    text: pair.as_str().into(),
                    span,
                });
            }
            Rule::EOI => {}
            _ => match build_item(pair, sources, prepared) {
                Ok(Some(mut item)) => {
                    *item.leading_trivia_mut() = std::mem::take(&mut pending);
                    items.push(item);
                }
                Ok(None) => pending.clear(),
                Err(diag) => {
                    pending.clear();
                    errors.push(*diag);
                }
            },
        }
    }
    (items, errors)
}

fn build_item<'a>(
    pair: Pair<'a, Rule>,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> BuildResult<Option<SleighItem>> {
    let ps = pair.as_span();
    let span = sources.map_preprocessed_bytes(prepared, ps.start(), ps.end());
    Ok(match pair.as_rule() {
        Rule::endianness_def => Some(SleighItem::Endianness(build_endianness(pair, span))),
        Rule::alignment_def => Some(SleighItem::Alignment(build_alignment(pair, span))),
        Rule::space_def => Some(SleighItem::Space(build_space(pair, span))),
        Rule::register_def => Some(SleighItem::Register(build_register(pair, span))),
        Rule::bitrange_def => Some(SleighItem::BitRange(build_bitrange(pair, span))),
        Rule::pcodeop_def => Some(SleighItem::PcodeOp(build_pcodeop(pair, span))),
        Rule::token_def => Some(SleighItem::Token(build_token(
            pair, span, sources, prepared,
        ))),
        Rule::context_def => Some(SleighItem::Context(build_context(
            pair, span, sources, prepared,
        ))),
        Rule::attach_var => Some(SleighItem::AttachVar(build_attach_var(pair, span))),
        Rule::attach_val => Some(SleighItem::AttachVal(build_attach_val(pair, span))),
        Rule::attach_str => Some(SleighItem::AttachStr(build_attach_str(pair, span))),
        Rule::r#macro => Some(SleighItem::Macro(build_macro(
            pair, span, sources, prepared,
        )?)),
        Rule::constructor => Some(SleighItem::Constructor(build_constructor(
            pair, span, sources, prepared,
        )?)),
        Rule::with_block => Some(SleighItem::WithBlock(build_with_block(
            pair, span, sources, prepared,
        )?)),
        _ => None,
    })
}

fn build_endianness(pair: Pair<'_, Rule>, span: crate::source::Span) -> EndiannessDef {
    let big_endian = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::endian)
        .and_then(|endian| {
            endian
                .into_inner()
                .find(|p| matches!(p.as_rule(), Rule::keyword_big | Rule::keyword_little))
        })
        .map(|p| p.as_rule() == Rule::keyword_big)
        .unwrap_or(false);
    EndiannessDef {
        span,
        big_endian,
        leading_trivia: Vec::new(),
    }
}

fn build_alignment(pair: Pair<'_, Rule>, span: crate::source::Span) -> AlignmentDef {
    let alignment = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::integer)
        .map(ast_parse_int)
        .unwrap_or(1);
    AlignmentDef {
        span,
        alignment,
        leading_trivia: Vec::new(),
    }
}

fn build_space(pair: Pair<'_, Rule>, span: crate::source::Span) -> SpaceDef {
    let children: Vec<_> = pair.into_inner().collect();
    let name = children
        .iter()
        .find(|p| p.as_rule() == Rule::identifier)
        .map(|p| p.as_str().into())
        .unwrap_or_else(|| "".into());
    let mut ty = SpaceType::Ram;
    let mut addr_size = 4;
    let mut word_size = 1;
    let mut is_default = false;

    for attr in children.iter().filter(|p| p.as_rule() == Rule::space_attr) {
        let Some(child) = attr.clone().into_inner().next() else {
            continue;
        };
        match child.as_rule() {
            Rule::type_attr => {
                if let Some(ty_kw) = child.into_inner().find(|p| {
                    matches!(
                        p.as_rule(),
                        Rule::keyword_ram_space
                            | Rule::keyword_rom_space
                            | Rule::keyword_register_space
                    )
                }) {
                    ty = match ty_kw.as_rule() {
                        Rule::keyword_ram_space => SpaceType::Ram,
                        Rule::keyword_rom_space => SpaceType::Rom,
                        Rule::keyword_register_space => SpaceType::Register,
                        _ => SpaceType::Ram,
                    };
                }
            }
            Rule::size_attr => {
                if let Some(int) = child.into_inner().find(|p| p.as_rule() == Rule::integer) {
                    addr_size = ast_parse_int(int);
                }
            }
            Rule::default_attr => is_default = true,
            Rule::wordsize_attr => {
                if let Some(int) = child.into_inner().find(|p| p.as_rule() == Rule::integer) {
                    word_size = ast_parse_int(int);
                }
            }
            _ => {}
        }
    }
    SpaceDef {
        span,
        name,
        ty,
        addr_size,
        word_size,
        is_default,
        leading_trivia: Vec::new(),
    }
}

fn build_register(pair: Pair<'_, Rule>, span: crate::source::Span) -> RegisterDef {
    let children: Vec<_> = pair.into_inner().collect();
    let space = children
        .iter()
        .find(|p| p.as_rule() == Rule::identifier)
        .map(|p| p.as_str().into())
        .unwrap_or_else(|| "".into());
    let ints: Vec<_> = children
        .iter()
        .filter(|p| p.as_rule() == Rule::integer)
        .collect();
    let offset = ints
        .first()
        .map(|p| ast_parse_int((*p).clone()))
        .unwrap_or(0);
    let size = ints
        .get(1)
        .map(|p| ast_parse_int((*p).clone()))
        .unwrap_or(1);
    let names = children
        .into_iter()
        .find(|p| p.as_rule() == Rule::string_list)
        .map(|list| {
            ast_list_items(list)
                .into_iter()
                .map(|p| {
                    if ast_is_underscore(&p) {
                        None
                    } else {
                        Some(ast_unquote(p.as_str()).into())
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    RegisterDef {
        span,
        space,
        offset,
        size,
        names,
        leading_trivia: Vec::new(),
    }
}

fn build_bitrange(pair: Pair<'_, Rule>, span: crate::source::Span) -> BitRangeDef {
    let items = pair
        .into_inner()
        .filter(|p| p.as_rule() == Rule::bitrange_item)
        .map(|item| {
            let children: Vec<_> = item.into_inner().collect();
            let ids: Vec<_> = children
                .iter()
                .filter(|p| p.as_rule() == Rule::identifier)
                .collect();
            let ints: Vec<_> = children
                .iter()
                .filter(|p| p.as_rule() == Rule::integer)
                .collect();
            BitRangeItem {
                name: ids
                    .first()
                    .map(|p| p.as_str().into())
                    .unwrap_or_else(|| "".into()),
                register: ids
                    .get(1)
                    .map(|p| p.as_str().into())
                    .unwrap_or_else(|| "".into()),
                low: ints
                    .first()
                    .map(|p| ast_parse_int((*p).clone()))
                    .unwrap_or(0),
                high: ints
                    .get(1)
                    .map(|p| ast_parse_int((*p).clone()))
                    .unwrap_or(0),
            }
        })
        .collect();
    BitRangeDef {
        span,
        items,
        leading_trivia: Vec::new(),
    }
}

fn build_pcodeop(pair: Pair<'_, Rule>, span: crate::source::Span) -> PcodeOpDef {
    let name = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::identifier)
        .map(|p| p.as_str().into())
        .unwrap_or_else(|| "".into());
    PcodeOpDef {
        span,
        name,
        leading_trivia: Vec::new(),
    }
}

fn build_field(pair: Pair<'_, Rule>, sources: &SourceDb, prepared: PreparedSourceId) -> FieldDef {
    let ps = pair.as_span();
    let span = sources.map_preprocessed_bytes(prepared, ps.start(), ps.end());
    let children: Vec<_> = pair.into_inner().collect();
    let name = children
        .iter()
        .find(|p| p.as_rule() == Rule::identifier)
        .map(|p| p.as_str().into())
        .unwrap_or_else(|| "".into());
    let ints: Vec<_> = children
        .iter()
        .filter(|p| p.as_rule() == Rule::integer)
        .collect();
    let low = ints
        .first()
        .map(|p| ast_parse_int((*p).clone()))
        .unwrap_or(0);
    let high = ints
        .get(1)
        .map(|p| ast_parse_int((*p).clone()))
        .unwrap_or(0);
    let attribute = |want: &str| {
        children
            .iter()
            .any(|p| p.as_rule() == Rule::field_attributes && p.as_str() == want)
    };
    FieldDef {
        span,
        name,
        low,
        high,
        signed: attribute("signed"),
        noflow: attribute("noflow"),
    }
}

fn build_token(
    pair: Pair<'_, Rule>,
    span: crate::source::Span,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> TokenDef {
    let children: Vec<_> = pair.into_inner().collect();
    let name = children
        .iter()
        .find(|p| p.as_rule() == Rule::identifier)
        .map(|p| p.as_str().into())
        .unwrap_or_else(|| "".into());
    let size = children
        .iter()
        .find(|p| p.as_rule() == Rule::integer)
        .map(|p| ast_parse_int(p.clone()))
        .unwrap_or(0);
    // `token_endian` wraps an optional `endian`, which in turn wraps the
    // keyword: descending only one level compared the `endian` rule itself
    // against `keyword_big`, so every token read as little-endian regardless of
    // what it declared.
    let endian = children
        .iter()
        .find(|p| p.as_rule() == Rule::token_endian)
        .and_then(|p| p.clone().into_inner().find(|p| p.as_rule() == Rule::endian))
        .and_then(|endian| {
            endian
                .into_inner()
                .find(|p| matches!(p.as_rule(), Rule::keyword_big | Rule::keyword_little))
        })
        .map(|kw| kw.as_rule() == Rule::keyword_big);
    let fields = children
        .into_iter()
        .filter(|p| p.as_rule() == Rule::field_def)
        .map(|p| build_field(p, sources, prepared))
        .collect();
    TokenDef {
        span,
        name,
        size,
        endian,
        fields,
        leading_trivia: Vec::new(),
    }
}

fn build_context(
    pair: Pair<'_, Rule>,
    span: crate::source::Span,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> ContextDef {
    let children: Vec<_> = pair.into_inner().collect();
    let register = children
        .iter()
        .find(|p| p.as_rule() == Rule::identifier)
        .map(|p| p.as_str().into())
        .unwrap_or_else(|| "".into());
    let fields = children
        .into_iter()
        .filter(|p| p.as_rule() == Rule::field_def)
        .map(|p| build_field(p, sources, prepared))
        .collect();
    ContextDef {
        span,
        register,
        fields,
        leading_trivia: Vec::new(),
    }
}

fn build_attach_var(pair: Pair<'_, Rule>, span: crate::source::Span) -> AttachVarDef {
    let mut lists = pair
        .into_inner()
        .filter(|p| matches!(p.as_rule(), Rule::identifier_list | Rule::string_list));
    let fields = lists
        .next()
        .map(|list| {
            ast_list_items(list)
                .into_iter()
                .map(|p| p.as_str().into())
                .collect()
        })
        .unwrap_or_default();
    let registers = lists
        .next()
        .map(|list| {
            ast_list_items(list)
                .into_iter()
                .map(|p| {
                    if ast_is_underscore(&p) {
                        None
                    } else {
                        Some(ast_unquote(p.as_str()).into())
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    AttachVarDef {
        span,
        fields,
        registers,
        leading_trivia: Vec::new(),
    }
}

fn build_attach_str(pair: Pair<'_, Rule>, span: crate::source::Span) -> AttachStrDef {
    let mut lists = pair
        .into_inner()
        .filter(|p| matches!(p.as_rule(), Rule::identifier_list | Rule::string_list));
    let fields = lists
        .next()
        .map(|list| {
            ast_list_items(list)
                .into_iter()
                .map(|p| p.as_str().into())
                .collect()
        })
        .unwrap_or_default();
    let names = lists
        .next()
        .map(|list| {
            ast_list_items(list)
                .into_iter()
                .map(|p| {
                    if ast_is_underscore(&p) {
                        None
                    } else {
                        Some(ast_unquote(p.as_str()).into())
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    AttachStrDef {
        span,
        fields,
        names,
        leading_trivia: Vec::new(),
    }
}

fn build_attach_val(pair: Pair<'_, Rule>, span: crate::source::Span) -> AttachValDef {
    let mut lists = pair
        .into_inner()
        .filter(|p| matches!(p.as_rule(), Rule::identifier_list | Rule::integer_list));
    let fields = lists
        .next()
        .map(|list| {
            ast_list_items(list)
                .into_iter()
                .map(|p| p.as_str().into())
                .collect()
        })
        .unwrap_or_default();
    let values = lists
        .next()
        .map(|list| {
            ast_list_items(list)
                .into_iter()
                .map(|item| match item.as_rule() {
                    Rule::punctuation_underscore => None,
                    _ => Some(ast_parse_signed_int(item)),
                })
                .collect()
        })
        .unwrap_or_default();
    AttachValDef {
        span,
        fields,
        values,
        leading_trivia: Vec::new(),
    }
}

fn build_macro<'a>(
    pair: Pair<'a, Rule>,
    span: crate::source::Span,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> BuildResult<MacroDef> {
    let children: Vec<_> = pair.into_inner().collect();
    let name: Box<str> = children
        .iter()
        .find(|p| p.as_rule() == Rule::identifier)
        .map(|p| p.as_str().into())
        .unwrap_or_else(|| "".into());
    let arg_names: Vec<&str> = children
        .iter()
        .find(|p| p.as_rule() == Rule::macro_args)
        .map(|p| {
            p.clone()
                .into_inner()
                .filter(|p| p.as_rule() == Rule::identifier)
                .map(|p| p.as_str())
                .collect()
        })
        .unwrap_or_default();
    let args: Vec<Box<str>> = arg_names.iter().map(|s| (*s).into()).collect();
    let semantics = children
        .into_iter()
        .find(|p| p.as_rule() == Rule::semantics);
    let pcode = match semantics {
        Some(sem) => parse_pcode_macro(sem, arg_names)
            .map_err(|e| pcode_error_to_diagnostic(e, sources, prepared))?,
        None => crate::pmacro::PCodeMacro::empty(),
    };
    Ok(MacroDef {
        span,
        name,
        args,
        pcode,
        leading_trivia: Vec::new(),
    })
}

fn build_constructor<'a>(
    pair: Pair<'a, Rule>,
    span: crate::source::Span,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> BuildResult<ConstructorDef> {
    let children: Vec<_> = pair.into_inner().collect();
    let table = children
        .iter()
        .find(|p| p.as_rule() == Rule::table_header)
        .and_then(|hdr| {
            hdr.clone()
                .into_inner()
                .find(|p| p.as_rule() == Rule::identifier)
        })
        .map(|p| p.as_str().into());
    let constraint = children
        .iter()
        .find(|p| p.as_rule() == Rule::bit_pattern)
        .map(|p| parse_constraint(p.clone(), sources, prepared))
        .unwrap_or_else(|| crate::constraint::ConstraintAst {
            value: crate::constraint::BitPatternAstNode::Int(0),
            span,
        });
    let display_pair = children
        .iter()
        .find(|p| p.as_rule() == Rule::display)
        .cloned();
    let is_start = display_pair
        .as_ref()
        .map(|p| p.as_span().end().saturating_sub(2))
        .unwrap_or(0);
    let display = display_pair
        .map(|p| build_display_tokens(p))
        .unwrap_or_default();
    let actions = children
        .iter()
        .find(|p| p.as_rule() == Rule::actions)
        .map(|p| build_actions(p.clone()))
        .unwrap_or_default();
    let semantics = children
        .into_iter()
        .find(|p| p.as_rule() == Rule::semantics);
    let pcode = match semantics {
        Some(sem) => parse_pcode_macro(sem, Vec::new())
            .map_err(|e| pcode_error_to_diagnostic(e, sources, prepared))?,
        None => crate::pmacro::PCodeMacro::empty(),
    };
    Ok(ConstructorDef {
        span,
        table,
        constraint,
        display,
        is_start,
        actions,
        pcode,
        leading_trivia: Vec::new(),
    })
}

fn build_with_block<'a>(
    pair: Pair<'a, Rule>,
    span: crate::source::Span,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> BuildResult<WithBlockDef> {
    let children: Vec<_> = pair.into_inner().collect();
    let table = children
        .iter()
        .find(|p| p.as_rule() == Rule::table_header)
        .and_then(|hdr| {
            hdr.clone()
                .into_inner()
                .find(|p| p.as_rule() == Rule::identifier)
        })
        .map(|p| p.as_str().into());
    let constraint = children
        .iter()
        .find(|p| p.as_rule() == Rule::bit_pattern)
        .map(|p| parse_constraint(p.clone(), sources, prepared))
        .unwrap_or_else(|| crate::constraint::ConstraintAst {
            value: crate::constraint::BitPatternAstNode::Int(0),
            span,
        });
    let actions = children
        .iter()
        .find(|p| p.as_rule() == Rule::actions)
        .map(|p| build_actions(p.clone()))
        .unwrap_or_default();
    let (items, errors) = collect_items(children.into_iter(), sources, prepared);
    if let Some(first_error) = errors.into_iter().next() {
        return Err(Box::new(first_error));
    }
    Ok(WithBlockDef {
        span,
        table,
        constraint,
        actions,
        items,
        leading_trivia: Vec::new(),
    })
}

fn build_actions(pair: Pair<'_, Rule>) -> Vec<UnresolvedAction> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::action)
        .map(build_action)
        .collect()
}

fn build_action(pair: Pair<'_, Rule>) -> UnresolvedAction {
    // `action` wraps exactly one of `action_globalset` / `action_assign`.
    let inner = pair
        .into_inner()
        .find(|p| matches!(p.as_rule(), Rule::action_globalset | Rule::action_assign));
    let Some(inner) = inner else {
        return UnresolvedAction::Assign {
            field: "".into(),
            expr: UnresolvedExpr::Int(0),
        };
    };
    let is_globalset = inner.as_rule() == Rule::action_globalset;

    let children: Vec<_> = inner
        .into_inner()
        .filter(|p| !matches!(p.as_rule(), Rule::WHITESPACE | Rule::COMMENT))
        .collect();
    let field = children
        .iter()
        .find(|p| p.as_rule() == Rule::identifier)
        .map(|p| p.as_str().into())
        .unwrap_or_else(|| "".into());
    let expr = children
        .into_iter()
        .find(|p| p.as_rule() == Rule::action_expression)
        .map(build_action_expr)
        .unwrap_or(UnresolvedExpr::Int(0));

    if is_globalset {
        UnresolvedAction::GlobalSet { addr: expr, field }
    } else {
        UnresolvedAction::Assign { field, expr }
    }
}

fn build_action_expr(pair: Pair<'_, Rule>) -> UnresolvedExpr {
    AST_ACTION_PRATT
        .map_primary(build_action_primary)
        .map_prefix(|op, rhs| {
            let op = match op.as_rule() {
                Rule::operator_minus => ActionUnOp::Neg,
                Rule::operator_not => ActionUnOp::Not,
                _ => ActionUnOp::Neg,
            };
            UnresolvedExpr::Unary {
                op,
                expr: Box::new(rhs),
            }
        })
        .map_infix(|lhs, op, rhs| {
            let bin_op = match op.as_rule() {
                Rule::action_or => ActionBinOp::Or,
                Rule::action_xor => ActionBinOp::Xor,
                Rule::action_and => ActionBinOp::And,
                Rule::action_shl => ActionBinOp::Shl,
                Rule::action_shr => ActionBinOp::Shr,
                Rule::action_plus => ActionBinOp::Add,
                Rule::action_sub => ActionBinOp::Sub,
                Rule::action_times => ActionBinOp::Mul,
                Rule::action_div => ActionBinOp::Div,
                _ => ActionBinOp::Or,
            };
            UnresolvedExpr::Binary {
                op: bin_op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            }
        })
        .parse(ast_non_trivia(pair.into_inner()))
}

fn build_action_primary(pair: Pair<'_, Rule>) -> UnresolvedExpr {
    match pair.as_rule() {
        Rule::identifier => UnresolvedExpr::Ident(pair.as_str().into()),
        Rule::integer => UnresolvedExpr::Int(ast_parse_int(pair) as i64),
        Rule::action_expression | Rule::action_binop => build_action_expr(pair),
        Rule::action_paren => {
            let inner = pair
                .into_inner()
                .find(|p| p.as_rule() == Rule::action_binop)
                .expect("action_paren has action_binop");
            build_action_expr(inner)
        }
        _ => UnresolvedExpr::Int(0),
    }
}

fn build_display_tokens(pair: Pair<'_, Rule>) -> Vec<UnresolvedDisplayToken> {
    debug_assert_eq!(pair.as_rule(), Rule::display);

    let mut tokens: Vec<UnresolvedDisplayToken> = Vec::new();
    // `pending_space` is set when whitespace is seen; flushed before the next real token.
    // `suppress_space` suppresses the pending space — set initially (no leading space) and
    // by `^` (SLEIGH's "no-space" operator).
    let mut pending_space = false;
    let mut suppress_space = true;

    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::punctuation_colon | Rule::keyword_is => {}
            Rule::WHITESPACE => {
                if !suppress_space {
                    pending_space = true;
                }
            }
            Rule::punctuation_carret => {
                pending_space = false;
                suppress_space = true;
            }
            rule => {
                if pending_space {
                    tokens.push(UnresolvedDisplayToken::Literal(" ".into()));
                    pending_space = false;
                }
                suppress_space = false;
                match rule {
                    Rule::quoted_string => {
                        let text = child.as_str();
                        let content = text
                            .strip_prefix('"')
                            .and_then(|s| s.strip_suffix('"'))
                            .unwrap_or(text);
                        tokens.push(UnresolvedDisplayToken::Literal(content.into()));
                    }
                    Rule::identifier => {
                        tokens.push(UnresolvedDisplayToken::Ident(child.as_str().into()));
                    }
                    Rule::literal_char => {
                        tokens.push(UnresolvedDisplayToken::Literal(child.as_str().into()));
                    }
                    _ => {}
                }
            }
        }
    }

    tokens
}

// ── AST builder utilities ─────────────────────────────────────────────────────

/// Parses an integer literal, or a negated one from an `attach values` list.
///
/// A negative value is returned as its two's-complement bit pattern, which is
/// how the attach table stores it.
fn ast_parse_signed_int(pair: Pair<'_, Rule>) -> u64 {
    let text = pair.as_str();
    match text.strip_prefix('-') {
        Some(magnitude) => (parse_int_str(magnitude) as u64).wrapping_neg(),
        None => parse_int_str(text) as u64,
    }
}

fn ast_parse_int(pair: Pair<'_, Rule>) -> usize {
    parse_int_str(pair.as_str())
}

fn parse_int_str(s: &str) -> usize {
    if let Some(hex) = s.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).unwrap_or(0)
    } else if let Some(bin) = s.strip_prefix("0b") {
        usize::from_str_radix(bin, 2).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn ast_list_items(pair: Pair<'_, Rule>) -> Vec<Pair<'_, Rule>> {
    pair.into_inner()
        .filter(|p| {
            matches!(
                p.as_rule(),
                Rule::identifier
                    | Rule::integer
                    | Rule::signed_integer
                    | Rule::quoted_string
                    | Rule::punctuation_underscore
            )
        })
        .collect()
}

fn ast_is_underscore(pair: &Pair<'_, Rule>) -> bool {
    pair.as_rule() == Rule::punctuation_underscore || pair.as_str() == "_"
}

fn ast_unquote(text: &str) -> &str {
    text.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(text)
}

fn ast_non_trivia(pairs: Pairs<'_, Rule>) -> impl Iterator<Item = Pair<'_, Rule>> {
    pairs.filter(|p| !matches!(p.as_rule(), Rule::WHITESPACE | Rule::COMMENT))
}

fn pcode_error_to_diagnostic(
    err: crate::pcode_error::PcodeError,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> Diagnostic {
    let root = sources
        .prepared_root(prepared)
        .expect("prepared source has root file");
    let primary = err
        .span
        .and_then(|(s, e)| sources.try_map_preprocessed_bytes(prepared, s, e))
        .unwrap_or_else(|| Span::file_level(root));
    Diagnostic::error(DiagnosticCode::Parse, err.to_string(), primary)
}
