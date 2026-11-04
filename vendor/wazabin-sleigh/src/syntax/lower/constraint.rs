//! Raw lowering for constructor bit-pattern constraints.
//!
//! The constraint grammar is expression-shaped and precedence-sensitive, so it
//! uses a small Pratt parser before producing the `ConstraintAst` consumed by
//! constructor matching.

use std::sync::LazyLock;

use crate::constraint::{BitPatternAstNode, BitVerb, ConstraintAst, ConstraintVerb, ValueVerb};
use crate::raw_parsing::{Rule, unreachable_rule};
use crate::source::{PreparedSourceId, SourceDb, Span};
use pest::iterators::{Pair, Pairs};
use pest::pratt_parser::{Assoc, Op, PrattParser};

static CONSTRAINT_PRATT: LazyLock<PrattParser<Rule>> = LazyLock::new(|| {
    use Assoc::*;

    PrattParser::new()
        .op(Op::infix(Rule::operator_cat, Left))
        .op(Op::infix(Rule::operator_or, Left))
        .op(Op::infix(Rule::operator_and, Left))
        .op(Op::postfix(Rule::operator_ellipsis))
        // A leading `...` is a distinct grammar rule so that it can be a
        // prefix operator here: pest's Pratt table cannot hold one rule as
        // both prefix and postfix.
        .op(Op::prefix(Rule::operator_ellipsis_left))
        .op(Op::infix(Rule::constraint_verb, Left))
        // Tightest bindings last: shift < add/sub < mul/div, as in C.
        .op(Op::infix(Rule::cs_op_shift, Left))
        .op(Op::infix(Rule::cs_op_add, Left))
        .op(Op::infix(Rule::cs_op_mul, Left))
});

pub(crate) fn parse_constraint(
    pair: Pair<'_, Rule>,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> ConstraintAst {
    debug_assert_eq!(pair.as_rule(), Rule::bit_pattern);
    parse_constraint_expr(pair, sources, prepared)
}

fn pair_span(pair: &Pair<'_, Rule>, sources: &SourceDb, prepared: PreparedSourceId) -> Span {
    let ps = pair.as_span();
    sources.map_preprocessed_bytes(prepared, ps.start(), ps.end())
}

fn merge_spans(lhs: Span, rhs: Span) -> Span {
    Span {
        file: lhs.file,
        start: lhs.start,
        end: rhs.end,
        start_line: lhs.start_line,
        start_col: lhs.start_col,
        end_line: rhs.end_line,
        end_col: rhs.end_col,
    }
}

fn parse_constraint_expr(
    pair: Pair<'_, Rule>,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> ConstraintAst {
    CONSTRAINT_PRATT
        .map_primary(|p| parse_constraint_primary(p, sources, prepared))
        .map_prefix(|p, rhs| parse_constraint_prefix(p, rhs, sources, prepared))
        .map_postfix(|lhs, p| parse_constraint_postfix(lhs, p, sources, prepared))
        .map_infix(|lhs, p, rhs| parse_constraint_infix(lhs, p, rhs, sources, prepared))
        .parse(non_trivia(pair.into_inner()))
}

fn parse_constraint_primary(
    pair: Pair<'_, Rule>,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> ConstraintAst {
    let span = pair_span(&pair, sources, prepared);
    match pair.as_rule() {
        Rule::identifier => ConstraintAst {
            value: BitPatternAstNode::Ident(pair.as_str().into()),
            span,
        },
        Rule::integer => ConstraintAst {
            value: BitPatternAstNode::Int(parse_int(pair) as u64),
            span,
        },
        Rule::bit_pattern | Rule::constraint_expression => {
            parse_constraint_expr(pair, sources, prepared)
        }
        Rule::bit_pattern_paren => parse_constraint(
            pair.into_inner()
                .find(|p| p.as_rule() == Rule::bit_pattern)
                .expect("bit-pattern paren has bit pattern"),
            sources,
            prepared,
        ),
        Rule::constraint_expression_paren => parse_constraint_expr(
            pair.into_inner()
                .find(|p| p.as_rule() == Rule::constraint_expression)
                .expect("constraint-expression paren has expression"),
            sources,
            prepared,
        ),
        _ => unreachable_rule!(pair),
    }
}

fn parse_constraint_prefix(
    pair: Pair<'_, Rule>,
    rhs: ConstraintAst,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> ConstraintAst {
    match pair.as_rule() {
        Rule::operator_ellipsis_left => ConstraintAst {
            value: BitPatternAstNode::LElipsis(Box::new(rhs)),
            span: pair_span(&pair, sources, prepared),
        },
        _ => unreachable_rule!(pair),
    }
}

fn parse_constraint_postfix(
    lhs: ConstraintAst,
    pair: Pair<'_, Rule>,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> ConstraintAst {
    match pair.as_rule() {
        Rule::operator_ellipsis => ConstraintAst {
            value: BitPatternAstNode::RElipsis(Box::new(lhs)),
            span: pair_span(&pair, sources, prepared),
        },
        _ => unreachable_rule!(pair),
    }
}

fn parse_constraint_infix(
    lhs: ConstraintAst,
    pair: Pair<'_, Rule>,
    rhs: ConstraintAst,
    sources: &SourceDb,
    prepared: PreparedSourceId,
) -> ConstraintAst {
    let _ = (sources, prepared); // span is derived from lhs/rhs
    let span = merge_spans(lhs.span, rhs.span);
    if matches!(pair.as_rule(), Rule::constraint_verb) {
        let lhs_name = match lhs.value {
            BitPatternAstNode::Ident(name) => name,
            _ => unreachable!(),
        };
        return ConstraintAst {
            value: BitPatternAstNode::Constraint {
                lhs: lhs_name,
                op: match pair.as_str() {
                    "=" => ConstraintVerb::Eq,
                    "!=" => ConstraintVerb::Ne,
                    "<" => ConstraintVerb::Lt,
                    "<=" => ConstraintVerb::Le,
                    ">" => ConstraintVerb::Gt,
                    ">=" => ConstraintVerb::Ge,
                    _ => unreachable_rule!(pair),
                },
                rhs: Box::new(rhs),
            },
            span,
        };
    }
    if matches!(
        pair.as_rule(),
        Rule::cs_op_shift | Rule::cs_op_add | Rule::cs_op_mul
    ) {
        return ConstraintAst {
            value: BitPatternAstNode::ValueBinOp {
                lhs: Box::new(lhs),
                op: match pair.as_str() {
                    "+" => ValueVerb::Add,
                    "-" => ValueVerb::Sub,
                    "*" => ValueVerb::Mul,
                    "/" => ValueVerb::Div,
                    "<<" => ValueVerb::Shl,
                    ">>" => ValueVerb::Shr,
                    _ => unreachable_rule!(pair),
                },
                rhs: Box::new(rhs),
            },
            span,
        };
    }
    ConstraintAst {
        value: BitPatternAstNode::BinOp {
            lhs: Box::new(lhs),
            op: match pair.as_str() {
                "&" => BitVerb::And,
                "|" => BitVerb::Or,
                ";" => BitVerb::Cat,
                _ => unreachable_rule!(pair),
            },
            rhs: Box::new(rhs),
        },
        span,
    }
}

fn non_trivia(pairs: Pairs<'_, Rule>) -> impl Iterator<Item = Pair<'_, Rule>> {
    pairs.filter(|pair| !matches!(pair.as_rule(), Rule::WHITESPACE | Rule::COMMENT))
}

fn parse_int(pair: Pair<'_, Rule>) -> usize {
    debug_assert_eq!(pair.as_rule(), Rule::integer);
    let s = pair.as_str();
    if let Some(hex) = s.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).unwrap()
    } else if let Some(bin) = s.strip_prefix("0b") {
        usize::from_str_radix(bin, 2).unwrap()
    } else {
        s.parse().unwrap()
    }
}
