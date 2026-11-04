//! Raw lowering for semantic p-code blocks.
//!
//! SLEIGH constructor bodies and `macro` definitions use this language. It has
//! the richest expression grammar in the raw frontend, so the statement parser,
//! expression Pratt parser, and p-code-specific name resolution live together.

use std::sync::LazyLock;

use crate::pcode_error::{PcodeError, PcodeErrorTy, PcodeResult};
use crate::pmacro::{
    PCodeMacro,
    expression::{
        BinaryOperator, Expression, ExpressionTy, Ident, Load, LocalVarInterner, Range, RangeParam,
        SpaceRef, Unop,
    },
    statement::{Ast, AstNode, DelaySlotArg, LabelOrNode},
};
use crate::raw_parsing::{Rule, unreachable_rule};
use pest::{
    iterators::{Pair, Pairs},
    pratt_parser::{Assoc, Op, PrattParser},
};

static PCODE_PRATT: LazyLock<PrattParser<Rule>> = LazyLock::new(|| {
    use Assoc::*;

    PrattParser::new()
        .op(Op::infix(Rule::operator_or_log, Left))
        .op(Op::infix(Rule::operator_xor_log, Left))
        .op(Op::infix(Rule::operator_and_log, Left))
        .op(Op::infix(Rule::operator_or, Left))
        .op(Op::infix(Rule::operator_xor, Left))
        .op(Op::infix(Rule::operator_and, Left))
        .op(Op::infix(Rule::operator_eq, Left)
            | Op::infix(Rule::operator_not_equal, Left)
            | Op::infix(Rule::operator_feq, Left)
            | Op::infix(Rule::operator_fne, Left))
        .op(Op::infix(Rule::operator_less, Left)
            | Op::infix(Rule::operator_greater, Left)
            | Op::infix(Rule::operator_le, Left)
            | Op::infix(Rule::operator_ge, Left)
            | Op::infix(Rule::operator_slt, Left)
            | Op::infix(Rule::operator_sgt, Left)
            | Op::infix(Rule::operator_sle, Left)
            | Op::infix(Rule::operator_sge, Left)
            | Op::infix(Rule::operator_flt, Left)
            | Op::infix(Rule::operator_fgt, Left)
            | Op::infix(Rule::operator_fle, Left)
            | Op::infix(Rule::operator_fge, Left))
        .op(Op::infix(Rule::operator_shift_l, Left)
            | Op::infix(Rule::operator_shift_r, Left)
            | Op::infix(Rule::operator_sshr, Left))
        .op(Op::infix(Rule::operator_plus, Left)
            | Op::infix(Rule::operator_minus, Left)
            | Op::infix(Rule::operator_fadd, Left)
            | Op::infix(Rule::operator_fsub, Left))
        .op(Op::infix(Rule::operator_times, Left)
            | Op::infix(Rule::operator_div, Left)
            | Op::infix(Rule::operator_sdiv, Left)
            | Op::infix(Rule::operator_mod, Left)
            | Op::infix(Rule::operator_smod, Left)
            | Op::infix(Rule::operator_fmul, Left)
            | Op::infix(Rule::operator_fdiv, Left))
        .op(Op::prefix(Rule::operator_not_log)
            | Op::prefix(Rule::op_not_log)
            | Op::prefix(Rule::op_not_bit)
            | Op::prefix(Rule::op_minus)
            | Op::prefix(Rule::op_fminus)
            | Op::prefix(Rule::op_addr_size)
            | Op::prefix(Rule::op_addr))
});

/// Rejects a `delayslot(...)` that is not a well-formed directive.
///
/// `delayslot_stmt` claims the two forms the language allows, ahead of
/// `expr_stmt`. Anything else with that name reaches the *expression* parser,
/// where SLEIGH's `x(n)` truncation syntax would read it as a subpiece of an
/// implicit local — a statement reading an uninitialized temporary. Every
/// delay-slot architecture uses this directive on every branch, so a silent
/// misreading would corrupt all of them.
fn reject_delayslot(name: &Pair<'_, Rule>) -> PcodeResult<()> {
    if name.as_str() == "delayslot" {
        return Err(PcodeError::new(
            PcodeErrorTy::Unsupported(
                "`delayslot` is a statement taking one constant or field, not an expression".into(),
            ),
            bspan(name),
        ));
    }
    Ok(())
}

fn bspan(pair: &Pair<'_, Rule>) -> (usize, usize) {
    let s = pair.as_span();
    (s.start(), s.end())
}

pub(crate) fn parse_pcode_macro<'a>(
    pair: Pair<'a, Rule>,
    arg_names: Vec<&'a str>,
) -> PcodeResult<PCodeMacro> {
    let mut interner = LocalVarInterner::new();
    let args = arg_names
        .iter()
        .map(|name| interner.intern(name))
        .collect::<Vec<_>>();
    let mut body = Vec::new();
    let mut export = None;

    for stmt_pair in pair
        .into_inner()
        .filter(|pair| is_pcode_statement_rule(pair.as_rule()))
    {
        if export.is_some() {
            return Err(PcodeError::export_not_last(bspan(&stmt_pair)));
        }
        let ast = parse_pcode_statement(&mut interner, stmt_pair)?;
        if let AstNode::Export(export_expr) = ast.ty {
            if export.is_some() {
                return Err(PcodeError::multiple_exports(ast.span));
            }
            export = Some(export_expr);
            continue;
        }
        body.push(ast);
    }

    Ok(PCodeMacro {
        args,
        local_var_count: interner.count(),
        body,
        export,
        non_build_table_refs: Vec::new(),
        local_widths: std::collections::HashMap::new(),
        unsized_locals: Vec::new(),
        runtime: std::sync::OnceLock::new(),
    })
}

fn is_pcode_statement_rule(rule: Rule) -> bool {
    matches!(
        rule,
        Rule::delayslot_stmt
            | Rule::definition_stmt
            | Rule::store_stmt
            | Rule::assign_stmt
            | Rule::expr_stmt
            | Rule::build_stmt
            | Rule::export_stmt
            | Rule::branch_stmt
            | Rule::cbranch_stmt
            | Rule::branchind_stmt
            | Rule::call_stmt
            | Rule::call_ind
            | Rule::return_stmt
            | Rule::label
    )
}

fn parse_pcode_statement<'a>(
    interner: &mut LocalVarInterner<'a>,
    pair: Pair<'a, Rule>,
) -> PcodeResult<Ast<(usize, usize)>> {
    let span = bspan(&pair);
    let ty = match pair.as_rule() {
        Rule::definition_stmt => {
            let children = pair.into_inner().collect::<Vec<_>>();
            let name = first_from_slice_q(&children, Rule::identifier)?;
            let size = children
                .iter()
                .find(|pair| pair.as_rule() == Rule::pcode_size)
                .map(|pair| parse_size(pair.clone()));
            let rhs = children
                .iter()
                .find(|pair| pair.as_rule() == Rule::pcode_expr)
                .map(|pair| parse_pcode_expr(interner, pair.clone()))
                .transpose()?;
            AstNode::Assignment {
                lhs: Ident::Named(interner.intern(name.as_str())),
                size,
                rhs: rhs.unwrap_or_else(|| Expression::new_int(0, None, span)),
            }
        }
        Rule::assign_stmt => {
            let children = pair.into_inner().collect::<Vec<_>>();
            let lvalue = children
                .iter()
                .find(|pair| matches!(pair.as_rule(), Rule::identifier | Rule::load | Rule::range))
                .cloned()
                .expect("assignment has lvalue");
            let size = children
                .iter()
                .find(|pair| pair.as_rule() == Rule::pcode_size)
                .map(|pair| parse_size(pair.clone()));
            let rhs = children
                .iter()
                .rev()
                .find(|pair| pair.as_rule() == Rule::pcode_expr)
                .cloned()
                .expect("assignment has rhs");
            let rhs = parse_pcode_expr(interner, rhs)?;
            match lvalue.as_rule() {
                Rule::identifier => AstNode::Assignment {
                    // A sized bare-identifier lvalue (`one:4 = …`) is an implicit
                    // local declaration — intern it here so it shadows any
                    // same-named spec symbol (register/field) for the rest of the
                    // block, matching the explicit `local one:4` (definition_stmt)
                    // path. Without a size it's an ordinary reference, deferred to
                    // Phase 3 resolution via Ident::Global.
                    lhs: match size {
                        Some(_) => Ident::Named(interner.intern(lvalue.as_str())),
                        None => parse_pcode_ident(interner, lvalue)?,
                    },
                    size,
                    rhs,
                },
                Rule::load => AstNode::LoadAssignment {
                    lhs: parse_pcode_load(interner, lvalue)?,
                    size,
                    rhs,
                },
                Rule::range => AstNode::RangeAssignment {
                    lhs: parse_pcode_range(interner, lvalue)?,
                    size,
                    rhs,
                },
                _ => unreachable_rule!(lvalue),
            }
        }
        Rule::store_stmt => {
            let children = pair.into_inner().collect::<Vec<_>>();
            let space = children
                .iter()
                .find(|pair| pair.as_rule() == Rule::space)
                .map(|pair| first_child_q(pair.clone(), Rule::identifier))
                .transpose()?
                .map(|pair| SpaceRef::Deferred(pair.as_str().into()));
            let size = children
                .iter()
                .find(|pair| pair.as_rule() == Rule::pcode_size)
                .map(|pair| parse_size(pair.clone()));
            let mut exprs = children
                .iter()
                .filter(|pair| pair.as_rule() == Rule::pcode_expr);
            let ptr = parse_pcode_expr(
                interner,
                exprs
                    .next()
                    .ok_or_else(|| PcodeError::spanless(PcodeErrorTy::UnknownSize))?
                    .clone(),
            )?;
            let rhs = parse_pcode_expr(
                interner,
                exprs
                    .next()
                    .ok_or_else(|| PcodeError::spanless(PcodeErrorTy::UnknownSize))?
                    .clone(),
            )?;
            AstNode::LoadAssignment {
                lhs: Load {
                    space,
                    size,
                    ptr: Box::new(ptr),
                },
                size: None,
                rhs,
            }
        }
        Rule::expr_stmt => {
            let expr = parse_pcode_expr(interner, first_child_q(pair, Rule::pcode_expr)?)?;
            AstNode::Expression(expr)
        }
        Rule::delayslot_stmt => {
            let arg = pair
                .into_inner()
                .find(|pair| matches!(pair.as_rule(), Rule::integer | Rule::identifier))
                .expect("the grammar requires a delayslot argument");
            AstNode::DelaySlot(match arg.as_rule() {
                Rule::integer => DelaySlotArg::Bytes(parse_int(arg) as u64),
                // Resolved against the symbol table in Phase 3: Phase 2 parses
                // against an empty spec and cannot tell a field from a typo.
                _ => DelaySlotArg::Deferred(arg.as_str().into()),
            })
        }
        Rule::build_stmt => {
            let name = first_child_q(pair, Rule::identifier)?;
            AstNode::DeferredBuild(name.as_str().into())
        }
        Rule::export_stmt => {
            let expr = parse_pcode_expr(interner, first_child_q(pair, Rule::pcode_expr)?)?;
            AstNode::Export(expr)
        }
        Rule::label => {
            let name = first_child_q(pair, Rule::identifier)?;
            AstNode::Label(name.as_str().into())
        }
        Rule::branch_stmt => {
            let target = parse_label_or_node(first_label_or_identifier(pair)?);
            AstNode::Branch { target }
        }
        Rule::cbranch_stmt => {
            let children = pair.into_inner().collect::<Vec<_>>();
            let condition =
                parse_pcode_expr(interner, first_from_slice_q(&children, Rule::pcode_expr)?)?;
            let target = parse_label_or_node(
                children
                    .into_iter()
                    .find(|pair| {
                        matches!(
                            pair.as_rule(),
                            Rule::label | Rule::identifier | Rule::integer
                        )
                    })
                    .expect("conditional branch has target"),
            );
            AstNode::ConditionalBranch { condition, target }
        }
        Rule::branchind_stmt => {
            let target = parse_pcode_expr(interner, first_child_q(pair, Rule::pcode_expr)?)?;
            AstNode::BranchIndirect { target }
        }
        Rule::call_stmt => {
            let target = parse_label_or_node(first_label_or_identifier(pair)?);
            AstNode::Call { target }
        }
        Rule::call_ind => {
            let target = parse_pcode_expr(interner, first_child_q(pair, Rule::pcode_expr)?)?;
            AstNode::CallIndirect { target }
        }
        Rule::return_stmt => {
            let target = parse_pcode_expr(interner, first_child_q(pair, Rule::pcode_expr)?)?;
            AstNode::Return { target }
        }
        _ => unreachable_rule!(pair),
    };
    Ok(Ast { ty, span })
}

fn parse_label_or_node(pair: Pair<'_, Rule>) -> LabelOrNode<(usize, usize)> {
    match pair.as_rule() {
        Rule::label => LabelOrNode::Label(
            pair.into_inner()
                .find(|pair| pair.as_rule() == Rule::identifier)
                .expect("label has identifier")
                .as_str()
                .into(),
        ),
        Rule::identifier => LabelOrNode::Node(pair.as_str().into()),

        // A literal destination is an address in the default space. Its width
        // is not known here — the resolve pass fills it in once the default
        // space is known, the same width `inst_next` gets.
        Rule::integer => {
            let span = bspan(&pair);
            LabelOrNode::Expr(Expression::new_int(parse_int(pair) as u64, None, span))
        }

        _ => unreachable_rule!(pair),
    }
}

fn first_label_or_identifier(pair: Pair<'_, Rule>) -> PcodeResult<Pair<'_, Rule>> {
    pair.into_inner()
        .find(|pair| {
            matches!(
                pair.as_rule(),
                Rule::label | Rule::identifier | Rule::integer
            )
        })
        .ok_or_else(|| PcodeError::spanless(PcodeErrorTy::UnknownSize))
}

fn parse_pcode_expr<'a>(
    interner: &mut LocalVarInterner<'a>,
    pair: Pair<'a, Rule>,
) -> PcodeResult<Expression<(usize, usize)>> {
    debug_assert_eq!(pair.as_rule(), Rule::pcode_expr);
    PCODE_PRATT
        .map_primary(|pair| parse_pcode_primary(interner, pair))
        .map_prefix(|op, expr| Ok(parse_pcode_prefix(op, expr?)))
        .map_infix(|lhs, op, rhs| Ok(parse_pcode_infix(lhs?, op, rhs?)))
        .parse(non_trivia(pair.into_inner()))
}

fn parse_pcode_primary<'a>(
    interner: &mut LocalVarInterner<'a>,
    pair: Pair<'a, Rule>,
) -> PcodeResult<Expression<(usize, usize)>> {
    let span = bspan(&pair);
    let ty = match pair.as_rule() {
        Rule::integer => ExpressionTy::SizedInt {
            value: parse_int(pair) as u64,
            size: None,
        },
        Rule::sized_integer => {
            let mut inner = pair.into_inner();
            let value = parse_int(next_child(&mut inner, Rule::integer).unwrap()) as u64;
            let size = parse_size(next_child(&mut inner, Rule::pcode_size).unwrap());
            ExpressionTy::SizedInt {
                value,
                size: Some(size),
            }
        }
        Rule::subpiece => {
            let child = pair.into_inner().next().expect("subpiece has a child");
            match child.as_rule() {
                Rule::subpiece_msb => {
                    let mut inner = child.into_inner();
                    let name = next_child(&mut inner, Rule::identifier).unwrap();
                    reject_delayslot(&name)?;
                    let src = parse_pcode_ident_expr(interner, name)?;
                    let count = parse_int(next_child(&mut inner, Rule::integer).unwrap());
                    ExpressionTy::SubPieceMsb {
                        src: Box::new(src),
                        count,
                    }
                }
                Rule::subpiece_lsb => {
                    let mut inner = child.into_inner();
                    let src = parse_pcode_ident_expr(
                        interner,
                        next_child(&mut inner, Rule::identifier).unwrap(),
                    )?;
                    let count = parse_int(next_child(&mut inner, Rule::integer).unwrap());
                    ExpressionTy::SubPieceLsb {
                        src: Box::new(src),
                        count,
                    }
                }
                _ => unreachable_rule!(child),
            }
        }
        Rule::identifier => return parse_pcode_ident_expr(interner, pair),
        Rule::range => ExpressionTy::Range(parse_pcode_range(interner, pair)?),
        Rule::load => ExpressionTy::Load(parse_pcode_load(interner, pair)?),
        Rule::func_call => parse_func_call(interner, pair)?,
        Rule::paren_expr => {
            return parse_pcode_expr(interner, first_child_q(pair, Rule::pcode_expr)?);
        }
        Rule::pcode_expr => return parse_pcode_expr(interner, pair),
        _ => unreachable_rule!(pair),
    };
    Ok(Expression {
        size: parsed_expr_size(&ty),
        ty,
        span,
    })
}

fn parse_pcode_ident_expr<'a>(
    interner: &mut LocalVarInterner<'a>,
    pair: Pair<'a, Rule>,
) -> PcodeResult<Expression<(usize, usize)>> {
    let span = bspan(&pair);
    Ok(Expression {
        ty: ExpressionTy::Ident(parse_pcode_ident(interner, pair)?),
        size: None,
        span,
    })
}

fn parse_pcode_ident<'a>(
    interner: &mut LocalVarInterner<'a>,
    pair: Pair<'a, Rule>,
) -> PcodeResult<Ident> {
    let name = pair.as_str();
    if let Some(id) = interner.get(name) {
        return Ok(Ident::Named(id));
    }
    Ok(Ident::Global(name.into()))
}

fn parse_func_call<'a>(
    interner: &mut LocalVarInterner<'a>,
    pair: Pair<'a, Rule>,
) -> PcodeResult<ExpressionTy<(usize, usize)>> {
    let mut inner = pair.into_inner();
    let name_pair = next_child(&mut inner, Rule::identifier).unwrap();
    reject_delayslot(&name_pair)?;
    let name = name_pair.as_str();
    let args = inner
        .find(|pair| pair.as_rule() == Rule::arg_list)
        .map(|pair| {
            pair.into_inner()
                .filter(|pair| pair.as_rule() == Rule::pcode_expr)
                .map(|pair| parse_pcode_expr(interner, pair))
                .collect::<PcodeResult<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(ExpressionTy::DeferredCall {
        name: name.into(),
        args,
    })
}

fn parse_pcode_prefix(
    op: Pair<'_, Rule>,
    expr: Expression<(usize, usize)>,
) -> Expression<(usize, usize)> {
    let span = (op.as_span().start(), expr.span.1);
    let op_rule = op.as_rule();
    let unary_op = match op_rule {
        Rule::operator_not_log => crate::pmacro::expression::UnaryOperator::LogicalNot,
        Rule::op_not_log => crate::pmacro::expression::UnaryOperator::LogicalNot,
        Rule::op_not_bit => crate::pmacro::expression::UnaryOperator::BitwiseNot,
        Rule::op_minus => crate::pmacro::expression::UnaryOperator::Minus,
        Rule::op_fminus => crate::pmacro::expression::UnaryOperator::FloatMinus,
        Rule::op_addr_size => {
            crate::pmacro::expression::UnaryOperator::AddressOf(Some(parse_size(
                op.into_inner()
                    .find(|p| p.as_rule() == Rule::pcode_size)
                    .expect("address-of-size has size"),
            )))
        }
        Rule::op_addr => crate::pmacro::expression::UnaryOperator::AddressOf(None),
        _ => unreachable_rule!(op),
    };
    Expression {
        ty: ExpressionTy::Unop(Unop {
            op: unary_op,
            e: Box::new(expr),
        }),
        size: None,
        span,
    }
}

fn parse_pcode_infix(
    lhs: Expression<(usize, usize)>,
    op: Pair<'_, Rule>,
    rhs: Expression<(usize, usize)>,
) -> Expression<(usize, usize)> {
    let span = (lhs.span.0, rhs.span.1);
    let bin_op = match op.as_rule() {
        Rule::operator_times => BinaryOperator::Mul,
        Rule::operator_div => BinaryOperator::Div,
        Rule::operator_sdiv => BinaryOperator::SignedDiv,
        Rule::operator_mod => BinaryOperator::Mod,
        Rule::operator_smod => BinaryOperator::SignedMod,
        Rule::operator_fdiv => BinaryOperator::FloatDiv,
        Rule::operator_fmul => BinaryOperator::FloatMul,
        Rule::operator_plus => BinaryOperator::Add,
        Rule::operator_minus => BinaryOperator::Sub,
        Rule::operator_fadd => BinaryOperator::FloatAdd,
        Rule::operator_fsub => BinaryOperator::FloatSub,
        Rule::operator_shift_l => BinaryOperator::LeftShift,
        Rule::operator_shift_r => BinaryOperator::RightShift,
        Rule::operator_sshr => BinaryOperator::SignedRightShift,
        Rule::operator_slt => BinaryOperator::SignedLessThan,
        Rule::operator_sgt => BinaryOperator::SignedGreaterThan,
        Rule::operator_sle => BinaryOperator::SignedLessEqual,
        Rule::operator_sge => BinaryOperator::SignedGreaterEqual,
        Rule::operator_le => BinaryOperator::LessEqual,
        Rule::operator_ge => BinaryOperator::GreaterEqual,
        Rule::operator_less => BinaryOperator::LessThan,
        Rule::operator_greater => BinaryOperator::GreaterThan,
        Rule::operator_fle => BinaryOperator::FloatLessEqual,
        Rule::operator_fge => BinaryOperator::FloatGreaterEqual,
        Rule::operator_flt => BinaryOperator::FloatLessThan,
        Rule::operator_fgt => BinaryOperator::FloatGreaterThan,
        Rule::operator_eq => BinaryOperator::Equal,
        Rule::operator_not_equal => BinaryOperator::NotEqual,
        Rule::operator_feq => BinaryOperator::FloatEqual,
        Rule::operator_fne => BinaryOperator::FloatNotEqual,
        Rule::operator_xor_log => BinaryOperator::LogicalXor,
        Rule::operator_and_log => BinaryOperator::LogicalAnd,
        Rule::operator_or_log => BinaryOperator::LogicalOr,
        Rule::operator_xor => BinaryOperator::BitwiseXor,
        Rule::operator_or => BinaryOperator::BitwiseOr,
        Rule::operator_and => BinaryOperator::BitwiseAnd,
        _ => unreachable_rule!(op),
    };
    Expression {
        ty: ExpressionTy::Binop(crate::pmacro::expression::Binop {
            op: bin_op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }),
        size: None,
        span,
    }
}

fn parse_pcode_range<'a>(
    interner: &mut LocalVarInterner<'a>,
    pair: Pair<'a, Rule>,
) -> PcodeResult<Range<(usize, usize)>> {
    let mut inner = pair.into_inner();
    let value =
        parse_pcode_ident_expr(interner, next_child(&mut inner, Rule::identifier).unwrap())?;
    let start = parse_range_param(next_child(&mut inner, Rule::range_param).unwrap(), interner);
    let size = parse_range_param(next_child(&mut inner, Rule::range_param).unwrap(), interner);
    Ok(Range {
        value: Box::new(value),
        start,
        size,
    })
}

fn parse_range_param<'a>(pair: Pair<'a, Rule>, interner: &mut LocalVarInterner<'a>) -> RangeParam {
    let child = pair.into_inner().next().expect("range_param has a child");
    match child.as_rule() {
        Rule::integer => RangeParam::Literal(parse_int(child)),
        Rule::identifier => RangeParam::MacroArg(interner.intern(child.as_str())),
        _ => unreachable_rule!(child),
    }
}

fn parse_pcode_load<'a>(
    interner: &mut LocalVarInterner<'a>,
    pair: Pair<'a, Rule>,
) -> PcodeResult<Load<(usize, usize)>> {
    let mut space = None;
    let mut size = None;
    let mut ptr = None;
    let mut prefix = None;
    for child in pair.into_inner() {
        match child.as_rule() {
            // `prefix_operator` is silent, so its alternatives arrive directly.
            Rule::op_not_log
            | Rule::op_not_bit
            | Rule::op_minus
            | Rule::op_fminus
            | Rule::op_addr_size
            | Rule::op_addr => prefix = Some(child),

            Rule::space => {
                let space_pair = first_child_q(child, Rule::identifier)?;
                space = Some(SpaceRef::Deferred(space_pair.as_str().into()));
            }
            Rule::pcode_size => size = Some(parse_size(child)),
            Rule::sized_integer
            | Rule::integer
            | Rule::subpiece
            | Rule::load
            | Rule::range
            | Rule::func_call
            | Rule::identifier
            | Rule::paren_expr
            | Rule::pcode_expr => ptr = Some(parse_pcode_primary(interner, child)?),
            _ => {}
        }
    }
    if let Some(op) = prefix
        && let Some(expr) = ptr.take()
    {
        ptr = Some(parse_pcode_prefix(op, expr));
    }
    Ok(Load {
        space,
        size,
        ptr: Box::new(ptr.expect("load has pointer expression")),
    })
}

fn parsed_expr_size<S>(ty: &ExpressionTy<S>) -> Option<usize> {
    match ty {
        ExpressionTy::SizedInt { size, .. } => *size,
        ExpressionTy::Load(load) => load.size,
        _ => None,
    }
}

fn parse_size(pair: Pair<'_, Rule>) -> usize {
    debug_assert_eq!(pair.as_rule(), Rule::pcode_size);
    parse_int(
        pair.into_inner()
            .find(|pair| pair.as_rule() == Rule::integer)
            .expect("pcode_size has integer"),
    )
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

fn first_child_q<'a>(pair: Pair<'a, Rule>, rule: Rule) -> PcodeResult<Pair<'a, Rule>> {
    pair.into_inner()
        .find(|p| p.as_rule() == rule)
        .ok_or_else(|| PcodeError::spanless(PcodeErrorTy::UnknownSize))
}

fn next_child<'a>(
    pairs: &mut impl Iterator<Item = Pair<'a, Rule>>,
    rule: Rule,
) -> Option<Pair<'a, Rule>> {
    pairs.find(|p| p.as_rule() == rule)
}

fn first_from_slice_q<'a>(pairs: &[Pair<'a, Rule>], rule: Rule) -> PcodeResult<Pair<'a, Rule>> {
    pairs
        .iter()
        .find(|p| p.as_rule() == rule)
        .cloned()
        .ok_or_else(|| PcodeError::spanless(PcodeErrorTy::UnknownSize))
}
