pub(crate) use pcode_types::{
    BinaryOperator, Binop, Builtin, Expression, ExpressionTy, Ident, Load, LocalVarId,
    LocalVarInterner, PcodeSpaceRef as SpaceRef, Range, RangeParam, UnaryOperator, Unop,
};

pub(crate) fn infer_expr_size(spec: &crate::spec::Spec, expr: &mut Expression) -> Option<usize> {
    if expr.size.is_some() {
        return expr.size;
    }
    let size = match &mut expr.ty {
        ExpressionTy::SizedInt { size, .. } => *size,
        ExpressionTy::Ident(ident) => ident_size(spec, ident),
        ExpressionTy::Load(load) => load.size,
        ExpressionTy::SubPieceMsb { src, count } => {
            infer_expr_size(spec, src).map(|size| size.saturating_sub(*count))
        }
        ExpressionTy::SubPieceLsb { count, .. } => Some(*count),
        ExpressionTy::Range(_) => None,
        ExpressionTy::FunctionCall { builtin, args } => match builtin {
            Builtin::Carry | Builtin::Scarry | Builtin::Sborrow | Builtin::Nan => Some(1),
            Builtin::Abs | Builtin::Sqrt | Builtin::Floor | Builtin::Ceil | Builtin::Round => {
                args.first_mut().and_then(|arg| infer_expr_size(spec, arg))
            }
            _ => None,
        },
        ExpressionTy::PcodeOp { .. } => None,
        ExpressionTy::MacroCall { .. } | ExpressionTy::DeferredCall { .. } => None,
        ExpressionTy::Unop(unop) => match unop.op {
            UnaryOperator::LogicalNot => Some(1),
            UnaryOperator::AddressOf(size) => size,
            _ => infer_expr_size(spec, &mut unop.e),
        },
        ExpressionTy::Binop(binop) => {
            if binop.op.is_comparison() {
                Some(1)
            } else {
                infer_expr_size(spec, &mut binop.lhs)
            }
        }
    };
    expr.size = size;
    size
}

pub(crate) fn ident_size(spec: &crate::spec::Spec, ident: &Ident) -> Option<usize> {
    match ident {
        Ident::Register(id) => Some(spec.registers[*id].size),
        Ident::BitRange(id) => Some(spec.bitranges[*id].size().div_ceil(8)),
        Ident::Named(_) | Ident::Field(_) | Ident::Table(_) | Ident::Global(_) => None,
    }
}
