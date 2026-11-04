use crate::{
    instance::ConstructorInstance,
    objects::field::{
        FIELD_INST_NEXT, FIELD_INST_NEXT2, FIELD_INST_START, FieldId, FieldParent, FieldValue,
    },
    pmacro::expression::{Expression, ExpressionTy, Ident},
    runtime::pcode::make_int_expr,
    spec::Spec,
};
use pcode_types::{
    RegisterId,
    streaming::{ExprKind, ExprNode},
};

/// A field as the semantic section sees it once an instruction is decoded.
///
/// Every variant is a leaf, so this is `Copy` and costs nothing to produce:
/// a view resolves a field each time it is asked about rather than caching an
/// owned expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Resolved {
    /// The constant this encoding gave the field, at the width the field's
    /// kind implies.
    Int { value: u64, size: usize },
    /// The register the field's attach table maps this encoding to.
    Register { id: RegisterId, size: usize },
    /// A field this decode supplies no value for. Left in place for the
    /// consumer to report.
    Field(FieldId),
}

impl Resolved {
    pub(super) fn size(self) -> Option<usize> {
        match self {
            Self::Int { size, .. } | Self::Register { size, .. } => Some(size),
            Self::Field(_) => None,
        }
    }

    pub(super) fn kind<'a, E: ExprNode>(self) -> ExprKind<'a, E> {
        match self {
            Self::Int { value, size } => ExprKind::SizedInt {
                value,
                size: Some(size),
            },
            Self::Register { id, .. } => ExprKind::Ident(Ident::Register(id)),
            Self::Field(id) => ExprKind::Ident(Ident::Field(id)),
        }
    }

    pub(super) fn into_expr(self) -> Expression {
        match self {
            Self::Int { value, size } => make_int_expr(value, size),
            Self::Register { id, size } => Expression {
                ty: ExpressionTy::Ident(Ident::Register(id)),
                size: Some(size),
                span: (),
            },
            Self::Field(id) => Expression {
                ty: ExpressionTy::Ident(Ident::Field(id)),
                size: None,
                span: (),
            },
        }
    }
}

/// Resolve the runtime value of a field from a constructor instance, if known.
pub(super) fn resolve_field_value(
    spec: &Spec,
    instance: &ConstructorInstance,
    field_id: FieldId,
) -> Option<Resolved> {
    let constructor = instance.constructor(spec);
    let field = &spec.fields[field_id];

    let (raw_value, size) = if field.parent == FieldParent::Global {
        constructor.global_map.get(&field_id).map(|idx| {
            (
                instance.global_values[*idx as usize],
                spec.spaces[spec.default_space].addr_size,
            )
        })
    } else {
        instance.field_value(spec, field_id).map(|value| {
            let size = if field.signed {
                spec.spaces[spec.default_space].addr_size
            } else {
                field.range.size().div_ceil(8)
            };
            (value as u64, size)
        })
    }?;

    match field.value(&spec.field_tables, raw_value)? {
        FieldValue::Int(value) => Some(Resolved::Int {
            value: value as u64,
            size,
        }),
        FieldValue::UInt(value) => Some(Resolved::Int { value, size }),
        FieldValue::Register(id) => Some(Resolved::Register {
            id,
            size: spec.registers[id].size,
        }),
        FieldValue::String(_) => None,
    }
}

/// Resolve inst_start / inst_next / inst_next2 / arbitrary field to a value.
///
/// `inst_next` is passed in rather than read off `instance`: the semantic
/// section sees the address past the delay slot, while the instance carries the
/// unextended value that disassembly actions and `globalset` use.
pub(super) fn resolve_field_ident(
    spec: &Spec,
    field_id: FieldId,
    instance: &ConstructorInstance,
    inst_next: u64,
    inst_next2: Option<u64>,
) -> Resolved {
    // `inst_start`/`inst_next` are code addresses: size them to the target's
    // address width (8 on x86-64, 4 on i386), matching how `resolve_field_value`
    // sizes global address fields. Hardcoding 8 produced an 8-byte return-address
    // literal on i386, which a 4-byte `&:4 inst_next` push could not narrow, so
    // mem2reg refused to promote the (mixed-width) return-address slot.
    let size = spec.spaces[spec.default_space].addr_size;
    if field_id == FIELD_INST_START {
        return Resolved::Int {
            value: instance.inst_start,
            size,
        };
    }
    if field_id == FIELD_INST_NEXT {
        return Resolved::Int {
            value: inst_next,
            size,
        };
    }
    if field_id == FIELD_INST_NEXT2
        && let Some(value) = inst_next2
    {
        return Resolved::Int { value, size };
    }
    resolve_field_value(spec, instance, field_id).unwrap_or(Resolved::Field(field_id))
}
