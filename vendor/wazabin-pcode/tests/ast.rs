use pcode_types::{
    Ast, AstNode, BinaryOperator, Binop, BitRangeFieldId, Builtin, DelaySlotArg, Expression,
    ExpressionTy, FieldId, Ident, LabelOrNode, Load, LocalVarId, LocalVarInterner, PCodeOpId,
    PMacroId, PcodeAst, PcodeResolver, PcodeSpaceRef, Range, RangeParam, RegisterId, SpaceId,
    TableId, UnaryOperator, Unop, pretty_print_ident,
};

struct Names;

impl PcodeResolver for Names {
    fn ident_name(&self, ident: &Ident) -> String {
        match ident {
            Ident::Register(id) => format!("r{}", usize::from(*id)),
            Ident::BitRange(id) => format!("bits{}", usize::from(*id)),
            Ident::Field(id) => format!("field{}", usize::from(*id)),
            _ => unreachable!("only resolved named identifiers reach the resolver"),
        }
    }

    fn field_name(&self, id: FieldId) -> String {
        format!("field{}", usize::from(id))
    }

    fn space_name(&self, id: SpaceId) -> String {
        format!("space{}", usize::from(id))
    }

    fn pcode_op_name(&self, id: PCodeOpId) -> String {
        format!("userop{}", usize::from(id))
    }

    fn macro_name(&self, id: PMacroId) -> String {
        format!("macro{}", usize::from(id))
    }
}

fn int(value: u64) -> Expression {
    ExpressionTy::SizedInt { value, size: None }.into()
}

fn parsed(ty: ExpressionTy<(usize, usize)>) -> Expression<(usize, usize)> {
    Expression {
        ty,
        size: Some(4),
        span: (10, 20),
    }
}

#[test]
fn every_builtin_has_its_official_name() {
    let expected = [
        (Builtin::Carry, "carry"),
        (Builtin::Scarry, "scarry"),
        (Builtin::Sborrow, "sborrow"),
        (Builtin::Nan, "nan"),
        (Builtin::Abs, "abs"),
        (Builtin::Sqrt, "sqrt"),
        (Builtin::Floor, "floor"),
        (Builtin::Ceil, "ceil"),
        (Builtin::Round, "round"),
        (Builtin::Int2Float, "int2float"),
        (Builtin::Float2Float, "float2float"),
        (Builtin::Trunc, "trunc"),
        (Builtin::Zext, "zext"),
        (Builtin::Sext, "sext"),
        (Builtin::Popcount, "popcount"),
        (Builtin::Lzcount, "lzcount"),
        (Builtin::Cpool, "cpool"),
        (Builtin::NewObject, "newobject"),
    ];
    assert_eq!(Builtin::ALL.len(), expected.len());
    for (builtin, name) in expected {
        assert_eq!(builtin.as_str(), name);
        assert_eq!(Builtin::from_name(name), Some(builtin));
    }
    assert_eq!(Builtin::from_name("epsilon"), None);
    assert_eq!(Builtin::from_name("float2int"), None);
}

#[test]
fn local_interner_is_stable_and_defaultable() {
    let mut names = LocalVarInterner::default();
    assert_eq!(names.count(), 0);
    assert_eq!(names.get("tmp"), None);
    assert_eq!(names.intern("tmp"), LocalVarId(0));
    assert_eq!(names.intern("other"), LocalVarId(1));
    assert_eq!(names.intern("tmp"), LocalVarId(0));
    assert_eq!(names.count(), 2);
    assert_eq!(names.get("other"), Some(LocalVarId(1)));
}

#[test]
fn identifiers_and_expression_forms_render() {
    let names = Names;
    assert_eq!(
        pretty_print_ident(&names, &Ident::Named(LocalVarId(3))),
        "v3"
    );
    assert_eq!(
        pretty_print_ident(&names, &Ident::Register(RegisterId::new(1))),
        "r1"
    );
    assert_eq!(
        pretty_print_ident(&names, &Ident::BitRange(BitRangeFieldId::new(2))),
        "bits2"
    );
    assert_eq!(
        pretty_print_ident(&names, &Ident::Field(FieldId::new(3))),
        "field3"
    );
    assert_eq!(
        pretty_print_ident(&names, &Ident::Table(TableId::new(4))),
        "table4"
    );
    assert_eq!(
        pretty_print_ident(&names, &Ident::Global("missing".into())),
        "?missing"
    );

    let forms: Vec<(Expression, &str)> = vec![
        (
            ExpressionTy::SizedInt {
                value: 12,
                size: Some(2),
            }
            .into(),
            "12:2",
        ),
        (
            ExpressionTy::SubPieceMsb {
                src: Box::new(int(1)),
                count: 2,
            }
            .into(),
            "subpiece_msb(1, 2)",
        ),
        (
            ExpressionTy::SubPieceLsb {
                src: Box::new(int(1)),
                count: 2,
            }
            .into(),
            "subpiece_lsb(1, 2)",
        ),
        (
            ExpressionTy::Load(Load {
                space: Some(PcodeSpaceRef::Resolved(SpaceId::new(1))),
                size: Some(4),
                ptr: Box::new(int(9)),
            })
            .into(),
            "load(space=space1, size=4, ptr=9)",
        ),
        (
            ExpressionTy::Range(Range {
                value: Box::new(int(1)),
                start: RangeParam::Literal(2),
                size: RangeParam::MacroArg(LocalVarId(3)),
            })
            .into(),
            "range(1, 2, arg3)",
        ),
        (
            ExpressionTy::FunctionCall {
                builtin: Builtin::Zext,
                args: vec![int(1)],
            }
            .into(),
            "zext(1)",
        ),
        (
            ExpressionTy::PcodeOp {
                id: PCodeOpId::new(2),
                args: vec![int(1)],
            }
            .into(),
            "userop2(1)",
        ),
        (
            ExpressionTy::MacroCall {
                id: PMacroId::new(3),
                args: vec![int(1)],
            }
            .into(),
            "macro3(1)",
        ),
        (
            ExpressionTy::DeferredCall {
                name: "later".into(),
                args: vec![int(1)],
            }
            .into(),
            "later(1)",
        ),
        (
            ExpressionTy::Ident(Ident::Register(RegisterId::new(1))).into(),
            "r1",
        ),
        (
            ExpressionTy::Unop(Unop {
                op: UnaryOperator::AddressOf(Some(8)),
                e: Box::new(int(1)),
            })
            .into(),
            "&:8 1",
        ),
        (
            ExpressionTy::Binop(Binop {
                op: BinaryOperator::Add,
                lhs: Box::new(int(1)),
                rhs: Box::new(int(2)),
            })
            .into(),
            "(1 + 2)",
        ),
    ];
    for (expression, expected) in forms {
        assert_eq!(expression.pretty_print(&names), expected);
    }
    assert_eq!(
        ExpressionTy::SizedInt {
            value: 1,
            size: None
        }
        .with_size(8)
        .size,
        Some(8)
    );
}

#[test]
fn every_binary_operator_has_its_spelling_and_classification() {
    use BinaryOperator::*;
    let operators = [
        (Mul, "*"),
        (Div, "/"),
        (SignedDiv, "s/"),
        (Mod, "%"),
        (SignedMod, "s%"),
        (FloatDiv, "f/"),
        (FloatMul, "f*"),
        (Add, "+"),
        (Sub, "-"),
        (FloatAdd, "f+"),
        (FloatSub, "f-"),
        (LeftShift, "<<"),
        (RightShift, ">>"),
        (SignedRightShift, "s>>"),
        (SignedLessThan, "s<"),
        (SignedGreaterThan, "s>"),
        (SignedLessEqual, "s<="),
        (SignedGreaterEqual, "s>="),
        (LessEqual, "<="),
        (GreaterEqual, ">="),
        (LessThan, "<"),
        (GreaterThan, ">"),
        (FloatLessEqual, "f<="),
        (FloatGreaterEqual, "f>="),
        (FloatLessThan, "f<"),
        (FloatGreaterThan, "f>"),
        (Equal, "=="),
        (NotEqual, "!="),
        (FloatEqual, "f=="),
        (FloatNotEqual, "f!="),
        (LogicalXor, "^^"),
        (LogicalAnd, "&&"),
        (LogicalOr, "||"),
        (BitwiseXor, "^"),
        (BitwiseOr, "|"),
        (BitwiseAnd, "&"),
    ];
    for (operator, spelling) in operators {
        assert_eq!(operator.pretty_print(), spelling);
    }
    for operator in [
        LessEqual,
        GreaterEqual,
        LessThan,
        GreaterThan,
        SignedLessThan,
        SignedGreaterThan,
        SignedLessEqual,
        SignedGreaterEqual,
        Equal,
        NotEqual,
        FloatLessThan,
        FloatLessEqual,
        FloatGreaterThan,
        FloatGreaterEqual,
        FloatEqual,
        FloatNotEqual,
    ] {
        assert!(operator.is_comparison());
    }
    for operator in [LeftShift, RightShift, SignedRightShift] {
        assert!(operator.is_shift());
    }
    for operator in [
        SignedLessThan,
        SignedGreaterThan,
        SignedLessEqual,
        SignedGreaterEqual,
    ] {
        assert!(operator.is_signed_comparison());
    }
    for operator in [
        FloatDiv,
        FloatMul,
        FloatAdd,
        FloatSub,
        FloatLessEqual,
        FloatGreaterEqual,
        FloatLessThan,
        FloatGreaterThan,
        FloatEqual,
        FloatNotEqual,
    ] {
        assert!(operator.is_float());
    }
    for operator in [
        FloatLessThan,
        FloatLessEqual,
        FloatGreaterThan,
        FloatGreaterEqual,
        FloatEqual,
        FloatNotEqual,
    ] {
        assert!(operator.is_float_comparison());
    }
    for operator in [LogicalXor, LogicalAnd, LogicalOr] {
        assert!(operator.is_logical());
    }
    for operator in [
        SignedDiv,
        SignedMod,
        SignedLessThan,
        SignedGreaterThan,
        SignedLessEqual,
        SignedGreaterEqual,
        SignedRightShift,
    ] {
        assert!(operator.is_signed_integer());
    }
    assert!(!Add.is_comparison() && !Add.is_shift() && !Add.is_float() && !Add.is_logical());
}

#[test]
fn statements_render_in_order() {
    let names = Names;
    let range = Range {
        value: Box::new(int(1)),
        start: RangeParam::Literal(0),
        size: RangeParam::Literal(1),
    };
    let load = Load {
        space: Some(PcodeSpaceRef::Deferred("ram".into())),
        size: Some(2),
        ptr: Box::new(int(3)),
    };
    let statements = vec![
        (
            AstNode::Assignment {
                lhs: Ident::Named(LocalVarId(0)),
                size: Some(4),
                rhs: int(1),
            },
            "v0:4 = 1;",
        ),
        (
            AstNode::LoadAssignment {
                lhs: load,
                size: None,
                rhs: int(4),
            },
            "load(space=?ram, size=2, ptr=3) = 4;",
        ),
        (
            AstNode::RangeAssignment {
                lhs: range,
                size: Some(1),
                rhs: int(1),
            },
            "range(1, 0, 1):1 = 1;",
        ),
        (AstNode::Build(TableId::new(2)), "build table2;"),
        (AstNode::DelaySlot(DelaySlotArg::Bytes(4)), "delayslot(4);"),
        (
            AstNode::DelaySlot(DelaySlotArg::Field(FieldId::new(2))),
            "delayslot(field2);",
        ),
        (
            AstNode::DelaySlot(DelaySlotArg::Deferred("n".into())),
            "delayslot(n);",
        ),
        (AstNode::DeferredBuild("operand".into()), "build operand;"),
        (AstNode::Label("loop".into()), "<loop>"),
        (
            AstNode::Branch {
                target: LabelOrNode::Label("loop".into()),
            },
            "goto <loop>;",
        ),
        (
            AstNode::ConditionalBranch {
                condition: int(1),
                target: LabelOrNode::Node("target".into()),
            },
            "if 1 goto target;",
        ),
        (AstNode::BranchIndirect { target: int(1) }, "goto [1];"),
        (
            AstNode::Call {
                target: LabelOrNode::Expr(int(2)),
            },
            "call 2;",
        ),
        (AstNode::CallIndirect { target: int(3) }, "call [3];"),
        (AstNode::Return { target: int(4) }, "return [4];"),
        (AstNode::Export(int(5)), "export 5;"),
        (AstNode::Expression(int(6)), "6;"),
    ];
    for (statement, expected) in &statements {
        assert_eq!(
            statement.clone().strip_span().pretty_print(&names),
            *expected
        );
    }
    let ast = PcodeAst {
        statements: statements
            .iter()
            .cloned()
            .map(|(statement, _)| Ast::from(statement))
            .collect(),
    };
    assert_eq!(
        ast.pretty_print(&names),
        statements
            .iter()
            .map(|(_, text)| *text)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn strip_span_recurses_through_expression_and_statement_forms() {
    let expression = parsed(ExpressionTy::Binop(Binop {
        op: BinaryOperator::Add,
        lhs: Box::new(parsed(ExpressionTy::Load(Load {
            space: Some(PcodeSpaceRef::Deferred("ram".into())),
            size: Some(2),
            ptr: Box::new(parsed(ExpressionTy::Range(Range {
                value: Box::new(parsed(ExpressionTy::Unop(Unop {
                    op: UnaryOperator::Minus,
                    e: Box::new(parsed(ExpressionTy::SizedInt {
                        value: 1,
                        size: Some(1),
                    })),
                }))),
                start: RangeParam::MacroArg(LocalVarId(0)),
                size: RangeParam::Literal(3),
            }))),
        }))),
        rhs: Box::new(parsed(ExpressionTy::FunctionCall {
            builtin: Builtin::Sext,
            args: vec![parsed(ExpressionTy::SubPieceLsb {
                src: Box::new(parsed(ExpressionTy::SubPieceMsb {
                    src: Box::new(parsed(ExpressionTy::Ident(Ident::Global("x".into())))),
                    count: 1,
                })),
                count: 1,
            })],
        })),
    }));
    let statement = Ast {
        ty: AstNode::ConditionalBranch {
            condition: expression,
            target: LabelOrNode::Expr(parsed(ExpressionTy::PcodeOp {
                id: PCodeOpId::new(1),
                args: vec![parsed(ExpressionTy::MacroCall {
                    id: PMacroId::new(1),
                    args: vec![parsed(ExpressionTy::DeferredCall {
                        name: "call".into(),
                        args: vec![],
                    })],
                })],
            })),
        },
        span: (1, 2),
    };
    let stripped = statement.strip_span();
    assert_eq!(stripped.span, ());
    assert!(matches!(stripped.ty, AstNode::ConditionalBranch { .. }));
}

#[test]
fn space_references_expose_only_resolved_ids() {
    assert_eq!(
        PcodeSpaceRef::Resolved(SpaceId::new(2)).resolved(),
        SpaceId::new(2)
    );
    assert!(std::panic::catch_unwind(|| PcodeSpaceRef::Deferred("ram".into()).resolved()).is_err());
}

#[test]
fn ast_serialization_round_trips() {
    let ast = PcodeAst {
        statements: vec![Ast::from(AstNode::Assignment {
            lhs: Ident::Register(RegisterId::new(1)),
            size: Some(4),
            rhs: ExpressionTy::Binop(Binop {
                op: BinaryOperator::Add,
                lhs: Box::new(int(1)),
                rhs: Box::new(int(2)),
            })
            .with_size(4),
        })],
    };
    let bytes = bincode::serde::encode_to_vec(&ast, bincode::config::standard()).unwrap();
    let (decoded, _): (PcodeAst, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(decoded, ast);
}

#[test]
fn errors_preserve_kind_and_render_their_span() {
    use pcode_types::{PcodeError, PcodeErrorTy};
    let errors = [
        PcodeError::range_out_of_bounds(1..3, (2, 4)),
        PcodeError::argument_count_mismatch(1, 2, (2, 4)),
        PcodeError::unknown_size((2, 4)),
        PcodeError::unknown_macro("missing", (2, 4)),
        PcodeError::multiple_exports((2, 4)),
        PcodeError::export_not_last((2, 4)),
        PcodeError::function_is_a_statement((2, 4)),
        PcodeError::spanless(PcodeErrorTy::Unsupported("extension".into())).with_span((2, 4)),
    ];
    for error in errors {
        assert_eq!(error.span, Some((2, 4)));
        assert!(error.to_string().contains("bytes 2..4"));
    }
    assert_eq!(
        PcodeError::unknown_size((1, 2)),
        PcodeError::spanless(PcodeErrorTy::UnknownSize)
    );
}
