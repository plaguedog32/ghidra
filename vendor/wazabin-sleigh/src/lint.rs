use std::collections::{HashMap, HashSet};

use crate::{
    builder::SpecBuilder,
    constraint::{BitPatternAstNode, ConstraintAst},
    constructor::{DisplayElement, PatternOrConstraint},
    diagnostic::{Diagnostic, DiagnosticCode, DiagnosticLabel, Severity},
    objects::field::{FIELD_INST_NEXT, FIELD_INST_START, FieldId, FieldParent},
    pattern::OperandType,
    source::Span,
    syntax::{SleighFile, SleighItem},
};

const EXPLOSION_THRESHOLD: usize = 64;

/// Names of every field read by the bit patterns of `items`, including the
/// constraints `with` blocks conjoin onto their constructors.
///
/// Concretization compiles constraints down to bit masks, so once the
/// builder has run there is no record of which fields a pattern tested.
/// The AST still has them.
fn collect_constrained_fields<'a>(items: &'a [SleighItem], out: &mut HashSet<&'a str>) {
    for item in items {
        match item {
            SleighItem::Constructor(d) => constrained_fields(&d.constraint, out),
            SleighItem::WithBlock(d) => {
                constrained_fields(&d.constraint, out);
                collect_constrained_fields(&d.items, out);
            }
            _ => {}
        }
    }
}

fn constrained_fields<'a>(ast: &'a ConstraintAst, out: &mut HashSet<&'a str>) {
    match &ast.value {
        BitPatternAstNode::Ident(name) => {
            out.insert(name);
        }
        BitPatternAstNode::Constraint { lhs, rhs, .. } => {
            out.insert(lhs);
            constrained_fields(rhs, out);
        }
        BitPatternAstNode::ValueBinOp { lhs, rhs, .. }
        | BitPatternAstNode::BinOp { lhs, rhs, .. } => {
            constrained_fields(lhs, out);
            constrained_fields(rhs, out);
        }
        BitPatternAstNode::RElipsis(inner) | BitPatternAstNode::LElipsis(inner) => {
            constrained_fields(inner, out);
        }
        BitPatternAstNode::Int(_) => {}
    }
}

fn is_builtin_field(fid: FieldId) -> bool {
    fid == FIELD_INST_START || fid == FIELD_INST_NEXT
}

fn collect_field_def_spans(items: &[SleighItem], out: &mut HashMap<Box<str>, Span>) {
    for item in items {
        match item {
            SleighItem::Token(d) => {
                for f in &d.fields {
                    out.entry(f.name.clone()).or_insert(f.span);
                }
            }
            SleighItem::Context(d) => {
                for f in &d.fields {
                    out.entry(f.name.clone()).or_insert(f.span);
                }
            }
            SleighItem::WithBlock(d) => {
                collect_field_def_spans(&d.items, out);
            }
            _ => {}
        }
    }
}

pub(crate) fn run_lints(builder: &SpecBuilder, file: &SleighFile) -> Vec<Diagnostic> {
    let mut out = Vec::new();

    let mut field_def_spans: HashMap<Box<str>, Span> = HashMap::new();
    collect_field_def_spans(&file.items, &mut field_def_spans);

    // Field usage tracking. A field tested by a pattern is used, even if
    // nothing displays or exports it: `op` is what selects the constructor.
    let mut constrained: HashSet<&str> = HashSet::new();
    collect_constrained_fields(&file.items, &mut constrained);
    let mut referenced_fields: HashSet<FieldId> = constrained
        .iter()
        .filter_map(|name| builder.try_get_field(name))
        .map(|field| field.id)
        .collect();
    // context field writes: field_id -> span of first writing constructor
    let mut ctx_writes: HashMap<FieldId, Span> = HashMap::new();
    // context fields read via operands, display, or action expressions
    let mut ctx_reads: HashSet<FieldId> = HashSet::new();

    for table in builder.tables.iter() {
        let table_id = table.id;
        let ctors: Vec<_> = table.constructors.iter().collect();
        let ctor_count = ctors.len();

        for i in 0..ctor_count {
            let a = &ctors[i];
            let PatternOrConstraint::Pattern(a_pat) = &a.pattern else {
                continue;
            };
            let a_disjuncts: Vec<_> = a_pat.combined_patterns().collect();

            // Collect field references
            for op in &a_pat.operands {
                if let OperandType::Field(fid) = op.ty {
                    referenced_fields.insert(fid);
                    if builder.fields[fid].parent == FieldParent::Context {
                        ctx_reads.insert(fid);
                    }
                }
            }
            for d in &a.display_list {
                if let DisplayElement::Field(fid) = *d {
                    referenced_fields.insert(fid);
                    if builder.fields[fid].parent == FieldParent::Context {
                        ctx_reads.insert(fid);
                    }
                }
            }
            for action in &a.actions {
                // A `globalset` only *reads* the variable it commits, so it has
                // no written field: counting it as a write would hide a
                // context variable that nothing ever assigns.
                let written = action.written_field();
                if let Some(written) = written {
                    referenced_fields.insert(written);
                    if builder.fields[written].parent == FieldParent::Context {
                        ctx_writes.entry(written).or_insert(a.src);
                    }
                }
                for read in action.fields() {
                    if Some(read) != written {
                        referenced_fields.insert(read);
                        if builder.fields[read].parent == FieldParent::Context {
                            ctx_reads.insert(read);
                        }
                    }
                }
            }

            // Pattern explosion
            let disjunct_count = a_disjuncts.len();
            if disjunct_count > EXPLOSION_THRESHOLD {
                out.push(Diagnostic {
                    severity: Severity::Warning,
                    code: DiagnosticCode::Lint("pattern-explosion".into()),
                    message: format!(
                        "constructor in table `{}` expands to {disjunct_count} pattern alternatives (threshold: {EXPLOSION_THRESHOLD})",
                        table.name
                    ),
                    primary: a.src,
                    labels: Vec::new(),
                });
            }

            // Always-false pattern (empty disjunction arises when contradictory
            // constraints are ANDed and all resulting atoms are pruned by normalization)
            if a_disjuncts.is_empty() || a_disjuncts.iter().all(|p| p.is_always_false()) {
                out.push(Diagnostic {
                    severity: Severity::Warning,
                    code: DiagnosticCode::Lint("always-false-pattern".into()),
                    message: format!(
                        "constructor in table `{}` has a pattern that can never match",
                        table.name
                    ),
                    primary: a.src,
                    labels: Vec::new(),
                });
            }

            // Trivial catch-all alongside siblings
            if ctor_count > 1 && a_disjuncts.iter().any(|p| p.is_always_true()) {
                out.push(Diagnostic {
                    severity: Severity::Warning,
                    code: DiagnosticCode::Lint("trivial-catch-all".into()),
                    message: format!(
                        "constructor in table `{}` matches unconditionally, shadowing {} other constructor(s)",
                        table.name,
                        ctor_count - 1
                    ),
                    primary: a.src,
                    labels: Vec::new(),
                });
            }

            // Self-referencing display
            let mut reported_self_ref = false;
            for d in &a.display_list {
                if !reported_self_ref
                    && let DisplayElement::Table(tid) = *d
                    && tid == table_id
                {
                    reported_self_ref = true;
                    out.push(Diagnostic {
                                severity: Severity::Warning,
                                code: DiagnosticCode::Lint("self-referencing-display".into()),
                                message: format!(
                                    "constructor in table `{}` references its own table in the display, risking infinite recursion",
                                    table.name
                                ),
                                primary: a.src,
                                labels: Vec::new(),
                            });
                }
            }

            // Duplicate and ambiguous constructor pairs
            for b in ctors.iter().skip(i + 1) {
                let PatternOrConstraint::Pattern(b_pat) = &b.pattern else {
                    continue;
                };

                if a_pat == b_pat {
                    out.push(Diagnostic {
                        severity: Severity::Warning,
                        code: DiagnosticCode::Lint("duplicate-constructor".into()),
                        message: format!(
                            "constructor in table `{}` has an identical pattern; the second is unreachable",
                            table.name
                        ),
                        primary: b.src,
                        labels: vec![DiagnosticLabel {
                            span: a.src,
                            message: "first defined here".into(),
                        }],
                    });
                    continue;
                }

                let b_disjuncts: Vec<_> = b_pat.combined_patterns().collect();
                let mut ambiguous = false;
                'outer: for ap in &a_disjuncts {
                    for bp in &b_disjuncts {
                        if !ap.and(bp, 0).is_always_false()
                            && !ap.is_less_specific(bp)
                            && !bp.is_less_specific(ap)
                        {
                            ambiguous = true;
                            break 'outer;
                        }
                    }
                }
                if ambiguous {
                    out.push(Diagnostic {
                        severity: Severity::Warning,
                        code: DiagnosticCode::Lint("ambiguous-constructors".into()),
                        message: format!(
                            "ambiguous constructors in table `{}`: patterns overlap and neither is more specific",
                            table.name
                        ),
                        primary: a.src,
                        labels: vec![DiagnosticLabel {
                            span: b.src,
                            message: "overlaps with this constructor".into(),
                        }],
                    });
                }
            }
        }
    }

    // Context field written but never read (via actions/operands/display)
    for (fid, write_span) in &ctx_writes {
        if !ctx_reads.contains(fid) {
            let name = &builder.fields[*fid].name;
            out.push(Diagnostic {
                severity: Severity::Warning,
                code: DiagnosticCode::Lint("context-field-write-only".into()),
                message: format!(
                    "context field `{name}` is written here but never read in actions, operands, or display"
                ),
                primary: *write_span,
                labels: Vec::new(),
            });
        }
    }

    // Unused token / context fields
    for f in builder.fields.iter() {
        let fid = f.id;
        if is_builtin_field(fid) {
            continue;
        }
        if !matches!(f.parent, FieldParent::Token(_) | FieldParent::Context) {
            continue;
        }
        if referenced_fields.contains(&fid) {
            continue;
        }
        if let Some(&span) = field_def_spans.get(f.name.as_ref()) {
            out.push(Diagnostic {
                severity: Severity::Warning,
                code: DiagnosticCode::Lint("unused-field".into()),
                message: format!(
                    "field `{}` is never used in any constructor's pattern, operands, display, or actions",
                    f.name
                ),
                primary: span,
                labels: Vec::new(),
            });
        }
    }

    out
}
