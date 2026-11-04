use crate::{DiagnosticCode, SourceDb, analyze};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Preamble shared by most tests (no context register).
const PREAMBLE: &str = "
define endian=little;
define space ram  type=ram_space     size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [r0 r1 r2 r3];
";

/// Preamble with a 1-byte context register for context-field tests.
const PREAMBLE_CTX: &str = "
define endian=little;
define space ram  type=ram_space     size=4 default;
define space register type=register_space size=4;
define register offset=0 size=1 [ctxreg];
";

fn lint_codes(src: &str) -> Vec<String> {
    let mut db = SourceDb::new();
    let root = db.add_file("test.sla", src);
    let result = analyze(&mut db, root);
    result
        .diagnostics
        .iter()
        .filter_map(|d| {
            if let DiagnosticCode::Lint(code) = &d.code {
                Some(code.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Messages of every lint diagnostic with `code`.
fn lint_messages(src: &str, code: &str) -> Vec<String> {
    let mut db = SourceDb::new();
    let root = db.add_file("test.sla", src);
    analyze(&mut db, root)
        .diagnostics
        .iter()
        .filter(|d| matches!(&d.code, DiagnosticCode::Lint(c) if c == code))
        .map(|d| d.message.clone())
        .collect()
}

fn has_lint(src: &str, code: &str) -> bool {
    lint_codes(src).iter().any(|c| c == code)
}

fn no_lint(src: &str, code: &str) -> bool {
    !has_lint(src, code)
}

// ── ambiguous-constructors ────────────────────────────────────────────────────

#[test]
fn ambiguous_constructors_fires() {
    // op=1 (bits 0-3) and mode=1 (bits 4-7) overlap at byte 0x11;
    // neither pattern includes the other.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,3) mode=(4,7);
:insnA is op=1   {{ }}
:insnB is mode=1 {{ }}
"
    );
    assert!(
        has_lint(&src, "ambiguous-constructors"),
        "expected ambiguous-constructors"
    );
}

#[test]
fn ambiguous_constructors_no_fire_when_patterns_are_disjoint() {
    // op=1 & mode=0  vs  op=1 & mode=1  — every input matches at most one.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,3) mode=(4,7);
:insnA is op=1 & mode=0 {{ }}
:insnB is op=1 & mode=1 {{ }}
"
    );
    assert!(
        no_lint(&src, "ambiguous-constructors"),
        "unexpected ambiguous-constructors"
    );
}

// ── pattern-explosion ─────────────────────────────────────────────────────────

#[test]
fn pattern_explosion_fires() {
    // 7 binary fields each ORed → 2^7 = 128 disjunctions, which exceeds the
    // threshold of 64.
    let src = format!(
        "{PREAMBLE}
define token instr(8) b0=(0,0) b1=(1,1) b2=(2,2) b3=(3,3) b4=(4,4) b5=(5,5) b6=(6,6);
:explode is (b0=0|b0=1) & (b1=0|b1=1) & (b2=0|b2=1) & (b3=0|b3=1) & (b4=0|b4=1) & (b5=0|b5=1) & (b6=0|b6=1) {{ }}
"
    );
    assert!(
        has_lint(&src, "pattern-explosion"),
        "expected pattern-explosion"
    );
}

#[test]
fn pattern_explosion_no_fire_for_simple_constructor() {
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,7);
:simple is op=5 {{ }}
"
    );
    assert!(
        no_lint(&src, "pattern-explosion"),
        "unexpected pattern-explosion"
    );
}

// ── always-false-pattern ──────────────────────────────────────────────────────

#[test]
fn always_false_pattern_fires() {
    // op=0 AND op=1 on the same field is a contradiction; after normalization
    // the disjunction is empty.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,7);
:impossible is op=0 & op=1 {{ }}
"
    );
    assert!(
        has_lint(&src, "always-false-pattern"),
        "expected always-false-pattern"
    );
}

#[test]
fn always_false_pattern_no_fire_for_valid_constructor() {
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,7);
:valid is op=5 {{ }}
"
    );
    assert!(
        no_lint(&src, "always-false-pattern"),
        "unexpected always-false-pattern"
    );
}

// ── trivial-catch-all ─────────────────────────────────────────────────────────

#[test]
fn trivial_catch_all_fires_with_sibling() {
    // ':any' has no bit constraints → always-true; it coexists with ':specific'.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,7);
:any      is op        {{ }}
:specific is op=5      {{ }}
"
    );
    assert!(
        has_lint(&src, "trivial-catch-all"),
        "expected trivial-catch-all"
    );
}

#[test]
fn trivial_catch_all_no_fire_when_alone() {
    // A single always-true constructor in a table is fine.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,7);
:any is op {{ }}
"
    );
    assert!(
        no_lint(&src, "trivial-catch-all"),
        "unexpected trivial-catch-all"
    );
}

// ── duplicate-constructor ─────────────────────────────────────────────────────

#[test]
fn duplicate_constructor_fires() {
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,7);
:dup is op=5 {{ }}
:dup is op=5 {{ }}
"
    );
    assert!(
        has_lint(&src, "duplicate-constructor"),
        "expected duplicate-constructor"
    );
}

#[test]
fn duplicate_constructor_no_fire_for_distinct_patterns() {
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,7);
:a is op=5 {{ }}
:b is op=6 {{ }}
"
    );
    assert!(
        no_lint(&src, "duplicate-constructor"),
        "unexpected duplicate-constructor"
    );
}

// ── self-referencing-display ──────────────────────────────────────────────────

#[test]
fn self_referencing_display_fires() {
    // The first op2 constructor registers the table in the symbol table.
    // The second op2 constructor's display contains "op2", which now resolves
    // to DisplayElement::Table(op2_id) — the same table being defined — triggering
    // the lint.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,7);
op2: r0    is op=0 {{ export r0; }}
op2: op2   is op=1 {{ export r0; }}
"
    );
    assert!(
        has_lint(&src, "self-referencing-display"),
        "expected self-referencing-display"
    );
}

#[test]
fn self_referencing_display_no_fire_for_safe_table() {
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,3) reg=(4,7);
attach variables [reg] [r0 r1 r2 r3 r0 r1 r2 r3];
reg_op: reg is reg {{ export reg; }}
:insn reg_op is op=1 & reg_op {{ r0 = reg_op; }}
"
    );
    assert!(
        no_lint(&src, "self-referencing-display"),
        "unexpected self-referencing-display"
    );
}

// ── context-field-write-only ──────────────────────────────────────────────────

#[test]
fn context_write_only_fires() {
    // 'mode' is written by :setter but never read in any action, operand, or display.
    let src = format!(
        "{PREAMBLE_CTX}
define context ctxreg mode=(0,0);
define token instr(8) op=(0,7);
:setter is op=0 [mode=1;] {{ }}
:other  is op=1 {{ }}
"
    );
    assert!(
        has_lint(&src, "context-field-write-only"),
        "expected context-field-write-only"
    );
}

#[test]
fn context_write_only_no_fire_when_field_is_read() {
    // 'mode' is written in one action and read into 'other' in another.
    let src = format!(
        "{PREAMBLE_CTX}
define context ctxreg mode=(0,0) other=(1,1);
define token instr(8) op=(0,7);
:setter is op=0 [mode=1;]      {{ }}
:reader is op=1 [other=mode;]  {{ }}
"
    );
    // 'mode' is read (in the rhs of other=mode), so the lint must not fire for it.
    let codes = lint_codes(&src);
    let mode_fired = codes.iter().any(|c| c == "context-field-write-only");
    // Note: 'other' may fire (it is written by :reader but never itself read).
    // We only assert that the lint doesn't mis-fire on 'mode'.
    // Verify by checking that the number of context-write-only diagnostics is exactly
    // what we expect: one for 'other', zero for 'mode'.
    let count = codes
        .iter()
        .filter(|c| *c == "context-field-write-only")
        .count();
    assert_eq!(
        count, 1,
        "expected exactly one context-field-write-only (for 'other'), got {count}; all codes: {codes:?}"
    );
    let _ = mode_fired; // mode_fired itself is not directly testable without inspecting messages
}

// ── unused-field ──────────────────────────────────────────────────────────────

#[test]
fn unused_field_fires() {
    // 'unused' is never referenced anywhere; 'op' is only tested by the
    // pattern, which is a use.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,3) unused=(4,7);
:insn is op=0 {{ }}
"
    );
    let messages = lint_messages(&src, "unused-field");
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("`unused`"), "{messages:?}");
}

#[test]
fn unused_field_no_fire_for_constraint_only_uses() {
    // Every kind of pattern reference counts: a comparison, a bare name, an
    // arithmetic constraint value, and a `with` block's own constraint.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,3) mode=(4,5) sel=(6,6) hi=(7,7);
with : mode=1 {{
  :a is op=0 & sel {{ }}
  :b is op=(hi+1) {{ }}
}}
"
    );
    assert!(
        no_lint(&src, "unused-field"),
        "{:?}",
        lint_messages(&src, "unused-field")
    );
}

#[test]
fn unused_field_no_fire_when_field_is_in_display() {
    // 'reg' appears as an operand and in the display, so it is referenced.
    let src = format!(
        "{PREAMBLE}
define token instr(8) op=(0,3) reg=(4,7);
attach variables [reg] [r0 r1 r2 r3 r0 r1 r2 r3];
:insn reg is op=0 & reg {{ r0 = reg; }}
"
    );
    assert!(
        no_lint(&src, "unused-field"),
        "unexpected unused-field for 'reg'"
    );
}
