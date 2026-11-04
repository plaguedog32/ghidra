//! Fixture shared by the decode benchmark and the allocation probe.
//!
//! Both measure the same hot path on the same inputs, so the specification,
//! context and instruction corpus live here once. The test binary pulls this
//! file in with `#[path]`; it is not a bench target of its own because
//! Criterion only discovers files at the root of `benches/`.

use std::{
    hint::black_box,
    path::{Path, PathBuf},
};

use sleigh::{
    CompiledSpec, Compiler, ContextBytes, Decoder, Instruction, LabelId, Opcode, PcodePlan,
    PcodeSink, SourceDb, Varnode,
};

/// Address every case is decoded at. `lea r11, [rip+disp]` and `jz rel8`
/// resolve against it, so it is fixed rather than zero to keep the resulting
/// constants non-trivial.
pub const ADDRESS: u64 = 0x1000;

/// One instruction of the corpus.
pub struct Case {
    /// Benchmark id and probe label; short, no spaces.
    pub name: &'static str,
    /// The encoding, and nothing after it: the decoder must not read past the
    /// instruction, so no trailing bytes are supplied to hide such a read.
    pub bytes: &'static [u8],
}

/// x86-64 instructions in long mode, from the cheapest to the busiest lowering.
///
/// The set is chosen to touch distinct parts of the pipeline rather than to
/// be statistically representative of a binary:
///
/// - `nop`: a single constructor, no operands, no p-code.
/// - `push_rbp`: one register operand, a store and an address temporary.
/// - `mov_rcx_mem_rdx`: a REX prefix and a memory operand sub-table.
/// - `add_rax_rcx`: flag computation, the richest temporary usage.
/// - `jz_rel8`: a conditional branch to an instruction-external address, which
///   the plan reports as a direct branch.
/// - `cmpxchg_rax_rcx`: the only case with an instruction-local label, so the
///   sink's `label` and `branch_label` paths are exercised.
/// - `rep_movsb`: a string loop; the busiest lowering, with two direct
///   branches (back to itself and to the fall-through).
/// - `lea_r11_rip`: a 7-byte encoding with a `rip`-relative displacement.
pub const X64_CASES: &[Case] = &[
    Case {
        name: "nop",
        bytes: b"\x90",
    },
    Case {
        name: "push_rbp",
        bytes: b"\x55",
    },
    Case {
        name: "mov_rcx_mem_rdx",
        bytes: b"\x48\x8b\x0a",
    },
    Case {
        name: "add_rax_rcx",
        bytes: b"\x48\x01\xc8",
    },
    Case {
        name: "jz_rel8",
        bytes: b"\x74\x05",
    },
    Case {
        name: "cmpxchg_rax_rcx",
        bytes: b"\x48\x0f\xb1\xc8",
    },
    Case {
        name: "rep_movsb",
        bytes: b"\xf3\xa4",
    },
    Case {
        name: "lea_r11_rip",
        bytes: b"\x4c\x8d\x1d\x20\x00\x00\x00",
    },
];

fn spec_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

/// Compiles the vendored x86-64 specification. Takes a few hundred
/// milliseconds: call once, outside anything timed.
pub fn x64_spec() -> CompiledSpec {
    let mut sources = SourceDb::new();
    let root = sources
        .add_file_from_path(spec_path(
            "../precompile/open_sleigh/src/x86/x86-64.slaspec",
        ))
        .expect("x86-64 spec should load; run `just setup` to fetch the open_sleigh submodule");
    Compiler::new(&mut sources)
        .compile(root)
        .expect("x86-64 spec should compile")
}

/// The long-mode context `sleigh-precompile` builds x64 with.
pub fn x64_context(spec: &CompiledSpec) -> ContextBytes {
    let mut context = spec.new_context();
    for (name, value) in [("longMode", 1), ("addrsize", 2), ("opsize", 1)] {
        let field = spec.field(name).expect("x86-64 context field exists");
        spec.set_context_field(&mut context, field.id, value)
            .expect("x86-64 context value is valid");
    }
    context
}

/// Decodes `case`, panicking with its name if the corpus has gone stale.
pub fn decode<'spec>(
    decoder: &Decoder<'spec>,
    context: &ContextBytes,
    case: &Case,
) -> Instruction<'spec, 'static> {
    decoder
        .decode_one(ADDRESS, black_box(case.bytes), context)
        .unwrap_or_else(|error| panic!("{}: decode failed: {error}", case.name))
}

/// A sink that keeps nothing: it tallies what arrives and lets every operand
/// pass through `black_box`, so the emitter cannot be optimised away and the
/// sink itself adds neither allocation nor retained output to the measurement.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TallySink {
    pub ops: usize,
    pub labels: usize,
    pub local_branches: usize,
    pub direct_branches: usize,
    pub direct_calls: usize,
}

impl TallySink {
    /// The `make_sink` argument of [`Instruction::pcode_ops_streamed`].
    pub fn from_plan(plan: &PcodePlan) -> Self {
        Self {
            direct_branches: plan.direct_branches().len(),
            direct_calls: plan.direct_calls().len(),
            ..Self::default()
        }
    }
}

impl PcodeSink for TallySink {
    #[inline]
    fn op(&mut self, opcode: Opcode, output: Option<Varnode>, inputs: &[Varnode]) {
        black_box((opcode, output, inputs));
        self.ops += 1;
    }

    #[inline]
    fn label(&mut self, label: LabelId) {
        black_box(label);
        self.labels += 1;
    }

    #[inline]
    fn branch_label(&mut self, opcode: Opcode, label: LabelId, condition: Option<Varnode>) {
        black_box((opcode, label, condition));
        self.local_branches += 1;
    }
}

/// Decode + streamed lowering, the production path.
pub fn stream(instruction: &Instruction<'_, '_>, name: &str) -> TallySink {
    instruction
        .pcode_ops_streamed(TallySink::from_plan)
        .unwrap_or_else(|error| panic!("{name}: streamed lowering failed: {error}"))
}
