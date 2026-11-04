//! Runtime hot path: instruction bytes → [`Decoder::decode_one`] → p-code.
//!
//! Three stages of the same pipeline are timed separately on each instruction
//! of the corpus in `support`, so the cost of each stage is the difference
//! between neighbouring groups:
//!
//! - `decode`: pattern matching only, producing an [`Instruction`].
//! - `decode+streamed`: plus [`Instruction::pcode_ops_streamed`] into a sink
//!   that retains nothing. This is the production lowering path.
//! - `decode+owned`: plus [`Instruction::pcode_ops`], which builds the owned
//!   flat [`InstructionPcode`](sleigh::InstructionPcode) the streamed API was
//!   introduced to avoid. Kept as a comparison point for that cost.
//!
//! The specification is compiled once per process and the decoder, context
//! and input bytes are reused across iterations: only the per-instruction work
//! is inside the timed closure. Compilation has its own benchmark
//! (`compile.rs`) and is not a proxy for this.
//!
//! ```sh
//! cargo bench -p wazabin-sleigh --bench decode
//! cargo bench -p wazabin-sleigh --bench decode -- 'decode/'          # decode only
//! cargo bench -p wazabin-sleigh --bench decode -- add_rax_rcx        # one instruction
//! cargo bench -p wazabin-sleigh --bench decode -- --save-baseline before
//! cargo bench -p wazabin-sleigh --bench decode -- --baseline before  # compare a change
//! ```
//!
//! The allocation counts for the same three paths come from
//! `tests/allocations.rs`.

mod support;

use std::{hint::black_box, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sleigh::Decoder;
use support::{Case, X64_CASES};

fn group(
    c: &mut Criterion,
    name: &str,
    mut run: impl FnMut(&Decoder<'_>, &sleigh::ContextBytes, &Case),
) {
    let spec = support::x64_spec();
    let context = support::x64_context(&spec);
    let decoder = Decoder::new(&spec);

    let mut group = c.benchmark_group(name);
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    for case in X64_CASES {
        group.throughput(Throughput::Bytes(case.bytes.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(case.name), case, |b, case| {
            b.iter(|| run(&decoder, &context, case))
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    group(c, "decode", |decoder, context, case| {
        let instruction = support::decode(decoder, context, case);
        black_box(instruction.len());
    });
}

fn bench_decode_streamed(c: &mut Criterion) {
    group(c, "decode+streamed", |decoder, context, case| {
        let instruction = support::decode(decoder, context, case);
        black_box(support::stream(&instruction, case.name));
    });
}

fn bench_decode_owned(c: &mut Criterion) {
    group(c, "decode+owned", |decoder, context, case| {
        let instruction = support::decode(decoder, context, case);
        let pcode = instruction
            .pcode_ops()
            .unwrap_or_else(|error| panic!("{}: owned lowering failed: {error}", case.name));
        black_box(pcode.ops.len());
    });
}

criterion_group!(
    benches,
    bench_decode,
    bench_decode_streamed,
    bench_decode_owned
);
criterion_main!(benches);
