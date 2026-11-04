use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use criterion::{Criterion, criterion_group, criterion_main};
use sleigh::{Compiler, SourceDb};

fn spec_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn compile_spec(path: &str) {
    let mut sources = SourceDb::new();
    let root = sources
        .add_file_from_path(spec_path(path))
        .expect("spec should load");
    Compiler::new(&mut sources)
        .compile(root)
        .expect("spec should compile");
}

fn bench_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(10));

    group.bench_function("x86", |b| {
        b.iter(|| compile_spec("../precompile/open_sleigh/src/x86/x86.slaspec"))
    });

    group.bench_function("x86-64", |b| {
        b.iter(|| compile_spec("../precompile/open_sleigh/src/x86/x86-64.slaspec"))
    });

    group.bench_function("aarch64", |b| {
        b.iter(|| compile_spec("../precompile/open_sleigh/src/AARCH64/AARCH64.slaspec"))
    });

    group.finish();
}

criterion_group!(benches, bench_compile);
criterion_main!(benches);
