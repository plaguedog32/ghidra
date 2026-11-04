use std::{
    hint::black_box,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sleigh::{CompiledSpec, Compiler, ContextBytes, Decoder, SourceDb};

struct Case {
    name: &'static str,
    bytes: &'static [u8],
}

fn spec_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn compile_spec(path: &str) -> CompiledSpec {
    let mut sources = SourceDb::new();
    let root = sources
        .add_file_from_path(spec_path(path))
        .expect("benchmark SLEIGH spec should load");
    Compiler::new(&mut sources)
        .compile(root)
        .expect("benchmark SLEIGH spec should compile")
}

fn set_context(spec: &CompiledSpec, context: &mut ContextBytes, name: &str, value: u64) {
    let field = spec.field(name).expect("benchmark context field exists");
    spec.set_context_field(context, field.id, value)
        .expect("benchmark context value is valid");
}

fn x86_context(spec: &CompiledSpec) -> ContextBytes {
    let mut context = spec.new_context();
    set_context(spec, &mut context, "addrsize", 1);
    set_context(spec, &mut context, "opsize", 1);
    context
}

fn x64_context(spec: &CompiledSpec) -> ContextBytes {
    let mut context = spec.new_context();
    set_context(spec, &mut context, "longMode", 1);
    set_context(spec, &mut context, "addrsize", 2);
    set_context(spec, &mut context, "opsize", 1);
    context
}

fn bench_decode(
    spec: &CompiledSpec,
    context: &ContextBytes,
    cases: &[Case],
    iterations: usize,
) -> Duration {
    let decoder = Decoder::new(spec);
    let started = Instant::now();
    for i in 0..iterations {
        let case = &cases[i % cases.len()];
        let instruction = decoder
            .decode_one(0x1000, black_box(case.bytes), context)
            .expect(case.name);
        black_box(instruction.len());
    }
    started.elapsed()
}

fn bench_decode_pcode(
    spec: &CompiledSpec,
    context: &ContextBytes,
    cases: &[Case],
    iterations: usize,
) -> Duration {
    let decoder = Decoder::new(spec);
    let started = Instant::now();
    for i in 0..iterations {
        let case = &cases[i % cases.len()];
        let instruction = decoder
            .decode_one(0x1000, black_box(case.bytes), context)
            .expect(case.name);
        black_box(instruction.pcode_ast().expect(case.name));
    }
    started.elapsed()
}

fn bench_decode_display(
    spec: &CompiledSpec,
    context: &ContextBytes,
    cases: &[Case],
    iterations: usize,
) -> Duration {
    let decoder = Decoder::new(spec);
    let started = Instant::now();
    for i in 0..iterations {
        let case = &cases[i % cases.len()];
        let instruction = decoder
            .decode_one(0x1000, black_box(case.bytes), context)
            .expect(case.name);
        black_box(instruction.to_string());
    }
    started.elapsed()
}

fn print_result(label: &str, elapsed: Duration, iterations: usize) {
    let nanos = elapsed.as_nanos() as f64 / iterations as f64;
    println!("{label:<24} {elapsed:>10.3?}  {nanos:>10.1} ns/iter");
}

fn run_suite(
    name: &str,
    spec: &CompiledSpec,
    context: &ContextBytes,
    cases: &[Case],
    iterations: usize,
) {
    println!("{name}: {} cases, {iterations} iterations", cases.len());
    print_result(
        "decode",
        bench_decode(spec, context, cases, iterations),
        iterations,
    );
    print_result(
        "decode+pcode",
        bench_decode_pcode(spec, context, cases, iterations),
        iterations,
    );
    print_result(
        "decode+display",
        bench_decode_display(spec, context, cases, iterations),
        iterations,
    );
    println!();
}

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse::<usize>().ok())
        .unwrap_or(100_000);

    let x86 = compile_spec("../precompile/open_sleigh/src/x86/x86.slaspec");
    let x86_context = x86_context(&x86);
    let x86_cases = [
        Case {
            name: "x86 push ebp",
            bytes: b"\x55",
        },
        Case {
            name: "x86 mov eax,[ecx]",
            bytes: b"\x8b\x01",
        },
        Case {
            name: "x86 mov eax,imm32",
            bytes: b"\xb8\x78\x56\x34\x12",
        },
        Case {
            name: "x86 ret",
            bytes: b"\xc3",
        },
    ];
    run_suite("x86", &x86, &x86_context, &x86_cases, iterations);

    let x64 = compile_spec("../precompile/open_sleigh/src/x86/x86-64.slaspec");
    let x64_context = x64_context(&x64);
    let x64_cases = [
        Case {
            name: "x64 mov eax,imm32",
            bytes: b"\xb8\x78\x56\x34\x12",
        },
        Case {
            name: "x64 mov rcx,[rdx]",
            bytes: b"\x48\x8b\x0a",
        },
        Case {
            name: "x64 add rax,rcx",
            bytes: b"\x48\x01\xc8",
        },
        Case {
            name: "x64 lea r11,rip",
            bytes: b"\x4c\x8d\x1d\x20\x00\x00\x00",
        },
    ];
    run_suite("x64", &x64, &x64_context, &x64_cases, iterations);
}
