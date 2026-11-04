//! Heap allocations per operation on the decode → p-code hot path.
//!
//! The benchmark in `benches/decode.rs` says how long each stage takes; this
//! says how often it hits the allocator, which is what an allocation-churn
//! optimisation actually changes and what timing alone can hide in noise.
//!
//! This is its own test binary because the counting allocator has to be the
//! process-wide `#[global_allocator]`: the library never installs one, and no
//! other test shares this binary, so nothing else allocates while a region is
//! being counted. It is one `#[test]` for the same reason — parallel tests
//! would count each other.
//!
//! ```sh
//! cargo test -p wazabin-sleigh --release --test allocations -- --nocapture
//! ```
//!
//! Measure in release. A debug build is not only slow to compile the
//! specification: `pcode_ops_streamed` runs a `debug_assertions`-only check
//! that re-infers local widths, and that check allocates, so debug counts for
//! the streamed path are higher than what production sees.

#[path = "../benches/support/mod.rs"]
mod support;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};

use sleigh::{ContextBytes, Decoder};
use support::{Case, X64_CASES};

/// The system allocator with four relaxed atomic counters in front of it.
///
/// Nothing here allocates, so reading the counters from inside a measured
/// region does not disturb it. `bytes` sums the sizes requested by `alloc`,
/// `alloc_zeroed` and `realloc` (its new size), so it is heap traffic, not a
/// high-water mark.
struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static DEALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCS.fetch_add(1, Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(new_size as u64, Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    allocs: u64,
    deallocs: u64,
    reallocs: u64,
    bytes: u64,
}

impl Counts {
    fn now() -> Self {
        Self {
            allocs: ALLOCS.load(Relaxed),
            deallocs: DEALLOCS.load(Relaxed),
            reallocs: REALLOCS.load(Relaxed),
            bytes: BYTES.load(Relaxed),
        }
    }

    fn since(self, start: Self) -> Self {
        Self {
            allocs: self.allocs - start.allocs,
            deallocs: self.deallocs - start.deallocs,
            reallocs: self.reallocs - start.reallocs,
            bytes: self.bytes - start.bytes,
        }
    }

    fn scaled(self, factor: u64) -> Self {
        Self {
            allocs: self.allocs * factor,
            deallocs: self.deallocs * factor,
            reallocs: self.reallocs * factor,
            bytes: self.bytes * factor,
        }
    }
}

/// Runs `f` `iterations` times and returns the allocator traffic of the whole
/// run. `f` must not retain anything across calls, or the numbers measure
/// growth of that retained state instead of the operation.
fn measure(iterations: u64, mut f: impl FnMut()) -> Counts {
    let start = Counts::now();
    for _ in 0..iterations {
        f();
    }
    Counts::now().since(start)
}

/// Iterations per counted region. Large enough that a one-off allocation
/// hiding in the loop would show as a non-integer per-operation count.
const ITERATIONS: u64 = 1_000;

struct Path {
    name: &'static str,
    /// The row this one adds work to, so the assertions can check that the
    /// extra work never *removes* allocations, and the table can show the
    /// cost of just that work.
    extends: Option<&'static str>,
    run: fn(&Decoder<'_>, &ContextBytes, &Case),
}

/// The pipeline stages. Two branch off `decode`: the streamed lowering walks
/// the resolved semantics directly, so it shares nothing with the owned AST,
/// and `decode+owned` is the AST plus flat lowering.
///
/// ```text
///   decode ─┬─ decode+streamed          (production path)
///           └─ decode+ast ─ decode+owned
/// ```
const PATHS: &[Path] = &[
    Path {
        name: "decode",
        extends: None,
        run: |decoder, context, case| {
            black_box(support::decode(decoder, context, case).len());
        },
    },
    Path {
        // The production path: plan and emit straight from the resolved
        // semantics, without an instruction-wide AST in between.
        name: "decode+streamed",
        extends: Some("decode"),
        run: |decoder, context, case| {
            let instruction = support::decode(decoder, context, case);
            black_box(support::stream(&instruction, case.name));
        },
    },
    Path {
        // The owned AST, for consumers that want the tree itself.
        name: "decode+ast",
        extends: Some("decode"),
        run: |decoder, context, case| {
            let instruction = support::decode(decoder, context, case);
            let ast = instruction
                .pcode_ast()
                .unwrap_or_else(|error| panic!("{}: AST expansion failed: {error}", case.name));
            black_box(ast.statements.len());
        },
    },
    Path {
        name: "decode+owned",
        extends: Some("decode+ast"),
        run: |decoder, context, case| {
            let instruction = support::decode(decoder, context, case);
            let pcode = instruction
                .pcode_ops()
                .unwrap_or_else(|error| panic!("{}: owned lowering failed: {error}", case.name));
            black_box(pcode.ops.len());
        },
    },
];

#[test]
fn allocations_per_operation() {
    // Everything that happens once per process happens here, before any
    // counting: compiling the specification, building the decoder, and the
    // walker's thread-local search budget on first use.
    let spec = support::x64_spec();
    let context = support::x64_context(&spec);
    let decoder = Decoder::new(&spec);
    for case in X64_CASES {
        for path in PATHS {
            (path.run)(&decoder, &context, case);
        }
    }

    // The probe itself: an empty loop must count nothing, or every number
    // below is inflated by the harness.
    let baseline = measure(ITERATIONS, || {
        black_box(());
    });
    assert_eq!(
        baseline.allocs, 0,
        "measurement loop allocates: {baseline:?}"
    );
    assert_eq!(
        baseline.reallocs, 0,
        "measurement loop reallocates: {baseline:?}"
    );

    println!();
    println!(
        "{:<18} {:<16} {:>8} {:>8} {:>8} {:>9} {:>12}   ({} iterations, per operation)",
        "instruction", "path", "allocs", "deallocs", "reallocs", "bytes", "over decode", ITERATIONS
    );
    for case in X64_CASES {
        let mut measured: Vec<(&str, Counts)> = Vec::new();
        for path in PATHS {
            let once = measure(1, || (path.run)(&decoder, &context, case));
            let total = measure(ITERATIONS, || (path.run)(&decoder, &context, case));
            let label = format!("{}/{}", case.name, path.name);

            // One iteration is the whole story: nothing is cached or grown
            // across calls, so N iterations cost exactly N times one.
            assert_eq!(
                total,
                once.scaled(ITERATIONS),
                "{label}: allocation count is not stable across iterations"
            );
            // Every iteration frees what it allocated. Reallocations move an
            // existing block, so they leave the live count alone.
            assert_eq!(
                once.allocs, once.deallocs,
                "{label}: leaks or frees foreign memory"
            );
            // Each path is the one it extends plus more work.
            let base = path.extends.map(|name| {
                measured
                    .iter()
                    .find(|(measured, _)| *measured == name)
                    .map(|(_, counts)| *counts)
                    .expect("paths are listed after the path they extend")
            });
            if let Some(base) = base {
                assert!(
                    once.allocs >= base.allocs,
                    "{label}: fewer allocations than the path it extends ({once:?} < {base:?})"
                );
            }
            measured.push((path.name, once));

            // What the p-code stage costs on top of the decode: the number an
            // allocation-churn change in the lowering actually moves.
            let over_decode = measured
                .first()
                .map(|(_, decode)| once.allocs - decode.allocs)
                .unwrap_or(0);
            println!(
                "{:<18} {:<16} {:>8} {:>8} {:>8} {:>9} {:>12}",
                case.name,
                path.name,
                once.allocs,
                once.deallocs,
                once.reallocs,
                once.bytes,
                over_decode
            );
        }
    }
    println!();
}
