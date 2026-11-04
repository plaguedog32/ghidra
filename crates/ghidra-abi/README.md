# Native compiler storage

This crate resolves compiler-spec storage declarations against actual language
registers and address spaces. It keeps signed stack addresses, register aliases
and join significance explicit. It is a native Rust layer and uses no Java or
Ghidra C++ process.

Argument allocation, register resource groups, prototype-rule evaluation,
injection compilation and type recovery remain separate stages. Successful
storage resolution does not mean that a calling convention is executable.

## API and ownership

`RegisterFile::new(spaces, default_space, registers, limits)` owns an immutable
physical register layout. Overlapping aliases are permitted; exact duplicate
register names, invalid spaces and overflowing extents are errors. Register IDs
retain input order. Name lookup follows Ghidra's exact/lower/upper spelling
policy for ASCII identifiers, with later case-variation collisions winning.
Other Unicode case folding and additional processor-spec register aliases are
not synthesized. Large declarative registers are permitted; this does not
extend the concrete P-code evaluator's maximum value width.

`CompilerStorage::new(Arc<CompilerSpec>, Arc<RegisterFile>, limits)` creates an
owned resolution overlay while sharing its inputs. `BindingSite` identifies
the original model/list index, so input/output pools, return locations,
unaffected/killed registers and other declarations remain attributable to the
source. Range, space-base and dead-code-delay declarations are resolved too.
`return_addresses(model)` applies the spec-level fallback; an explicit empty
model return list suppresses it. Queries borrow existing data and do not
allocate. The types are usable across threads without a compiled SLEIGH object.

`resolve_storage` resolves an individual declaration without a compiler model:

```rust
use ghidra_abi::{RegisterFile, ResolvedStorage, resolve_storage};
use ghidra_languages::Storage;
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let ram = AddressSpace { id: SpaceId(1), name: "ram".into(),
    kind: SpaceKind::Ram, address_size: 4, word_size: 1,
    endianness: Endianness::Little };
let file = RegisterFile::new(vec![ram], SpaceId(1), vec![], Default::default())?;
let declaration = Storage::Address { space: "stack".into(),
    offset: (-4_i64) as u64, size: Some(4) };
let resolved = resolve_storage(&file, None, &declaration, None, Default::default())?;
let ResolvedStorage::Single(range) = resolved else { unreachable!() };
assert_eq!(range.address.signed_stack_offset(), Some(-4));
# Ok(())
# }
```

## Address and storage policies

- Language spaces retain their actual IDs. Compiler-only `Stack` and `Other`
  use distinct enum variants, never invented colliding numeric IDs. Numeric
  join-space locations are rejected without a join record.
- Offsets are **bytes**, including in word-addressed spaces. Stack width is
  the smaller of the pointer register width and backing-space width; its unit
  size comes from the backing space. Without a stack pointer, the default
  language space supplies those properties. Stack domains wider than 64 byte
  address bits are rejected.
- Stack offsets use signed, sign-extended Java-long bits. Narrow unsigned
  spaces normalize accepted negative Java-long offsets as Ghidra does;
  arbitrary out-of-range offsets are rejected rather than blindly masked.
  Fully sized physical extents must also fit, which is stricter than Ghidra's
  first-address-only validation in some parameter declarations. Literals in
  constant space are values, not memory extents.
- An unsized address stays unsized. A parameter pool's `max_size` is capacity,
  not a concrete allocated argument width. A declared physical storage width
  must be at least that maximum. Group indices and alignment/extension/class
  constraints are retained without assigning ABI resource group numbers.
- Join pieces remain **most significant first**. Concatenation pieces carry
  their least-significant-byte position. A single piece with a different
  logical width is a floating-format extension/conversion, not a bit slice;
  conversion is not executed. Empty joins, unsupported logical overrides,
  zero-width pieces and size overflow fail explicitly.

The retained references for these policies are `RegisterBuilder`,
`AbstractAddressSpace.makeValidOffset`, `BasicCompilerSpec`, `ParamEntry`,
`AddressXML.readJoinXML` and native `AddrSpaceManager::findAddJoin`.

## Bounds and remaining work

Every registry construction, compiler overlay construction and standalone
resolution call has a fresh `AbiLimits` budget. Counts bound spaces, registers,
models, output records, space bases, per-join/total pieces, name length, visited
name bytes and work. Defaults include 100,000 registers/output records,
1,024 pieces per join, one million total pieces, 16 MiB of name bytes and
100 million work units. Limits are checked before protected allocation/growth;
errors return no partial result. Error labels retain at most 64 UTF-8 bytes
plus an ellipsis.
Input ownership is supplied by the caller, and ordinary Rust allocation
failure is not caught. Upstream XML parsing and SLEIGH compilation have their
own behavior and are outside this crate's budgets.

Index construction uses ordered maps rather than repeated vector scans.
Output records and physical pieces determine storage use; no allocation is
proportional to an address-space span. Name comparisons and lookups are
charged, including the ASCII lookup spellings. Public queries must be bounded
by their caller if repeatedly applied to untrusted inputs.

The overlay preserves source diagnostics and incomplete-model status. It does
not establish legal nesting of parameter overlaps, derive resource groups,
allocate/justify arguments, evaluate model rules or merged-model scores,
compile injection bodies, initialize tracked registers, recover types or
apply call effects to SSA. These are required follow-on stages for the full
Rust replacement.

## Validation evidence

Expected values in the tests come from retained Ghidra sources, retained
`.sinc`/`.cspec` text or small independent models, not from replaying this
crate. `tests/basics.rs` is the original regression set. The behavioral suites
are:

- `registry.rs`: rejected layouts with their specific reasons (space count,
  width/unit/name, duplicate IDs and names, default-space kind, register space,
  zero or overflowing extents, empty and over-long names). Case-variant lookup
  is checked against a model of `RegisterBuilder`'s put order, including
  generated collisions. Alias overlap is checked against explicit byte sets in
  little- and big-endian spaces, the big-endian MIPS FPU pair layout, and
  extents ending at `u64::MAX`. Count, name-length, name-byte and work budgets
  are checked at their exact size and one below. A 4x larger register file costs
  4x the name bytes and less than 6x the work.
- `normalization.rs`: a reference model transcribed from
  `AbstractAddressSpace` (constructor and `makeValidOffset`) plus the documented
  whole-extent rule. It is compared with ram, stack and constant spaces of
  1/2/4/8-byte addresses and 1/2/4/8-byte units (more than 3,000 cases). Other
  checks cover accepted Java-long negatives, out-of-domain rejection, signed
  stack bounds, extents that would wrap, stack geometry (no-pointer fallback,
  minimum of pointer and backing width, backing units, growth/justification,
  `OTHER` backing, domains over 64 bits), default sizes, labels truncated on a
  character boundary, and standalone budgets at their exact thresholds.
- `joins.rs`: mixed-width significance, declaration order, and the nine join
  declarations taken from the retained `AARCH64_golang.cspec` text. Also float
  extensions in both directions, the native single-constant-piece exception,
  every invalid variant, a byte total of exactly `u32::MAX` versus overflow, and
  1,024 versus 1,025 pieces. The piece count is checked before any name is
  resolved.
- `compiler.rs`: every `BindingSite` kind at its source position. Also group,
  alignment, class and extension constraints; an unsized 500-byte stack pool;
  `TooSmall` exactly at the storage width, including a float extension's
  logical width; inherited, explicit and empty return addresses; open, signed
  and register ranges; space bases and dead-code delays; errors attributed to
  their site; shared `Arc` inputs; construction budgets at their exact size and
  one below; and linear overlay scaling.
- `real_catalog.rs` (ignored by default): run
  `cargo test --release -p ghidra-abi --test real_catalog -- --ignored`. It
  compiles each retained source once and resolves x86-64 `windows`, `gcc` and
  `golang`, ARMv7 `default`, MIPS32 BE `default` and AArch64 `golang`. Register
  offsets, inputs, groups, stack pools, local ranges, return-address fallback
  and Go join order are compared with the retained text. Binding, range, piece,
  space-base and delay counts are recomputed from the parsed declarations. On
  Windows, after a release build, the four probes ran in about 2 s. Observed
  output: x86-64 has 1,440 registers; its `windows`, `gcc` and `golang` specs
  produce 71/83/214 bindings, 6/4/3 ranges and 72/84/216 pieces. ARMv7 has 153
  registers, 88 bindings, 1 range and 88 pieces. MIPS32 BE has 471 registers,
  44 bindings, 4 ranges and 44 pieces. AArch64 Go has 633 registers, 157
  bindings, 1 range and 194 pieces. These are observations, not fixed
  expectations. Only these six language/compiler pairs are proven to resolve;
  parsing every catalog `.cspec` is not proof that it resolves.

Known divergences, pinned by tests named `divergence_*` so that changing them is
deliberate:

- Ghidra rejects address spaces with unit sizes outside 1..=8, or with more than
  2^64 bytes. `RegisterFile` accepts them and caps the byte domain at 2^64. A
  stack over such a domain is still rejected.
- `RegisterBuilder` turns a register with an identical address and bit range
  into an alias of the earlier `Register`. Here each declaration keeps its own
  `RegisterId`; the two still overlap. No such pair occurs in the four compiled
  probe layouts.

Other differences from Ghidra that are known and accepted: an empty register or
space name is reported as `Limit("name length")` rather than as an invalid
layout. Range bounds are normalized, and reversed ranges are rejected, which
Ghidra's `restoreRangeXml` does not check. Parameter size bounds are checked
after the storage resolves, so a declaration with both problems reports the
storage error first.

Not yet validated: the MSRV toolchain, the other catalog compiler specs,
big-endian AArch64/ARM probe layouts, and any behavior that depends on
argument allocation or prototype-rule execution.
