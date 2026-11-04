# Native datatype layout

`ghidra-types` owns an immutable graph of declared datatypes and computes their
storage geometry in Rust. It runs no Java or C++ process and uses no host C ABI.
It is a foundation for datatype-driven compiler rules and type recovery; neither
of those consumers is integrated yet.

```rust
use std::sync::Arc;
use ghidra_languages::DataOrganization;
use ghidra_types::*;

let definitions: Arc<[TypeDefinition]> = vec![
    TypeDefinition::new("char", TypeKind::Builtin(Builtin::Char)),
    TypeDefinition::new("int", TypeKind::Builtin(Builtin::Int)),
    TypeDefinition::new("record", TypeKind::Structure(Composite {
        fields: vec![Field::new("tag", TypeId(0)), Field::new("value", TypeId(1))],
        ..Default::default()
    })),
].into();
let organization = DataOrganization::default().resolve(8);
let layouts = TypeLayouts::new(definitions, organization, Limits::default())?;
let record = layouts.layout(TypeId(2))?;
assert_eq!(record.geometry.size, Some(8));
assert_eq!(record.fields[1].offset, 4);
# Ok::<(), ghidra_types::Error>(())
```

The model covers sized integer/float/opaque scalars, compiler-sized builtins,
enum storage, void, incomplete types, pointers, aliases, fixed/zero-count arrays,
automatically packed structures/unions, and unsized function signatures. IDs
retain input order. Names are bounded metadata, not identifiers in a C namespace.
Enum values and integer signedness interpretation do not affect layout. `Char`
uses the supplied organization's size; its signedness remains available through
`organization().char_signed` rather than being inferred from the host.

`Geometry` preserves raw logical size, public/display length, aligned length and
alignment separately. Empty composites and zero-count arrays have logical size
zero but public/aligned length one. Void has actual length zero. Incomplete types
and functions have no length and cannot be embedded by value. An array uses its
element's aligned length as its stride, including the one-byte placeholder of an
empty composite. Ordinary zero-sized fields align the structure cursor but consume
no bytes. Aliases copy geometry without copying expanded field arrays.

Alignment follows the retained `DataOrganizationImpl`, `DataTypeImpl`,
`PointerDataType`, `ArrayDataType`, `EnumDataType`, `AlignedComponentPacker`,
`AlignedStructurePacker`, and `CompositeAlignmentHelper` implementations:

- Primitive aligned length rounds raw size using the size-map floor lookup;
  primitive alignment then uses the aligned length's floor lookup. Enum aligned
  length remains its raw width.
- A pointer keeps its declared/default width. When that width has no exact map
  key, pointer alignment uses `default_pointer_alignment` without the absolute
  maximum clamp. Other primitive lookups clamp by the absolute maximum.
- Positive packing caps member placement alignment. Nested aggregate layouts
  remain intact. Default aggregate alignment uses the LCM of conveyed alignments.
  GCC structures convey the running maximum within their ordinary-member group;
  MS structures and unions convey each member's alignment separately. These
  coincide for power-of-two alignments; other alignment orders can differ.
- A structure raises that alignment with `max(minimum, alignment)`. A union uses
  LCM with its minimum and then applies the absolute maximum. Both pad their
  final nonzero lengths. Empty aggregates retain zero logical size.
- Arbitrary positive alignments use overflow-checked arithmetic, not power-of-two
  bit masks. Zero alignments, malformed/unsorted size maps and overflow fail
  explicitly. This engine does not emulate Java signed-int overflow.

The caller supplies a **final** `ResolvedDataOrganization`. The retained Java
`DataOrganizationImpl.restoreXml` assigns primitive sizes directly; it does not
call its separate coupled primitive-size setter methods. `DataOrganization::resolve`
correctly preserves those independent XML values. This layout engine also leaves
a hand-built organization's sizes intact rather than imposing C size ordering.
Zero size/alignment settings are rejected by the geometry validator even though
the compiler-spec data model can capture them.

`Field::bitfield(name, base, declared_bits)` declares a bitfield; `Field::new`
still declares an ordinary member, and `Field::bit_width` tells them apart. Each
declared field, including a zero-width bitfield, keeps exactly one `FieldLayout`
at its declaration index, so the composite and field index remain its identity.
For a bitfield, `FieldLayout::bitfield` reports `BitfieldLayout` separately:

- `declared_bits` (`0..=255`) and `effective_bits` (the declared width clamped
  to `8 * base_bytes`);
- `base_bytes`, the base's raw length and the MS allocation unit;
- `storage_bytes`, the minimal bytes containing the field from its byte offset;
- `bit_offset` (`0..=7`), the right shift of the field's least-significant bit
  within `storage_bytes` read as a big-endian value.

`FieldLayout::bytes` is that minimal storage, or zero for a zero-width bitfield,
whose storage is still one byte and whose bit offset is 0 for little-endian and
7 for big-endian. `FieldLayout::alignment` is the declared base's alignment
capped by packing; compiler placement need not put a bitfield at a multiple of
it.

```rust
use std::sync::Arc;
use ghidra_languages::DataOrganization;
use ghidra_types::*;

// struct B1 { char a; unsigned short b:6; int c:8; short d:4; }
let definitions: Arc<[TypeDefinition]> = vec![
    TypeDefinition::new("char", TypeKind::Builtin(Builtin::Char)),
    TypeDefinition::new("ushort", TypeKind::Builtin(Builtin::UnsignedShort)),
    TypeDefinition::new("int", TypeKind::Builtin(Builtin::Int)),
    TypeDefinition::new("short", TypeKind::Builtin(Builtin::Short)),
    TypeDefinition::new("B1", TypeKind::Structure(Composite {
        fields: vec![
            Field::new("a", TypeId(0)),
            Field::bitfield("b", TypeId(1), 6),
            Field::bitfield("c", TypeId(2), 8),
            Field::bitfield("d", TypeId(3), 4),
        ],
        ..Default::default()
    })),
].into();
let gcc = DataOrganization::default().resolve(8);
assert_eq!(
    TypeLayouts::new(definitions.clone(), gcc.clone(), Limits::default()).unwrap_err(),
    Error::EndiannessRequired { owner: TypeId(4), field: 1 },
);
let layouts =
    TypeLayouts::new_with_endianness(definitions, gcc, Endianness::Little, Limits::default())?;
let record = layouts.layout(TypeId(4))?;
let c = record.fields[2].bitfield.unwrap();
assert_eq!((record.fields[2].offset, c.storage_bytes, c.bit_offset), (1, 2, 6));
assert_eq!((record.geometry.size, record.geometry.alignment), (Some(4), 4));
# Ok::<(), ghidra_types::Error>(())
```

Byte order determines bit offsets, so it is an explicit input. `TypeLayouts::new`
keeps its behavior for bitfield-free graphs and returns
`Error::EndiannessRequired` for any declared bitfield, even in an unreferenced
type. `TypeLayouts::new_with_endianness` takes the program byte order; it is
never inferred from the host or the data organization. Byte order changes only
bit offsets: offsets, sizes and alignments are identical in both orders.

A base must be an integer (including `Bool` and the char builtins), an enum, or
an alias chain to one, as in `BitFieldDataType.isValidBaseDataType`. `WChar`,
float, opaque, pointer, array, composite, void, incomplete and function bases,
and widths above 255, fail with `Error::InvalidBitfield`. Base classes propagate
through aliases in dependency order, so no bitfield walks an alias chain.

Structures follow `AlignedComponentPacker` and `AlignedStructurePacker`; the
convention is `use_ms_bitfield_convention`:

- GCC keeps one group from the first member until a zero-width bitfield. MS also
  starts a group at each ordinary/bitfield transition and between adjacent
  nonzero bitfields whose base byte sizes differ; signedness and type identity
  do not matter.
- A group's first bitfield is placed at the packed alignment of its primitive
  base. For an enum that is the unsigned integer of the enum's length, whose
  alignment can differ from the enum's own. That alignment is always conveyed.
- A continuation starts in the previous bitfield's last byte after its consumed
  bits, or at the next byte when that byte is full. Under GCC it also follows an
  ordinary member at that member's end. It uses the packed declared-base
  alignment, or 1 for GCC with any explicit packing. If its tentative storage is
  misaligned or larger than its base and would leave the base-sized window at
  the aligned byte at or below its offset, it moves to the next aligned byte.
- An MS group reserves its whole allocation unit. When a continuation's
  tentative last byte reaches past that unit, a new unit starts at its offset.
  A GCC structure ends at the last component's minimal storage.
- A zero-width bitfield is placed with its successor at the later of the
  zero's aligned offset and the successor's minimum aligned offset. An ordinary
  successor uses its packed alignment. A bitfield successor uses the zero's
  alignment under GCC and its own placement alignment under MS, and then no
  boundary test applies. A trailing zero-width bitfield rounds to its base's
  natural alignment regardless of packing and conveys its packed alignment:
  `pack(1)` with a trailing `long long :0` can give size 8 and alignment 1.
- MS ignores a zero-width bitfield without a preceding bitfield and otherwise
  conveys its packed base alignment. GCC places an interior one at natural
  alignment, ignoring packing, and conveys that alignment only through a
  bitfield successor. With `bitfield_type_alignment_enabled == false`, GCC uses
  the positive `bitfield_zero_length_boundary`, else 1. MS forces type
  alignment on and the boundary to zero. The flag affects only zero widths.

Unions place every member at offset zero with normalized minimal storage: bit
offset 0 for little-endian, and `8 * storage - width` (7 at zero width) for
big-endian. A bitfield allocates its whole base under MS, even at zero width.
Under GCC it allocates nothing at zero width, `LCM(minimal storage, pack)` when a
positive pack is below the base size (a 17-bit `int` with `pack(2)` allocates
six bytes), and otherwise its base. GCC unions ignore a zero-width bitfield's
alignment. The ordinary union minimum, LCM and absolute-maximum rules follow.

Policies where the retained source is history-dependent or narrower:

- Java never re-places a non-final zero-width bitfield whose successor is also
  zero-width; its stored offset comes from an earlier pack. This engine reports
  the offset that declaration-order construction stores, its trailing placement
  at that point. GCC derives the next zero's group offset from it; MS advances
  by the first zero's base size, even when MS ignored that zero.
- Java's union insertion rewrites a declared width above the base width to the
  effective width. This engine keeps the caller's declared width; layout is the
  same.
- Integer bases may have widths without a retained Java integer class (outside
  1..=8 and 16); the same arithmetic applies.
- These source rules are reproduced, not verified against compilers, and may
  differ from a compiler ABI: no boundary test after a zero-width bitfield, GCC
  conveying an interior zero's alignment through a bitfield successor, and
  packed placement alignment 1 letting a bitfield cross its base unit, including
  under MS.

A composite without bitfields never enters the bitfield packer, so its ordinary
layout is unchanged. A crate test routes generated ordinary graphs through both
paths and requires identical results.

All references are checked, including pointer targets, function signatures and
unreferenced types. An iterative dependency walk rejects aliases/arrays/aggregate
cycles by value. Pointer targets and signature references are not size
dependencies, so a recursive structure through a pointer is valid. There is no
recursive traversal or recursively owned type tree.

`Limits` bounds input types, fields, references, name lengths/bytes, size-map
entries, dependency depth, each type/field byte extent and work. Node/field counts
are checked before output allocation, and depth before stack growth. Arithmetic
and work charges are checked before growth; failure returns no partial snapshot.
No allocation depends on an array count or object byte size. Allocation failure
uses ordinary Rust behavior. The default byte-size cap is `i32::MAX`; callers
can explicitly raise it, with checked `u64` geometry still enforced.

With N types, F fields, R references, M alignment-map entries and A the largest
alignment, time is `O(N + F + R + M + (N + F) log(M+1) + F log A)` and storage
is `O(N + F)` besides owned inputs. The per-field lookup term is for enum
bitfield bases. No allocation depends on a bit width. Work includes validation
visits, dependency steps, layout visits, conservative binary-search charges and
Euclidean GCD steps. `stats()` reports work and input counts. Work can expire
before other caps.

Still required for the full port: manual/disabled composite layout, including
explicitly placed bitfields; bitfield pragmas such as `bit_field_size`,
`bit_field_align` and `bit_packing`, and other member-specific alignment
attributes; dynamic/factory datatypes; mutable datatype managers and their
repack history; bitfield value extraction and display; archive/import/export
formats; enumerator semantics; source parsing; rule classification; ABI use of
bitfield-bearing types; type inference and propagation. There is no C output or
inferred function signature. Tested toolchain and validation are recorded with
each integration; the workspace minimum Rust version remains 1.88.

Validation includes 16 layout/reference/error/budget tests, seven independent
aggregate-oracle tests and the README example. The oracle checks 192 generated
acyclic graphs (24,000 types and 24,048 fields) against separate arithmetic,
then permutes every graph's IDs and checks another 24,000 layouts with forward
and backward by-value references.
Exact and one-below limits, every smaller work budget, a 100,000-type alias
chain, pointer recursion and large arrays with constant-size metadata are
covered. This evidence does not establish complete datatype-framework parity.

Independent review approved the foundation at `e17225c4db`, including separate
source-derived oracles over about 142,000 shuffled-ID types, exact resource
boundaries, allocation probes and 100,000-deep aggregates in debug/release.
Rust 1.88 was not run. The review does not cover later bitfield or ABI consumers.

Bitfield validation compares all 156 retained Java composite expectations: 47
structures and 5 unions for each of GCC x86-64 little-endian, MIPS big-endian
and MSVC x86-64. They are extracted mechanically from the six Java test classes
and compared field by field with a transcription of `bitfields.h`; the same
declarations are checked for byte-order symmetry. Seventeen directed tests cover
the API, the rules and policies above, base eligibility, exact and one-below
limits with every smaller work budget, overflow, a 100,000-alias chain shared by
20,000 bitfields, and 100,000 maximal-width bitfields. An independent
bit-cursor reference checks 4,500 generated composites per byte order (16,232
bitfields, 3,792 zero-width) over three nondecreasing power-of-two maps and
five GCC/MS zero-width settings, with storage, ordering, nonoverlap and
containment properties. The bitfield README example and the ordinary-path
equivalence test complete it. This evidence does not establish complete
datatype-framework or compiler-ABI parity.
