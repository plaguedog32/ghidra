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

The caller supplies a **final** `ResolvedDataOrganization`. This engine does not
replay XML setters or repair a hand-built organization's coupled primitive sizes.
In particular, retained Java setters can adjust other integer/float sizes in
declaration order; `DataOrganization::resolve` currently captures configured size
fields without that cross-field replay. A pathological custom `.cspec` can
therefore supply geometry different from Java's eventual settings. No claim of
complete compiler-spec loader normalization is made here.

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
alignment, time is `O(N + F + R + M + N log(M+1) + F log A)` and storage is
`O(N + F)` besides owned inputs. Work includes validation visits, dependency
steps, layout visits, conservative binary-search charges and Euclidean GCD steps.
`stats()` reports work and input counts. Work can expire before other caps.

Still required for the full port: bitfield packing, manual/disabled composite
layout, dynamic/factory datatypes, member-specific alignment attributes, mutable
datatype managers, archive/import/export formats, enumerator semantics, source
parsing, rule classification, type inference and propagation. There is no C output
or inferred function signature. Tested toolchain and validation are recorded with
each integration; the workspace minimum Rust version remains 1.88.

Validation includes 16 layout/reference/error/budget tests, seven independent
aggregate-oracle tests and the README example. The oracle checks 192 generated
acyclic graphs (24,000 types and 24,048 fields) against separate arithmetic.
Exact and one-below limits, every smaller work budget, a 100,000-type alias
chain, pointer recursion and large arrays with constant-size metadata are
covered. This evidence does not establish complete datatype-framework parity.
