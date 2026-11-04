# ELF RELR metadata inspection

This is an implementation contract, not completed loader support. The native
Linkage view currently omits packed relative relocations. This stage adds
their inspection to the existing core and desktop/headless metadata path;
relocation application remains separate work.

## Source basis

The [ELF ABI, section 6.2](https://gabi.xinuos.com/elf/06-reloc.html#relative-relocation-table)
defines class-sized words and virtual addresses. An even word supplies one
address. Odd words are bitmaps over the following 31 or 63 address-sized
units; consecutive bitmaps cover successive complete blocks. The first word
must be an address. Odd relocation addresses cannot be represented. Relative
relocations adjust stored values by the load-time/link-time address difference.

The retained `ElfRelocationTable.java:165–239` supplies the corresponding
parser. `ElfHeader.java` recognizes both standard and Android RELR tables;
`ElfSectionHeaderConstants.java` defines section types 19 and `0x6fffff00`.
The Java parser treats the first word unconditionally as an address; reject
an initial bitmap according to the ABI instead of carrying that lax behavior.

Pinned `object 0.37.3` exposes raw ELF headers and a RELR iterator. Its generic
relocation enumeration omits these tables. The dedicated iterator increments
32/64-bit offsets without checked arithmetic, so use a bounded decoder for
untrusted data. Its iterator can be an independent valid-input test reference.

## Integration and records

Add a focused module under `crates/ghidra-core/src/linkage/`. Use the pinned
`read::elf::ElfFile`, `FileHeader` and `SectionHeader` APIs to locate sections,
borrow checked data ranges and obtain class/endian/entry-size metadata. Do not
duplicate the complete ELF header parser or change dependencies.

Read `SHT_RELR` and `SHT_ANDROID_RELR` by section type, independent of names.
Preserve encoded virtual addresses; do not add the relocation section's
address. Width comes from ELF class, not architecture name: ELFCLASS32 x32
still contains 32-bit RELR words. No new disassembler support is implied.

Emit the existing `Relocation` shape: width 32 or 64 bits, distinct standard/
Android encoding labels, target `load bias`, and explicit table addend zero.
Stored values are not read or modified. Keep an explicit warning that the
in-place values/addends are not evaluated. Do not invent architecture-specific
numeric `R_*_RELATIVE` types, symbols or relocation results.

Process each packed section once. Preserve repeated and out-of-order encoded
addresses as records: this is not the redundant traditional section/dynamic
view that the existing `seen` set coalesces. Keep the final stable address sort
and the existing metadata field/schema layout.

Update the ELF coverage warning to state the remaining sectionless dynamic
table and Android APS2 gaps, rather than claiming all RELR is omitted. Dynamic
`DT_RELR`/Android tables without sections, APS2, relocation application and
new executable formats are outside this stage. Compressed RELR sections need
an explicit unsupported warning and must not be decoded as raw records.

## Decoder and limits

- Entry size must equal the ELF class width, including for an empty table.
  Reject partial words, invalid ranges and an initial bitmap with clear errors.
  Read both byte orders from byte chunks, without host-alignment assumptions.
- Direct addresses need only the format's even-address constraint; do not add
  a pointer-alignment requirement.
- Use a widened cursor and slot end. A relocated word ending exactly at the
  exclusive address-space end `2^32`/`2^64` is valid. Reject emitted storage
  outside that domain; never wrap to an invented low address.
- Empty bitmaps still advance by a full block. They can move the widened
  cursor past the domain without emitting a record; a later direct address
  resets it. A subsequent set bit outside the domain must fail.
- Iterating only set bits is sufficient, but each bitmap must advance by the
  entire block, not by the last emitted bit.
- Share the existing 100,000 inspected-relocation allowance with traditional
  records. Count decoded packed records even when their addresses repeat.
  Check the cap before output growth or inspecting the next relocation.
- Separately bound total packed words across all RELR sections to 100,000,
  including empty bitmaps. Caps return the established partial metadata plus
  explicit coverage warnings. Malformed input returns an error, not a partial
  successful result. Do not inspect malformed records beyond an exhausted cap.
- Work is bounded by packed words plus decoded records, with no allocation
  proportional to a bitmap's address span. Existing section/file/name limits
  remain. No recursion or new unbounded global table is needed.

## Acceptance evidence

Use byte-constructed ELF fixtures and an independently written address-list
encoder or reference for both classes, both byte orders and both section
types. Assert public `BinaryImage::parse(...).linkage()` records and warnings,
not just a private decoder's output. Cover:

- Direct entries, bitmaps with low/high bits, consecutive sparse/empty/dense
  bitmaps, new bases, repeated/unsorted addresses and even unaligned addresses.
- First bitmap, wrong/zero entry size, partial/truncated data, compressed
  sections and unrelated traditional relocations.
- Exact address-domain ends, real overflow, zero bitmaps beyond the domain
  and later resets; no debug overflow panic or release wrapping.
- Encoded and decoded limits at exactly the cap and one beyond it, including
  duplicate records and empty bitmaps. Traditional and packed records must
  share their inspection budget.
- Seeded address-list round trips and independent valid-input comparison to
  the pinned object iterator. Meaningful mutations must catch wrong bitmap
  origin, advancement, endian/width, lost duplicates, overflow and cap checks.
- Byte-identical input data before/after inspection, explicit missing
  in-place values, and unchanged PE/raw/function-report examples.

Run focused/core and workspace checks, stable and Rust 1.88 tests, formatting,
Clippy/rustdoc with warnings denied, release and Java-free headless inspection.
Provide a real compiler-produced RELR fixture/probe if available, with clear
provenance; do not run imported programs. A later independent review must
inspect parser safety, bounds, address semantics and public integration.
