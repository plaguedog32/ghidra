mod common;

use std::sync::Arc;

use common::*;
use ghidra_abi::*;
use ghidra_languages::{
    CompilerSpec, Extension, JoinPiece, ModelStatus, ParamEntry, Storage, StorageClass,
};
use ghidra_pcode::Endianness;

const INPUT: BindingSite = BindingSite::Input { model: 0, entry: 0 };
const OUTPUT: BindingSite = BindingSite::Output { model: 0, entry: 0 };

fn source(input: &str, output: &str, stack_attrs: &str) -> CompilerSpec {
    parse(&format!(
        r#"<compiler_spec><stackpointer register="sp" space="ram" {stack_attrs}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0"><input>{input}</input>
<output>{output}</output></prototype></default_proto></compiler_spec>"#
    ))
}

fn file(data_big: bool, register_big: bool, ram_width: u8, word: u32) -> Arc<RegisterFile> {
    let mut spaces = spaces(ram_width);
    spaces[1].word_size = word;
    spaces[1].endianness = if data_big {
        Endianness::Big
    } else {
        Endianness::Little
    };
    spaces[2].endianness = if register_big {
        Endianness::Big
    } else {
        Endianness::Little
    };
    Arc::new(RegisterFile::new(spaces, RAM, small_registers(), Default::default()).unwrap())
}

fn overlay(input: &str, stack: &str, data_big: bool, reg_big: bool) -> CompilerStorage {
    storage(
        source(input, input, stack),
        &file(data_big, reg_big, 4, 1),
        Default::default(),
    )
    .unwrap()
}

fn query(storage: &CompilerStorage, site: BindingSite, request: PlacementRequest) -> Placement {
    place_parameter(storage, site, request, Default::default()).unwrap()
}

fn placed(result: &Placement) -> &PlacedValue {
    match &result.outcome {
        PlacementOutcome::Placed(value) => value,
        other => panic!("expected placement, got {other:?}"),
    }
}

fn pieces(result: &Placement) -> &[PlacedPiece] {
    match &placed(result).storage {
        PlacedStorage::Bits { pieces } => pieces,
        other => panic!("expected bits, got {other:?}"),
    }
}

fn no_fit(result: &Placement, reason: NoFit, next_slot: u64) {
    assert_eq!(result.outcome, PlacementOutcome::NoFit(reason));
    assert_eq!(result.next_slot, next_slot);
}

#[test]
fn exclusion_pools_bound_sizes_preserve_extensions_and_do_not_consume_the_cursor() {
    for (text, extension) in [
        ("none", Extension::None),
        ("sign", Extension::Sign),
        ("zero", Extension::Zero),
        ("inttype", Extension::IntType),
    ] {
        let storage = overlay(
            &format!(
                r#"<pentry minsize="2" maxsize="4" extension="{text}"><register name="d0"/></pentry>"#
            ),
            "",
            false,
            false,
        );
        no_fit(
            &query(&storage, INPUT, PlacementRequest::new(1)),
            NoFit::BelowMinimum,
            0,
        );
        no_fit(
            &query(&storage, INPUT, PlacementRequest::new(5)),
            NoFit::AboveCapacity,
            0,
        );
        for size in 2..=4 {
            let result = query(&storage, INPUT, PlacementRequest::new(size));
            assert_eq!(result.next_slot, 0);
            assert_eq!(placed(&result).extension, extension);
            assert_eq!(placed(&result).size, size);
            assert_eq!(pieces(&result)[0].storage.address.offset, 0);
            assert_eq!(pieces(&result)[0].storage.size, Some(size));
            assert_eq!(
                pieces(&result)[0].storage.register,
                Some(storage.register_file().register_id("d0").unwrap())
            );
            assert_eq!(result, query(&storage, INPUT, PlacementRequest::new(size)));
            let output = query(&storage, OUTPUT, PlacementRequest::new(size));
            assert_eq!(output.outcome, result.outcome);
        }
        no_fit(
            &query(
                &storage,
                INPUT,
                PlacementRequest {
                    used_slots: 1,
                    ..PlacementRequest::new(3)
                },
            ),
            NoFit::ExclusionUsed,
            1,
        );
    }
}

#[test]
fn justification_uses_pool_width_and_each_spaces_byte_order() {
    for data_big in [false, true] {
        for register_big in [false, true] {
            let input = r#"<pentry minsize="1" maxsize="4"><register name="d0"/></pentry>
<pentry minsize="1" maxsize="20" align="4"><addr space="stack" offset="8"/></pentry>"#;
            let storage = overlay(input, "", data_big, register_big);
            for (justification, forced) in [
                (Justification::Default, None),
                (Justification::Left, Some(false)),
                (Justification::Right, Some(true)),
            ] {
                let request = PlacementRequest {
                    justification,
                    ..PlacementRequest::new(1)
                };
                let result = query(&storage, INPUT, request);
                // Named d0 is eight bytes wide, but its pool's maxsize is four.
                assert_eq!(
                    pieces(&result)[0].storage.address.offset,
                    if forced.unwrap_or(register_big) { 3 } else { 0 }
                );
                let stack = query(&storage, BindingSite::Input { model: 0, entry: 1 }, request);
                assert_eq!(
                    pieces(&stack)[0].storage.address.offset,
                    if forced.unwrap_or(data_big) { 11 } else { 8 }
                );
            }
        }
    }
}

#[test]
fn aligned_pools_round_sizes_skip_relative_alignment_holes_and_report_failed_cursors() {
    let storage = overlay(
        r#"<pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="4"/></pentry>"#,
        "",
        false,
        false,
    );
    let request = PlacementRequest {
        used_slots: 1,
        type_alignment: 8,
        ..PlacementRequest::new(5)
    };
    let result = query(&storage, INPUT, request);
    assert_eq!(result.next_slot, 4); // skip slot 1, then consume slots 2 and 3
    assert_eq!(pieces(&result)[0].storage.address.offset, 12); // relative alignment, not absolute 8
    assert_eq!(pieces(&result)[0].storage.size, Some(5));
    no_fit(
        &query(
            &storage,
            INPUT,
            PlacementRequest {
                used_slots: 125,
                ..request
            },
        ),
        NoFit::SlotsExhausted,
        126,
    );
    no_fit(
        &query(
            &storage,
            INPUT,
            PlacementRequest {
                used_slots: 124,
                ..request
            },
        ),
        NoFit::SlotsExhausted,
        124,
    );
    let right = query(
        &storage,
        INPUT,
        PlacementRequest {
            justification: Justification::Right,
            ..request
        },
    );
    assert_eq!(pieces(&right)[0].storage.address.offset, 15);
}

#[test]
fn arbitrary_alignment_is_exact_without_floor_division_or_linear_search() {
    // Every answer is checked by enumerating slots here, independently of gcd.
    for pool_alignment in 1..=12_u32 {
        for type_alignment in 1..=15_u32 {
            let storage = overlay(
                &format!(
                    r#"<pentry minsize="1" maxsize="240" align="{pool_alignment}"><addr space="stack" offset="0"/></pentry>"#
                ),
                "",
                false,
                false,
            );
            for used in 0..=24_u64 {
                let cursor = (used..)
                    .find(|slot| {
                        (slot * u64::from(pool_alignment)) % u64::from(type_alignment) == 0
                    })
                    .unwrap();
                let result = query(
                    &storage,
                    INPUT,
                    PlacementRequest {
                        used_slots: used,
                        type_alignment,
                        ..PlacementRequest::new(1)
                    },
                );
                if cursor < u64::from(240 / pool_alignment) {
                    assert_eq!(result.next_slot, cursor + 1);
                    assert_eq!(
                        pieces(&result)[0].storage.address.offset,
                        cursor * u64::from(pool_alignment)
                    );
                } else {
                    no_fit(&result, NoFit::SlotsExhausted, cursor);
                }
                assert!(result.work < 80);
            }
        }
    }
}

#[test]
fn upward_stack_growth_reverses_all_aligned_pools_and_big_stack_can_force_left() {
    let input = r#"<pentry minsize="1" maxsize="16" align="4"><addr space="stack" offset="-16"/></pentry>
<pentry minsize="1" maxsize="16" align="4"><addr space="register" offset="0"/></pentry>"#;
    for big in [false, true] {
        let storage = overlay(input, r#"growth="positive""#, big, big);
        let result = query(&storage, INPUT, PlacementRequest::new(3));
        assert_eq!(
            pieces(&result)[0].storage.address.signed_stack_offset(),
            Some(if big { -3 } else { -4 })
        );
        let register = query(
            &storage,
            BindingSite::Input { model: 0, entry: 1 },
            PlacementRequest::new(3),
        );
        assert_eq!(
            pieces(&register)[0].storage.address.offset,
            if big { 13 } else { 12 }
        );
        let next = query(
            &storage,
            INPUT,
            PlacementRequest {
                used_slots: result.next_slot,
                ..PlacementRequest::new(4)
            },
        );
        assert_eq!(
            pieces(&next)[0].storage.address.signed_stack_offset(),
            Some(-8)
        );
    }
    let storage = overlay(
        input,
        r#"growth="positive" reversejustify="true""#,
        true,
        true,
    );
    let result = query(&storage, INPUT, PlacementRequest::new(3));
    assert_eq!(
        pieces(&result)[0].storage.address.signed_stack_offset(),
        Some(-4)
    );
    let right = query(
        &storage,
        INPUT,
        PlacementRequest {
            justification: Justification::Right,
            ..PlacementRequest::new(3)
        },
    );
    assert_eq!(
        pieces(&right)[0].storage.address.signed_stack_offset(),
        Some(-3)
    );
    let storage = overlay(input, r#"reversejustify="true""#, false, false);
    assert!(matches!(
        place_parameter(
            &storage,
            INPUT,
            PlacementRequest::new(3),
            Default::default()
        ),
        Err(PlacementError::Unsupported { .. })
    ));
}

#[test]
fn actual_extents_fit_without_wrapping_even_when_pool_capacity_does_not() {
    let file = file(false, false, 1, 1);
    let source = source(
        r#"<pentry minsize="1" maxsize="500" align="1"><addr space="ram" offset="250"/></pentry>
<pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="120"/></pentry>"#,
        "",
        "",
    );
    let storage = storage(source, &file, Default::default()).unwrap();
    assert_eq!(
        pieces(&query(&storage, INPUT, PlacementRequest::new(6)))[0]
            .storage
            .address
            .offset,
        250
    );
    no_fit(
        &query(
            &storage,
            INPUT,
            PlacementRequest {
                used_slots: 1,
                ..PlacementRequest::new(6)
            },
        ),
        NoFit::AddressDomain,
        1,
    );
    let stack = BindingSite::Input { model: 0, entry: 1 };
    assert_eq!(
        pieces(&query(
            &storage,
            stack,
            PlacementRequest {
                used_slots: 1,
                ..PlacementRequest::new(4)
            }
        ))[0]
            .storage
            .address
            .signed_stack_offset(),
        Some(124)
    );
    no_fit(
        &query(
            &storage,
            stack,
            PlacementRequest {
                used_slots: 2,
                ..PlacementRequest::new(4)
            },
        ),
        NoFit::AddressDomain,
        2,
    );

    let storage = overlay(
        r#"<pentry minsize="1" maxsize="500" align="1"><addr space="register" offset="0xffffffffffffffff"/></pentry>"#,
        "",
        false,
        false,
    );
    assert_eq!(
        pieces(&query(&storage, INPUT, PlacementRequest::new(1)))[0]
            .storage
            .address
            .offset,
        u64::MAX
    );
    no_fit(
        &query(&storage, INPUT, PlacementRequest::new(2)),
        NoFit::AddressDomain,
        0,
    );
}

#[test]
fn word_domains_are_counted_in_bytes_and_large_values_do_not_allocate_payloads() {
    let file = file(false, false, 1, 2);
    let spec = source(
        r#"<pentry minsize="1" maxsize="500" align="1"><addr space="ram" offset="510"/></pentry>"#,
        "",
        "",
    );
    let storage = storage(spec, &file, Default::default()).unwrap();
    let result = query(&storage, INPUT, PlacementRequest::new(2));
    assert_eq!(pieces(&result)[0].storage.address.offset, 510);
    no_fit(
        &query(&storage, INPUT, PlacementRequest::new(3)),
        NoFit::AddressDomain,
        0,
    );

    let spec = source(
        r#"<pentry minsize="1" maxsize="2147483647"><addr space="ram" offset="0"/></pentry>"#,
        "",
        "",
    );
    let storage = common::storage(spec, &small_file(), Default::default()).unwrap();
    let result = query(&storage, INPUT, PlacementRequest::new(i32::MAX as u32));
    assert_eq!(pieces(&result).len(), 1);
    assert_eq!(pieces(&result)[0].storage.size, Some(i32::MAX as u32));
    assert!(result.work < 30);
}

#[test]
fn float_extensions_preserve_the_physical_format_instead_of_selecting_bytes() {
    for big in [false, true] {
        let storage = overlay(
            r#"<pentry minsize="1" maxsize="8" extension="float"><register name="f0d"/></pentry>"#,
            "",
            big,
            big,
        );
        for size in 1..8 {
            let result = query(&storage, INPUT, PlacementRequest::new(size));
            match &placed(&result).storage {
                PlacedStorage::FloatConversion {
                    container,
                    logical_size,
                } => {
                    assert_eq!(*logical_size, size);
                    assert_eq!(container.address.offset, 0x100);
                    assert_eq!(container.size, Some(8));
                }
                other => panic!("not a floating conversion: {other:?}"),
            }
        }
        assert_eq!(
            pieces(&query(&storage, INPUT, PlacementRequest::new(8)))[0]
                .storage
                .size,
            Some(8)
        );
        let storage = overlay(
            r#"<pentry minsize="1" maxsize="4"><addr space="join" piece1="f0d" size="4"/></pentry>"#,
            "",
            big,
            big,
        );
        assert!(
            matches!(&placed(&query(&storage, INPUT, PlacementRequest::new(4))).storage,
            PlacedStorage::FloatConversion { container, logical_size: 4 } if container.size == Some(8))
        );
        assert!(matches!(
            place_parameter(
                &storage,
                INPUT,
                PlacementRequest::new(2),
                Default::default()
            ),
            Err(PlacementError::Unsupported { .. })
        ));
    }
}

#[test]
fn partial_join_selection_matches_an_expanded_native_byte_address_model() {
    let mut seed = 0x53c5_3190_27b4_219f_u64;
    let mut comparisons = 0;
    for case in 0..240 {
        let data_big = case % 2 == 0;
        let first_big = case % 4 < 2;
        let mut attributes = String::new();
        let mut physical = Vec::new();
        let count = 2 + case % 7;
        for index in 0..count {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let size = 1 + (seed >> 40) as u32 % 7;
            let offset = 0x1000 + index as u64 * 32;
            // Alternate physical spaces. Only the first piece determines
            // native JoinRecord byte traversal, even for mixed-endian pieces.
            let space = if index % 2 == 0 { "register" } else { "ram" };
            attributes.push_str(&format!(
                r#" piece{}="{space}:{offset:#x}:{size}""#,
                index + 1
            ));
            physical.push((if index % 2 == 0 { REGISTER } else { RAM }, offset, size));
        }
        let total: u32 = physical.iter().map(|(_, _, size)| size).sum();
        let max_size = total - (case % 3) as u32; // sometimes smaller than the physical join
        let storage = overlay(
            &format!(
                r#"<pentry minsize="1" maxsize="{max_size}"><addr space="join"{attributes}/></pentry>"#
            ),
            "",
            data_big,
            first_big,
        );
        let mut mapping = Vec::new();
        let order: Vec<_> = if first_big {
            (0..count).collect()
        } else {
            (0..count).rev().collect()
        };
        for i in order {
            let (space, base, size) = physical[i];
            mapping.extend((0..size).map(|byte| (space, base + u64::from(byte))));
        }
        for size in 1..=max_size {
            for (justification, right) in [
                (Justification::Default, data_big),
                (Justification::Left, false),
                (Justification::Right, true),
            ] {
                let request = PlacementRequest {
                    justification,
                    ..PlacementRequest::new(size)
                };
                let result = query(&storage, INPUT, request);
                let start = if right { max_size - size } else { 0 } as usize;
                let expected = &mapping[start..start + size as usize];
                let selected = pieces(&result);
                let mut actual = Vec::new();
                let indices: Vec<_> = if first_big {
                    (0..selected.len()).collect()
                } else {
                    (0..selected.len()).rev().collect()
                };
                for index in indices {
                    let piece = &selected[index];
                    let AbiSpace::Language(space) = piece.storage.address.space else {
                        panic!()
                    };
                    let length = piece.storage.size.unwrap();
                    actual.extend(
                        (0..length)
                            .map(|byte| (space, piece.storage.address.offset + u64::from(byte))),
                    );
                }
                assert_eq!(
                    actual, expected,
                    "case {case}, size {size}, {justification:?}"
                );
                let mut remaining = size;
                for piece in selected {
                    remaining -= piece.storage.size.unwrap();
                    assert_eq!(piece.lsb_byte, remaining);
                    assert_eq!(
                        piece.storage.address.offset,
                        physical[piece.source_piece].1 + u64::from(piece.source_byte_offset)
                    );
                    assert_eq!(piece.role, PieceRole::Storage);
                }
                assert_eq!(remaining, 0);
                comparisons += 1;
            }
        }
    }
    assert!(comparisons > 12_000);
}

#[test]
fn constant_join_padding_remains_unvalued_provenance_with_partial_slices() {
    let storage = overlay(
        r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="const:0xffffffffffffffff:4" piece2="r0"/></pentry>"#,
        "",
        false,
        false,
    );
    let result = query(&storage, INPUT, PlacementRequest::new(6));
    let selected = pieces(&result);
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].role, PieceRole::Padding);
    assert_eq!(selected[0].storage.address.offset, u64::MAX);
    assert_eq!(selected[0].storage.size, Some(2));
    assert_eq!(selected[0].lsb_byte, 4);
    assert_eq!(selected[1].role, PieceRole::Storage);
    assert_eq!(selected[1].storage.address.offset, 0);
    // A single-piece selection retains its source index rather than
    // reusing the old Java partial-array indexing bug.
    let small = query(&storage, INPUT, PlacementRequest::new(1));
    assert_eq!(pieces(&small).len(), 1);
    assert_eq!(pieces(&small)[0].source_piece, 1);
}

#[test]
fn aligned_join_pools_use_logical_slot_windows_then_map_to_physical_pieces() {
    let storage = overlay(
        r#"<pentry minsize="1" maxsize="8" align="2"><addr space="join" piece1="r0" piece2="r1"/></pentry>"#,
        "",
        false,
        false,
    );
    let result = query(
        &storage,
        INPUT,
        PlacementRequest {
            used_slots: 1,
            ..PlacementRequest::new(3)
        },
    );
    assert_eq!(result.next_slot, 3);
    let selected = pieces(&result);
    assert_eq!(selected.len(), 2);
    assert_eq!(
        (
            selected[0].source_piece,
            selected[0].storage.address.offset,
            selected[0].storage.size
        ),
        (0, 0, Some(1))
    );
    assert_eq!(
        (
            selected[1].source_piece,
            selected[1].storage.address.offset,
            selected[1].storage.size
        ),
        (1, 6, Some(2))
    );
    assert_eq!((selected[0].lsb_byte, selected[1].lsb_byte), (2, 0));
}

#[test]
fn limits_are_exact_and_work_is_bounded_before_output_growth() {
    let storage = overlay(
        r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r0" piece2="r1"/></pentry>"#,
        "",
        false,
        false,
    );
    for size in [1, 5, 8] {
        let request = PlacementRequest::new(size);
        let expected = query(&storage, INPUT, request);
        let limits = PlacementLimits {
            max_source_pieces: 2,
            max_output_pieces: pieces(&expected).len(),
            max_work: expected.work,
        };
        assert_eq!(
            place_parameter(&storage, INPUT, request, limits).unwrap(),
            expected
        );
        assert!(matches!(
            place_parameter(
                &storage,
                INPUT,
                request,
                PlacementLimits {
                    max_source_pieces: 1,
                    ..limits
                }
            ),
            Err(PlacementError::Limit("source pieces"))
        ));
        assert!(matches!(
            place_parameter(
                &storage,
                INPUT,
                request,
                PlacementLimits {
                    max_output_pieces: pieces(&expected).len() - 1,
                    ..limits
                }
            ),
            Err(PlacementError::Limit("output pieces"))
        ));
        for work in 0..expected.work {
            assert!(matches!(
                place_parameter(
                    &storage,
                    INPUT,
                    request,
                    PlacementLimits {
                        max_work: work,
                        ..limits
                    }
                ),
                Err(PlacementError::Limit("work"))
            ));
        }
    }
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Placement>();
}

#[test]
fn invalid_sites_requests_and_caller_constructed_specs_fail_explicitly() {
    let mut spec = source(
        r#"<pentry minsize="1" maxsize="8" align="4"><register name="d0"/></pentry>"#,
        "",
        "",
    );
    let storage = common::storage(spec.clone(), &small_file(), Default::default()).unwrap();
    for site in [
        BindingSite::Global(0),
        BindingSite::Input { model: 1, entry: 0 },
        BindingSite::Input { model: 0, entry: 1 },
    ] {
        assert!(matches!(
            place_parameter(&storage, site, PlacementRequest::new(1), Default::default()),
            Err(PlacementError::Invalid { .. })
        ));
    }
    for request in [
        PlacementRequest::new(0),
        PlacementRequest {
            type_alignment: 0,
            ..PlacementRequest::new(1)
        },
        PlacementRequest {
            used_slots: u64::MAX,
            ..PlacementRequest::new(1)
        },
    ] {
        assert!(matches!(
            place_parameter(&storage, INPUT, request, Default::default()),
            Err(PlacementError::InvalidRequest(_))
        ));
    }
    spec.prototypes[0].status = ModelStatus::Incomplete { errors: 1 };
    let storage = common::storage(spec, &small_file(), Default::default()).unwrap();
    assert!(matches!(
        place_parameter(
            &storage,
            INPUT,
            PlacementRequest::new(1),
            Default::default()
        ),
        Err(PlacementError::Invalid { .. })
    ));
    let mut spec = source(
        r#"<pentry minsize="1" maxsize="8" align="4"><register name="d0"/></pentry>"#,
        "",
        "",
    );
    spec.stack_pointer.as_mut().unwrap().growth = ghidra_languages::StackGrowth::Positive;
    spec.prototypes[0].input.entries[0].max_size = 7;
    let storage = common::storage(spec, &small_file(), Default::default()).unwrap();
    assert!(matches!(
        place_parameter(
            &storage,
            INPUT,
            PlacementRequest::new(1),
            Default::default()
        ),
        Err(PlacementError::Invalid {
            reason: "positive growth requires a whole number of pool slots",
            ..
        })
    ));
}

#[test]
fn many_piece_join_scaling_depends_on_piece_count_and_not_payload_bytes() {
    fn large(count: usize) -> Placement {
        let size = count as u32 * 1000;
        // XML deliberately caps attributes per tag. Build the public typed
        // declaration directly to exercise the larger placement piece budget.
        let mut spec = source("", "", "");
        spec.prototypes[0].input.entries.push(ParamEntry {
            min_size: 1,
            max_size: size,
            align: None,
            storage_class: StorageClass::General,
            extension: Extension::None,
            group: None,
            line: 0,
            storage: Storage::Join {
                logical_size: None,
                pieces: (0..count)
                    .map(|i| JoinPiece::Varnode {
                        space: "register".into(),
                        offset: 0x10000 + i as u64 * 1000,
                        size: 1000,
                    })
                    .collect(),
            },
        });
        let storage = common::storage(spec, &small_file(), Default::default()).unwrap();
        query(&storage, INPUT, PlacementRequest::new(size))
    }
    let small = large(500);
    let big = large(1000);
    assert_eq!(pieces(&small).len(), 500);
    assert_eq!(pieces(&big).len(), 1000);
    assert!(big.work <= small.work * 2);
    assert!(big.work < 12_000);
    assert_eq!(placed(&big).size, 1_000_000);
}
