use ghidra_types::{
    BitfieldLayout, BitfieldValueError as Error, Endianness, FieldLayout, IntegerFormat, TypeId,
};

fn layout(declared_bits: u32, base_bytes: u64, bit_offset: u8) -> BitfieldLayout {
    let effective_bits = u128::from(declared_bits).min(8 * u128::from(base_bytes)) as u32;
    BitfieldLayout {
        declared_bits,
        effective_bits,
        base_bytes,
        storage_bytes: u64::from((effective_bits + u32::from(bit_offset)).div_ceil(8)).max(1),
        bit_offset,
    }
}

#[test]
fn shift_mask_and_sign_use_component_byte_order() {
    // 0x35A0 >> 5 = 0x1AD: 429 unsigned, -83 as a signed nine-bit integer.
    let spec = layout(9, 2, 5);
    for (endian, bytes) in [
        (Endianness::Little, [0xA0, 0x35]),
        (Endianness::Big, [0x35, 0xA0]),
    ] {
        let unsigned = spec.read_value(&bytes, endian, false).unwrap();
        let signed = spec.read_value(&bytes, endian, true).unwrap();
        assert_eq!(unsigned.unsigned_bytes_le(), &[0xAD, 1]);
        assert_eq!(signed.unsigned_bytes_le(), unsigned.unsigned_bytes_le());
        assert_eq!(unsigned.to_u64(), Some(429));
        assert_eq!(unsigned.to_i64(), Some(429));
        assert_eq!(signed.to_i64(), Some(-83));
        assert_eq!(unsigned.to_string(), "429");
        assert_eq!(signed.to_string(), "-83");
        assert!(signed.is_negative());
        assert_eq!(
            signed.representation(IntegerFormat::Hexadecimal, false),
            "1ADh"
        );
        assert_eq!(
            signed.representation(IntegerFormat::Binary, true),
            "110101101b"
        );
        assert_eq!(signed.representation(IntegerFormat::Octal, true), "655o");
        assert_eq!(signed.representation(IntegerFormat::Decimal, true), "-83");
        // Bytes after minimal storage do not enter the value.
        let mut longer = bytes.to_vec();
        longer.extend_from_slice(&[0xFF; 16]);
        assert_eq!(spec.read_value(&longer, endian, true).unwrap(), signed);
    }
    assert_eq!(
        spec.read_value(&[0x35, 0xA0], Endianness::Little, true)
            .unwrap()
            .to_i64(),
        Some(-255)
    );
}

#[test]
fn zero_width_reads_no_memory_and_has_an_empty_representation() {
    for endian in [Endianness::Little, Endianness::Big] {
        for offset in 0..=7 {
            let spec = layout(0, 4, offset);
            let value = spec.read_value(&[], endian, false).unwrap();
            assert_eq!(value.bit_width(), 0);
            assert!(value.is_signed(), "Scalar(0, 0) uses default signedness");
            assert!(!value.is_negative());
            assert!(value.is_zero());
            assert_eq!(value.unsigned_bytes_le(), &[]);
            assert_eq!(value.to_u64(), Some(0));
            assert_eq!(value.to_i64(), Some(0));
            assert_eq!(value.to_string(), "0");
            for format in [
                IntegerFormat::Hexadecimal,
                IntegerFormat::Decimal,
                IntegerFormat::Binary,
                IntegerFormat::Octal,
            ] {
                assert_eq!(value.representation(format, true), "");
            }
            assert_eq!(value.boolean_representation(), "");
            let field = FieldLayout {
                ty: TypeId(0),
                offset: u64::MAX,
                bytes: 0,
                alignment: 1,
                bitfield: Some(spec),
            };
            assert_eq!(field.read_bitfield_value(&[], endian, true).unwrap(), value);
        }
    }
}

#[test]
fn numeric_padding_uses_bits_not_storage_and_boolean_is_nonzero() {
    let spec = layout(13, 2, 3);
    let value = spec.read_value(&[8, 0], Endianness::Little, true).unwrap();
    assert_eq!(
        value.representation(IntegerFormat::Hexadecimal, false),
        "1h"
    );
    assert_eq!(
        value.representation(IntegerFormat::Hexadecimal, true),
        "0001h"
    );
    assert_eq!(
        value.representation(IntegerFormat::Binary, true),
        "0000000000001b"
    );
    assert_eq!(value.representation(IntegerFormat::Octal, true), "00001o");
    assert_eq!(value.representation(IntegerFormat::Decimal, true), "1");
    assert_eq!(value.boolean_representation(), "TRUE");
    let zero = spec.read_value(&[0, 0], Endianness::Little, false).unwrap();
    assert_eq!(zero.boolean_representation(), "FALSE");
    let noncanonical = layout(8, 1, 0)
        .read_value(&[2], Endianness::Big, false)
        .unwrap();
    assert_eq!(noncanonical.boolean_representation(), "TRUE");
    let negative = layout(8, 1, 0)
        .read_value(&[0xFF], Endianness::Big, true)
        .unwrap();
    assert_eq!(negative.boolean_representation(), "TRUE");
    assert_eq!(
        negative.representation(IntegerFormat::Hexadecimal, true),
        "FFh"
    );
    assert_eq!(negative.representation(IntegerFormat::Octal, true), "377o");
}

#[test]
fn maximal_width_can_require_33_storage_bytes_and_has_bounded_formatting() {
    let spec = layout(255, 32, 7);
    assert_eq!(spec.storage_bytes, 33);
    for endian in [Endianness::Little, Endianness::Big] {
        let value = spec.read_value(&[0xFF; 33], endian, false).unwrap();
        assert_eq!(value.bit_width(), 255);
        assert_eq!(value.unsigned_bytes_le().len(), 32);
        assert_eq!(value.unsigned_bytes_le()[31], 0x7F);
        assert_eq!(value.to_u64(), None);
        assert_eq!(value.to_i64(), None);
        assert_eq!(
            value.to_string(),
            "57896044618658097711785492504343953926634992332820282019728792003956564819967"
        );
        assert_eq!(
            value.representation(IntegerFormat::Binary, true),
            format!("{}b", "1".repeat(255))
        );
        assert_eq!(
            value.representation(IntegerFormat::Octal, true),
            format!("{}o", "7".repeat(85))
        );
        assert_eq!(
            value.representation(IntegerFormat::Hexadecimal, true),
            format!("7{}h", "F".repeat(63))
        );
        let signed = spec.read_value(&[0xFF; 33], endian, true).unwrap();
        assert_eq!(signed.to_string(), "-1");
        assert_eq!(signed.to_i64(), Some(-1));

        let zero = spec.read_value(&[0; 33], endian, false).unwrap();
        // Defined even when padding needs more than Java's fixed 64 zeroes.
        assert_eq!(
            zero.representation(IntegerFormat::Binary, true),
            format!("{}b", "0".repeat(255))
        );
        assert_eq!(
            zero.representation(IntegerFormat::Octal, true),
            format!("{}o", "0".repeat(85))
        );
        assert_eq!(
            zero.representation(IntegerFormat::Hexadecimal, true),
            format!("{}h", "0".repeat(64))
        );
    }
    let mut minimum = [0; 33];
    minimum[32] = 0x20; // selected sign bit is storage bit 254 + 7 = 261.
    let value = spec.read_value(&minimum, Endianness::Little, true).unwrap();
    assert_eq!(
        value.to_string(),
        "-28948022309329048855892746252171976963317496166410141009864396001978282409984"
    );
    assert_eq!(value.to_i64(), None);
}

#[test]
fn checked_integer_conversions_use_value_and_signedness() {
    let spec = layout(64, 8, 0);
    let min = spec
        .read_value(&i64::MIN.to_le_bytes(), Endianness::Little, true)
        .unwrap();
    assert_eq!(min.to_i64(), Some(i64::MIN));
    assert_eq!(min.to_u64(), Some(1 << 63));
    let unsigned = spec.read_value(&[0xFF; 8], Endianness::Big, false).unwrap();
    assert_eq!(unsigned.to_u64(), Some(u64::MAX));
    assert_eq!(unsigned.to_i64(), None);
    let wide = layout(255, 32, 0);
    for n in [-1_i64, -256, i64::MIN, i64::MAX] {
        let mut bytes = [if n < 0 { 0xFF } else { 0 }; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        bytes[31] &= 0x7F;
        let value = wide.read_value(&bytes, Endianness::Little, true).unwrap();
        assert_eq!(value.to_i64(), Some(n));
        assert_eq!(value.to_string(), n.to_string());
    }
    let mut below_min = [0xFF; 32];
    below_min[..8].copy_from_slice(&(i64::MAX as u64).to_le_bytes());
    below_min[31] = 0x7F;
    let value = wide
        .read_value(&below_min, Endianness::Little, true)
        .unwrap();
    assert_eq!(value.to_i64(), None);
    assert_eq!(value.to_string(), "-9223372036854775809");
    let mut above_max = [0; 32];
    above_max[..8].copy_from_slice(&(1_u64 << 63).to_le_bytes());
    assert_eq!(
        wide.read_value(&above_max, Endianness::Little, true)
            .unwrap()
            .to_i64(),
        None
    );
}

#[test]
fn declared_width_is_clamped_and_signedness_is_explicit() {
    let spec = layout(255, 1, 7);
    assert_eq!(spec.effective_bits, 8);
    let signed = spec
        .read_value(&[0x80, 0x7F], Endianness::Little, true)
        .unwrap();
    assert_eq!(signed.to_i64(), Some(-1));
    let enum_or_bool = spec
        .read_value(&[0x80, 0x7F], Endianness::Little, false)
        .unwrap();
    assert_eq!(enum_or_bool.to_i64(), Some(255));
    assert!(!enum_or_bool.is_signed());
    assert_eq!(enum_or_bool.unsigned_bytes_le(), &[0xFF]);
}

#[test]
fn public_layouts_are_validated_before_reading_memory() {
    let valid = layout(13, 2, 3);
    let check = |spec: BitfieldLayout| spec.read_value(&[], Endianness::Big, false).unwrap_err();
    for invalid in [
        BitfieldLayout {
            declared_bits: 256,
            ..valid
        },
        BitfieldLayout {
            effective_bits: 256,
            ..valid
        },
        BitfieldLayout {
            base_bytes: 0,
            ..valid
        },
        BitfieldLayout {
            effective_bits: 12,
            ..valid
        },
        BitfieldLayout {
            bit_offset: 8,
            ..valid
        },
        BitfieldLayout {
            storage_bytes: 0,
            ..valid
        },
        BitfieldLayout {
            storage_bytes: u64::MAX,
            ..valid
        },
    ] {
        assert!(matches!(check(invalid), Error::InvalidLayout(_)));
    }
    assert_eq!(
        check(valid),
        Error::BufferTooShort {
            required: 2,
            available: 0
        }
    );
    let spec = layout(255, 32, 7);
    assert_eq!(
        spec.read_value(&[0; 32], Endianness::Little, false)
            .unwrap_err(),
        Error::BufferTooShort {
            required: 33,
            available: 32
        }
    );
}

#[test]
fn aggregate_offsets_are_checked_without_wrapping() {
    let field = FieldLayout {
        ty: TypeId(2),
        offset: 3,
        bytes: 2,
        alignment: 1,
        bitfield: Some(layout(9, 2, 5)),
    };
    assert_eq!(
        field
            .read_bitfield_value(&[0, 0, 0, 0xA0, 0x35, 0xFF], Endianness::Little, true)
            .unwrap()
            .to_i64(),
        Some(-83)
    );
    assert_eq!(
        field
            .read_bitfield_value(&[0; 4], Endianness::Little, true)
            .unwrap_err(),
        Error::BufferTooShort {
            required: 5,
            available: 4
        }
    );
    let extreme = FieldLayout {
        offset: u64::MAX,
        ..field
    };
    assert_eq!(
        extreme
            .read_bitfield_value(&[], Endianness::Big, true)
            .unwrap_err(),
        Error::BufferTooShort {
            required: u128::from(u64::MAX) + 2,
            available: 0
        }
    );
    assert!(matches!(
        FieldLayout { bytes: 1, ..field }.read_bitfield_value(&[0; 16], Endianness::Big, false),
        Err(Error::InvalidLayout(_))
    ));
    assert_eq!(
        FieldLayout {
            bitfield: None,
            ..field
        }
        .read_bitfield_value(&[0; 16], Endianness::Big, false)
        .unwrap_err(),
        Error::NotBitfield
    );
}

#[test]
fn layout_guards_reject_cases_that_satisfy_the_other_rules() {
    // Each of the first three cases would pass every later equality check if
    // its own guard disappeared. These cannot be masked by another rule.
    let only_width = BitfieldLayout {
        declared_bits: 256,
        effective_bits: 8,
        base_bytes: 1,
        storage_bytes: 1,
        bit_offset: 0,
    };
    let only_base = BitfieldLayout {
        declared_bits: 0,
        effective_bits: 0,
        base_bytes: 0,
        storage_bytes: 1,
        bit_offset: 0,
    };
    let only_offset = BitfieldLayout {
        bit_offset: 8,
        storage_bytes: 3,
        ..layout(13, 2, 3)
    };
    let overflow_without_width_guard = BitfieldLayout {
        declared_bits: u32::MAX,
        effective_bits: u32::MAX,
        base_bytes: u64::MAX,
        storage_bytes: 536_870_912,
        bit_offset: 1,
    };
    let oversized_without_offset_guard = BitfieldLayout {
        declared_bits: 255,
        effective_bits: 255,
        base_bytes: 32,
        storage_bytes: 64,
        bit_offset: 255,
    };
    for spec in [
        only_width,
        only_base,
        only_offset,
        overflow_without_width_guard,
        oversized_without_offset_guard,
    ] {
        assert!(matches!(
            spec.read_value(&[0xFF; 64], Endianness::Little, false),
            Err(Error::InvalidLayout(_))
        ));
    }
    // An enormous base does not cause an allocation or a read of its extent;
    // only the validated minimal component storage is read.
    let wide_base = BitfieldLayout {
        base_bytes: u64::MAX,
        ..layout(255, 32, 7)
    };
    assert_eq!(
        wide_base
            .read_value(&[0xFF; 33], Endianness::Big, true)
            .unwrap()
            .to_i64(),
        Some(-1)
    );
}

#[test]
fn native_integer_reference_checks_reads_formats_and_conversions() {
    // This oracle uses whole u128 shifts and the standard integer formatter,
    // independent of the production per-bit reader and byte-array division.
    let mut seed = 0x15C0_5701_8D31_7D6A_u128;
    let mut cases = 0;
    for width in 1..=121 {
        for offset in 0..=7 {
            let spec = layout(width, 16, offset);
            let size = spec.storage_bytes as usize;
            for _ in 0..3 {
                seed ^= seed << 17;
                seed ^= seed >> 29;
                seed ^= seed << 43;
                let mut bytes = seed.to_le_bytes()[..size].to_vec();
                let raw = (seed >> offset) & ((1_u128 << width) - 1);
                for endian in [Endianness::Little, Endianness::Big] {
                    if endian == Endianness::Big {
                        bytes.reverse();
                    }
                    for signed in [false, true] {
                        cases += 1;
                        let value = spec.read_value(&bytes, endian, signed).unwrap();
                        let mut le = [0; 16];
                        le[..value.unsigned_bytes_le().len()]
                            .copy_from_slice(value.unsigned_bytes_le());
                        assert_eq!(u128::from_le_bytes(le), raw);
                        let number = if signed && raw & (1 << (width - 1)) != 0 {
                            (raw as i128) - (1_i128 << width)
                        } else {
                            raw as i128
                        };
                        assert_eq!(value.to_string(), number.to_string());
                        assert_eq!(value.to_u64(), u64::try_from(raw).ok());
                        assert_eq!(value.to_i64(), i64::try_from(number).ok());
                        assert_eq!(
                            value.representation(IntegerFormat::Decimal, true),
                            number.to_string()
                        );
                        for (format, digits, nominal, suffix) in [
                            (
                                IntegerFormat::Hexadecimal,
                                format!("{raw:X}"),
                                width.div_ceil(4),
                                'h',
                            ),
                            (IntegerFormat::Binary, format!("{raw:b}"), width, 'b'),
                            (
                                IntegerFormat::Octal,
                                format!("{raw:o}"),
                                width.div_ceil(3),
                                'o',
                            ),
                        ] {
                            assert_eq!(
                                value.representation(format, false),
                                format!("{digits}{suffix}")
                            );
                            let padded =
                                format!("{digits:0>length$}{suffix}", length = nominal as usize);
                            assert_eq!(value.representation(format, true), padded);
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 11_616);
}

#[test]
fn gcc_and_ms_layout_components_can_be_read_from_aggregate_storage() {
    use ghidra_languages::DataOrganization;
    use ghidra_types::{Composite, Field, Limits, Packing, TypeDefinition, TypeKind, TypeLayouts};
    for ms in [false, true] {
        for endian in [Endianness::Little, Endianness::Big] {
            let mut org = DataOrganization::default().resolve(8);
            org.use_ms_bitfield_convention = ms;
            let definitions = vec![
                TypeDefinition::new(
                    "int",
                    TypeKind::Integer {
                        bytes: 4,
                        signed: true,
                    },
                ),
                TypeDefinition::new("alias", TypeKind::Alias(TypeId(0))),
                TypeDefinition::new(
                    "record",
                    TypeKind::Structure(Composite {
                        fields: vec![
                            Field::bitfield("a", TypeId(1), 3),
                            Field::bitfield("b", TypeId(0), 11),
                            Field::bitfield("boundary", TypeId(0), 0),
                            Field::bitfield("c", TypeId(0), 13),
                        ],
                        packing: Packing::Explicit(1),
                        ..Default::default()
                    }),
                ),
            ]
            .into();
            let layouts =
                TypeLayouts::new_with_endianness(definitions, org, endian, Limits::default())
                    .unwrap();
            let record = layouts.layout(TypeId(2)).unwrap();
            let size = record.geometry.length.unwrap() as usize;
            let storage: Vec<u8> = (0..size)
                .map(|n| (n as u8).wrapping_mul(73).wrapping_add(0x91))
                .collect();
            let mut checked = 0;
            for field in &record.fields {
                let bits = field.bitfield.unwrap();
                let value = field.read_bitfield_value(&storage, endian, true).unwrap();
                if bits.effective_bits == 0 {
                    assert_eq!(value.to_i64(), Some(0));
                    continue;
                }
                let start = field.offset as usize;
                let end = start + bits.storage_bytes as usize;
                let raw = storage[start..end]
                    .iter()
                    .enumerate()
                    .fold(0_u64, |word, (n, byte)| {
                        let shift = match endian {
                            Endianness::Little => n,
                            Endianness::Big => end - start - n - 1,
                        } * 8;
                        word | (u64::from(*byte) << shift)
                    });
                let selected = (raw >> bits.bit_offset) & ((1 << bits.effective_bits) - 1);
                let signed = if selected & (1 << (bits.effective_bits - 1)) != 0 {
                    selected as i64 - (1 << bits.effective_bits)
                } else {
                    selected as i64
                };
                assert_eq!(value.to_i64(), Some(signed));
                checked += 1;
            }
            assert_eq!(checked, 3);
        }
    }
}
