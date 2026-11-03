//! Pure P-code integer semantics ported from this checkout's Java opbehavior
//! classes and `Decompiler/src/decompile/cpp/opbehavior.cc`.
//!
//! INSERT, ZPULL, SPULL, CAST, and pointer arithmetic additionally follow the
//! current `Decompiler/src/main/doc/pcoderef.xml` definitions. Bit-range position
//! and size parameters are concrete values here; an IR consumer must separately
//! enforce the reference's requirement that these operands are constants.
//! Memory, control flow, SSA/context operations, and floating point are rejected.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};

use crate::{Error, Opcode, Value};

/// Evaluate one context-free operation. Values and output sizes are in bytes;
/// shift amounts and INSERT/ZPULL/SPULL parameters are in bits, whereas SUBPIECE
/// offsets are in bytes. Every result wraps to its declared output width.
///
/// BOOL operations retain Ghidra's byte-wise behavior: NEGATE toggles bit zero,
/// and XOR/AND/OR operate on all bits. They do not normalize nonzero bytes to one.
pub fn evaluate_pure(opcode: Opcode, inputs: &[Value], output_size: u32) -> Result<Value, Error> {
    if crate::eval_float::is_float(opcode) {
        return crate::eval_float::evaluate_float(opcode, inputs, output_size);
    }
    use Opcode::*;
    let expected = match opcode {
        Copy | Cast | IntZext | IntSext | Int2Comp | IntNegate | BoolNegate | Popcount
        | Lzcount => 1,
        IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal | IntAdd
        | IntSub | IntCarry | IntScarry | IntSborrow | IntXor | IntAnd | IntOr | IntLeft
        | IntRight | IntSright | IntMult | IntDiv | IntSdiv | IntRem | IntSrem | BoolXor
        | BoolAnd | BoolOr | Piece | Subpiece | Ptrsub => 2,
        Ptradd | Zpull | Spull => 3,
        Insert => 4,
        _ => return Err(Error::UnsupportedOpcode(opcode)),
    };
    if inputs.len() != expected {
        return Err(Error::InvalidArity {
            opcode,
            expected: expected.to_string(),
            actual: inputs.len(),
        });
    }
    check_size(output_size)?;
    for value in inputs {
        check_size(value.size())?;
        require(
            opcode,
            value.bits().bits() <= u64::from(value.size()) * 8,
            "an input contains bits outside its declared width",
        )?;
    }
    let first = &inputs[0];
    let a = first.bits();
    let width_bits = (output_size * 8) as usize;
    let output_modulus = BigUint::one() << width_bits;
    let output_mask = &output_modulus - BigUint::one();

    // Validate complete shapes before evaluating or indexing any optional input.
    match opcode {
        IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal | IntCarry
        | IntScarry | IntSborrow => {
            require(
                opcode,
                output_size == 1,
                "comparison and carry outputs must be one byte",
            )?;
            require(
                opcode,
                first.size() == inputs[1].size(),
                "input widths must match",
            )?;
        }
        BoolNegate | BoolXor | BoolAnd | BoolOr => require(
            opcode,
            output_size == 1 && inputs.iter().all(|value| value.size() == 1),
            "boolean inputs and output must be one byte",
        )?,
        IntZext | IntSext => require(
            opcode,
            output_size > first.size(),
            "extension output must be strictly wider than its input",
        )?,
        IntLeft | IntRight | IntSright | Ptradd | Ptrsub | Insert => require(
            opcode,
            first.size() == output_size,
            "first input and output widths must match",
        )?,
        Piece => require(
            opcode,
            first.size().checked_add(inputs[1].size()) == Some(output_size),
            "PIECE output must equal the sum of its input widths",
        )?,
        Subpiece => require(
            opcode,
            output_size <= first.size(),
            "SUBPIECE output cannot be wider than its source",
        )?,
        Popcount | Lzcount | Zpull | Spull => {}
        _ => require(
            opcode,
            inputs.iter().all(|value| value.size() == output_size),
            "input and output widths must match",
        )?,
    }

    let bits = match opcode {
        Copy | Cast | IntZext => a.clone(),
        IntSext => return signed_result(output_size, first.signed()),
        IntEqual => bool_bits(a == inputs[1].bits()),
        IntNotequal => bool_bits(a != inputs[1].bits()),
        IntSless => bool_bits(first.signed() < inputs[1].signed()),
        IntSlessequal => bool_bits(first.signed() <= inputs[1].signed()),
        IntLess => bool_bits(a < inputs[1].bits()),
        IntLessequal => bool_bits(a <= inputs[1].bits()),
        IntAdd | Ptrsub => a + inputs[1].bits(),
        IntSub => a + &output_modulus - inputs[1].bits(),
        IntCarry => bool_bits((a + inputs[1].bits()).bits() > u64::from(first.size()) * 8),
        IntScarry | IntSborrow => {
            let input_bits = (first.size() * 8) as usize;
            let modulus = BigUint::one() << input_bits;
            let result = if opcode == IntScarry {
                a + inputs[1].bits()
            } else {
                a + &modulus - inputs[1].bits()
            };
            let sign_bit = (input_bits - 1) as u64;
            let sign_a = a.bit(sign_bit);
            let sign_b = inputs[1].bits().bit(sign_bit);
            let sign_result = result.bit(sign_bit);
            bool_bits(if opcode == IntScarry {
                sign_a == sign_b && sign_result != sign_a
            } else {
                sign_a != sign_b && sign_result != sign_a
            })
        }
        Int2Comp => &output_modulus - a,
        IntNegate => &output_mask ^ a,
        IntXor | BoolXor => a ^ inputs[1].bits(),
        IntAnd | BoolAnd => a & inputs[1].bits(),
        IntOr | BoolOr => a | inputs[1].bits(),
        BoolNegate => a ^ BigUint::one(),
        IntLeft | IntRight | IntSright => {
            // Compare as arbitrary precision before converting to a host index:
            // a 4096-bit shift amount must never trigger a huge allocation.
            if inputs[1].bits() >= &BigUint::from(width_bits) {
                if opcode == IntSright && a.bit((width_bits - 1) as u64) {
                    output_mask.clone()
                } else {
                    BigUint::zero()
                }
            } else {
                let amount = inputs[1]
                    .bits()
                    .to_usize()
                    .expect("shift bounded by 4096 bits");
                match opcode {
                    IntLeft => a << amount,
                    IntRight => a >> amount,
                    _ => return signed_result(output_size, first.signed() >> amount),
                }
            }
        }
        IntMult => a * inputs[1].bits(),
        IntDiv | IntRem | IntSdiv | IntSrem => {
            if inputs[1].bits().is_zero() {
                return Err(Error::DivisionByZero);
            }
            match opcode {
                IntDiv => a / inputs[1].bits(),
                IntRem => a % inputs[1].bits(),
                IntSdiv => return signed_result(output_size, first.signed() / inputs[1].signed()),
                _ => return signed_result(output_size, first.signed() % inputs[1].signed()),
            }
        }
        Piece => (a << (inputs[1].size() * 8) as usize) | inputs[1].bits(),
        Subpiece => {
            if inputs[1].bits() >= &BigUint::from(first.size()) {
                BigUint::zero()
            } else {
                let offset = inputs[1]
                    .bits()
                    .to_usize()
                    .expect("byte offset bounded by 512");
                a >> (offset * 8)
            }
        }
        Ptradd => a + inputs[1].bits() * inputs[2].bits(),
        Insert => {
            let (position, count) = bit_range(
                opcode,
                &inputs[2],
                &inputs[3],
                width_bits,
                (inputs[1].size() * 8) as usize,
            )?;
            let field_mask = (BigUint::one() << count) - BigUint::one();
            let cleared = a & (&output_mask ^ (&field_mask << position));
            cleared | ((inputs[1].bits() & field_mask) << position)
        }
        Zpull | Spull => {
            let (position, count) = bit_range(
                opcode,
                &inputs[1],
                &inputs[2],
                (first.size() * 8) as usize,
                width_bits,
            )?;
            let extracted = (a >> position) & ((BigUint::one() << count) - BigUint::one());
            if opcode == Spull && extracted.bit((count - 1) as u64) {
                extracted + (&output_modulus - (BigUint::one() << count))
            } else {
                extracted
            }
        }
        Popcount => BigUint::from(a.iter_u64_digits().map(u64::count_ones).sum::<u32>()),
        Lzcount => BigUint::from(u64::from(first.size()) * 8 - a.bits()),
        _ => return Err(Error::UnsupportedOpcode(opcode)),
    };
    Value::new(output_size, bits)
}

fn check_size(size: u32) -> Result<(), Error> {
    if (1..=512).contains(&size) {
        Ok(())
    } else {
        Err(Error::InvalidSize(size))
    }
}

fn require(opcode: Opcode, condition: bool, message: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::InvalidOperands {
            opcode,
            message: message.into(),
        })
    }
}

fn bool_bits(value: bool) -> BigUint {
    BigUint::from(u8::from(value))
}

fn signed_result(size: u32, value: BigInt) -> Result<Value, Error> {
    let modulus = BigInt::one() << (size * 8) as usize;
    let mut result = value % &modulus;
    if result.sign() == Sign::Minus {
        result += modulus;
    }
    Value::new(
        size,
        result.to_biguint().expect("modular result is nonnegative"),
    )
}

/// Validate bit ranges without converting unbounded integer parameters to host
/// indices. Both the source interval and the destination field must fit.
fn bit_range(
    opcode: Opcode,
    position: &Value,
    count: &Value,
    source_bits: usize,
    field_bits: usize,
) -> Result<(usize, usize), Error> {
    require(
        opcode,
        !count.bits().is_zero(),
        "bit-range size must be nonzero",
    )?;
    require(
        opcode,
        count.bits() <= &BigUint::from(field_bits),
        "bit-range size exceeds its field width",
    )?;
    require(
        opcode,
        position.bits() < &BigUint::from(source_bits),
        "bit-range position exceeds its source width",
    )?;
    let position = position
        .bits()
        .to_usize()
        .expect("position bounded by 4096 bits");
    let count = count
        .bits()
        .to_usize()
        .expect("field width bounded by 4096 bits");
    require(
        opcode,
        position + count <= source_bits,
        "bit range extends beyond its source width",
    )?;
    Ok((position, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(size: u32, bits: u64) -> Value {
        Value::from_u64(size, bits).unwrap()
    }
    fn ones(size: u32) -> Value {
        Value::new(
            size,
            (BigUint::one() << (size * 8) as usize) - BigUint::one(),
        )
        .unwrap()
    }
    fn eval(opcode: Opcode, inputs: &[Value], output_size: u32) -> Value {
        evaluate_pure(opcode, inputs, output_size).unwrap()
    }
    fn number(opcode: Opcode, inputs: &[Value], output_size: u32) -> u64 {
        eval(opcode, inputs, output_size).to_u64().unwrap()
    }

    #[test]
    fn upstream_32_bit_shift_vectors_and_64_bit_wrap() {
        use Opcode::*;
        for (amount, expected) in [(8, 0x100), (31, 0x80000000), (32, 0), (33, 0)] {
            assert_eq!(
                number(IntLeft, &[value(4, 1), value(4, amount)], 4),
                expected
            );
        }
        assert_eq!(number(IntAdd, &[ones(8), value(8, 1)], 8), 0);
        assert_eq!(number(IntSub, &[value(8, 0), value(8, 1)], 8), u64::MAX);
        assert_eq!(number(IntMult, &[value(8, 1 << 63), value(8, 2)], 8), 0);
        assert_eq!(number(Int2Comp, &[value(8, 0)], 8), 0);
        assert_eq!(number(Int2Comp, &[value(8, 1)], 8), u64::MAX);
        assert_eq!(number(IntNegate, &[value(8, 0)], 8), u64::MAX);
    }

    #[test]
    fn arbitrary_width_arithmetic_wraps_at_128_and_4096_bits() {
        use Opcode::*;
        for size in [16, 512] {
            let maximum = ones(size);
            let zero = value(size, 0);
            let one = value(size, 1);
            assert!(
                eval(IntAdd, &[maximum.clone(), one.clone()], size)
                    .bits()
                    .is_zero()
            );
            assert_eq!(
                eval(IntSub, &[zero, one.clone()], size).bits(),
                maximum.bits()
            );
            assert_eq!(number(IntCarry, &[maximum.clone(), one], 1), 1);
            assert_eq!(
                eval(IntMult, &[maximum, value(size, 2)], size).bits(),
                &((BigUint::one() << (size * 8) as usize) - BigUint::from(2_u8))
            );
        }
    }

    #[test]
    fn signed_carry_and_borrow_match_upstream_sign_bit_formulas() {
        use Opcode::*;
        for size in [1, 8, 16, 512] {
            let sign = BigUint::one() << (size * 8 - 1) as usize;
            let minimum = Value::new(size, sign.clone()).unwrap();
            let maximum = Value::new(size, &sign - BigUint::one()).unwrap();
            assert_eq!(number(IntScarry, &[maximum.clone(), value(size, 1)], 1), 1);
            assert_eq!(number(IntScarry, &[minimum.clone(), ones(size)], 1), 1);
            assert_eq!(number(IntScarry, &[minimum.clone(), maximum.clone()], 1), 0);
            assert_eq!(number(IntSborrow, &[minimum, value(size, 1)], 1), 1);
            assert_eq!(number(IntSborrow, &[maximum, ones(size)], 1), 1);
            assert_eq!(number(IntSborrow, &[value(size, 0), value(size, 1)], 1), 0);
        }
    }

    #[test]
    fn one_byte_flags_agree_with_independent_host_overflow_operations() {
        use Opcode::*;
        for a in 0_u8..=255 {
            for b in [0_u8, 1, 0x7f, 0x80, 0xfe, 0xff] {
                let operands = [value(1, u64::from(a)), value(1, u64::from(b))];
                assert_eq!(
                    number(IntCarry, &operands, 1),
                    u64::from(a.overflowing_add(b).1)
                );
                assert_eq!(
                    number(IntScarry, &operands, 1),
                    u64::from((a as i8).overflowing_add(b as i8).1)
                );
                assert_eq!(
                    number(IntSborrow, &operands, 1),
                    u64::from((a as i8).overflowing_sub(b as i8).1)
                );
            }
        }
    }

    #[test]
    fn signed_division_and_remainder_truncate_toward_zero_and_wrap_overflow() {
        use Opcode::*;
        assert_eq!(number(IntSdiv, &[value(1, 0xf9), value(1, 3)], 1), 0xfe); // -7/3 = -2
        assert_eq!(number(IntSrem, &[value(1, 0xf9), value(1, 3)], 1), 0xff); // -7%3 = -1
        assert_eq!(number(IntSdiv, &[value(1, 7), value(1, 0xfd)], 1), 0xfe);
        assert_eq!(number(IntSrem, &[value(1, 7), value(1, 0xfd)], 1), 1);
        for size in [1, 8, 16, 512] {
            let minimum = Value::new(size, BigUint::one() << (size * 8 - 1) as usize).unwrap();
            assert_eq!(
                eval(IntSdiv, &[minimum.clone(), ones(size)], size).bits(),
                minimum.bits()
            );
            assert!(eval(IntSrem, &[minimum, ones(size)], size).bits().is_zero());
            for opcode in [IntDiv, IntSdiv, IntRem, IntSrem] {
                assert!(matches!(
                    evaluate_pure(opcode, &[value(size, 1), value(size, 0)], size),
                    Err(Error::DivisionByZero)
                ));
            }
        }
    }

    #[test]
    fn huge_shifts_are_bounded_and_signed_right_fills_sign_bits() {
        use Opcode::*;
        let huge = Value::new(512, BigUint::one() << 4095_usize).unwrap();
        for opcode in [IntLeft, IntRight] {
            assert_eq!(number(opcode, &[ones(8), huge.clone()], 8), 0);
        }
        assert_eq!(number(IntSright, &[value(8, 1 << 63), huge], 8), u64::MAX);
        assert_eq!(number(IntSright, &[value(1, 0x80), value(4, 1)], 1), 0xc0);
        assert_eq!(number(IntSright, &[value(1, 0x80), value(4, 8)], 1), 0xff);
        assert_eq!(number(IntSright, &[value(1, 0x7f), value(4, 100)], 1), 0);
        assert_eq!(number(IntRight, &[value(1, 0x80), value(4, 1)], 1), 0x40);
    }

    #[test]
    fn comparisons_distinguish_signed_and_unsigned_values() {
        use Opcode::*;
        for size in [1, 8, 16, 512] {
            assert_eq!(number(IntSless, &[ones(size), value(size, 0)], 1), 1);
            assert_eq!(number(IntLess, &[ones(size), value(size, 0)], 1), 0);
            assert_eq!(number(IntEqual, &[ones(size), ones(size)], 1), 1);
            assert_eq!(number(IntNotequal, &[ones(size), value(size, 0)], 1), 1);
            assert_eq!(
                number(IntSlessequal, &[value(size, 0), value(size, 0)], 1),
                1
            );
            assert_eq!(number(IntLessequal, &[ones(size), value(size, 0)], 1), 0);
        }
    }

    #[test]
    fn boolean_ops_preserve_upstream_byte_behavior() {
        use Opcode::*;
        assert_eq!(number(BoolNegate, &[value(1, 0)], 1), 1);
        assert_eq!(number(BoolNegate, &[value(1, 1)], 1), 0);
        assert_eq!(number(BoolNegate, &[value(1, 0x80)], 1), 0x81);
        assert_eq!(number(BoolXor, &[value(1, 0xf0), value(1, 0x55)], 1), 0xa5);
        assert_eq!(number(BoolAnd, &[value(1, 0xf0), value(1, 0x55)], 1), 0x50);
        assert_eq!(number(BoolOr, &[value(1, 0xf0), value(1, 0x55)], 1), 0xf5);
    }

    #[test]
    fn extensions_copy_cast_piece_and_byte_subpiece_preserve_bits() {
        use Opcode::*;
        assert_eq!(number(IntZext, &[value(1, 0x80)], 8), 0x80);
        assert_eq!(number(IntSext, &[value(1, 0x80)], 8), 0xffffffffffffff80);
        assert_eq!(
            number(Copy, &[value(8, 0xff00000000000000)], 8),
            0xff00000000000000
        );
        assert_eq!(
            number(Cast, &[value(8, 0xff00000000000000)], 8),
            0xff00000000000000
        );
        assert_eq!(
            number(Piece, &[value(2, 0xabcd), value(2, 0x1234)], 4),
            0xabcd1234
        );
        let wide = eval(Piece, &[ones(8), value(8, 0x123456789abcdef0)], 16);
        assert_eq!(number(Subpiece, &[wide.clone(), value(4, 8)], 8), u64::MAX);
        assert_eq!(
            number(Subpiece, &[wide.clone(), value(4, 2)], 4),
            0x56789abc
        );
        assert_eq!(number(Subpiece, &[wide, ones(512)], 4), 0);
    }

    #[test]
    fn pointer_arithmetic_matches_cpp_including_ptrsub_addition() {
        use Opcode::*;
        assert_eq!(
            number(Ptradd, &[value(8, 0x1000), value(4, 3), value(4, 8)], 8),
            0x1018
        );
        assert_eq!(number(Ptrsub, &[value(8, 0x1000), value(4, 8)], 8), 0x1008);
        assert_eq!(number(Ptradd, &[ones(8), value(1, 2), value(1, 2)], 8), 3);
    }

    #[test]
    fn bitrange_semantics_follow_current_insert_zpull_spull_reference() {
        use Opcode::*;
        assert_eq!(
            number(
                Insert,
                &[value(2, 0xffff), value(1, 0x12), value(4, 4), value(4, 8)],
                2
            ),
            0xf12f
        );
        assert_eq!(
            number(Zpull, &[value(2, 0xf12f), value(4, 4), value(4, 8)], 4),
            0x12
        );
        assert_eq!(
            number(Spull, &[value(2, 0xf82f), value(4, 4), value(4, 8)], 4),
            0xffffff82
        );
        assert_eq!(
            number(Spull, &[value(2, 0xf12f), value(4, 4), value(4, 8)], 4),
            0x12
        );
        let full = eval(Spull, &[ones(512), value(4, 0), value(4, 4096)], 512);
        assert_eq!(full.bits(), ones(512).bits());
    }

    #[test]
    fn bit_counts_are_width_aware_and_results_wrap_to_output() {
        use Opcode::*;
        assert_eq!(number(Popcount, &[value(8, 0xf000000000000001)], 1), 5);
        assert_eq!(number(Lzcount, &[value(8, 1)], 1), 63);
        assert_eq!(number(Lzcount, &[value(1, 1)], 1), 7);
        assert_eq!(number(Lzcount, &[value(8, 0)], 1), 64);
        assert_eq!(number(Popcount, &[ones(512)], 2), 4096);
        assert_eq!(number(Popcount, &[ones(512)], 1), 0);
        assert_eq!(number(Lzcount, &[value(512, 0)], 2), 4096);
    }

    #[test]
    fn invalid_arities_widths_and_bitranges_return_errors_without_indexing_panics() {
        use Opcode::*;
        for opcode in [
            Copy, Cast, IntAdd, IntSdiv, BoolAnd, Piece, Subpiece, Ptradd, Insert, Zpull, Spull,
        ] {
            assert!(matches!(
                evaluate_pure(opcode, &[], 1),
                Err(Error::InvalidArity { .. })
            ));
            assert!(matches!(
                evaluate_pure(opcode, &vec![value(1, 0); 5], 1),
                Err(Error::InvalidArity { .. })
            ));
        }
        assert!(matches!(
            evaluate_pure(Copy, &[value(1, 0)], 0),
            Err(Error::InvalidSize(0))
        ));
        for (opcode, inputs, out) in [
            (IntAdd, vec![value(1, 1), value(2, 1)], 1),
            (IntEqual, vec![value(1, 1), value(1, 1)], 2),
            (BoolNegate, vec![value(2, 1)], 1),
            (IntSext, vec![value(2, 1)], 1),
            (IntZext, vec![value(1, 1)], 1),
            (Cast, vec![value(4, 1)], 8),
            (Piece, vec![value(4, 1), value(4, 1)], 4),
            (Subpiece, vec![value(4, 1), value(1, 0)], 8),
            (
                Insert,
                vec![value(1, 0), value(1, 1), value(1, 7), value(1, 2)],
                1,
            ),
            (Zpull, vec![value(1, 1), value(1, 0), value(1, 0)], 1),
            (Spull, vec![value(1, 1), ones(512), value(1, 1)], 1),
        ] {
            assert!(
                matches!(
                    evaluate_pure(opcode, &inputs, out),
                    Err(Error::InvalidOperands { .. })
                ),
                "{opcode:?}"
            );
        }
    }

    #[test]
    fn context_memory_and_control_opcodes_are_explicitly_unsupported() {
        use Opcode::*;
        for opcode in [
            Unimplemented,
            Load,
            Store,
            Branch,
            Cbranch,
            Branchind,
            Call,
            Callind,
            Callother,
            Return,
            Multiequal,
            Indirect,
            Segmentop,
            Cpoolref,
            New,
        ] {
            assert!(
                matches!(evaluate_pure(opcode, &[], 1), Err(Error::UnsupportedOpcode(reported)) if reported == opcode)
            );
        }
    }

    #[test]
    fn invalid_internal_value_shapes_are_rejected_before_arithmetic() {
        let invalid = Value {
            size: 0,
            bits: BigUint::zero(),
        };
        assert!(matches!(
            evaluate_pure(Opcode::Copy, &[invalid], 1),
            Err(Error::InvalidSize(0))
        ));
        let invalid = Value {
            size: 1,
            bits: BigUint::one() << 8_usize,
        };
        assert!(matches!(
            evaluate_pure(Opcode::Copy, &[invalid], 1),
            Err(Error::InvalidOperands { .. })
        ));
    }
}
