//! Software floating-point P-code semantics. Arithmetic/conversions use the pure
//! Rust LLVM APFloat port, never host floating-point instructions or a JVM.
//!
//! Supported formats are IEEE binary16/32/64/128 and canonical x87 binary80.
//! Ghidra's FloatFormat.java, BigFloat.java, and pcoderef.xml are the reference,
//! with these intentional consistency rules across every supported width:
//! - comparisons use IEEE unordered NaNs and equal signed zeros;
//! - x87 uses processor-standard explicit-integer-bit special encodings;
//! - TRUNC rejects NaN, infinity, and signed integer overflow, instead of Java's
//!   inconsistent long saturation / BigInteger wrapping and infinity behavior;
//! - ROUND is exact floor(x + 0.5), ties toward positive infinity, without a
//!   rounded intermediate addition that could change an already integral value.
//!
//! IEEE arithmetic exceptions produce the normal IEEE results; status flags are
//! not exposed. Noncanonical x87 encodings and other formats are rejected.

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use rustc_apfloat::{
    Float, FloatConvert, Round,
    ieee::{Double, Half, Quad, Single, X87DoubleExtended},
};

use crate::{Error, Opcode, Value, validate_size};

pub(crate) fn is_float(opcode: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opcode,
        FloatEqual
            | FloatNotequal
            | FloatLess
            | FloatLessequal
            | FloatNan
            | FloatAdd
            | FloatDiv
            | FloatMult
            | FloatSub
            | FloatNeg
            | FloatAbs
            | FloatSqrt
            | FloatInt2Float
            | FloatFloat2Float
            | FloatTrunc
            | FloatCeil
            | FloatFloor
            | FloatRound
    )
}

pub(crate) fn evaluate_float(
    opcode: Opcode,
    inputs: &[Value],
    output_size: u32,
) -> Result<Value, Error> {
    use Opcode::*;
    let arity = match opcode {
        FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatAdd | FloatDiv
        | FloatMult | FloatSub => 2,
        FloatNan | FloatNeg | FloatAbs | FloatSqrt | FloatInt2Float | FloatFloat2Float
        | FloatTrunc | FloatCeil | FloatFloor | FloatRound => 1,
        _ => return Err(Error::UnsupportedOpcode(opcode)),
    };
    if inputs.len() != arity {
        return Err(Error::InvalidArity {
            opcode,
            expected: arity.to_string(),
            actual: inputs.len(),
        });
    }
    validate_size(output_size)?;
    for value in inputs {
        validate_size(value.size())?;
        require(
            opcode,
            value.bits().bits() <= u64::from(value.size()) * 8,
            "input bits exceed declared width",
        )?;
    }
    let first = &inputs[0];
    if arity == 2 {
        require(
            opcode,
            first.size() == inputs[1].size(),
            "floating-point input widths must match",
        )?;
    }
    match opcode {
        FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan => {
            require(
                opcode,
                output_size == 1,
                "floating-point comparison output must be one byte",
            )?;
        }
        FloatInt2Float | FloatFloat2Float | FloatTrunc => {}
        _ => require(
            opcode,
            first.size() == output_size,
            "floating-point input and output widths must match",
        )?,
    }

    if opcode == FloatInt2Float {
        // At most 4096 binary bits / 1235 decimal characters. APFloat parses this
        // exact integer directly to the destination precision with one rounding.
        let text = first.signed().to_str_radix(10);
        Format::for_size(opcode, output_size)?;
        return match output_size {
            2 => integer_to_float::<Half>(opcode, &text, output_size),
            4 => integer_to_float::<Single>(opcode, &text, output_size),
            8 => integer_to_float::<Double>(opcode, &text, output_size),
            10 => integer_to_float::<X87DoubleExtended>(opcode, &text, output_size),
            16 => integer_to_float::<Quad>(opcode, &text, output_size),
            _ => unreachable!("validated supported format"),
        };
    }
    let format = Format::for_size(opcode, first.size())?;
    let mut raw = Vec::with_capacity(inputs.len());
    for input in inputs {
        let bits = input
            .bits()
            .to_u128()
            .expect("supported float has at most 128 bits");
        format.validate_encoding(opcode, bits)?;
        raw.push(bits);
    }
    if opcode == FloatFloat2Float {
        Format::for_size(opcode, output_size)?;
    }
    match first.size() {
        2 => evaluate::<Half>(opcode, &raw, output_size, format),
        4 => evaluate::<Single>(opcode, &raw, output_size, format),
        8 => evaluate::<Double>(opcode, &raw, output_size, format),
        10 => evaluate::<X87DoubleExtended>(opcode, &raw, output_size, format),
        16 => evaluate::<Quad>(opcode, &raw, output_size, format),
        _ => unreachable!("validated supported format"),
    }
}

fn integer_to_float<F: Float>(opcode: Opcode, text: &str, size: u32) -> Result<Value, Error> {
    let result = F::from_str_r(text, Round::NearestTiesToEven).map_err(|error| {
        invalid(
            opcode,
            &format!("software integer conversion failed: {error:?}"),
        )
    })?;
    float_value(result.value, size)
}

fn evaluate<F>(
    opcode: Opcode,
    raw: &[u128],
    output_size: u32,
    format: Format,
) -> Result<Value, Error>
where
    F: Float
        + FloatConvert<Half>
        + FloatConvert<Single>
        + FloatConvert<Double>
        + FloatConvert<X87DoubleExtended>
        + FloatConvert<Quad>,
{
    use Opcode::*;
    let a = F::from_bits(raw[0]);
    let b = raw.get(1).map(|bits| F::from_bits(*bits));
    let truth = match opcode {
        FloatEqual => Some(a == b.expect("validated binary arity")),
        FloatNotequal => Some(a != b.expect("validated binary arity")),
        FloatLess => Some(a < b.expect("validated binary arity")),
        FloatLessequal => Some(a <= b.expect("validated binary arity")),
        FloatNan => Some(a.is_nan()),
        _ => None,
    };
    if let Some(truth) = truth {
        return Value::from_u64(1, u64::from(truth));
    }
    if opcode == FloatFloat2Float {
        return match output_size {
            2 => convert::<F, Half>(a, output_size),
            4 => convert::<F, Single>(a, output_size),
            8 => convert::<F, Double>(a, output_size),
            10 => convert::<F, X87DoubleExtended>(a, output_size),
            16 => convert::<F, Quad>(a, output_size),
            _ => unreachable!("validated output float format"),
        };
    }
    if opcode == FloatTrunc {
        require(
            opcode,
            a.is_finite(),
            "TRUNC is undefined for NaN and infinity",
        )?;
        return truncate_integer(opcode, raw[0], format, output_size);
    }
    let result = match opcode {
        FloatAdd => {
            a.add_r(b.expect("validated binary arity"), Round::NearestTiesToEven)
                .value
        }
        FloatSub => {
            a.sub_r(b.expect("validated binary arity"), Round::NearestTiesToEven)
                .value
        }
        FloatMult => {
            a.mul_r(b.expect("validated binary arity"), Round::NearestTiesToEven)
                .value
        }
        FloatDiv => {
            a.div_r(b.expect("validated binary arity"), Round::NearestTiesToEven)
                .value
        }
        FloatNeg => -a,
        FloatAbs => a.abs(),
        FloatCeil => a.round_to_integral(Round::TowardPositive).value,
        FloatFloor => a.round_to_integral(Round::TowardNegative).value,
        FloatRound => round_ties_positive(a, raw[0], format),
        FloatSqrt => square_root(a, raw[0], format),
        _ => return Err(Error::UnsupportedOpcode(opcode)),
    };
    float_value(result, output_size)
}

fn convert<F: Float + FloatConvert<T>, T: Float>(input: F, size: u32) -> Result<Value, Error> {
    float_value(
        input.convert_r(Round::NearestTiesToEven, &mut false).value,
        size,
    )
}

fn float_value<F: Float>(input: F, size: u32) -> Result<Value, Error> {
    Value::new(size, BigUint::from(input.to_bits()))
}

#[derive(Clone, Copy)]
struct Format {
    precision: u32,
    exponent_bits: u32,
    exponent_shift: u32,
    bias: i32,
    explicit_integer: bool,
}

impl Format {
    fn for_size(opcode: Opcode, size: u32) -> Result<Self, Error> {
        let (precision, exponent_bits, exponent_shift, bias) = match size {
            2 => (11, 5, 10, 15),
            4 => (24, 8, 23, 127),
            8 => (53, 11, 52, 1023),
            10 => (64, 15, 64, 16383),
            16 => (113, 15, 112, 16383),
            _ => {
                return Err(invalid(
                    opcode,
                    "supported float sizes are 2, 4, 8, 10 (canonical x87), and 16 bytes",
                ));
            }
        };
        Ok(Self {
            precision,
            exponent_bits,
            exponent_shift,
            bias,
            explicit_integer: size == 10,
        })
    }

    fn validate_encoding(self, opcode: Opcode, bits: u128) -> Result<(), Error> {
        if self.explicit_integer {
            // Reject pseudo-denormals, unnormals, and pseudo-infinity/NaN. Unlike
            // Ghidra's Java extension format, canonical x87 specials include J=1.
            let exponent = self.exponent(bits);
            let integer_bit = bits & (1_u128 << 63) != 0;
            require(
                opcode,
                integer_bit == (exponent != 0),
                "noncanonical x87 encoding: explicit integer bit disagrees with exponent",
            )?;
        }
        Ok(())
    }

    fn exponent(self, bits: u128) -> u32 {
        ((bits >> self.exponent_shift) & ((1_u128 << self.exponent_bits) - 1)) as u32
    }

    /// A finite absolute value is significand * 2^scale, with an exact integer
    /// significand. Sign is stored separately in the encoded representation.
    fn decompose(self, bits: u128) -> (BigUint, i32, bool) {
        let exponent = self.exponent(bits);
        let mut significand = bits & ((1_u128 << self.exponent_shift) - 1);
        if exponent != 0 && !self.explicit_integer {
            significand |= 1_u128 << (self.precision - 1);
        }
        let scale = exponent.max(1) as i32 - self.bias - (self.precision - 1) as i32;
        let negative = bits & (1_u128 << (self.exponent_shift + self.exponent_bits)) != 0;
        (BigUint::from(significand), scale, negative)
    }

    /// Encode a positive normal value; the caller has already rounded its
    /// precision-bit significand and unbiased binary exponent.
    fn encode_normal(self, significand: &BigUint, exponent: i32) -> u128 {
        let mut significand = significand.to_u128().expect("at most 113 significand bits");
        if !self.explicit_integer {
            significand &= (1_u128 << (self.precision - 1)) - 1;
        }
        ((exponent + self.bias) as u128) << self.exponent_shift | significand
    }
}

fn truncate_integer(
    opcode: Opcode,
    bits: u128,
    format: Format,
    output_size: u32,
) -> Result<Value, Error> {
    let (significand, scale, negative) = format.decompose(bits);
    let output_bits = output_size * 8;
    // Avoid constructing a huge integer merely to find that the output overflows.
    let result_bits = if significand.is_zero() {
        0
    } else if scale >= 0 {
        significand.bits() + scale as u64
    } else {
        significand
            .bits()
            .saturating_sub(u64::from(scale.unsigned_abs()))
    };
    require(
        opcode,
        result_bits <= u64::from(output_bits),
        "TRUNC result exceeds the signed output range",
    )?;
    let magnitude = if scale >= 0 {
        significand << scale as usize
    } else {
        significand >> scale.unsigned_abs() as usize
    };
    let sign_limit = BigUint::one() << (output_bits - 1) as usize;
    require(
        opcode,
        if negative {
            magnitude <= sign_limit
        } else {
            magnitude < sign_limit
        },
        "TRUNC result exceeds the signed output range",
    )?;
    let result = if negative && !magnitude.is_zero() {
        (BigUint::one() << output_bits as usize) - magnitude
    } else {
        magnitude
    };
    Value::new(output_size, result)
}

fn round_ties_positive<F: Float>(input: F, bits: u128, format: Format) -> F {
    if input.is_nan() {
        return input.round_to_integral(Round::TowardPositive).value;
    }
    if input.is_infinite() || input.is_integer() && !input.is_zero() {
        return input;
    }
    if input.is_zero() {
        return F::ZERO;
    }
    let (significand, scale, negative) = format.decompose(bits);
    debug_assert!(
        scale < 0,
        "nonintegral finite value has negative binary scale"
    );
    let shift = scale.unsigned_abs() as usize;
    if shift > significand.bits() as usize {
        return F::ZERO;
    }
    let mut integer = &significand >> shift;
    let remainder = &significand - (&integer << shift);
    let half = BigUint::one() << (shift - 1);
    if if negative {
        remainder > half
    } else {
        remainder >= half
    } {
        integer += BigUint::one();
    }
    let result = F::from_u128(
        integer
            .to_u128()
            .expect("fractional input's integer part fits precision"),
    )
    .value;
    if negative && !integer.is_zero() {
        -result
    } else {
        result
    }
}

/// Correctly rounded sqrt without a host float. For x = s*2^e, select the
/// destination ulp so that sqrt(x)/ulp = sqrt(N) for integer N (<= 227 bits).
/// Integer sqrt gives the lower candidate q; compare 4*N with (2*q+1)^2 to
/// choose the nearest candidate, including the ties-to-even rule explicitly.
fn square_root<F: Float>(input: F, bits: u128, format: Format) -> F {
    if input.is_zero() {
        return input;
    } // includes sqrt(-0) = -0
    if input.is_nan() {
        return input.add_r(input, Round::NearestTiesToEven).value;
    }
    if input.is_negative() {
        return F::NAN;
    }
    if input.is_infinite() {
        return input;
    }
    let (significand, scale, _) = format.decompose(bits);
    let binary_exponent = significand.bits() as i32 - 1 + scale;
    let mut exponent = binary_exponent.div_euclid(2);
    let shift = scale + 2 * ((format.precision - 1) as i32 - exponent);
    debug_assert!(shift >= 0);
    let radicand = significand << shift as usize;
    let mut rounded = radicand.sqrt();
    let midpoint = (&rounded << 1_usize) + BigUint::one();
    let comparison = (&radicand << 2_usize).cmp(&(&midpoint * &midpoint));
    if comparison.is_gt() || comparison.is_eq() && rounded.bit(0) {
        rounded += BigUint::one();
    }
    if rounded.bits() > u64::from(format.precision) {
        rounded >>= 1_usize;
        exponent += 1;
    }
    // For every supported format, sqrt(the smallest subnormal) is normal.
    debug_assert!(exponent + format.bias > 0);
    F::from_bits(format.encode_normal(&rounded, exponent))
}

fn invalid(opcode: Opcode, message: &str) -> Error {
    Error::InvalidOperands {
        opcode,
        message: message.into(),
    }
}

fn require(opcode: Opcode, condition: bool, message: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(invalid(opcode, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(size: u32, bits: u128) -> Value {
        Value::new(size, BigUint::from(bits)).unwrap()
    }
    fn f64_value(value: f64) -> Value {
        raw(8, u128::from(value.to_bits()))
    }
    fn eval(opcode: Opcode, inputs: &[Value], size: u32) -> Value {
        evaluate_float(opcode, inputs, size).unwrap()
    }
    fn bits(opcode: Opcode, inputs: &[Value], size: u32) -> u128 {
        eval(opcode, inputs, size).bits().to_u128().unwrap()
    }

    #[test]
    fn ieee_arithmetic_vectors_and_round_to_even_at_format_precision() {
        use Opcode::*;
        assert_eq!(
            bits(FloatAdd, &[raw(4, 0x3f800000), raw(4, 0x3f800000)], 4),
            0x40000000
        );
        assert_eq!(
            bits(FloatSub, &[f64_value(7.0), f64_value(2.5)], 8),
            4.5_f64.to_bits() as u128
        );
        assert_eq!(
            bits(FloatMult, &[f64_value(1.5), f64_value(-2.0)], 8),
            (-3.0_f64).to_bits() as u128
        );
        assert_eq!(
            bits(FloatDiv, &[f64_value(1.0), f64_value(3.0)], 8),
            0x3fd5555555555555
        );
        // binary16: 1 + half of one ulp ties down to even 1; next odd value ties up.
        assert_eq!(bits(FloatAdd, &[raw(2, 0x3c00), raw(2, 0x1000)], 2), 0x3c00);
        assert_eq!(bits(FloatAdd, &[raw(2, 0x3c01), raw(2, 0x1000)], 2), 0x3c02);
    }

    #[test]
    fn nan_is_unordered_and_signed_zeros_compare_equal_at_every_format() {
        use Opcode::*;
        for (size, zero_sign, infinity, nan) in [
            (2, 0x8000, 0x7c00, 0x7e00),
            (4, 0x80000000, 0x7f800000, 0x7fc00000),
            (
                8,
                0x8000000000000000,
                0x7ff0000000000000,
                0x7ff8000000000000,
            ),
            (
                10,
                1_u128 << 79,
                0x7fff8000000000000000,
                0x7fffc000000000000000,
            ),
            (
                16,
                1_u128 << 127,
                0x7fff0000000000000000000000000000,
                0x7fff8000000000000000000000000000,
            ),
        ] {
            assert_eq!(
                bits(FloatEqual, &[raw(size, 0), raw(size, zero_sign)], 1),
                1
            );
            assert_eq!(bits(FloatLess, &[raw(size, zero_sign), raw(size, 0)], 1), 0);
            assert_eq!(bits(FloatNan, &[raw(size, infinity)], 1), 0);
            assert_eq!(bits(FloatNan, &[raw(size, nan)], 1), 1);
            assert_eq!(bits(FloatEqual, &[raw(size, nan), raw(size, nan)], 1), 0);
            assert_eq!(bits(FloatNotequal, &[raw(size, nan), raw(size, nan)], 1), 1);
            for opcode in [FloatLess, FloatLessequal] {
                assert_eq!(bits(opcode, &[raw(size, nan), raw(size, 0)], 1), 0);
                assert_eq!(bits(opcode, &[raw(size, 0), raw(size, nan)], 1), 0);
            }
        }
    }

    #[test]
    fn ieee_infinities_division_by_zero_and_sign_operations() {
        use Opcode::*;
        assert_eq!(
            bits(FloatDiv, &[f64_value(1.0), f64_value(0.0)], 8),
            f64::INFINITY.to_bits() as u128
        );
        let nan = eval(FloatDiv, &[f64_value(0.0), f64_value(0.0)], 8);
        assert_eq!(bits(FloatNan, &[nan], 1), 1);
        assert_eq!(
            bits(FloatNeg, &[f64_value(0.0)], 8),
            (-0.0_f64).to_bits() as u128
        );
        assert_eq!(bits(FloatAbs, &[f64_value(-0.0)], 8), 0);
        assert_eq!(
            bits(FloatNeg, &[f64_value(f64::INFINITY)], 8),
            f64::NEG_INFINITY.to_bits() as u128
        );
    }

    #[test]
    fn round_has_positive_ties_and_preserves_large_integral_values() {
        use Opcode::*;
        for (input, expected) in [
            (2.5_f64, 3.0_f64),
            (-2.5, -2.0),
            (2.25, 2.0),
            (-2.75, -3.0),
            (0.5, 1.0),
            (-0.5, 0.0),
            (-0.0, 0.0),
        ] {
            assert_eq!(
                bits(FloatRound, &[f64_value(input)], 8),
                expected.to_bits() as u128
            );
        }
        assert_eq!(bits(FloatRound, &[raw(4, 0x4b000001)], 4), 0x4b000001);
        assert_eq!(
            bits(FloatCeil, &[f64_value(-2.5)], 8),
            (-2.0_f64).to_bits() as u128
        );
        assert_eq!(
            bits(FloatFloor, &[f64_value(-2.5)], 8),
            (-3.0_f64).to_bits() as u128
        );
    }

    #[test]
    fn integer_conversions_support_signed_4096_bit_inputs_without_host_double() {
        use Opcode::*;
        let large = Value::new(512, (BigUint::one() << 4000_usize) + BigUint::one()).unwrap();
        let quadruple = bits(FloatInt2Float, &[large], 16);
        assert_eq!(quadruple, (16383_u128 + 4000) << 112);
        let negative = Value::new(
            512,
            (BigUint::one() << 4096_usize) - (BigUint::one() << 4000_usize),
        )
        .unwrap();
        assert_eq!(
            bits(FloatInt2Float, &[negative], 16),
            quadruple | (1_u128 << 127)
        );
        assert_eq!(
            bits(FloatInt2Float, &[Value::from_u64(1, 0xfe).unwrap()], 8),
            (-2.0_f64).to_bits() as u128
        );
        let tie = Value::from_u64(8, 16_777_217).unwrap();
        assert_eq!(bits(FloatInt2Float, &[tie], 4), 0x4b800000);
    }

    #[test]
    fn conversions_preserve_x87_quad_range_and_standard_special_encodings() {
        use Opcode::*;
        let x87_huge = ((16383_u128 + 4000) << 64) | (1_u128 << 63);
        let quad_huge = (16383_u128 + 4000) << 112;
        assert_eq!(bits(FloatFloat2Float, &[raw(10, x87_huge)], 16), quad_huge);
        assert_eq!(bits(FloatFloat2Float, &[raw(16, quad_huge)], 10), x87_huge);
        assert_eq!(
            bits(FloatAdd, &[raw(16, quad_huge), raw(16, quad_huge)], 16),
            (16383_u128 + 4001) << 112
        );
        assert_eq!(
            bits(FloatFloat2Float, &[raw(16, quad_huge)], 8),
            f64::INFINITY.to_bits() as u128
        );
        assert_eq!(
            bits(FloatFloat2Float, &[f64_value(f64::INFINITY)], 10),
            0x7fff8000000000000000
        );
    }

    #[test]
    fn narrowing_conversions_round_ties_and_preserve_gradual_underflow() {
        use Opcode::*;
        assert_eq!(
            bits(FloatFloat2Float, &[raw(8, 0x3ff0000010000000)], 4),
            0x3f800000
        );
        assert_eq!(
            bits(FloatFloat2Float, &[raw(8, 0x3ff0000030000000)], 4),
            0x3f800002
        );
        assert_eq!(bits(FloatFloat2Float, &[raw(8, 0x3e60000000000000)], 2), 0); // 2^-25
        assert_eq!(bits(FloatFloat2Float, &[raw(8, 0x3e70000000000000)], 2), 1); // 2^-24
        assert_eq!(bits(FloatFloat2Float, &[raw(2, 1)], 8), 0x3e70000000000000);
    }

    #[test]
    fn truncation_is_exact_and_rejects_undefined_or_overflowing_integer_results() {
        use Opcode::*;
        assert_eq!(
            bits(FloatTrunc, &[f64_value(-2.5)], 8),
            (-2_i64) as u64 as u128
        );
        assert_eq!(bits(FloatTrunc, &[f64_value(-128.9)], 1), 0x80);
        assert_eq!(bits(FloatTrunc, &[f64_value(127.9)], 1), 0x7f);
        for input in [128.0, -129.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            assert!(matches!(
                evaluate_float(FloatTrunc, &[f64_value(input)], 1),
                Err(Error::InvalidOperands { .. })
            ));
        }
        let huge = raw(16, (16383_u128 + 4000) << 112);
        assert_eq!(
            eval(FloatTrunc, &[huge], 512).bits(),
            &(BigUint::one() << 4000_usize)
        );
        let minimum = raw(16, ((16383_u128 + 4095) << 112) | (1_u128 << 127));
        assert_eq!(
            eval(FloatTrunc, &[minimum], 512).bits(),
            &(BigUint::one() << 4095_usize)
        );
        assert!(evaluate_float(FloatTrunc, &[raw(16, (16383_u128 + 4095) << 112)], 512).is_err());
    }

    #[test]
    fn software_sqrt_handles_extreme_exponents_subnormals_and_special_values() {
        use Opcode::*;
        assert_eq!(bits(FloatSqrt, &[f64_value(2.0)], 8), 0x3ff6a09e667f3bcd);
        assert_eq!(bits(FloatSqrt, &[raw(8, 1)], 8), 0x1e60000000000000);
        assert_eq!(
            bits(
                FloatSqrt,
                &[raw(16, 0x40000000000000000000000000000000)],
                16
            ),
            0x3fff6a09e667f3bcc908b2fb1366ea95
        );
        assert_eq!(
            bits(FloatSqrt, &[raw(16, (16383_u128 + 4000) << 112)], 16),
            (16383_u128 + 2000) << 112
        );
        let x87 = ((16383_u128 + 4000) << 64) | (1_u128 << 63);
        assert_eq!(
            bits(FloatSqrt, &[raw(10, x87)], 10),
            ((16383_u128 + 2000) << 64) | (1_u128 << 63)
        );
        assert_eq!(
            bits(FloatSqrt, &[f64_value(-0.0)], 8),
            (-0.0_f64).to_bits() as u128
        );
        assert_eq!(
            bits(FloatSqrt, &[f64_value(f64::INFINITY)], 8),
            f64::INFINITY.to_bits() as u128
        );
        let nan = eval(FloatSqrt, &[f64_value(-1.0)], 8);
        assert_eq!(bits(FloatNan, &[nan], 1), 1);
    }

    #[test]
    fn every_nonnegative_finite_binary16_sqrt_matches_independent_host_oracle() {
        // Binary64 has ample precision for the correctly rounded binary16 sqrt:
        // integer radicands have <=23 bits, far below its 53-bit precision.
        for encoded in 0_u128..0x7c00 {
            let input = Half::from_bits(encoded);
            let widened: Double = input.convert(&mut false).value;
            let host = f64::from_bits(widened.to_bits() as u64).sqrt();
            let expected: Half = Double::from_bits(host.to_bits() as u128)
                .convert(&mut false)
                .value;
            assert_eq!(
                bits(Opcode::FloatSqrt, &[raw(2, encoded)], 2),
                expected.to_bits(),
                "binary16 {encoded:04x}"
            );
        }
    }

    #[test]
    fn software_binary64_sqrt_agrees_with_independent_host_across_exponents() {
        let mut state = 0x89abcdef01234567_u64;
        for _ in 0..2048 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let encoded = state & 0x7fff_ffff_ffff_ffff;
            if encoded >> 52 == 0x7ff {
                continue;
            }
            let expected = f64::from_bits(encoded).sqrt().to_bits();
            assert_eq!(
                bits(Opcode::FloatSqrt, &[raw(8, u128::from(encoded))], 8),
                u128::from(expected),
                "binary64 {encoded:016x}"
            );
        }
    }

    #[test]
    fn invalid_shapes_formats_and_noncanonical_x87_are_rejected_before_indexing() {
        use Opcode::*;
        for opcode in [
            FloatEqual,
            FloatNan,
            FloatAdd,
            FloatRound,
            FloatTrunc,
            FloatInt2Float,
        ] {
            assert!(matches!(
                evaluate_float(opcode, &[], 8),
                Err(Error::InvalidArity { .. })
            ));
            assert!(matches!(
                evaluate_float(opcode, &vec![f64_value(0.0); 3], 8),
                Err(Error::InvalidArity { .. })
            ));
        }
        for (opcode, inputs, output) in [
            (FloatEqual, vec![f64_value(0.0), raw(4, 0)], 1),
            (FloatEqual, vec![f64_value(0.0), f64_value(0.0)], 8),
            (FloatAdd, vec![f64_value(1.0), f64_value(1.0)], 4),
            (FloatNan, vec![raw(3, 0)], 1),
            (FloatFloat2Float, vec![f64_value(1.0)], 32),
            (FloatNan, vec![raw(10, 0x7fff0000000000000000)], 1),
            (FloatNan, vec![raw(10, 1_u128 << 63)], 1),
        ] {
            assert!(matches!(
                evaluate_float(opcode, &inputs, output),
                Err(Error::InvalidOperands { .. })
            ));
        }
        assert!(matches!(
            evaluate_float(FloatNan, &[f64_value(0.0)], 0),
            Err(Error::InvalidSize(0))
        ));
    }
}
