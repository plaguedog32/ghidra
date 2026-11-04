use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Integer identifier for a local p-code variable.  Strings are never stored;
/// uniqueness is guaranteed by allocation order within each macro/constructor scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocalVarId(
    /// Allocation index within the scope this variable belongs to. Unique
    /// within one decoded instruction, since each spliced body — a macro
    /// expansion, a sub-table, a delay slot — is given its own base offset.
    pub u32,
);

/// Parse-time interner: maps source name strings to [`LocalVarId`]s.
/// Only alive during parsing — discarded once the producer has built its macro.
pub struct LocalVarInterner<'str> {
    map: HashMap<&'str str, LocalVarId>,
    count: u32,
}

impl<'str> Default for LocalVarInterner<'str> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'str> LocalVarInterner<'str> {
    /// Creates an empty interner.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            count: 0,
        }
    }

    /// Returns the identifier for `name`, allocating one on its first use.
    pub fn intern(&mut self, name: &'str str) -> LocalVarId {
        if let Some(&id) = self.map.get(name) {
            return id;
        }
        let id = LocalVarId(self.count);
        self.count += 1;
        self.map.insert(name, id);
        id
    }

    /// Returns the number of distinct names interned so far.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Returns an existing identifier without allocating one.
    pub fn get(&self, name: &str) -> Option<LocalVarId> {
        self.map.get(name).copied()
    }
}

/// The built-in SLEIGH functions — a spec may call these without declaring
/// them, unlike `define pcodeop` names.
///
/// They appear as [`ExpressionTy::FunctionCall`](super::ExpressionTy::FunctionCall)
/// and every one of them has a direct p-code meaning, so a consumer lowering to
/// its own IR is expected to implement them rather than treat them as opaque
/// calls. The two exceptions are noted on their variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Builtin {
    /// `carry(a, b)` — would the unsigned addition `a + b` carry out of the
    /// top bit? One byte.
    Carry,

    /// `scarry(a, b)` — would the signed addition `a + b` overflow? One byte.
    Scarry,

    /// `sborrow(a, b)` — would the signed subtraction `a - b` overflow? One
    /// byte.
    Sborrow,

    /// `nan(x)` — is the floating-point value `x` a NaN? One byte.
    Nan,

    /// `abs(x)` — floating-point absolute value.
    Abs,

    /// `sqrt(x)` — floating-point square root.
    Sqrt,

    /// `floor(x)` — round towards negative infinity, staying floating-point.
    Floor,

    /// `ceil(x)` — round towards positive infinity, staying floating-point.
    Ceil,

    /// `round(x)` — round to nearest, staying floating-point.
    Round,

    /// `int2float(x)` — signed integer to floating-point.
    Int2Float,

    /// `float2float(x)` — change floating-point width, preserving the value.
    Float2Float,

    /// `trunc(x)` — floating-point to signed integer, truncating towards zero.
    Trunc,

    /// `zext(x)` — widen, filling with zeroes. The result width comes from the
    /// context the call sits in, not from the argument.
    Zext,

    /// `sext(x)` — widen, filling with copies of the sign bit.
    Sext,

    /// `popcount(x)` — number of set bits.
    Popcount,

    /// `lzcount(x)` — number of leading zero bits.
    Lzcount,
    /// Constant-pool reference. Has no p-code expansion: a consumer must
    /// resolve it against the binary's constant pool.
    Cpool,
    /// Object allocation, the companion of [`Builtin::Cpool`] in
    /// bytecode-oriented specifications.
    NewObject,
}

impl Builtin {
    /// Every builtin, in declaration order.
    ///
    /// The symbol table is seeded from this, so a variant added here is
    /// automatically callable from a specification.
    pub const ALL: &'static [Builtin] = &[
        Builtin::Carry,
        Builtin::Scarry,
        Builtin::Sborrow,
        Builtin::Nan,
        Builtin::Abs,
        Builtin::Sqrt,
        Builtin::Floor,
        Builtin::Ceil,
        Builtin::Round,
        Builtin::Int2Float,
        Builtin::Float2Float,
        Builtin::Trunc,
        Builtin::Zext,
        Builtin::Sext,
        Builtin::Popcount,
        Builtin::Lzcount,
        Builtin::Cpool,
        Builtin::NewObject,
    ];

    /// The name a specification calls this builtin by.
    pub fn as_str(self) -> &'static str {
        match self {
            Builtin::Carry => "carry",
            Builtin::Scarry => "scarry",
            Builtin::Sborrow => "sborrow",
            Builtin::Nan => "nan",
            Builtin::Abs => "abs",
            Builtin::Sqrt => "sqrt",
            Builtin::Floor => "floor",
            Builtin::Ceil => "ceil",
            Builtin::Round => "round",
            Builtin::Int2Float => "int2float",
            Builtin::Float2Float => "float2float",
            Builtin::Trunc => "trunc",
            Builtin::Zext => "zext",
            Builtin::Sext => "sext",
            Builtin::Popcount => "popcount",
            Builtin::Lzcount => "lzcount",
            Builtin::Cpool => "cpool",
            Builtin::NewObject => "newobject",
        }
    }

    /// Returns the builtin with the SLEIGH source spelling `s`.
    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|b| b.as_str() == s)
    }
}

#[cfg(test)]
mod builtin_tests {
    use super::Builtin;

    /// `ALL` seeds the symbol table, so a builtin missing from it is not
    /// callable from a specification however well `as_str` knows it.
    #[test]
    fn every_builtin_round_trips_through_all() {
        for &builtin in Builtin::ALL {
            assert_eq!(Builtin::from_name(builtin.as_str()), Some(builtin));
        }
        assert_eq!(Builtin::from_name("not_a_builtin"), None);
        assert_eq!(Builtin::from_name("epsilon"), None);
        assert_eq!(Builtin::from_name("float2int"), None);
    }
}
