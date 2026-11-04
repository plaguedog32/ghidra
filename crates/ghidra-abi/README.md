# Native compiler storage

This crate resolves compiler-spec storage declarations against actual language
registers and address spaces. It keeps signed stack addresses, register aliases
and join significance explicit. It is a native Rust layer and uses no Java or
Ghidra C++ process.

Argument allocation, register resource groups, prototype-rule evaluation,
injection compilation and type recovery remain separate stages. Successful
storage resolution does not mean that a calling convention is executable.
