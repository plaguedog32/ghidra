#![allow(dead_code)]

use ghidra_cfg::{Cfg, CfgError, CfgInput, Edge, EdgeRole, Limits, NodeId, ProgramPoint};
use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Varnode,
};

pub const CONST: u32 = 0;
pub const RAM: u32 = 1;
pub const REG: u32 = 2;
pub const UNIQUE: u32 = 3;

pub fn space(id: u32, name: &str, kind: SpaceKind, address_size: u8) -> AddressSpace {
    AddressSpace {
        id: SpaceId(id),
        name: name.into(),
        kind,
        address_size,
        word_size: 1,
        endianness: Endianness::Little,
    }
}

pub fn spaces() -> Vec<AddressSpace> {
    vec![
        space(CONST, "const", SpaceKind::Constant, 8),
        space(RAM, "ram", SpaceKind::Ram, 8),
        space(REG, "register", SpaceKind::Register, 8),
        space(UNIQUE, "unique", SpaceKind::Unique, 8),
    ]
}

pub fn vn(space: u32, offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId(space),
        offset,
        size,
    }
}
pub fn c(value: u64, size: u32) -> Varnode {
    vn(CONST, value, size)
}
/// A relative label: signed displacement from the current operation index.
pub fn rel(displacement: i32) -> Varnode {
    vn(CONST, u64::from(displacement as u32), 4)
}
pub fn ram(address: u64) -> Varnode {
    vn(RAM, address, 8)
}
pub fn reg(index: u64) -> Varnode {
    vn(REG, index * 8, 8)
}
pub fn flag(index: u64) -> Varnode {
    vn(UNIQUE, index, 1)
}

pub fn op(opcode: Opcode, output: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
    PcodeOperation {
        opcode,
        output,
        inputs,
    }
}
pub fn copy(output: Varnode, input: Varnode) -> PcodeOperation {
    op(Opcode::Copy, Some(output), vec![input])
}
pub fn set_flag(index: u64) -> PcodeOperation {
    copy(flag(index), c(1, 1))
}
pub fn branch(target: Varnode) -> PcodeOperation {
    op(Opcode::Branch, None, vec![target])
}
pub fn cbranch(target: Varnode, condition: Varnode) -> PcodeOperation {
    op(Opcode::Cbranch, None, vec![target, condition])
}
pub fn call(target: Varnode) -> PcodeOperation {
    op(Opcode::Call, None, vec![target])
}
pub fn ret(target: Varnode) -> PcodeOperation {
    op(Opcode::Return, None, vec![target])
}

pub fn ins(address: u64, length: u32, ops: Vec<PcodeOperation>) -> PcodeInstruction {
    PcodeInstruction {
        address,
        length,
        ops,
    }
}

pub fn try_build_with(
    spaces: Vec<AddressSpace>,
    entry: u64,
    instructions: Vec<PcodeInstruction>,
    limits: Limits,
) -> Result<Cfg, CfgError> {
    Cfg::new(
        CfgInput::new(spaces, SpaceId(RAM), entry, instructions),
        limits,
    )
}
pub fn try_build(entry: u64, instructions: Vec<PcodeInstruction>) -> Result<Cfg, CfgError> {
    try_build_with(spaces(), entry, instructions, Limits::default())
}
pub fn build(entry: u64, instructions: Vec<PcodeInstruction>) -> Cfg {
    try_build(entry, instructions).unwrap()
}

pub fn point(address: u64, operation: u32) -> ProgramPoint {
    ProgramPoint::new(address, operation)
}
pub fn block_at(cfg: &Cfg, address: u64, operation: u32) -> NodeId {
    let node = cfg.block_of(point(address, operation)).unwrap();
    assert_eq!(
        cfg.block_points(node).unwrap()[0],
        point(address, operation),
        "expected a block to start at {address:#x}:{operation}"
    );
    node
}
pub fn out(cfg: &Cfg, node: NodeId, role: EdgeRole) -> Edge {
    let edges: Vec<_> = cfg
        .out_edges(node)
        .unwrap()
        .iter()
        .filter(|edge| edge.role == role)
        .copied()
        .collect();
    assert_eq!(edges.len(), 1, "node {node} has {edges:?} for {role:?}");
    edges[0]
}
