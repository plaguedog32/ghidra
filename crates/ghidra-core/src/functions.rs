//! Recursive traversal of directly reachable x86 code, without executing it.
//!
//! Entry points and named function symbols seed traversal. Direct calls introduce
//! additional functions; branches introduce reachable blocks. Indirect targets,
//! exception/unwind metadata, jump tables, and speculative prologues are not
//! recovered. Shared tails have deterministic ownership and are reported as
//! incomplete, rather than copied into multiple apparently independent functions.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind};
use serde::Serialize;

use crate::{BasicBlock, BinaryImage, Error, Instruction, MAX_INSTRUCTIONS, Reference};

const MAX_FUNCTIONS: usize = 4096;
const MAX_WARNINGS: usize = 128;

#[derive(Debug, Clone, Copy)]
pub struct DiscoveryLimits {
    pub max_functions: usize,
    /// Global decoder budget across all functions, including invalid encodings.
    pub max_instructions: usize,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_functions: MAX_FUNCTIONS,
            max_instructions: MAX_INSTRUCTIONS,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FunctionDiscovery {
    pub functions: Vec<Function>,
    pub warnings: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Function {
    pub entry: u64,
    pub name: String,
    pub instructions: Vec<Instruction>,
    pub blocks: Vec<BasicBlock>,
    pub references: Vec<Reference>,
    /// Entry addresses of functions that directly call or tail-transfer here.
    pub callers: Vec<u64>,
    /// False if traversal encountered a budget, conflict, missing code, shared
    /// tail, invalid instruction, or unresolved indirect control flow. True does
    /// not prove that this is a complete semantic function or recover exceptions.
    pub complete: bool,
}

#[derive(Debug)]
struct CodeRange {
    start: u64,
    end: u64,
    file_offset: usize,
}

struct CodeMap<'a> {
    bytes: &'a [u8],
    ranges: Vec<CodeRange>,
}

impl<'a> CodeMap<'a> {
    fn new(image: &'a BinaryImage) -> Result<Self, Error> {
        if image.sections.len() > 4096 {
            return Err(Error::InvalidBinary("too many section mappings".into()));
        }
        let mut ranges = Vec::new();
        for section in image.sections.iter().filter(|section| section.executable) {
            let length = section.size.min(section.file_size);
            if length == 0 {
                continue;
            }
            let end = section
                .address
                .checked_add(length)
                .ok_or(Error::AddressOverflow)?;
            let file_end = section
                .file_offset
                .checked_add(length)
                .ok_or(Error::AddressOverflow)?;
            if file_end > image.bytes.len() as u64 {
                return Err(Error::InvalidBinary(
                    "executable section is outside the file".into(),
                ));
            }
            if image.bitness == 32 && end > u32::MAX as u64 + 1 {
                return Err(Error::AddressOverflow);
            }
            ranges.push(CodeRange {
                start: section.address,
                end,
                file_offset: section.file_offset as usize,
            });
        }
        ranges.sort_by_key(|range| range.start);
        if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(Error::InvalidBinary(
                "overlapping executable section mappings".into(),
            ));
        }
        Ok(Self {
            bytes: &image.bytes,
            ranges,
        })
    }

    fn bytes_at(&self, address: u64) -> Option<&[u8]> {
        let index = self
            .ranges
            .partition_point(|range| range.start <= address)
            .checked_sub(1)?;
        let range = &self.ranges[index];
        if address >= range.end {
            return None;
        }
        let offset = range.file_offset + (address - range.start) as usize;
        let count = (range.end - address).min(15) as usize;
        self.bytes.get(offset..offset + count)
    }
}

#[derive(Debug)]
struct Node {
    instruction: Instruction,
    references: Vec<Reference>,
    successors: Vec<u64>,
    complete: bool,
}

#[derive(Default)]
struct Warnings {
    items: Vec<String>,
    omitted: usize,
}

impl Warnings {
    fn push(&mut self, message: String) {
        if self.items.contains(&message) {
            return;
        }
        if self.items.len() < MAX_WARNINGS {
            self.items.push(message);
        } else {
            self.omitted += 1;
        }
    }

    fn finish(mut self) -> Vec<String> {
        if self.omitted > 0 {
            self.items.push(format!(
                "{} additional discovery warnings omitted.",
                self.omitted
            ));
        }
        self.items
    }
}

impl BinaryImage {
    pub fn discover_functions(&self, limits: DiscoveryLimits) -> Result<FunctionDiscovery, Error> {
        if !self.x86 || !matches!(self.bitness, 32 | 64) {
            return Err(Error::UnsupportedArchitecture(self.architecture.clone()));
        }
        if !(1..=MAX_FUNCTIONS).contains(&limits.max_functions)
            || !(1..=MAX_INSTRUCTIONS).contains(&limits.max_instructions)
        {
            return Err(Error::InvalidBinary(format!(
                "discovery limits require 1..={MAX_FUNCTIONS} functions and 1..={MAX_INSTRUCTIONS} total instructions"
            )));
        }
        let map = CodeMap::new(self)?;
        let mut warnings = Warnings::default();
        let mut seeds = BTreeMap::new();
        let mut truncated = false;
        if map.bytes_at(self.entry).is_some() {
            seeds.insert(self.entry, "entry".to_owned());
        }
        for symbol in self.symbols.iter().filter(|symbol| symbol.is_function) {
            if map.bytes_at(symbol.address).is_none() {
                continue;
            }
            if let Some(name) = seeds.get_mut(&symbol.address) {
                if name == "entry" {
                    *name = symbol.name.clone();
                }
            } else if seeds.len() < limits.max_functions {
                seeds.insert(symbol.address, symbol.name.clone());
            } else {
                truncated = true;
                warnings.push(format!(
                    "Function budget {} reached; additional symbol seeds omitted.",
                    limits.max_functions
                ));
                break;
            }
        }
        if seeds.is_empty()
            && let Some(range) = map.ranges.first()
        {
            seeds.insert(range.start, generated_name(range.start));
            warnings.push("No mapped entry point or function symbols; traversal starts at the first executable section.".into());
        }
        if seeds.is_empty() {
            warnings.push("No file-backed executable sections to discover functions in.".into());
            return Ok(FunctionDiscovery {
                warnings: warnings.finish(),
                ..Default::default()
            });
        }

        let mut pending: BTreeSet<_> = seeds.keys().copied().collect();
        let mut nodes: BTreeMap<u64, Node> = BTreeMap::new();
        let mut failed = BTreeSet::new();
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_hex_prefix("0x");
        formatter.options_mut().set_hex_suffix("");
        let mut decoded_count = 0;
        while let Some(address) = pending.pop_first() {
            if nodes.contains_key(&address) || failed.contains(&address) {
                continue;
            }
            if let Some((&previous, node)) = nodes.range(..address).next_back()
                && previous + node.instruction.bytes.len() as u64 > address
            {
                warnings.push(format!("Control-flow target 0x{address:X} enters the middle of the instruction at 0x{previous:X}."));
                nodes
                    .get_mut(&previous)
                    .expect("existing predecessor")
                    .complete = false;
                failed.insert(address);
                continue;
            }
            if decoded_count == limits.max_instructions {
                truncated = true;
                warnings.push(format!(
                    "Global instruction budget {} reached; reachable code remains undecoded.",
                    limits.max_instructions
                ));
                break;
            }
            let Some(bytes) = map.bytes_at(address) else {
                failed.insert(address);
                continue;
            };
            decoded_count += 1;
            let mut node = decode_node(bytes, address, self.bitness, &mut formatter);
            let end = address + node.instruction.bytes.len() as u64;
            if let Some((&overlap, _)) = nodes.range(address..end).next() {
                warnings.push(format!("Instruction at 0x{address:X} overlaps an existing instruction at 0x{overlap:X}."));
                nodes.get_mut(&overlap).expect("existing overlap").complete = false;
                failed.insert(address);
                continue;
            }
            if !node.complete {
                warnings.push(format!(
                    "Unresolved {} at 0x{address:X} limits function recovery.",
                    node.instruction.flow
                ));
            }
            if node.instruction.flow == "call"
                && let Some(target) = node.instruction.target
                && map.bytes_at(target).is_some()
                && !seeds.contains_key(&target)
            {
                if seeds.len() < limits.max_functions {
                    seeds.insert(target, generated_name(target));
                    if !nodes.contains_key(&target) && !failed.contains(&target) {
                        pending.insert(target);
                    }
                } else {
                    truncated = true;
                    warnings.push(format!(
                        "Function budget {} reached; call target 0x{target:X} omitted.",
                        limits.max_functions
                    ));
                }
            }
            for successor in &node.successors {
                if map.bytes_at(*successor).is_none() {
                    node.complete = false;
                    warnings.push(format!("Control flow from 0x{address:X} leaves mapped executable code at 0x{successor:X}."));
                } else if !nodes.contains_key(successor) && !failed.contains(successor) {
                    pending.insert(*successor);
                }
            }
            nodes.insert(address, node);
        }

        let mut owners = BTreeMap::new();
        let mut shared = BTreeSet::new();
        let mut functions = Vec::with_capacity(seeds.len());
        for (&entry, name) in &seeds {
            let mut function = Function {
                entry,
                name: name.clone(),
                instructions: Vec::new(),
                blocks: Vec::new(),
                references: Vec::new(),
                callers: Vec::new(),
                complete: true,
            };
            let mut work = BTreeSet::from([entry]);
            let mut local = BTreeMap::new();
            while let Some(address) = work.pop_first() {
                if local.contains_key(&address) {
                    continue;
                }
                if let Some(owner) = owners.get(&address) {
                    shared.insert(*owner);
                    shared.insert(entry);
                    function.complete = false;
                    warnings.push(format!("Functions 0x{owner:X} and 0x{entry:X} share code at 0x{address:X}; the first function retains ownership."));
                    continue;
                }
                let Some(node) = nodes.get(&address) else {
                    function.complete = false;
                    continue;
                };
                owners.insert(address, entry);
                local.insert(address, node);
                function.complete &= node.complete;
                for reference in &node.references {
                    let mut reference = reference.clone();
                    if reference.kind == "branch"
                        && reference.to != entry
                        && seeds.contains_key(&reference.to)
                    {
                        reference.kind = "tail-call".into();
                    }
                    function.references.push(reference);
                }
                for &successor in &node.successors {
                    if successor != entry && seeds.contains_key(&successor) {
                        if !function
                            .references
                            .iter()
                            .rev()
                            .take(node.references.len())
                            .any(|reference| {
                                reference.from == address
                                    && reference.to == successor
                                    && reference.kind == "tail-call"
                            })
                        {
                            function.references.push(Reference {
                                from: address,
                                to: successor,
                                kind: "tail-call".into(),
                            });
                        }
                        if !nodes.contains_key(&successor) || failed.contains(&successor) {
                            function.complete = false;
                        }
                    } else if !nodes.contains_key(&successor) || failed.contains(&successor) {
                        function.complete = false;
                    } else if let Some(owner) =
                        owners.get(&successor).filter(|owner| **owner != entry)
                    {
                        shared.insert(*owner);
                        shared.insert(entry);
                        function.complete = false;
                        function.references.push(Reference {
                            from: address,
                            to: successor,
                            kind: "shared-tail".into(),
                        });
                        warnings.push(format!("Functions 0x{owner:X} and 0x{entry:X} share code at 0x{successor:X}; the first function retains ownership."));
                    } else if !local.contains_key(&successor) {
                        work.insert(successor);
                    }
                }
                if node.instruction.flow == "call"
                    && let Some(target) = node.instruction.target
                    && failed.contains(&target)
                {
                    function.complete = false;
                }
            }
            function.instructions = local
                .values()
                .map(|node| node.instruction.clone())
                .collect();
            function.blocks = reachable_blocks(&local, entry);
            function.references.sort_by(|left, right| {
                (left.from, left.to, &left.kind).cmp(&(right.from, right.to, &right.kind))
            });
            function.references.dedup_by(|left, right| {
                left.from == right.from && left.to == right.to && left.kind == right.kind
            });
            functions.push(function);
        }
        let mut callers: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for function in &functions {
            for reference in &function.references {
                if matches!(reference.kind.as_str(), "call" | "tail-call")
                    && seeds.contains_key(&reference.to)
                {
                    callers
                        .entry(reference.to)
                        .or_default()
                        .insert(function.entry);
                }
            }
        }
        for function in &mut functions {
            function.callers = callers
                .remove(&function.entry)
                .unwrap_or_default()
                .into_iter()
                .collect();
            function.complete &= !shared.contains(&function.entry);
        }
        Ok(FunctionDiscovery {
            functions,
            warnings: warnings.finish(),
            truncated,
        })
    }
}

fn generated_name(address: u64) -> String {
    format!("sub_{address:X}")
}

fn decode_node(bytes: &[u8], address: u64, bitness: u32, formatter: &mut IntelFormatter) -> Node {
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let decoded = decoder.decode();
    let mut text = String::new();
    formatter.format(&decoded, &mut text);
    let flow = if decoded.is_invalid() {
        "invalid"
    } else {
        match decoded.flow_control() {
            FlowControl::Next => "next",
            FlowControl::UnconditionalBranch => "branch",
            FlowControl::ConditionalBranch => "conditional",
            FlowControl::IndirectBranch => "indirect-branch",
            FlowControl::Call => "call",
            FlowControl::IndirectCall => "indirect-call",
            FlowControl::Return => "return",
            FlowControl::Interrupt => "interrupt",
            FlowControl::Exception => "exception",
            FlowControl::XbeginXabortXend => "transaction",
        }
    };
    let target = matches!(
        decoded.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| decoded.near_branch_target());
    let mut references = Vec::new();
    if let Some(to) = target {
        references.push(Reference {
            from: address,
            to,
            kind: if flow == "call" { "call" } else { "branch" }.into(),
        });
    }
    if decoded.is_ip_rel_memory_operand() {
        references.push(Reference {
            from: address,
            to: decoded.ip_rel_memory_address(),
            kind: "data".into(),
        });
    }
    let next = address + decoder.position() as u64;
    let mut successors = match flow {
        "branch" => target.into_iter().collect(),
        "conditional" | "transaction" => target.into_iter().chain([next]).collect(),
        "return" | "exception" | "invalid" | "indirect-branch" | "interrupt" => Vec::new(),
        _ => vec![next],
    };
    successors.sort_unstable();
    successors.dedup();
    Node {
        instruction: Instruction {
            address,
            bytes: bytes[..decoder.position()].to_vec(),
            text,
            flow: flow.into(),
            target,
        },
        references,
        successors,
        complete: !matches!(
            flow,
            "invalid" | "indirect-branch" | "indirect-call" | "interrupt" | "transaction"
        ) && !(matches!(flow, "branch" | "call") && target.is_none()),
    }
}

fn reachable_blocks(nodes: &BTreeMap<u64, &Node>, entry: u64) -> Vec<BasicBlock> {
    let Some((&first, _)) = nodes.first_key_value() else {
        return Vec::new();
    };
    let mut leaders = BTreeSet::from([first, entry]);
    let mut predecessors: BTreeMap<u64, usize> = BTreeMap::new();
    for node in nodes.values() {
        for &successor in &node.successors {
            if nodes.contains_key(&successor) {
                *predecessors.entry(successor).or_default() += 1;
                if node.instruction.flow != "next" {
                    leaders.insert(successor);
                }
            }
        }
    }
    leaders.extend(
        predecessors
            .into_iter()
            .filter_map(|(address, count)| (count > 1).then_some(address)),
    );
    let ordered: Vec<_> = nodes.values().copied().collect();
    let mut blocks = Vec::new();
    let mut start = first;
    for (index, node) in ordered.iter().enumerate() {
        let end = node.instruction.address + node.instruction.bytes.len() as u64;
        let finish = ordered.get(index + 1).is_none_or(|next| {
            next.instruction.address != end
                || leaders.contains(&next.instruction.address)
                || node.instruction.flow != "next"
        });
        if finish {
            blocks.push(BasicBlock {
                start,
                end,
                successors: node.successors.clone(),
            });
            if let Some(next) = ordered.get(index + 1) {
                start = next.instruction.address;
            }
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Section, Symbol};

    fn image(bytes: &[u8]) -> BinaryImage {
        BinaryImage {
            format: "test".into(),
            architecture: "X86_64".into(),
            bitness: 64,
            entry: 0x1000,
            image_base: 0x1000,
            sections: vec![Section {
                name: ".text".into(),
                address: 0x1000,
                size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                executable: true,
            }],
            symbols: Vec::new(),
            strings: Vec::new(),
            warnings: Vec::new(),
            bytes: bytes.to_vec(),
            x86: true,
        }
    }

    #[test]
    fn direct_calls_discover_separate_functions_and_do_not_sweep_after_returns() {
        // call 1008; ret; embedded invalid bytes; xor eax,eax; ret; trailing data.
        let image = image(&[0xe8, 3, 0, 0, 0, 0xc3, 0x0f, 0xff, 0x31, 0xc0, 0xc3, 0x90]);
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert_eq!(result.functions.len(), 2);
        assert_eq!(result.functions[0].instructions.len(), 2);
        assert_eq!(result.functions[1].entry, 0x1008);
        assert_eq!(result.functions[1].callers, vec![0x1000]);
        assert_eq!(result.functions[1].instructions.len(), 2);
        assert!(result.functions.iter().all(|function| function.complete));
    }

    #[test]
    fn unconditional_branch_skips_data_and_backwards_loop_has_correct_blocks() {
        let image = image(&[0xeb, 2, 0x0f, 0xff, 0x90, 0x75, 0xfd, 0xc3]);
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        let function = &result.functions[0];
        assert_eq!(
            function
                .instructions
                .iter()
                .map(|instruction| instruction.address)
                .collect::<Vec<_>>(),
            vec![0x1000, 0x1004, 0x1005, 0x1007]
        );
        assert_eq!(function.blocks.len(), 3);
        assert_eq!(function.blocks[0].successors, vec![0x1004]);
        assert_eq!(function.blocks[1].successors, vec![0x1004, 0x1007]);
        assert!(function.complete);
    }

    #[test]
    fn recursive_call_does_not_redecode_or_create_an_extra_function() {
        let image = image(&[0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3]);
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert_eq!(result.functions.len(), 1);
        assert_eq!(result.functions[0].callers, vec![0x1000]);
        assert_eq!(result.functions[0].instructions.len(), 2);
    }

    #[test]
    fn global_budget_applies_across_all_functions() {
        let image = image(&[0xe8, 1, 0, 0, 0, 0xc3, 0xc3]);
        let result = image
            .discover_functions(DiscoveryLimits {
                max_functions: 4,
                max_instructions: 2,
            })
            .unwrap();
        assert!(result.truncated);
        assert_eq!(
            result
                .functions
                .iter()
                .map(|function| function.instructions.len())
                .sum::<usize>(),
            2
        );
        assert!(!result.functions[1].complete);
        let result = image
            .discover_functions(DiscoveryLimits {
                max_functions: 1,
                max_instructions: 10,
            })
            .unwrap();
        assert_eq!(result.functions.len(), 1);
        assert!(result.truncated);
    }

    #[test]
    fn midpoint_target_is_reported_as_conflict() {
        // jne 1003 (inside the mov at 1002); mov eax,1; ret.
        let image = image(&[0x75, 1, 0xb8, 1, 0, 0, 0, 0xc3]);
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert!(!result.functions[0].complete);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("middle"))
        );
        assert!(
            !result.functions[0]
                .instructions
                .iter()
                .any(|instruction| instruction.address == 0x1003)
        );
    }

    #[test]
    fn branches_can_cross_executable_sections_without_decoding_padding() {
        let mut image = image(&[0xe9, 0xfb, 0x0f, 0, 0, 0xc3]); // jmp 2000
        image.sections[0].size = 5;
        image.sections[0].file_size = 5;
        image.sections.push(Section {
            name: ".other".into(),
            address: 0x2000,
            size: 1,
            file_offset: 5,
            file_size: 1,
            executable: true,
        });
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert_eq!(result.functions[0].instructions.len(), 2);
        assert_eq!(result.functions[0].instructions[1].address, 0x2000);
        assert_eq!(result.functions[0].blocks.len(), 2);
        assert!(result.functions[0].complete);
    }

    #[test]
    fn symbol_seeds_are_not_absorbed_and_tail_calls_record_callers() {
        let mut image = image(&[0x90, 0xeb, 0, 0xc3]);
        image.symbols.push(Symbol {
            name: "named".into(),
            address: 0x1003,
            size: 1,
            is_function: true,
        });
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert_eq!(result.functions[0].instructions.len(), 2);
        assert_eq!(result.functions[1].name, "named");
        assert_eq!(result.functions[1].callers, vec![0x1000]);
        assert!(
            result.functions[0]
                .references
                .iter()
                .any(|reference| reference.kind == "tail-call")
        );
    }

    #[test]
    fn late_call_seeds_are_partitioned_after_reachability_finishes() {
        // A branch reaches code that later reveals a recursive direct call.
        // The resulting function must not be absorbed into the initial entry.
        let image = image(&[
            0x75, 6, 0xc3, 0x0f, 0xff, 0x0f, 0xff, 0x90, 0x90, 0xe8, 0xfa, 0xff, 0xff, 0xff, 0xc3,
        ]);
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert_eq!(result.functions.len(), 2);
        assert_eq!(result.functions[0].instructions.len(), 2);
        assert_eq!(result.functions[1].entry, 0x1008);
        assert_eq!(result.functions[1].callers, vec![0x1000, 0x1008]);
        assert!(result.functions.iter().all(|function| function.complete));
    }

    #[test]
    fn function_entry_is_a_block_leader_when_reachable_code_precedes_it() {
        let mut image = image(&[0x90, 0x90, 0x75, 0xfc, 0xc3]);
        image.entry = 0x1002;
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        let function = &result.functions[0];
        assert_eq!(function.entry, 0x1002);
        assert!(function.blocks.iter().any(|block| block.start == 0x1002));
        assert_eq!(function.blocks[0].start, 0x1000);
        assert_eq!(function.blocks[0].end, 0x1002);
    }

    #[test]
    fn unresolved_indirect_jumps_terminate_and_mark_incomplete() {
        let image = image(&[0xff, 0xe0, 0x90, 0xc3]); // jmp rax
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert_eq!(result.functions[0].instructions.len(), 1);
        assert!(!result.functions[0].complete);
        assert!(result.functions[0].blocks[0].successors.is_empty());
    }

    #[test]
    fn shared_tail_is_not_duplicated_and_both_functions_are_incomplete() {
        let mut image = image(&[0xeb, 4, 0xeb, 2, 0x0f, 0xff, 0xc3]);
        image.symbols.push(Symbol {
            name: "other".into(),
            address: 0x1002,
            size: 2,
            is_function: true,
        });
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert_eq!(
            result
                .functions
                .iter()
                .map(|function| function.instructions.len())
                .sum::<usize>(),
            3
        );
        assert!(result.functions.iter().all(|function| !function.complete));
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("share code"))
        );
    }

    #[test]
    fn unsupported_architecture_invalid_limits_and_unmapped_entry() {
        let mut image = image(&[0xc3]);
        image.x86 = false;
        assert!(matches!(
            image.discover_functions(DiscoveryLimits::default()),
            Err(Error::UnsupportedArchitecture(_))
        ));
        image.x86 = true;
        assert!(
            image
                .discover_functions(DiscoveryLimits {
                    max_functions: 0,
                    max_instructions: 10
                })
                .is_err()
        );
        image.entry = 0;
        let result = image
            .discover_functions(DiscoveryLimits::default())
            .unwrap();
        assert_eq!(result.functions[0].entry, 0x1000);
        assert!(!result.warnings.is_empty());
    }
}
