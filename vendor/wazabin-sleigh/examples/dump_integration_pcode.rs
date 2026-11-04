use std::path::{Path, PathBuf};

use sleigh::{CompiledSpec, Compiler, ContextBytes, Decoder, PcodeAst, SourceDb};

fn spec_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn compile_spec(path: &str) -> CompiledSpec {
    let sources = Box::leak(Box::new(SourceDb::new()));
    let root = sources
        .add_file_from_path(spec_path(path))
        .expect("SLEIGH spec should load from fixture tree");

    Compiler::new(sources)
        .compile(root)
        .expect("SLEIGH spec should compile")
}

fn set_context(spec: &CompiledSpec, context: &mut ContextBytes, name: &str, value: u64) {
    let field = spec.field(name).expect("context field should exist");
    spec.set_context_field(context, field.id, value)
        .expect("context field value should be valid");
}

fn x86_context(spec: &CompiledSpec) -> ContextBytes {
    let mut context = spec.new_context();
    set_context(spec, &mut context, "addrsize", 1);
    set_context(spec, &mut context, "opsize", 1);
    context
}

fn x64_context(spec: &CompiledSpec) -> ContextBytes {
    let mut context = spec.new_context();
    set_context(spec, &mut context, "longMode", 1);
    set_context(spec, &mut context, "addrsize", 2);
    set_context(spec, &mut context, "opsize", 1);
    context
}

fn dump_case(spec: &CompiledSpec, context: &ContextBytes, name: &str, bytes: &[u8]) {
    let instruction = Decoder::new(spec)
        .decode_one(0x1000, bytes, context)
        .unwrap_or_else(|err| panic!("{name}: decode failed: {err}"));

    let ast = match instruction.pcode_ast() {
        Ok(ast) => ast,
        Err(err) if err.to_string().contains("emitted no p-code") => PcodeAst::default(),
        Err(err) => panic!("{name}: emit failed: {err}"),
    };

    println!("=== {name} ===");
    println!("display: {instruction}");
    println!("pcode:");
    print!("{}", ast.pretty_print(spec));
    println!("\n");
}

fn main() {
    let x86 = compile_spec("../precompile/open_sleigh/src/x86/x86.slaspec");
    let x86_context = x86_context(&x86);

    for (name, bytes) in [
        ("x86_push_ebp", b"\x55".as_slice()),
        ("x86_mov_eax_ptr_ecx", b"\x8b\x01".as_slice()),
        ("x86_mov_eax_imm32", b"\xb8\x78\x56\x34\x12".as_slice()),
        ("x86_ret", b"\xc3".as_slice()),
        ("x86_add_eax_ebx", b"\x01\xd8".as_slice()),
    ] {
        dump_case(&x86, &x86_context, name, bytes);
    }

    let x64 = compile_spec("../precompile/open_sleigh/src/x86/x86-64.slaspec");
    let x64_context = x64_context(&x64);

    for (name, bytes) in [
        ("x64_mov_dword_rbp_minus4_edi", b"\x89\x7d\xfc".as_slice()),
        ("x64_xor_al_imm8", b"\x34\x12".as_slice()),
        ("x64_mov_eax_imm32", b"\xb8\x78\x56\x34\x12".as_slice()),
        ("x64_mov_rcx_ptr_rdx", b"\x48\x8b\x0a".as_slice()),
        ("x64_mov_ptr_r8_disp_r9", b"\x4d\x89\x48\x10".as_slice()),
        (
            "x64_mov_r10_imm64",
            b"\x49\xba\x88\x77\x66\x55\x44\x33\x22\x11".as_slice(),
        ),
        (
            "x64_lea_r11_rip_relative",
            b"\x4c\x8d\x1d\x20\x00\x00\x00".as_slice(),
        ),
        ("x64_add_rax_rcx", b"\x48\x01\xc8".as_slice()),
        ("x64_sub_rdx_imm8", b"\x48\x83\xea\x05".as_slice()),
        ("x64_imul_rsi_rdi", b"\x48\x0f\xaf\xf7".as_slice()),
        ("x64_xor_r8_r8", b"\x4d\x31\xc0".as_slice()),
        ("x64_cmp_r9_r10", b"\x4d\x39\xd1".as_slice()),
        ("x64_cdqe", b"\x48\x98".as_slice()),
        ("x64_cqo", b"\x48\x99".as_slice()),
        ("x64_shl_rax_imm", b"\x48\xc1\xe0\x03".as_slice()),
        ("x64_sar_rcx_cl", b"\x48\xd3\xf9".as_slice()),
        ("x64_rol_rdx_one", b"\x48\xd1\xc2".as_slice()),
        ("x64_push_rbx", b"\x53".as_slice()),
        ("x64_pop_r12", b"\x41\x5c".as_slice()),
        ("x64_pushfq", b"\x9c".as_slice()),
        ("x64_popfq", b"\x9d".as_slice()),
        ("x64_call_rax", b"\xff\xd0".as_slice()),
        ("x64_jmp_rel32", b"\xe9\x00\x00\x00\x00".as_slice()),
        ("x64_ret", b"\xc3".as_slice()),
        ("x64_mov_rax_indexed", b"\x48\x8b\x44\x8b\x20".as_slice()),
        (
            "x64_mov_byte_ptr_addr",
            b"\xc6\x05\x00\x01\x00\x00\x7f".as_slice(),
        ),
        ("x64_movaps_xmm0_xmm1", b"\x0f\x28\xc1".as_slice()),
        ("x64_movsd_xmm2_ptr_rax", b"\xf2\x0f\x10\x10".as_slice()),
        ("x64_addss_xmm3_xmm4", b"\xf3\x0f\x58\xdc".as_slice()),
        ("x64_movsb_rep", b"\xf3\xa4".as_slice()),
        ("x64_cmpsb_repe", b"\xf3\xa6".as_slice()),
        ("x64_scasb_repne", b"\xf2\xae".as_slice()),
        ("x64_stosq_rep", b"\xf3\x48\xab".as_slice()),
        ("x64_lodsb_rep", b"\xf3\xac".as_slice()),
        ("x64_add_lock", b"\xf0\x48\x83\x00\x01".as_slice()),
        ("x64_xchg_lock", b"\xf0\x48\x87\x0b".as_slice()),
        ("x64_cmpxchg_lock", b"\xf0\x48\x0f\xb1\x37".as_slice()),
        ("x64_dec_ebx", b"\xff\xcb".as_slice()),
        ("x64_mov_ebx_imm32", b"\xbb\x78\x56\x34\x12".as_slice()),
        ("x64_mov_ax_bx", b"\x66\x89\xd8".as_slice()),
        ("x64_add_word_ptr", b"\x66\x83\x00\x05".as_slice()),
        ("x64_push_imm32", b"\x68\x34\x12\x00\x00".as_slice()),
        ("x64_imul_ax_cx", b"\x66\x0f\xaf\xc1".as_slice()),
        ("x64_mov_eax_ptr_ecx_addr32", b"\x67\x8b\x01".as_slice()),
        ("x64_mov_dword_ptr_indexed", b"\x67\x89\x04\xb2".as_slice()),
        ("x64_lea_eax_offset", b"\x67\x8d\x43\x04".as_slice()),
        (
            "x64_mov_fs",
            b"\x64\x48\x8b\x04\x25\x00\x00\x00\x00".as_slice(),
        ),
        (
            "x64_mov_gs",
            b"\x65\x48\x8b\x1c\x25\x30\x00\x00\x00".as_slice(),
        ),
        ("x64_mov_cs", b"\x2e\x8b\x05\x10\x00\x00\x00".as_slice()),
        ("x64_mov_rdx_rsp", b"\x48\x8b\x14\x24".as_slice()),
        ("x64_mov_r8_r9", b"\x4d\x89\xc8".as_slice()),
        ("x64_add_r10_r11", b"\x4d\x01\xda".as_slice()),
        ("x64_mov_r12_r13_ptr", b"\x4d\x8b\x65\x00".as_slice()),
        ("x64_lea_r14_r15_offset", b"\x4d\x8d\x77\x08".as_slice()),
        ("x64_movupd_xmm0_xmm1", b"\x66\x0f\x10\xc1".as_slice()),
        ("x64_addsd_xmm1_xmm2", b"\xf2\x0f\x58\xca".as_slice()),
        ("x64_movsd_xmm2_xmm3", b"\xf2\x0f\x10\xd3".as_slice()),
        ("x64_movss_xmm4_xmm5", b"\xf3\x0f\x10\xe5".as_slice()),
        ("x64_addpd_xmm6_xmm7", b"\x66\x0f\x58\xf7".as_slice()),
    ] {
        dump_case(&x64, &x64_context, name, bytes);
    }
}
