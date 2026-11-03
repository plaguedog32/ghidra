/// A tiny synthetic PE64 image. It is parsed and decoded like a real import.
/// No imported code is ever executed.
pub fn pe64() -> Vec<u8> {
    let mut bytes = vec![0; 0x400];
    bytes[..2].copy_from_slice(b"MZ");
    put32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, 1);
    put16(&mut bytes, 0x94, 0xf0);
    put16(&mut bytes, 0x96, 0x22);
    let optional = 0x98;
    put16(&mut bytes, optional, 0x20b);
    put32(&mut bytes, optional + 4, 0x200);
    put32(&mut bytes, optional + 16, 0x1000);
    put32(&mut bytes, optional + 20, 0x1000);
    bytes[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    put32(&mut bytes, optional + 32, 0x1000);
    put32(&mut bytes, optional + 36, 0x200);
    put16(&mut bytes, optional + 40, 6);
    put16(&mut bytes, optional + 48, 6);
    put32(&mut bytes, optional + 56, 0x2000);
    put32(&mut bytes, optional + 60, 0x200);
    put16(&mut bytes, optional + 68, 3);
    put32(&mut bytes, optional + 108, 16);
    let section = optional + 0xf0;
    bytes[section..section + 5].copy_from_slice(b".text");
    put32(&mut bytes, section + 8, 0x40);
    put32(&mut bytes, section + 12, 0x1000);
    put32(&mut bytes, section + 16, 0x200);
    put32(&mut bytes, section + 20, 0x200);
    put32(&mut bytes, section + 36, 0x6000_0020);
    let code: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, // prologue
        0xb9, 0x03, 0x00, 0x00, 0x00, // mov ecx,3
        0xe8, 0x0c, 0x00, 0x00, 0x00, // call 0x14000101e
        0x48, 0x83, 0xc4, 0x20, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xc0, 0x83,
        0xc0, 0x01, 0xff, 0xc9, 0x75, 0xf9, 0xc3,
    ];
    bytes[0x200..0x200 + code.len()].copy_from_slice(code);
    let text = b"Ghidra Rust - synthetic desktop analysis sample\0";
    bytes[0x300..0x300 + text.len()].copy_from_slice(text);
    bytes
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    #[test]
    fn demo_uses_the_real_import_and_analysis_path() {
        let loaded = crate::report::load_bytes("sample".into(), super::pe64()).unwrap();
        assert_eq!(loaded.image.entry, 0x1_4000_1000);
        let analysis = loaded.analysis.as_ref().unwrap();
        assert!(analysis.references.iter().any(|r| r.to == 0x1_4000_101e));
        assert!(analysis.blocks.len() >= 3);
        let report: serde_json::Value =
            serde_json::from_str(&crate::report::json(&loaded).unwrap()).unwrap();
        assert_eq!(report["schema_version"], 1);
        assert!(
            !report["analysis"]["instructions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}
