//! Native compiler-location inspection. This compiles the selected SLEIGH
//! source for its physical register layout; it does not allocate arguments.
use std::{ffi::OsString, io::Write, path::PathBuf, sync::Arc};

use ghidra_abi::{AbiLimits, CompilerResources, CompilerStorage, RegisterDefinition, RegisterFile};
use serde::Serialize;

const MAX_OUTPUT: usize = 64 * 1024 * 1024;
const OUTPUT_LIMIT: &str = "Compiler storage JSON exceeds 64 MiB";

pub(crate) struct Arguments {
    root: PathBuf,
    language: String,
    compiler: String,
    resources: bool,
}

impl Arguments {
    pub(crate) fn parse(mut arguments: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let (Some(root), Some(language), Some(compiler)) =
            (arguments.next(), arguments.next(), arguments.next())
        else {
            return Err("--compiler-storage requires ROOT LANGUAGE_ID COMPILER_ID".into());
        };
        let resources = match arguments.next() {
            None => false,
            Some(flag) if flag == "--resources" && arguments.next().is_none() => true,
            _ => {
                return Err(
                    "--compiler-storage accepts ROOT LANGUAGE_ID COMPILER_ID [--resources]".into(),
                );
            }
        };
        let id = |text: OsString| -> Result<String, String> {
            text.into_string()
                .ok()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .ok_or_else(|| "Language and compiler IDs must be UTF-8 and 1..1024 bytes".into())
        };
        Ok(Self {
            root: root.into(),
            language: id(language)?,
            compiler: id(compiler)?,
            resources,
        })
    }
}

#[derive(Serialize)]
struct Policies {
    storage_locations_resolved: bool,
    arguments_allocated: bool,
    prototype_rules_executed: bool,
    injections_compiled: bool,
    overlap_resource_groups_computed: bool,
}

const POLICIES: Policies = Policies {
    storage_locations_resolved: true,
    arguments_allocated: false,
    prototype_rules_executed: false,
    injections_compiled: false,
    overlap_resource_groups_computed: false,
};

#[derive(Serialize)]
struct Report<'a> {
    schema: &'static str,
    schema_version: u32,
    language_id: &'a str,
    compiler_id: &'a str,
    policies: Policies,
    declarations_fully_modeled: bool,
    specification: &'a ghidra_languages::CompilerSpec,
    registers: &'a RegisterFile,
    resolved_storage: &'a CompilerStorage,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<&'a CompilerResources>,
}

fn encode(
    language: &str,
    compiler: &str,
    storage: &CompilerStorage,
    resources: Option<&CompilerResources>,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    if resources.is_some_and(|plan| !std::ptr::eq(plan.storage().as_ref(), storage)) {
        return Err("Resource plan belongs to a different compiler-storage snapshot".into());
    }
    let specification = storage.source();
    let report = Report {
        schema: "ghidra-rs.compiler-storage",
        schema_version: 1,
        language_id: language,
        compiler_id: compiler,
        policies: Policies {
            overlap_resource_groups_computed: resources.is_some(),
            ..POLICIES
        },
        declarations_fully_modeled: specification.is_fully_modeled(),
        specification,
        registers: storage.register_file(),
        resolved_storage: storage,
        resources,
    };
    let mut output = crate::analysis_cli::LimitedOutput::new(maximum, OUTPUT_LIMIT);
    serde_json::to_writer_pretty(&mut output, &report).map_err(|e| e.to_string())?;
    output.write_all(b"\n").map_err(|e| e.to_string())?;
    Ok(output.into_bytes())
}

pub(crate) fn run(arguments: Arguments) -> Result<(), String> {
    let catalog =
        ghidra_languages::Catalog::discover(&arguments.root).map_err(|e| e.to_string())?;
    let definition = catalog
        .by_id(&arguments.language)
        .ok_or_else(|| format!("Unknown language ID: {}", arguments.language))?;
    // Check compiler selection before the more expensive source compilation.
    let specification = Arc::new(
        definition
            .load_compiler_spec(&arguments.compiler)
            .map_err(|e| e.to_string())?,
    );
    let language = ghidra_sleigh::SleighLanguage::from_language(definition, &Default::default())
        .map_err(|e| e.to_string())?;
    let registers = language
        .registers()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|r| RegisterDefinition {
            name: r.name,
            space: r.space,
            offset: r.offset,
            size: r.size,
        })
        .collect();
    let limits = AbiLimits::default();
    let file = Arc::new(
        RegisterFile::new(
            language.spaces().to_vec(),
            language.code_space(),
            registers,
            limits,
        )
        .map_err(|e| e.to_string())?,
    );
    drop(language);
    let storage =
        Arc::new(CompilerStorage::new(specification, file, limits).map_err(|e| e.to_string())?);
    let resources = arguments
        .resources
        .then(|| CompilerResources::new(storage.clone(), Default::default()))
        .transpose()
        .map_err(|e| e.to_string())?;
    let bytes = encode(
        &arguments.language,
        &arguments.compiler,
        &storage,
        resources.as_ref(),
        MAX_OUTPUT,
    )?;
    // Nothing reaches stdout until both resolution and bounded serialization succeed.
    std::io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};

    fn fixture() -> CompilerStorage {
        let spec = ghidra_languages::CompilerSpec::parse_str(
            r#"<compiler_spec><stackpointer register="SP" space="ram"/>
              <default_proto><prototype name="p" extrapop="0" stackshift="0">
                <input><pentry minsize="1" maxsize="500" align="8">
                  <addr space="stack" offset="-8"/></pentry></input>
                <output><pentry minsize="1" maxsize="8">
                  <register name="R0"/></pentry></output>
              </prototype></default_proto></compiler_spec>"#,
            None,
            &Default::default(),
        )
        .unwrap();
        assert!(spec.is_fully_modeled(), "{:?}", spec.diagnostics);
        let spaces = [
            (1, "ram", SpaceKind::Ram),
            (2, "register", SpaceKind::Register),
        ]
        .into_iter()
        .map(|(id, name, kind)| AddressSpace {
            id: SpaceId(id),
            name: name.into(),
            kind,
            address_size: 8,
            word_size: 1,
            endianness: Endianness::Little,
        })
        .collect();
        let registers = [("R0", 0), ("SP", 8)]
            .into_iter()
            .map(|(name, offset)| RegisterDefinition {
                name: name.into(),
                space: SpaceId(2),
                offset,
                size: 8,
            })
            .collect();
        let file = RegisterFile::new(spaces, SpaceId(1), registers, Default::default()).unwrap();
        CompilerStorage::new(Arc::new(spec), Arc::new(file), Default::default()).unwrap()
    }

    #[test]
    fn report_resolves_locations_without_claiming_argument_allocation() {
        let storage = fixture();
        let bytes = encode("example", "test", &storage, None, MAX_OUTPUT).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["schema"], "ghidra-rs.compiler-storage");
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["policies"]["arguments_allocated"], false);
        assert_eq!(report["policies"]["storage_locations_resolved"], true);
        assert_eq!(report["declarations_fully_modeled"], true);
        let binding = storage
            .binding(ghidra_abi::BindingSite::Input { model: 0, entry: 0 })
            .unwrap();
        assert_eq!(binding.storage.size(), None);
        let ghidra_abi::ResolvedStorage::Single(range) = &binding.storage else {
            panic!()
        };
        assert_eq!(range.address.signed_stack_offset(), Some(-8));
        assert_eq!(binding.parameter.as_ref().unwrap().max_size, 500);
        assert_eq!(
            report["registers"]["registers"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn serialization_caps_include_the_final_newline_at_exact_boundaries() {
        let storage = fixture();
        let exact = encode("example", "test", &storage, None, MAX_OUTPUT).unwrap();
        assert_eq!(
            encode("example", "test", &storage, None, exact.len()).unwrap(),
            exact
        );
        assert!(
            encode("example", "test", &storage, None, exact.len() - 1)
                .unwrap_err()
                .contains(OUTPUT_LIMIT)
        );
        assert!(encode("example", "test", &storage, None, 0).is_err());
    }

    #[test]
    fn resource_report_is_opt_in_snapshot_checked_and_bounded() {
        let storage = Arc::new(fixture());
        let resources = CompilerResources::new(storage.clone(), Default::default()).unwrap();
        let plain = encode("example", "test", &storage, None, MAX_OUTPUT).unwrap();
        let with = encode("example", "test", &storage, Some(&resources), MAX_OUTPUT).unwrap();
        let mut report: serde_json::Value = serde_json::from_slice(&with).unwrap();
        assert_eq!(report["policies"]["overlap_resource_groups_computed"], true);
        assert_eq!(report["resources"]["models"][0]["input"]["group_count"], 1);
        assert_eq!(
            report["resources"]["models"][0]["input"]["entries"][0]["slot_capacity"],
            62
        );
        report.as_object_mut().unwrap().remove("resources");
        report["policies"]["overlap_resource_groups_computed"] = false.into();
        assert_eq!(
            report,
            serde_json::from_slice::<serde_json::Value>(&plain).unwrap()
        );
        assert_eq!(
            encode("example", "test", &storage, Some(&resources), with.len()).unwrap(),
            with
        );
        assert!(
            encode(
                "example",
                "test",
                &storage,
                Some(&resources),
                with.len() - 1
            )
            .is_err()
        );
        assert!(
            encode("example", "test", &fixture(), Some(&resources), MAX_OUTPUT)
                .unwrap_err()
                .contains("different compiler-storage snapshot")
        );
    }

    #[test]
    fn argument_validation_precedes_catalog_io_and_compilation() {
        for arguments in [
            vec![],
            vec!["."],
            vec![".", "lang"],
            vec![".", "lang", "compiler", "extra"],
            vec![".", "lang", "compiler", "--resources", "--resources"],
            vec![".", "", "compiler"],
        ] {
            assert!(Arguments::parse(arguments.into_iter().map(OsString::from)).is_err());
        }
        assert!(
            Arguments::parse([".", "lang", "compiler"].into_iter().map(OsString::from)).is_ok()
        );
        assert!(
            Arguments::parse(
                [".", "lang", "compiler", "--resources"]
                    .into_iter()
                    .map(OsString::from)
            )
            .unwrap()
            .resources
        );
        assert!(
            Arguments::parse(
                [
                    OsString::from("."),
                    OsString::from("a".repeat(1025)),
                    OsString::from("compiler")
                ]
                .into_iter()
            )
            .is_err()
        );
    }
}
