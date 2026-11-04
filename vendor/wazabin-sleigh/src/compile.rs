//! Compilation facade for building runtime SLEIGH specifications.

use std::collections::HashMap;

use crate::{
    builder::SpecBuilder,
    diagnostic::{CompileError, Diagnostic, DiagnosticCode},
    resolve::resolve,
    runtime::{CompiledSpec, SpecFingerprint},
    source::{FileId, PreprocessOptions, SourceDb},
    spec::Spec,
    syntax::parse_to_ast,
};

/// Options that control SLEIGH compilation.
#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    /// Reserved for the source layer that will handle preprocessing in a later slice.
    pub defines: HashMap<String, String>,
}

/// Compiler for SLEIGH source files stored in a [`SourceDb`].
pub struct Compiler<'src> {
    sources: &'src mut SourceDb,
    options: CompileOptions,
}

impl<'src> Compiler<'src> {
    /// Creates a compiler with default options.
    pub fn new(sources: &'src mut SourceDb) -> Self {
        Self {
            sources,
            options: CompileOptions::default(),
        }
    }

    /// Replaces the compile options.
    pub fn with_options(mut self, options: CompileOptions) -> Self {
        self.options = options;
        self
    }

    /// Compiles `root` into a [`CompiledSpec`].
    ///
    /// # Errors
    ///
    /// Returns a [`CompileError`] carrying one or more [`Diagnostic`]s if the
    /// specification cannot be preprocessed, parsed, resolved or concretized —
    /// including for SLEIGH this crate parses but does not yet compile, such as
    /// a right-aligned pattern or a comparison between two fields.
    ///
    /// [`Diagnostic`]: crate::Diagnostic
    ///
    /// ```
    /// use sleigh::{Compiler, SourceDb};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sources = SourceDb::new();
    /// let root = sources.add_file(
    ///     "tiny.slaspec",
    ///     "define endian=little;
    ///      define space ram type=ram_space size=4 default;
    ///      define space register type=register_space size=4;
    ///      define register offset=0 size=4 [ r0 ];
    ///      define token instr(8) op=(0,7);
    ///      :nop is op=0 { }",
    /// );
    ///
    /// let spec = Compiler::new(&mut sources).compile(root)?;
    /// assert!(spec.register("r0").is_some());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Compiling is the expensive step — hundreds of milliseconds for a real
    /// processor — so do it once and keep the [`CompiledSpec`].
    pub fn compile(self, root: FileId) -> Result<CompiledSpec, CompileError> {
        self.compile_inner(root, false).map(|(spec, _)| spec)
    }

    /// Compiles `root` into a [`CompiledSpec`], additionally running the
    /// crate's lint pass over the resolved specification.
    ///
    /// The lints look for issues `compile` itself does not treat as errors —
    /// things like unused fields or context writes that are never read —
    /// using the same [`SpecBuilder`] and parsed AST that `compile` builds
    /// internally but does not otherwise expose. Use this instead of
    /// `compile` when you want that extra diagnostic pass; the cost is one
    /// additional traversal of the specification's constructors.
    ///
    /// # Errors
    ///
    /// Same as [`Compiler::compile`]: a [`CompileError`] if the specification
    /// cannot be preprocessed, parsed, resolved or concretized. Lints only
    /// run once concretization succeeds, so a compile failure never carries
    /// lint diagnostics.
    pub fn compile_with_lints(
        self,
        root: FileId,
    ) -> Result<(CompiledSpec, Vec<Diagnostic>), CompileError> {
        self.compile_inner(root, true)
    }

    /// Shared pipeline behind [`compile`](Self::compile) and
    /// [`compile_with_lints`](Self::compile_with_lints).
    fn compile_inner(
        self,
        root: FileId,
        lint: bool,
    ) -> Result<(CompiledSpec, Vec<Diagnostic>), CompileError> {
        let options = PreprocessOptions {
            defines: self.options.defines,
        };

        let (file, prepared) =
            parse_to_ast(self.sources, root, &options).map_err(CompileError::new)?;

        // Warnings are `analyze`'s business; compiling wants the specification.
        let (mut builder, _warnings): (SpecBuilder, _) =
            resolve(&file).map_err(CompileError::new)?;

        builder.concretize().map_err(|e| CompileError::one(*e))?;

        let lints = if lint {
            crate::lint::run_lints(&builder, &file)
        } else {
            Vec::new()
        };

        if let Err(error) = builder.finalize_pcode() {
            let location = error
                .span
                .and_then(|(s, e)| self.sources.try_map_preprocessed_bytes(prepared, s, e))
                .unwrap_or_else(|| crate::source::Span::file_level(root));
            let diagnostic =
                Diagnostic::error(DiagnosticCode::Compile, format!("{error}"), location);
            return Err(CompileError::one(diagnostic));
        }

        // The preprocessed text is the whole input the compiler saw, so its
        // digest identifies the compilation; see `SpecFingerprint`.
        let fingerprint = SpecFingerprint::of_compilation(
            self.sources
                .prepared_text(prepared)
                .expect("the source just preprocessed is in the database"),
        );
        let spec = Spec::from_builder(builder);
        Ok((CompiledSpec::from_spec(spec, fingerprint), lints))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: &str = "define endian=little;
        define space ram type=ram_space size=4 default;
        define space register type=register_space size=4;
        define register offset=0 size=4 [ r0 r1 ];
        define token instr(8) op=(0,7);
        :nop is op=0 { }
        :inc r0 is op=1 { r0 = r0 + 1; }";

    fn compile(text: &str, defines: &[(&str, &str)]) -> CompiledSpec {
        let mut sources = SourceDb::new();
        let root = sources.add_file("tiny.slaspec", text);
        Compiler::new(&mut sources)
            .with_options(CompileOptions {
                defines: defines
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            })
            .compile(root)
            .expect("the specification compiles")
    }

    #[test]
    fn the_fingerprint_is_a_function_of_the_source() {
        let first = compile(TINY, &[]);
        let again = compile(TINY, &[]);
        assert_eq!(first.fingerprint(), again.fingerprint());

        // The same registers and spaces, one constructor's semantics apart:
        // structurally alike, not the same specification.
        let alike = compile(&TINY.replace("r0 = r0 + 1", "r0 = r0 + 2"), &[]);
        assert_ne!(first.fingerprint(), alike.fingerprint());
    }

    #[test]
    fn defines_reach_the_fingerprint_through_the_preprocessed_text() {
        let text = format!("{TINY}\n@ifdef WIDE\n:wide r1 is op=2 {{ r1 = 0; }}\n@endif\n");
        let narrow = compile(&text, &[]);
        let wide = compile(&text, &[("WIDE", "1")]);
        assert_ne!(narrow.fingerprint(), wide.fingerprint());
        // An inactive conditional leaves the text the parser sees unchanged,
        // so the fingerprint is the base specification's.
        assert_eq!(narrow.fingerprint(), compile(TINY, &[]).fingerprint());
    }
}
