//! Lexical token classification of SLEIGH source, for highlighting.
//!
//! The compiler's parser is scannerless and only runs on text that parses.
//! Highlighting has the opposite needs: it runs on every keystroke, most of
//! them mid-edit, and must never hide the text under a wrong colour. So this
//! module is a separate, tolerant lexer with two rules:
//!
//! - **No token is ever altered.** [`tokens`] returns byte ranges into the
//!   caller's own text and nothing else, so a renderer that wraps ranges in
//!   spans is showing the specification's own characters by construction.
//! - **Unrecognised text is left unclassified.** Bytes that no token covers
//!   are meant to be rendered plain. Under-highlighting is invisible;
//!   mis-highlighting is a false claim about the code.
//!
//! The same character means different things in different parts of a
//! constructor: `&` conjoins constraints in a bit pattern and is bitwise-and
//! in a semantic body, and the display section is literal text where `[`,
//! `,` and `+` are punctuation to print. So the lexer tracks the
//! [`Region`] it is in and classifies accordingly. The region boundaries are
//! found lexically (`:`, `is`, `[`, `{`, `}`) rather than from the AST, which
//! is what makes the lexer usable on text that does not parse.
//!
//! Keywords are the grammar's own: a test checks [`KEYWORDS`] against every
//! `keyword_*` rule in `grammar/sleigh_raw.pest`.
//!
//! ```
//! use sleigh::highlight::{TokenKind, tokens};
//!
//! let text = ":NOP is op=0 { }";
//! let kinds: Vec<_> = tokens(text).into_iter().map(|t| (&text[t.range()], t.kind)).collect();
//! assert_eq!(kinds[0], (":", TokenKind::Table));
//! assert_eq!(kinds[1], ("NOP ", TokenKind::Display));
//! assert_eq!(kinds[2], ("is", TokenKind::Keyword));
//! assert_eq!(kinds[3], ("=", TokenKind::Operator));
//! ```

use std::ops::Range;

/// Every keyword the grammar reserves, in the order the grammar lists them.
pub const KEYWORDS: &[&str] = &[
    "alignment",
    "attach",
    "big",
    "bitrange",
    "build",
    "call",
    "context",
    "dec",
    "default",
    "delayslot",
    "define",
    "endian",
    "export",
    "globalset",
    "goto",
    "hex",
    "if",
    "is",
    "little",
    "local",
    "macro",
    "names",
    "noflow",
    "offset",
    "pcodeop",
    "ram_space",
    "register_space",
    "return",
    "rom_space",
    "signed",
    "size",
    "space",
    "token",
    "type",
    "unimpl",
    "values",
    "variables",
    "with",
    "wordsize",
];

/// What a run of source text is, lexically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// `# ...` to end of line.
    Comment,
    /// `"..."`.
    String,
    /// Decimal, hex, or binary literal.
    Number,
    /// One of [`KEYWORDS`].
    Keyword,
    /// A preprocessor directive such as `@define` or `@ifdef`.
    Directive,
    /// A preprocessor expansion `$(NAME)`, or the name of a macro being
    /// called or defined.
    Macro,
    /// A jump label `<name>` in a semantic body.
    Label,
    /// The name of the table a constructor defines, or `instruction` when
    /// the constructor starts with a bare `:`.
    Table,
    /// A constructor's display section: literal text between the table name
    /// and `is`.
    Display,
    /// In a bit pattern, what joins constraints: `&`, `|`, `;` and `...`.
    Structure,
    /// Everything else punctuation: comparison and arithmetic operators,
    /// assignment, `$and`/`$or`/`$xor`.
    Operator,
}

/// One classified run of source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Byte offset of the first byte.
    pub start: usize,
    /// Byte offset one past the last byte.
    pub end: usize,
    /// What the run is.
    pub kind: TokenKind,
}

impl Token {
    /// The token's byte range in the text it was lexed from.
    pub fn range(&self) -> Range<usize> {
        self.start..self.end
    }
}

/// Which part of a specification the lexer is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Region {
    /// Definitions, `attach`, `macro` headers, `with` headers: everything
    /// outside a constructor.
    Preamble,
    /// Between a constructor's `:` and its `is`.
    Display,
    /// Between `is` and the action block or semantic body.
    Pattern,
    /// A `[ ... ]` disassembly-action block.
    Action,
    /// A braced semantic body, with its nesting depth.
    Body(u32),
}

/// Classifies `text` into tokens, in source order, without overlap.
///
/// Bytes not covered by any token are unclassified and should be rendered
/// plain. Works on any input, including text that does not parse.
pub fn tokens(text: &str) -> Vec<Token> {
    Lexer {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        region: Region::Preamble,
        statement_is_with: false,
        out: Vec::new(),
    }
    .run()
}

struct Lexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    region: Region,
    /// Whether the current preamble statement began with `with`, so its `{`
    /// opens a block of constructors rather than a semantic body.
    statement_is_with: bool,
    out: Vec<Token>,
}

impl Lexer<'_> {
    fn run(mut self) -> Vec<Token> {
        while self.pos < self.bytes.len() {
            match self.region {
                Region::Preamble => self.preamble(),
                Region::Display => self.display(),
                Region::Pattern => self.pattern(),
                Region::Action => self.action(),
                Region::Body(_) => self.body(),
            }
        }
        self.out
    }

    // ── regions ────────────────────────────────────────────────────────

    fn preamble(&mut self) {
        let c = self.bytes[self.pos];
        if self.common(c) {
            return;
        }
        match c {
            b'@' => self.directive(),
            b':' => {
                // Bare `:` starts a constructor in the root table, or the
                // constraint of a `with` block.
                self.emit(1, TokenKind::Table);
                self.region = self.after_table_colon();
            }
            b'{' => {
                self.pos += 1;
                if self.statement_is_with {
                    self.statement_is_with = false;
                } else {
                    self.region = Region::Body(1);
                }
            }
            b'}' => self.pos += 1,
            _ if is_ident_start(c) => {
                let word = self.ident();
                let after = self.skip_spaces_from(self.pos + word);
                if self.bytes.get(after) == Some(&b':')
                    && !is_keyword(&self.text[self.pos..self.pos + word])
                {
                    // `table: display is ...`
                    self.emit(word, TokenKind::Table);
                    self.pos = after;
                    self.emit(1, TokenKind::Table);
                    self.region = self.after_table_colon();
                } else {
                    self.word(word, WordContext::Preamble);
                }
            }
            _ => self.operator(),
        }
    }

    fn display(&mut self) {
        // Everything up to the `is` keyword is literal display text. Newlines
        // split the run so a line-oriented renderer gets one token per line.
        let start = self.pos;
        while self.pos < self.bytes.len() {
            let c = self.bytes[self.pos];
            if c == b'\n' {
                self.pos += 1;
                break;
            }
            if c == b'#' {
                break;
            }
            if c == b'i' && self.at_keyword("is") {
                break;
            }
            self.pos += 1;
        }
        if self.pos > start {
            self.push(start, self.pos, TokenKind::Display);
        }
        if self.at(b'#') {
            self.comment();
        } else if self.at_keyword("is") {
            self.emit(2, TokenKind::Keyword);
            self.region = Region::Pattern;
        }
    }

    fn pattern(&mut self) {
        let c = self.bytes[self.pos];
        if self.common(c) {
            return;
        }
        match c {
            b'&' | b'|' | b';' => self.emit(1, TokenKind::Structure),
            b'.' if self.starts_with("...") => self.emit(3, TokenKind::Structure),
            b'[' => {
                self.pos += 1;
                self.region = Region::Action;
            }
            b'{' => {
                self.pos += 1;
                self.region = if self.statement_is_with {
                    Region::Preamble
                } else {
                    Region::Body(1)
                };
                self.statement_is_with = false;
            }
            b'}' => {
                // A stray close brace: the constructor is over.
                self.pos += 1;
                self.region = Region::Preamble;
            }
            _ if is_ident_start(c) => {
                let word = self.ident();
                let is_unimpl = &self.text[self.pos..self.pos + word] == "unimpl";
                self.word(word, WordContext::Pattern);
                if is_unimpl {
                    self.region = Region::Preamble;
                }
            }
            _ => self.operator(),
        }
    }

    fn action(&mut self) {
        let c = self.bytes[self.pos];
        if self.common(c) {
            return;
        }
        match c {
            b']' => {
                self.pos += 1;
                self.region = Region::Pattern;
            }
            b'{' => {
                // Unterminated action block; the body is more likely.
                self.pos += 1;
                self.region = Region::Body(1);
            }
            _ if is_ident_start(c) => {
                let word = self.ident();
                self.word(word, WordContext::Body);
            }
            _ => self.operator(),
        }
    }

    fn body(&mut self) {
        let Region::Body(depth) = self.region else {
            unreachable!()
        };
        let c = self.bytes[self.pos];
        if self.common(c) {
            return;
        }
        match c {
            b'<' if self.label_len() > 0 => {
                let len = self.label_len();
                self.emit(len, TokenKind::Label);
            }
            b'{' => {
                self.pos += 1;
                self.region = Region::Body(depth + 1);
            }
            b'}' => {
                self.pos += 1;
                self.region = if depth > 1 {
                    Region::Body(depth - 1)
                } else {
                    Region::Preamble
                };
            }
            _ if is_ident_start(c) => {
                let word = self.ident();
                self.word(word, WordContext::Body);
            }
            _ => self.operator(),
        }
    }

    /// A `with` header has no display section: its pattern follows the
    /// colon directly.
    fn after_table_colon(&self) -> Region {
        if self.statement_is_with {
            Region::Pattern
        } else {
            Region::Display
        }
    }

    // ── shared pieces ──────────────────────────────────────────────────

    /// Tokens that mean the same thing in every region. Returns whether it
    /// consumed anything.
    fn common(&mut self, c: u8) -> bool {
        match c {
            b'#' => self.comment(),
            b'"' => self.string(),
            b'$' if self.at(b'$') && self.bytes.get(self.pos + 1) == Some(&b'(') => {
                self.expansion()
            }
            b'$' => {
                let len = 1 + self.ident_len_at(self.pos + 1);
                if len > 1 {
                    self.emit(len, TokenKind::Operator);
                } else {
                    self.pos += 1;
                }
            }
            _ if c.is_ascii_digit() => self.number(),
            _ if c.is_ascii_whitespace() => self.pos += 1,
            _ => return false,
        }
        true
    }

    fn comment(&mut self) {
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos] != b'\n' {
            self.pos += 1;
        }
        self.push(start, self.pos, TokenKind::Comment);
    }

    fn string(&mut self) {
        let start = self.pos;
        self.pos += 1;
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b'"' => {
                    self.pos += 1;
                    break;
                }
                b'\n' => break,
                b'\\' => self.pos += 2,
                _ => self.pos += 1,
            }
        }
        self.pos = self.pos.min(self.bytes.len());
        self.push(start, self.pos, TokenKind::String);
    }

    fn directive(&mut self) {
        let len = 1 + self.ident_len_at(self.pos + 1);
        if len > 1 {
            self.emit(len, TokenKind::Directive);
        } else {
            self.pos += 1;
        }
    }

    /// `$(NAME)`.
    fn expansion(&mut self) {
        let name = self.ident_len_at(self.pos + 2);
        if name > 0 && self.bytes.get(self.pos + 2 + name) == Some(&b')') {
            self.emit(3 + name, TokenKind::Macro);
        } else {
            self.pos += 1;
        }
    }

    fn number(&mut self) {
        let start = self.pos;
        let radix = match (self.bytes[self.pos], self.bytes.get(self.pos + 1)) {
            (b'0', Some(b'x' | b'X')) => {
                self.pos += 2;
                16
            }
            (b'0', Some(b'b' | b'B')) => {
                self.pos += 2;
                2
            }
            _ => 10,
        };
        while self.pos < self.bytes.len() && (self.bytes[self.pos] as char).is_digit(radix) {
            self.pos += 1;
        }
        // A number glued to identifier characters is not a number.
        if self.pos < self.bytes.len() && is_ident_continue(self.bytes[self.pos]) {
            while self.pos < self.bytes.len() && is_ident_continue(self.bytes[self.pos]) {
                self.pos += 1;
            }
            return;
        }
        self.push(start, self.pos, TokenKind::Number);
    }

    fn operator(&mut self) {
        let start = self.pos;
        while self.pos < self.bytes.len() && is_operator(self.bytes[self.pos]) {
            self.pos += 1;
        }
        if self.pos == start {
            // Punctuation this lexer does not classify: brackets, commas.
            self.pos += 1;
        } else {
            self.push(start, self.pos, TokenKind::Operator);
        }
    }

    /// Classifies the identifier of `len` bytes at the cursor and advances.
    fn word(&mut self, len: usize, context: WordContext) {
        let word = &self.text[self.pos..self.pos + len];
        let after = self.skip_spaces_from(self.pos + len);
        let kind = if is_keyword(word) {
            Some(TokenKind::Keyword)
        } else if context != WordContext::Pattern && self.bytes.get(after) == Some(&b'(') {
            // A call in a body, or the name in `macro name(args)`.
            Some(TokenKind::Macro)
        } else {
            None
        };
        if word == "with" && context == WordContext::Preamble {
            self.statement_is_with = true;
        }
        match kind {
            Some(kind) => self.emit(len, kind),
            None => self.pos += len,
        }
    }

    // ── scanning helpers ───────────────────────────────────────────────

    fn at(&self, c: u8) -> bool {
        self.bytes.get(self.pos) == Some(&c)
    }

    fn starts_with(&self, s: &str) -> bool {
        self.bytes[self.pos..].starts_with(s.as_bytes())
    }

    /// Whether `word` sits at the cursor as a whole word.
    fn at_keyword(&self, word: &str) -> bool {
        self.starts_with(word)
            && !self
                .bytes
                .get(self.pos + word.len())
                .is_some_and(|&c| is_ident_continue(c))
            && !(self.pos > 0 && is_ident_continue(self.bytes[self.pos - 1]))
    }

    fn ident(&self) -> usize {
        self.ident_len_at(self.pos)
    }

    fn ident_len_at(&self, at: usize) -> usize {
        let mut end = at;
        if end < self.bytes.len() && is_ident_start(self.bytes[end]) {
            end += 1;
            while end < self.bytes.len() && is_ident_continue(self.bytes[end]) {
                end += 1;
            }
        }
        end - at
    }

    /// `<name>` at the cursor, or 0.
    fn label_len(&self) -> usize {
        let name = self.ident_len_at(self.pos + 1);
        if name > 0 && self.bytes.get(self.pos + 1 + name) == Some(&b'>') {
            name + 2
        } else {
            0
        }
    }

    fn skip_spaces_from(&self, mut at: usize) -> usize {
        while at < self.bytes.len() && matches!(self.bytes[at], b' ' | b'\t') {
            at += 1;
        }
        at
    }

    fn emit(&mut self, len: usize, kind: TokenKind) {
        self.push(self.pos, self.pos + len, kind);
        self.pos += len;
    }

    fn push(&mut self, start: usize, end: usize, kind: TokenKind) {
        self.out.push(Token { start, end, kind });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WordContext {
    Preamble,
    Pattern,
    Body,
}

fn is_keyword(word: &str) -> bool {
    KEYWORDS.contains(&word)
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c == b'.'
}

fn is_ident_continue(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.'
}

fn is_operator(c: u8) -> bool {
    matches!(
        c,
        b'&' | b'|' | b'^' | b'!' | b'=' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'%' | b'~'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(text: &str) -> Vec<(&str, TokenKind)> {
        tokens(text)
            .into_iter()
            .map(|t| (&text[t.range()], t.kind))
            .collect()
    }

    #[test]
    fn keywords_match_the_grammar() {
        let grammar = include_str!("grammar/sleigh_raw.pest");
        let from_grammar: Vec<&str> = grammar
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("keyword_")?;
                let quoted = rest.split('"').nth(1)?;
                Some(quoted)
            })
            .collect();
        assert_eq!(KEYWORDS, from_grammar.as_slice());
    }

    #[test]
    fn regions_change_what_ampersand_means() {
        let toks = lex(":ADD rd, rs is op=0x2 & rd & rs { rd = rd & rs; }");
        let amps: Vec<_> = toks
            .iter()
            .filter(|(s, _)| *s == "&")
            .map(|(_, k)| *k)
            .collect();
        assert_eq!(
            amps,
            [
                TokenKind::Structure,
                TokenKind::Structure,
                TokenKind::Operator
            ]
        );
    }

    #[test]
    fn display_is_literal_text() {
        let toks = lex("mode: [rs] is op=1 { }");
        assert_eq!(toks[0], ("mode", TokenKind::Table));
        assert_eq!(toks[1], (":", TokenKind::Table));
        assert_eq!(toks[2], (" [rs] ", TokenKind::Display));
        assert_eq!(toks[3], ("is", TokenKind::Keyword));
    }

    #[test]
    fn preamble_definitions() {
        let toks = lex("define token opcode (8)\n  op = (4,7)\n;\nattach variables [ rd ] [ r0 ];");
        assert!(toks.contains(&("define", TokenKind::Keyword)));
        assert!(toks.contains(&("token", TokenKind::Keyword)));
        assert!(toks.contains(&("8", TokenKind::Number)));
        assert!(toks.contains(&("attach", TokenKind::Keyword)));
        assert!(!toks.iter().any(|(_, k)| *k == TokenKind::Display));
    }

    #[test]
    fn body_labels_calls_and_macros() {
        let toks = lex(
            "macro push(v) { *:8 sp = v; }\n:BEQ imm is op=5; imm {\n  if (r0 != r1) goto <skip>;\n  push(r0);\n  <skip>\n}",
        );
        assert!(toks.contains(&("macro", TokenKind::Keyword)));
        assert_eq!(
            toks.iter()
                .filter(|(s, k)| *s == "push" && *k == TokenKind::Macro)
                .count(),
            2
        );
        assert_eq!(
            toks.iter()
                .filter(|(s, k)| *s == "<skip>" && *k == TokenKind::Label)
                .count(),
            2
        );
        assert!(toks.contains(&("goto", TokenKind::Keyword)));
        assert!(toks.contains(&(";", TokenKind::Structure)));
        assert!(toks.contains(&("!=", TokenKind::Operator)));
    }

    #[test]
    fn with_blocks_do_not_open_a_body() {
        let toks = lex("with : mode=1 {\n:X is op=1 { r0 = 1; }\n}");
        assert!(toks.contains(&("with", TokenKind::Keyword)));
        assert!(toks.contains(&("X ", TokenKind::Display)));
        assert!(toks.contains(&("=", TokenKind::Operator)));
    }

    #[test]
    fn preprocessor() {
        let toks = lex("@define WORD \"4\"\n@ifdef WORD\ndefine space ram size=$(WORD);\n@endif");
        assert!(toks.contains(&("@define", TokenKind::Directive)));
        assert!(toks.contains(&("\"4\"", TokenKind::String)));
        assert!(toks.contains(&("$(WORD)", TokenKind::Macro)));
        assert!(toks.contains(&("@endif", TokenKind::Directive)));
    }

    #[test]
    fn unimpl_ends_the_constructor() {
        let toks = lex(":A is op=1 unimpl\n:B is op=2 { }");
        assert!(toks.contains(&("unimpl", TokenKind::Keyword)));
        assert!(toks.contains(&("B ", TokenKind::Display)));
    }

    #[test]
    fn tokens_never_overlap_and_cover_only_real_bytes() {
        let text = include_str!("../../web/presets/toy16.slaspec");
        let mut last = 0;
        for t in tokens(text) {
            assert!(t.start >= last, "overlap at {}", t.start);
            assert!(t.end <= text.len());
            assert!(text.is_char_boundary(t.start) && text.is_char_boundary(t.end));
            last = t.end;
        }
    }

    #[test]
    fn broken_input_does_not_panic() {
        for text in [
            "",
            ":",
            "is",
            "{",
            "}}}",
            "\"",
            "$(",
            "@",
            "0x",
            "<",
            "define token (",
            "ééé:é is é { é }",
        ] {
            let _ = tokens(text);
        }
    }
}
