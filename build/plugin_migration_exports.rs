/// Name of the function a custom plugin exports to declare its migrations.
pub const PLUGIN_MIGRATIONS_FN: &str = "plugin_migrations";

/// Decides whether a custom plugin source exposes `plugin_migrations` at its
/// module root, where the generated collector calls
/// `<plugin>::plugin_migrations()`.
///
/// Returns `Ok(true)` when the plugin root defines `fn plugin_migrations` or
/// binds that name with a `use` declaration, such as
/// `pub use self::inner::plugin_migrations;`, a grouped
/// `pub use self::inner::{helper, plugin_migrations};`, or a rename
/// `pub use self::inner::declare as plugin_migrations;`. Returns `Ok(false)`
/// when the name is neither defined nor bound. Returns `Err` when
/// `fn plugin_migrations` is defined only inside braces (inline module, `impl`
/// block, function body) with no root binding: the collector could not reach
/// it, and silently omitting it would drop the plugin's migrations.
///
/// This is a small Rust-aware token scan, not a substring search, so valid
/// spellings the compiler accepts are recognized:
///
/// - any whitespace or comments between `fn`, the name, and `(`
///   (non-doc comments are whitespace to the compiler);
/// - the raw-identifier spelling `r#plugin_migrations`;
/// - any qualifiers before `fn` or `use` (`pub`, `pub(crate)`, `const`,
///   `extern "C"`).
///
/// Mentions in comments and string/char literals are ignored. Glob imports
/// (`pub use self::inner::*;`) and functions produced by macro expansion
/// cannot be resolved by a source scan and are not detected.
pub fn plugin_migrations_exported(source: &str) -> Result<bool, String> {
    let tokens = tokenize(source);
    let mut nested_definition = false;
    let mut i = 0;

    while i < tokens.len() {
        let token = &tokens[i];
        if token.is_keyword("fn") && tokens.get(i + 1).is_some_and(Token::is_migrations_name) {
            if token.depth == 0 {
                return Ok(true);
            }
            nested_definition = true;
        } else if token.depth == 0
            && token.is_keyword("use")
            && !tokens.get(i + 1).is_some_and(|next| next.is_punct('<'))
        {
            // `use<'a>` (a precise-capturing bound) was excluded above; this
            // is a use declaration, which ends at the next root-level `;`.
            let end = tokens[i..]
                .iter()
                .position(|t| t.depth == 0 && t.is_punct(';'))
                .map_or(tokens.len(), |offset| i + offset);
            if use_tree_binds_migrations(&tokens[i + 1..end]) {
                return Ok(true);
            }
            i = end;
            continue;
        }
        i += 1;
    }

    if nested_definition {
        return Err(format!(
            "`fn {PLUGIN_MIGRATIONS_FN}` is defined inside a nested item (inline module, \
             `impl` block, or function body) and is not re-exported at the plugin root; \
             the generated migration collector calls `<plugin>::{PLUGIN_MIGRATIONS_FN}()`, \
             so move the function to the plugin root, add \
             `pub use <path>::{PLUGIN_MIGRATIONS_FN};` at the plugin root, or rename the \
             nested function"
        ));
    }
    Ok(false)
}

/// Returns `true` when a use tree (the tokens between `use` and `;`) binds
/// the name `plugin_migrations`: either as a final path segment
/// (`a::plugin_migrations`, `a::{b, plugin_migrations}`) or as a rename
/// target (`a::declare as plugin_migrations`). A segment followed by `::` is
/// a module path, and one followed by `as` is renamed away.
fn use_tree_binds_migrations(tree: &[Token]) -> bool {
    tree.iter().enumerate().any(|(i, token)| {
        token.is_migrations_name()
            && !tree
                .get(i + 1)
                .is_some_and(|next| next.is_punct(':') || next.is_keyword("as"))
    })
}

enum TokenKind {
    /// Identifier or keyword; `raw` marks the `r#ident` spelling.
    Ident { name: String, raw: bool },
    Punct(char),
    Literal,
}

struct Token {
    kind: TokenKind,
    /// Brace depth outside this token (`{` and `}` carry the outer depth).
    depth: usize,
}

impl Token {
    fn is_keyword(&self, keyword: &str) -> bool {
        matches!(&self.kind, TokenKind::Ident { name, raw: false } if name == keyword)
    }

    fn is_migrations_name(&self) -> bool {
        matches!(&self.kind, TokenKind::Ident { name, .. } if name == PLUGIN_MIGRATIONS_FN)
    }

    fn is_punct(&self, ch: char) -> bool {
        matches!(self.kind, TokenKind::Punct(c) if c == ch)
    }
}

/// Split `source` into identifiers, punctuation, and opaque literals, skipping
/// whitespace and comments and tracking brace depth.
fn tokenize(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut depth: usize = 0;

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();

        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            i = skip_block_comment(&chars, i);
            continue;
        }
        if c == '"' {
            i = skip_quoted(&chars, i + 1, '"');
            tokens.push(Token {
                kind: TokenKind::Literal,
                depth,
            });
            continue;
        }
        if c == '\'' {
            i = skip_char_or_lifetime(&chars, i);
            tokens.push(Token {
                kind: TokenKind::Literal,
                depth,
            });
            continue;
        }
        if is_ident_start(c) {
            if let Some(end) = prefixed_literal_end(&chars, i) {
                i = end;
                tokens.push(Token {
                    kind: TokenKind::Literal,
                    depth,
                });
                continue;
            }
            let raw = c == 'r'
                && next == Some('#')
                && chars.get(i + 2).is_some_and(|&n| is_ident_start(n));
            let start = if raw { i + 2 } else { i };
            let mut end = start;
            while end < chars.len() && is_ident_continue(chars[end]) {
                end += 1;
            }
            let name: String = chars[start..end].iter().collect();
            tokens.push(Token {
                kind: TokenKind::Ident { name, raw },
                depth,
            });
            i = end;
            continue;
        }

        if c == '}' {
            depth = depth.saturating_sub(1);
        }
        tokens.push(Token {
            kind: TokenKind::Punct(c),
            depth,
        });
        if c == '{' {
            depth += 1;
        }
        i += 1;
    }

    tokens
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn is_ident_continue(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Skip a (possibly nested) block comment starting at `start` (`/*`).
fn skip_block_comment(chars: &[char], start: usize) -> usize {
    let mut i = start + 2;
    let mut nesting = 1usize;
    while i < chars.len() {
        if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
            nesting += 1;
            i += 2;
        } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
            nesting -= 1;
            i += 2;
            if nesting == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    chars.len()
}

/// Skip an escaped literal body starting just after its opening delimiter.
/// Returns the index just past the closing delimiter.
fn skip_quoted(chars: &[char], start: usize, delimiter: char) -> usize {
    let mut i = start;
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
        } else if chars[i] == delimiter {
            return i + 1;
        } else {
            i += 1;
        }
    }
    chars.len()
}

/// At a `'`: skip a char literal (`'x'`, `'\n'`), or only the quote of a
/// lifetime/label (`'a`) so its name is scanned as an ordinary identifier.
fn skip_char_or_lifetime(chars: &[char], start: usize) -> usize {
    if chars.get(start + 1) == Some(&'\\') {
        return skip_quoted(chars, start + 1, '\'');
    }
    if chars.get(start + 2) == Some(&'\'') {
        return start + 3;
    }
    start + 1
}

/// If an identifier-looking token at `start` is actually a prefixed literal
/// (`b"…"`, `b'…'`, `c"…"`, `r"…"`, `r#"…"#`, `br#"…"#`, `cr"…"`), return the
/// index just past it.
fn prefixed_literal_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    if matches!(chars[i], 'b' | 'c') {
        i += 1;
        match chars.get(i) {
            Some('"') => return Some(skip_quoted(chars, i + 1, '"')),
            Some('\'') if chars[start] == 'b' => return Some(skip_quoted(chars, i + 1, '\'')),
            Some('r') => {}
            _ => return None,
        }
    }
    if chars.get(i) != Some(&'r') {
        return None;
    }
    i += 1;
    let mut hashes = 0usize;
    while chars.get(i) == Some(&'#') {
        hashes += 1;
        i += 1;
    }
    if chars.get(i) != Some(&'"') {
        return None;
    }
    i += 1;
    while i < chars.len() {
        if chars[i] == '"' && (1..=hashes).all(|offset| chars.get(i + offset) == Some(&'#')) {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(chars.len())
}
