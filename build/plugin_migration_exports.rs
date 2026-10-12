/// Name of the function a custom plugin exports to declare its migrations.
pub const PLUGIN_MIGRATIONS_FN: &str = "plugin_migrations";

/// Returns `true` when `source` declares a module-level `fn plugin_migrations`.
///
/// This is a small Rust-aware token scan, not a substring search, so valid
/// spellings the compiler accepts are recognized:
///
/// - any whitespace or comments between `fn`, the name, and `(`
///   (non-doc comments are whitespace to the compiler);
/// - the raw-identifier spelling `r#plugin_migrations`;
/// - any qualifiers before `fn` (`pub`, `pub(crate)`, `const`, `extern "C"`).
///
/// Comments, string/char literals, and items nested inside braces (`impl`
/// blocks, inline modules, function bodies) are ignored, because only a
/// module-level function is reachable as `<plugin>::plugin_migrations()` from
/// the generated collector. Functions produced by macro expansion cannot be
/// seen by a source scan and are not detected.
pub fn source_defines_plugin_migrations(source: &str) -> bool {
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0;
    let mut depth: usize = 0;
    // The previous significant token was a module-level `fn` keyword.
    let mut after_top_level_fn = false;

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
            after_top_level_fn = false;
            continue;
        }
        if c == '\'' {
            i = skip_char_or_lifetime(&chars, i);
            after_top_level_fn = false;
            continue;
        }
        if is_ident_start(c) {
            if let Some(end) = prefixed_literal_end(&chars, i) {
                i = end;
                after_top_level_fn = false;
                continue;
            }
            let raw_ident = c == 'r'
                && next == Some('#')
                && chars.get(i + 2).is_some_and(|&n| is_ident_start(n));
            let start = if raw_ident { i + 2 } else { i };
            let mut end = start;
            while end < chars.len() && is_ident_continue(chars[end]) {
                end += 1;
            }
            let ident: String = chars[start..end].iter().collect();
            if after_top_level_fn && ident == PLUGIN_MIGRATIONS_FN {
                return true;
            }
            after_top_level_fn = depth == 0 && !raw_ident && ident == "fn";
            i = end;
            continue;
        }

        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        after_top_level_fn = false;
        i += 1;
    }

    false
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
