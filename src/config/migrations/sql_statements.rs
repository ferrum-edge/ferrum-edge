//! Quote/comment-aware SQL statement splitting for custom-plugin migrations.
//!
//! Custom-plugin multi-statement SQL used to split on raw `';'`, which broke
//! string literals, comments, PostgreSQL dollar-quoted bodies, and MySQL
//! compound routines. Classification (`CREATE INDEX CONCURRENTLY`, etc.) and
//! execution must share the same boundaries, and the full migration body must
//! parse successfully before statement one runs (fail-closed).

use std::fmt;

/// Failure while splitting custom-plugin migration SQL into statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlStatementSplitError {
    message: String,
    position: Option<usize>,
}

impl SqlStatementSplitError {
    fn new(message: impl Into<String>, position: Option<usize>) -> Self {
        Self {
            message: message.into(),
            position,
        }
    }
}

impl fmt::Display for SqlStatementSplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(pos) => write!(f, "{} (at byte offset {})", self.message, pos),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for SqlStatementSplitError {}

/// Split custom-plugin migration SQL into executable statements for `db_type`.
///
/// Supported quoting/comment forms (all dialects unless noted):
/// - single-quoted strings with doubled quotes (plus dialect-valid backslash escapes)
/// - double-quoted identifiers/strings with doubled quotes (plus MySQL backslash escapes)
/// - backtick identifiers (MySQL / SQLite), including doubled-backtick escapes
/// - `--` line comments and `/* ... */` block comments
/// - MySQL `#` line comments
/// - PostgreSQL dollar-quoted bodies (`$tag$ ... $tag$`)
/// - MySQL client `DELIMITER` meta-commands for compound routines
///
/// Empty segments (whitespace / comment-only after a delimiter) are omitted.
/// The entire input is scanned before returning; malformed or unsupported
/// constructs return [`Err`] so callers never partially apply a migration.
/// Transaction-control statements (`BEGIN`, `COMMIT`, `ROLLBACK`, …) are
/// rejected because the migration runner owns every transaction boundary.
pub fn split_plugin_migration_statements<'a>(
    sql: &'a str,
    db_type: &str,
) -> Result<Vec<&'a str>, SqlStatementSplitError> {
    let dialect = SplitDialect::from_db_type(db_type)?;
    let statements = scan_statements(sql, dialect)?;
    if dialect == SplitDialect::Mysql {
        validate_mysql_compound_statements(&statements)?;
    }
    reject_transaction_control_statements(&statements, dialect)?;
    Ok(statements)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SplitDialect {
    Sqlite,
    Postgres,
    Mysql,
}

impl SplitDialect {
    fn from_db_type(db_type: &str) -> Result<Self, SqlStatementSplitError> {
        match db_type {
            "sqlite" => Ok(Self::Sqlite),
            "postgres" => Ok(Self::Postgres),
            "mysql" => Ok(Self::Mysql),
            other => Err(SqlStatementSplitError::new(
                format!("unsupported database type for custom-plugin SQL splitting: {other:?}"),
                None,
            )),
        }
    }

    fn allows_hash_line_comments(self) -> bool {
        matches!(self, Self::Mysql)
    }

    fn allows_dollar_quotes(self) -> bool {
        matches!(self, Self::Postgres)
    }

    fn allows_delimiter_directives(self) -> bool {
        matches!(self, Self::Mysql)
    }

    fn allows_backticks(self) -> bool {
        matches!(self, Self::Mysql | Self::Sqlite)
    }
}

fn scan_statements(sql: &str, dialect: SplitDialect) -> Result<Vec<&str>, SqlStatementSplitError> {
    let bytes = sql.as_bytes();
    let mut statements = Vec::new();
    let mut i = 0usize;
    let mut stmt_start = 0usize;
    let mut delimiter = CowDelim::Semicolon;
    // Depth of compound BEGIN…END (and MySQL END IF / END WHILE / …) blocks.
    // Semicolon splits are suppressed while depth > 0 so trigger/procedure
    // bodies stay one executable statement. Transaction `BEGIN;` is excluded.
    let mut compound_depth: usize = 0;
    // SQL `CASE … END` expressions (and MySQL `CASE … END CASE`) must not pop
    // an enclosing BEGIN depth.
    let mut case_depth: usize = 0;
    // True while `[stmt_start, i)` holds only ASCII whitespace and complete
    // comments. Tracked incrementally so leading padding is scanned once
    // rather than rescanned at every byte.
    let mut at_statement_start = true;

    while i < bytes.len() {
        // Client DELIMITER directives are only meaningful at statement starts.
        // They are mysql-client meta-commands: never push them as executable SQL.
        // Only probe at the first non-whitespace byte so the directive parser
        // never rescans the remaining padding.
        if dialect.allows_delimiter_directives()
            && compound_depth == 0
            && case_depth == 0
            && at_statement_start
            && !bytes[i].is_ascii_whitespace()
            && let Some(new_delim) = try_parse_delimiter_directive(sql, &mut i)?
        {
            // [stmt_start, previous i) was only whitespace/comments; discarding it
            // with the directive avoids phantom comment-only or DELIMITER statements.
            delimiter = if new_delim == ";" {
                CowDelim::Semicolon
            } else {
                CowDelim::Custom(new_delim)
            };
            skip_whitespace_and_newlines(bytes, &mut i);
            stmt_start = i;
            at_statement_start = true;
            continue;
        }

        match bytes[i] {
            b'\'' => {
                i = scan_single_quoted(sql, i, dialect)?;
                at_statement_start = false;
            }
            b'"' => {
                i = scan_double_quoted(sql, i, dialect)?;
                at_statement_start = false;
            }
            b'`' if dialect.allows_backticks() => {
                i = scan_backtick_quoted(sql, i, dialect)?;
                at_statement_start = false;
            }
            b'-' if starts_dash_line_comment(bytes, i, dialect) => {
                i = scan_line_comment(bytes, i + 2);
            }
            b'#' if dialect.allows_hash_line_comments() => {
                i = scan_line_comment(bytes, i + 1);
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i = scan_block_comment(sql, i, dialect)?;
            }
            b'$' if dialect.allows_dollar_quotes() => {
                if let Some(after) = try_scan_dollar_quoted(sql, i)? {
                    i = after;
                } else {
                    i += 1;
                }
                at_statement_start = false;
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                at_statement_start = false;
                let word_start = i;
                i += 1;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                let word = &sql[word_start..i];
                if word.eq_ignore_ascii_case("BEGIN") {
                    if !is_transaction_begin_keyword(sql, i, dialect) {
                        compound_depth = compound_depth.saturating_add(1);
                    }
                } else if word.eq_ignore_ascii_case("CASE") {
                    case_depth = case_depth.saturating_add(1);
                } else if word.eq_ignore_ascii_case("END") {
                    // MySQL `END IF` / `END WHILE` / `END CASE` / … close
                    // non-BEGIN blocks. Bare `END` closes CASE expressions
                    // preferentially, then BEGIN.
                    if let Some(suffix) = consume_mysql_end_block_suffix(sql, &mut i) {
                        if suffix.eq_ignore_ascii_case("CASE") {
                            if case_depth == 0 {
                                return Err(SqlStatementSplitError::new(
                                    "unmatched END CASE while splitting custom-plugin migration SQL",
                                    Some(word_start),
                                ));
                            }
                            case_depth -= 1;
                        }
                        // END IF / WHILE / LOOP / REPEAT: only valid inside an
                        // enclosing BEGIN (or via DELIMITER). Depth unchanged.
                    } else if case_depth > 0 {
                        case_depth -= 1;
                    } else {
                        compound_depth = compound_depth.saturating_sub(1);
                    }
                }
            }
            _ => {
                if compound_depth == 0 && case_depth == 0 && delimiter.matches_at(sql, i) {
                    let delim_len = delimiter.len();
                    push_statement(sql, stmt_start, i, dialect, &mut statements)?;
                    i += delim_len;
                    skip_whitespace_and_newlines(bytes, &mut i);
                    stmt_start = i;
                    at_statement_start = true;
                } else {
                    if !bytes[i].is_ascii_whitespace() {
                        at_statement_start = false;
                    }
                    i += 1;
                }
            }
        }
    }

    if compound_depth != 0 {
        return Err(SqlStatementSplitError::new(
            "unclosed BEGIN … END compound statement in custom-plugin migration SQL",
            Some(stmt_start.min(bytes.len().saturating_sub(1))),
        ));
    }
    if case_depth != 0 {
        return Err(SqlStatementSplitError::new(
            "unclosed CASE … END expression in custom-plugin migration SQL",
            Some(stmt_start.min(bytes.len().saturating_sub(1))),
        ));
    }

    if stmt_start < bytes.len() {
        push_statement(sql, stmt_start, bytes.len(), dialect, &mut statements)?;
    }

    if !matches!(delimiter, CowDelim::Semicolon) {
        return Err(SqlStatementSplitError::new(
            "MySQL DELIMITER was changed away from ';' and never restored before end of migration SQL; \
             restore with `DELIMITER ;` after the compound statement",
            Some(stmt_start.min(bytes.len().saturating_sub(1))),
        ));
    }

    Ok(statements)
}

/// `BEGIN` starts a transaction when followed by `;` / EOF or a transaction mode keyword.
fn is_transaction_begin_keyword(sql: &str, after_begin: usize, dialect: SplitDialect) -> bool {
    let bytes = sql.as_bytes();
    let mut i = after_begin;
    skip_sql_whitespace_and_comments(sql, &mut i, dialect);
    if i >= bytes.len() || bytes[i] == b';' {
        return true;
    }
    let mut end = i;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    let word = &sql[i..end];
    match dialect {
        SplitDialect::Postgres => {
            word.eq_ignore_ascii_case("TRANSACTION")
                || word.eq_ignore_ascii_case("WORK")
                || word.eq_ignore_ascii_case("ISOLATION")
                || word.eq_ignore_ascii_case("READ")
                || word.eq_ignore_ascii_case("DEFERRABLE")
                || word.eq_ignore_ascii_case("NOT")
        }
        SplitDialect::Sqlite => {
            word.eq_ignore_ascii_case("TRANSACTION")
                || word.eq_ignore_ascii_case("IMMEDIATE")
                || word.eq_ignore_ascii_case("DEFERRED")
                || word.eq_ignore_ascii_case("EXCLUSIVE")
        }
        SplitDialect::Mysql => word.eq_ignore_ascii_case("WORK"),
    }
}

fn consume_mysql_end_block_suffix<'a>(sql: &'a str, i: &mut usize) -> Option<&'a str> {
    let bytes = sql.as_bytes();
    let mut j = *i;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    let mut end = j;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    if j == end {
        return None;
    }
    let word = &sql[j..end];
    if word.eq_ignore_ascii_case("IF")
        || word.eq_ignore_ascii_case("WHILE")
        || word.eq_ignore_ascii_case("LOOP")
        || word.eq_ignore_ascii_case("REPEAT")
        || word.eq_ignore_ascii_case("CASE")
    {
        *i = end;
        Some(word)
    } else {
        // `END <label>` — leave the label for later scanning; still a BEGIN closer.
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CowDelim {
    Semicolon,
    Custom(String),
}

impl CowDelim {
    fn len(&self) -> usize {
        match self {
            Self::Semicolon => 1,
            Self::Custom(d) => d.len(),
        }
    }

    fn matches_at(&self, sql: &str, i: usize) -> bool {
        match self {
            Self::Semicolon => sql.as_bytes().get(i) == Some(&b';'),
            Self::Custom(d) => sql
                .as_bytes()
                .get(i..i.saturating_add(d.len()))
                .is_some_and(|candidate| candidate == d.as_bytes()),
        }
    }
}

fn try_parse_delimiter_directive(
    sql: &str,
    i: &mut usize,
) -> Result<Option<String>, SqlStatementSplitError> {
    let rest = &sql[*i..];
    let trimmed_start = rest
        .char_indices()
        .find(|(_, c)| !c.is_whitespace())
        .map(|(off, _)| off)
        .unwrap_or(rest.len());
    let after_ws = *i + trimmed_start;
    if after_ws >= sql.len() {
        return Ok(None);
    }
    let from = &sql[after_ws..];
    let keyword = "DELIMITER";
    if !from
        .as_bytes()
        .get(..keyword.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(keyword.as_bytes()))
        || from
            .as_bytes()
            .get(keyword.len())
            .is_some_and(|b| is_ident_byte(*b))
    {
        return Ok(None);
    }

    let mut pos = after_ws + keyword.len();
    let bytes = sql.as_bytes();
    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t' | b'\r') {
        pos += 1;
    }
    if pos >= bytes.len() || bytes[pos] == b'\n' {
        return Err(SqlStatementSplitError::new(
            "MySQL DELIMITER directive requires a non-empty delimiter token",
            Some(after_ws),
        ));
    }

    let delim_start = pos;
    while pos < bytes.len() && !matches!(bytes[pos], b' ' | b'\t' | b'\r' | b'\n') {
        pos += 1;
    }
    let token = &sql[delim_start..pos];
    if token.is_empty() {
        return Err(SqlStatementSplitError::new(
            "MySQL DELIMITER directive requires a non-empty delimiter token",
            Some(delim_start),
        ));
    }
    if token.contains('\'') || token.contains('"') || token.contains('`') {
        return Err(SqlStatementSplitError::new(
            "MySQL DELIMITER token must not contain quote characters",
            Some(delim_start),
        ));
    }

    // Consume the rest of the line (mysql client treats DELIMITER as line-oriented).
    while pos < bytes.len() && bytes[pos] != b'\n' {
        if !bytes[pos].is_ascii_whitespace() {
            return Err(SqlStatementSplitError::new(
                "MySQL DELIMITER directive must be alone on its line (no trailing tokens)",
                Some(pos),
            ));
        }
        pos += 1;
    }
    if pos < bytes.len() && bytes[pos] == b'\n' {
        pos += 1;
    }
    *i = pos;
    Ok(Some(token.to_string()))
}

fn push_statement<'a>(
    sql: &'a str,
    start: usize,
    end: usize,
    dialect: SplitDialect,
    out: &mut Vec<&'a str>,
) -> Result<(), SqlStatementSplitError> {
    let raw = &sql[start..end];
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    // Preserve historical behavior of skipping pure-whitespace segments, but
    // also skip comment-only segments so classification/execution never see
    // non-SQL leftovers produced solely by comment stripping around delimiters.
    if strip_leading_sql_comments_for_dialect(trimmed, dialect).is_empty() {
        return Ok(());
    }
    out.push(trimmed);
    Ok(())
}

fn skip_whitespace_and_newlines(bytes: &[u8], i: &mut usize) {
    while *i < bytes.len() && bytes[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn starts_dash_line_comment(bytes: &[u8], start: usize, dialect: SplitDialect) -> bool {
    if bytes.get(start..start.saturating_add(2)) != Some(b"--") {
        return false;
    }
    if dialect != SplitDialect::Mysql {
        return true;
    }
    bytes
        .get(start + 2)
        .is_some_and(|next| next.is_ascii_whitespace() || next.is_ascii_control())
}

fn skip_sql_whitespace_and_comments(sql: &str, i: &mut usize, dialect: SplitDialect) {
    let bytes = sql.as_bytes();
    loop {
        while *i < bytes.len() && bytes[*i].is_ascii_whitespace() {
            *i += 1;
        }
        if starts_dash_line_comment(bytes, *i, dialect) {
            *i = scan_line_comment(bytes, *i + 2);
            continue;
        }
        if dialect.allows_hash_line_comments() && bytes.get(*i) == Some(&b'#') {
            *i = scan_line_comment(bytes, *i + 1);
            continue;
        }
        if bytes.get(*i..(*i).saturating_add(2)) == Some(b"/*") {
            match scan_block_comment(sql, *i, dialect) {
                Ok(next) => {
                    *i = next;
                    continue;
                }
                Err(_) => return,
            }
        }
        return;
    }
}

fn scan_single_quoted(
    sql: &str,
    start: usize,
    dialect: SplitDialect,
) -> Result<usize, SqlStatementSplitError> {
    // start points at opening '
    let bytes = sql.as_bytes();
    let backslash_escapes = match dialect {
        SplitDialect::Mysql => true,
        SplitDialect::Postgres => postgres_quote_uses_backslash(sql, start, true),
        SplitDialect::Sqlite => false,
    };
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2; // doubled quote escape
                } else {
                    return Ok(i + 1);
                }
            }
            b'\\' if backslash_escapes => {
                if i + 1 < bytes.len() {
                    i += 2;
                } else {
                    return Err(SqlStatementSplitError::new(
                        "unclosed single-quoted string (trailing backslash)",
                        Some(start),
                    ));
                }
            }
            _ => i += 1,
        }
    }
    Err(SqlStatementSplitError::new(
        "unclosed single-quoted string",
        Some(start),
    ))
}

fn scan_double_quoted(
    sql: &str,
    start: usize,
    dialect: SplitDialect,
) -> Result<usize, SqlStatementSplitError> {
    let bytes = sql.as_bytes();
    let backslash_escapes = match dialect {
        SplitDialect::Mysql => true,
        SplitDialect::Postgres => postgres_quote_uses_backslash(sql, start, false),
        SplitDialect::Sqlite => false,
    };
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                    i += 2;
                } else {
                    return Ok(i + 1);
                }
            }
            b'\\' if backslash_escapes => {
                if i + 1 < bytes.len() {
                    i += 2;
                } else {
                    return Err(SqlStatementSplitError::new(
                        "unclosed double-quoted identifier/string (trailing backslash)",
                        Some(start),
                    ));
                }
            }
            _ => i += 1,
        }
    }
    Err(SqlStatementSplitError::new(
        "unclosed double-quoted identifier/string",
        Some(start),
    ))
}

fn scan_backtick_quoted(
    sql: &str,
    start: usize,
    dialect: SplitDialect,
) -> Result<usize, SqlStatementSplitError> {
    let bytes = sql.as_bytes();
    let backslash_escapes = dialect == SplitDialect::Mysql;
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'`' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'`' {
                    i += 2;
                } else {
                    return Ok(i + 1);
                }
            }
            b'\\' if backslash_escapes => {
                if i + 1 < bytes.len() {
                    i += 2;
                } else {
                    return Err(SqlStatementSplitError::new(
                        "unclosed backtick-quoted identifier (trailing backslash)",
                        Some(start),
                    ));
                }
            }
            _ => i += 1,
        }
    }
    Err(SqlStatementSplitError::new(
        "unclosed backtick-quoted identifier",
        Some(start),
    ))
}

fn postgres_quote_uses_backslash(sql: &str, quote_start: usize, single_quote: bool) -> bool {
    let prefix = &sql[..quote_start];
    if single_quote
        && prefix
            .as_bytes()
            .last()
            .is_some_and(|last| matches!(last, b'E' | b'e'))
    {
        let prefix_start = quote_start - 1;
        if postgres_prefix_has_boundary(sql, prefix_start) {
            return true;
        }
    }
    if prefix.ends_with("U&") || prefix.ends_with("u&") {
        let prefix_start = quote_start - 2;
        return postgres_prefix_has_boundary(sql, prefix_start);
    }
    false
}

fn postgres_prefix_has_boundary(sql: &str, prefix_start: usize) -> bool {
    prefix_start == 0
        || !sql[..prefix_start]
            .chars()
            .next_back()
            .is_some_and(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '$'))
}

fn scan_line_comment(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    if i < bytes.len() { i + 1 } else { i }
}

fn scan_block_comment(
    sql: &str,
    start: usize,
    dialect: SplitDialect,
) -> Result<usize, SqlStatementSplitError> {
    // start points at '/' of '/*'
    let bytes = sql.as_bytes();
    let mut i = start + 2;
    let mut depth = 1usize;
    while i + 1 < bytes.len() {
        if dialect == SplitDialect::Postgres && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return Ok(i);
            }
            continue;
        }
        i += 1;
    }
    Err(SqlStatementSplitError::new(
        "unclosed block comment",
        Some(start),
    ))
}

/// Attempt to scan a PostgreSQL dollar-quoted string starting at `$`.
///
/// Returns `Ok(Some(end))` when a dollar quote was consumed, `Ok(None)` when
/// the `$` is not a dollar-quote opener (ordinary `$`), and `Err` on an
/// unclosed dollar-quoted body.
fn try_scan_dollar_quoted(
    sql: &str,
    start: usize,
) -> Result<Option<usize>, SqlStatementSplitError> {
    let bytes = sql.as_bytes();
    if bytes.get(start) != Some(&b'$') {
        return Ok(None);
    }
    if sql[..start]
        .chars()
        .next_back()
        .is_some_and(is_postgres_identifier_char)
    {
        return Ok(None);
    }
    let mut tag_end = start + 1;
    if bytes.get(tag_end) != Some(&b'$') {
        let Some(first) = sql[tag_end..].chars().next() else {
            return Ok(None);
        };
        if first != '_' && !first.is_alphabetic() {
            return Ok(None);
        }
        tag_end += first.len_utf8();
        while tag_end < bytes.len() {
            let Some(ch) = sql[tag_end..].chars().next() else {
                break;
            };
            if ch == '$' {
                break;
            }
            if ch != '_' && !ch.is_alphanumeric() {
                return Ok(None);
            }
            tag_end += ch.len_utf8();
        }
    }
    if tag_end >= bytes.len() || bytes[tag_end] != b'$' {
        // Not `$tag$` — treat the initial `$` as an ordinary character.
        return Ok(None);
    }
    let closer = &sql[start..=tag_end]; // includes both `$` markers
    let closer_bytes = closer.as_bytes();
    let mut i = tag_end + 1;
    while i + closer_bytes.len() <= bytes.len() {
        if bytes[i..].starts_with(closer_bytes) {
            return Ok(Some(i + closer_bytes.len()));
        }
        i += 1;
    }
    Err(SqlStatementSplitError::new(
        format!("unclosed PostgreSQL dollar-quoted string starting with {closer:?}"),
        Some(start),
    ))
}

fn is_postgres_identifier_char(ch: char) -> bool {
    ch.is_alphanumeric() || matches!(ch, '_' | '$')
}

fn strip_leading_sql_comments_for_dialect(mut sql: &str, dialect: SplitDialect) -> &str {
    loop {
        sql = sql.trim_start();
        let bytes = sql.as_bytes();
        if starts_dash_line_comment(bytes, 0, dialect) {
            sql = sql.split_once('\n').map_or("", |(_, rest)| rest);
            continue;
        }
        if dialect.allows_hash_line_comments() && bytes.first() == Some(&b'#') {
            sql = sql.split_once('\n').map_or("", |(_, rest)| rest);
            continue;
        }
        if bytes.get(..2) == Some(b"/*") {
            sql = match scan_block_comment(sql, 0, dialect) {
                Ok(after) => &sql[after..],
                Err(_) => "",
            };
            continue;
        }
        return sql;
    }
}

fn validate_mysql_compound_statements(statements: &[&str]) -> Result<(), SqlStatementSplitError> {
    for statement in statements {
        if mysql_stored_program_looks_incomplete(statement) {
            return Err(SqlStatementSplitError::new(
                "MySQL CREATE PROCEDURE/FUNCTION/TRIGGER/EVENT body appears to contain ';' \
                 while the statement delimiter is still ';'. Wrap the routine with \
                 `DELIMITER //` ... `//` `DELIMITER ;` so the compound body is one statement, \
                 or keep the body inside a single BEGIN … END block",
                None,
            ));
        }
        if is_orphan_mysql_end_block(statement) {
            return Err(SqlStatementSplitError::new(
                "MySQL migration SQL produced an orphan END IF/WHILE/LOOP/REPEAT/CASE statement; \
                 this usually means a compound routine was split on ';'. Use DELIMITER or a \
                 BEGIN … END body so the routine is one statement",
                None,
            ));
        }
    }
    Ok(())
}

fn is_orphan_mysql_end_block(statement: &str) -> bool {
    let body = strip_leading_sql_comments_for_dialect(statement, SplitDialect::Mysql).trim();
    let mut tokens = body.split_whitespace();
    match (tokens.next(), tokens.next(), tokens.next()) {
        (Some(end), Some(kind), None) => {
            end.eq_ignore_ascii_case("END")
                && (kind.eq_ignore_ascii_case("IF")
                    || kind.eq_ignore_ascii_case("WHILE")
                    || kind.eq_ignore_ascii_case("LOOP")
                    || kind.eq_ignore_ascii_case("REPEAT")
                    || kind.eq_ignore_ascii_case("CASE"))
        }
        (Some(end), None, None) => {
            // Bare `END` as its own statement is never valid migration SQL and
            // is the usual artifact of a mid-body BEGIN … END split.
            end.eq_ignore_ascii_case("END")
        }
        _ => false,
    }
}

fn mysql_stored_program_looks_incomplete(statement: &str) -> bool {
    let body = strip_leading_sql_comments_for_dialect(statement, SplitDialect::Mysql);
    if !starts_mysql_stored_program(body) {
        return false;
    }
    // Single-statement routine bodies (no BEGIN block) need no custom delimiter.
    if !contains_sql_word(body, "BEGIN") {
        return false;
    }
    // A complete compound body ends with END or END <label>. Anything else after
    // a CREATE ... BEGIN split is an unsafe mid-body boundary.
    !ends_with_mysql_end(body)
}

fn starts_mysql_stored_program(sql: &str) -> bool {
    let mut tokens = sql.split_whitespace();
    let Some(create) = tokens.next() else {
        return false;
    };
    if !create.eq_ignore_ascii_case("CREATE") {
        return false;
    }

    let mut next = tokens.next();
    if next.is_some_and(|t| t.eq_ignore_ascii_case("OR")) {
        let replace = tokens.next();
        if !replace.is_some_and(|t| t.eq_ignore_ascii_case("REPLACE")) {
            return false;
        }
        next = tokens.next();
    }

    // Skip optional DEFINER=`user`@`host` (may span several whitespace tokens).
    if next.is_some_and(|t| {
        t.eq_ignore_ascii_case("DEFINER")
            || t.eq_ignore_ascii_case("DEFINER=")
            || t.to_ascii_uppercase().starts_with("DEFINER=")
    }) {
        loop {
            next = tokens.next();
            let Some(tok) = next else {
                return false;
            };
            if is_mysql_stored_program_kind(tok) {
                return true;
            }
        }
    }

    next.is_some_and(is_mysql_stored_program_kind)
}

fn is_mysql_stored_program_kind(tok: &str) -> bool {
    tok.eq_ignore_ascii_case("TRIGGER")
        || tok.eq_ignore_ascii_case("PROCEDURE")
        || tok.eq_ignore_ascii_case("FUNCTION")
        || tok.eq_ignore_ascii_case("EVENT")
}

fn contains_sql_word(sql: &str, word: &str) -> bool {
    let bytes = sql.as_bytes();
    let word_bytes = word.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => match scan_single_quoted(sql, i, SplitDialect::Mysql) {
                Ok(next) => i = next,
                Err(_) => return false,
            },
            b'"' => match scan_double_quoted(sql, i, SplitDialect::Mysql) {
                Ok(next) => i = next,
                Err(_) => return false,
            },
            b'`' => match scan_backtick_quoted(sql, i, SplitDialect::Mysql) {
                Ok(next) => i = next,
                Err(_) => return false,
            },
            b'-' if starts_dash_line_comment(bytes, i, SplitDialect::Mysql) => {
                i = scan_line_comment(bytes, i + 2);
            }
            b'#' => i = scan_line_comment(bytes, i + 1),
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                match scan_block_comment(sql, i, SplitDialect::Mysql) {
                    Ok(next) => i = next,
                    Err(_) => return false,
                }
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                i += 1;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                if sql[start..i].eq_ignore_ascii_case(word) && word_bytes.len() == i - start {
                    return true;
                }
            }
            _ => i += 1,
        }
    }
    false
}

fn ends_with_mysql_end(sql: &str) -> bool {
    let trimmed = sql.trim_end();
    if trimmed.is_empty() {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut word_end = end;
    while word_end > 0 && is_ident_byte(bytes[word_end - 1]) {
        word_end -= 1;
    }
    if word_end == end {
        return false;
    }
    let last = &trimmed[word_end..end];
    if last.eq_ignore_ascii_case("END") {
        return true;
    }
    // END <label>
    let mut prev_end = word_end;
    while prev_end > 0 && bytes[prev_end - 1].is_ascii_whitespace() {
        prev_end -= 1;
    }
    let mut prev_start = prev_end;
    while prev_start > 0 && is_ident_byte(bytes[prev_start - 1]) {
        prev_start -= 1;
    }
    if prev_start == prev_end {
        return false;
    }
    let prev = &trimmed[prev_start..prev_end];
    prev.eq_ignore_ascii_case("END")
}

/// Bare SQL words in `statement`, in order, excluding comments, quoted
/// strings/identifiers, and PostgreSQL dollar-quoted bodies.
///
/// Statement classification must use these tokens rather than raw text: the
/// server treats comments as whitespace and never interprets quoted content
/// as keywords, so neither may change how a statement is executed.
fn sql_keyword_tokens(statement: &str, dialect: SplitDialect) -> Vec<&str> {
    let bytes = statement.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let next = match bytes[i] {
            b'\'' => scan_single_quoted(statement, i, dialect),
            b'"' => scan_double_quoted(statement, i, dialect),
            b'`' if dialect.allows_backticks() => scan_backtick_quoted(statement, i, dialect),
            b'-' if starts_dash_line_comment(bytes, i, dialect) => {
                Ok(scan_line_comment(bytes, i + 2))
            }
            b'#' if dialect.allows_hash_line_comments() => Ok(scan_line_comment(bytes, i + 1)),
            b'/' if bytes.get(i + 1) == Some(&b'*') => scan_block_comment(statement, i, dialect),
            b'$' if dialect.allows_dollar_quotes() => {
                let dollar_end = try_scan_dollar_quoted(statement, i);
                dollar_end.map(|end| end.unwrap_or(i + 1))
            }
            b if is_keyword_token_byte(b) => {
                let mut end = i + 1;
                while end < bytes.len() && is_keyword_token_byte(bytes[end]) {
                    end += 1;
                }
                tokens.push(&statement[i..end]);
                Ok(end)
            }
            _ => Ok(i + 1),
        };
        match next {
            Ok(next) => i = next,
            // Statements reaching classification already passed the full-body
            // split, so an unterminated construct cannot occur; stop scanning.
            Err(_) => break,
        }
    }
    tokens
}

/// Non-ASCII bytes continue a word so a keyword embedded in a Unicode
/// identifier is never split out as its own token.
fn is_keyword_token_byte(b: u8) -> bool {
    is_ident_byte(b) || !b.is_ascii()
}

fn token_is(tokens: &[&str], index: usize, keyword: &str) -> bool {
    tokens
        .get(index)
        .is_some_and(|token| token.eq_ignore_ascii_case(keyword))
}

/// The migration runner owns every transaction boundary: the SQLite migration
/// lock is itself a `BEGIN IMMEDIATE` transaction, and PostgreSQL bodies share
/// one runner transaction with their tracking row. A plugin statement that
/// begins, commits, or rolls back a transaction would end that boundary
/// before tracking is recorded (and on SQLite release the cross-process
/// lock), so the full body is rejected before statement one executes.
fn reject_transaction_control_statements(
    statements: &[&str],
    dialect: SplitDialect,
) -> Result<(), SqlStatementSplitError> {
    for statement in statements {
        if let Some(command) = transaction_control_command(statement, dialect) {
            return Err(SqlStatementSplitError::new(
                format!(
                    "custom-plugin migration SQL must not contain transaction-control \
                     statements ({command}); the migration runner owns transaction boundaries"
                ),
                None,
            ));
        }
    }
    Ok(())
}

fn transaction_control_command(statement: &str, dialect: SplitDialect) -> Option<&'static str> {
    let tokens = sql_keyword_tokens(statement, dialect);
    let first = tokens.first()?;
    if first.eq_ignore_ascii_case("BEGIN") {
        return Some("BEGIN");
    }
    if first.eq_ignore_ascii_case("COMMIT") {
        return Some("COMMIT");
    }
    // SQLite `END [TRANSACTION]` and PostgreSQL `END` are COMMIT aliases.
    if first.eq_ignore_ascii_case("END") {
        return Some("END");
    }
    // PostgreSQL `ABORT` is a ROLLBACK alias.
    if first.eq_ignore_ascii_case("ABORT") {
        return Some("ABORT");
    }
    if first.eq_ignore_ascii_case("ROLLBACK") {
        // `ROLLBACK [WORK | TRANSACTION] TO [SAVEPOINT] name` keeps the
        // enclosing transaction open.
        let to_index = if token_is(&tokens, 1, "WORK") || token_is(&tokens, 1, "TRANSACTION") {
            2
        } else {
            1
        };
        if token_is(&tokens, to_index, "TO") {
            return None;
        }
        return Some("ROLLBACK");
    }
    if first.eq_ignore_ascii_case("START") && token_is(&tokens, 1, "TRANSACTION") {
        return Some("START TRANSACTION");
    }
    if dialect == SplitDialect::Postgres
        && first.eq_ignore_ascii_case("PREPARE")
        && token_is(&tokens, 1, "TRANSACTION")
    {
        return Some("PREPARE TRANSACTION");
    }
    if dialect == SplitDialect::Mysql && first.eq_ignore_ascii_case("XA") {
        return Some("XA");
    }
    None
}

/// Whether any statement requires PostgreSQL top-level (non-transactional) execution.
///
/// Classification reads SQL keyword tokens only, so keywords inside comments
/// or quoted text never select (or suppress) top-level execution.
pub fn statements_require_non_transactional_postgres(db_type: &str, statements: &[&str]) -> bool {
    if db_type != "postgres" {
        return false;
    }
    statements
        .iter()
        .any(|statement| postgres_statement_requires_top_level(statement))
}

fn postgres_statement_requires_top_level(statement: &str) -> bool {
    let tokens = sql_keyword_tokens(statement, SplitDialect::Postgres);
    let at = |index: usize, keyword: &str| token_is(&tokens, index, keyword);
    let concurrently = tokens
        .iter()
        .any(|token| token.eq_ignore_ascii_case("CONCURRENTLY"));
    at(0, "VACUUM")
        || (at(0, "CREATE") && at(1, "DATABASE"))
        || (at(0, "DROP") && at(1, "DATABASE"))
        || (at(0, "ALTER") && at(1, "SYSTEM"))
        || (at(0, "REINDEX") && concurrently)
        || (at(0, "CREATE") && at(1, "INDEX") && concurrently)
        || (at(0, "CREATE") && at(1, "UNIQUE") && at(2, "INDEX") && concurrently)
        || (at(0, "DROP") && at(1, "INDEX") && concurrently)
}
