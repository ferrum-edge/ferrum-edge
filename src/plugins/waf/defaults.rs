use super::rules::{
    DefaultActionPolicy, MatchKind, QueryScanMirror, RuleAction, RuleTarget, Severity, WafRule,
};

/// Tightened XSS event-handler attribute list. The original `on[a-z]{3,32}=`
/// matched benign fields like `online=`/`onset=`; this enumerates real DOM
/// event handlers so the rule is safe to enforce.
const EVENT_HANDLER: &str = r"(?i)\bon(?:error|load|click|dblclick|mouseover|mouseout|mousemove|mousedown|mouseup|focus|focusin|blur|submit|change|input|keydown|keyup|keypress|abort|beforeunload|contextmenu|drag|dragstart|dragend|dragover|drop|toggle|wheel|pointerdown|pointerup|pointermove|pointerover|touchstart|touchend|touchmove|animationstart|animationend|transitionend|hashchange|popstate|message|scroll|resize|select|reset|copy|cut|paste)\s*=";

/// Level-1 SQLi signatures shared by query and body rules. Keeping one pattern
/// per attack shape prevents the body mirrors from drifting broader than the
/// established query-side false-positive posture: the `-B` mirrors reuse these
/// exact patterns, so the separator below is the only widening they receive.
///
/// SQL engines treat an inline `/*…*/` comment as token whitespace, so
/// `UNION/**/SELECT` and `;/**/DROP` are accepted by MySQL, PostgreSQL and
/// MSSQL while a plain `\s` class cannot match them. The layered decoder never
/// sees these payloads either — `has_decodable_marker` triggers only on `%`,
/// `+`, `\` and `&`, none of which a `/**/` payload has to contain — so the
/// separator has to live in the pattern itself. Every SQL token boundary in
/// these three signatures therefore uses the shared shape
///
/// ```text
/// (?:\s|/\*(?s:.){0,64}?\*/)
/// ```
///
/// written out inline in each pattern (Rust `const` concatenation is not worth
/// the ceremony here) — keep the three copies identical. `(?s:.)` makes the
/// comment body newline-tolerant; the `{0,64}?` bound keeps the compiled
/// finite-automaton program bounded, matching the house style of the other
/// bounded patterns in this file, which range `{0,80}`..`{1,200}`
/// (`FE-JNDI-002-*`, `FE-CMD-003`, `FE-SSTI-001`). The bound is deliberately
/// small: it is not a security parameter, because an attacker who cares can
/// always write one more comment character at *any* bound. What it does buy is
/// a narrow false-positive window between the two SQL tokens, and a compiled
/// program in line with what this `RegexSet` already carries — the separator
/// appears five times across the three signatures in each of the query and body
/// sets, and these sets are built once and matched on the request path. A
/// comment body longer than 64 characters is the accepted residual: the "any
/// comment token" catch-alls `FE-SQLI-004` (query) and `FE-SQLI-004-B` (body)
/// cover it at paranoia 2, where their false-positive cost is acceptable.
const SQLI_UNION_SELECT: &str =
    r"(?i)\bunion(?:\s|/\*(?s:.){0,64}?\*/)+(?:all(?:\s|/\*(?s:.){0,64}?\*/)+)?select\b";
/// The `||` branch accepts *zero* separators so the canonical unspaced
/// `1'||1=1` matches; the `or` branch keeps requiring at least one so a token
/// like `orX` cannot hit.
const SQLI_BOOLEAN_TAUTOLOGY: &str = r#"(?i)(?:\bor\b(?:\s|/\*(?s:.){0,64}?\*/)+|\|\|(?:\s|/\*(?s:.){0,64}?\*/)*)['"]?\d+['"]?\s*=\s*['"]?\d+"#;
const SQLI_STACKED_STATEMENT: &str =
    r"(?i);(?:\s|/\*(?s:.){0,64}?\*/)*(?:drop|insert|update|delete|alter)\b";

/// High-confidence query prototype-pollution tokens. Query keys and values
/// each get a rule because they are separate WAF targets; every mirror runs
/// after bounded query-component decoding.
const PROTOTYPE_POLLUTION_PROTO: &str = r"(?i)__proto__";
const PROTOTYPE_POLLUTION_CONSTRUCTOR: &str =
    r"(?i)constructor\s*(?:\.\s*prototype|\[\s*prototype\s*\])";

/// Time-delay (blind) SQL injection probes, claimed by `FE-SQLI-006` (query,
/// level 1) and its exact body mirror `FE-SQLI-006-B` (level 2). Automated
/// tools lean on these because they need no reflected output: MySQL
/// `SLEEP(n)` / `BENCHMARK(n, …)`, PostgreSQL `pg_sleep(n)`, MSSQL
/// `WAITFOR DELAY '0:0:5'`, Oracle `dbms_lock.sleep` /
/// `dbms_pipe.receive_message`, and SQLite `randomblob` amplification.
///
/// `sleep(n)` is also ordinary application code (`time.sleep(1)`,
/// `await sleep(100)`), so that one alternative requires SQL-shaped context
/// directly in front of it: the start of the value, a quote, `(`, `,`, `;`,
/// `=`, `|`, `&`, or an SQL keyword, optionally followed by the same
/// whitespace-or-bounded-comment separator the level-1 signatures above use.
/// A method call (`.sleep(`) never qualifies. A number followed by an
/// arithmetic, comparison, or bitwise operator (`1-sleep(5)`, `1*sleep(5)`,
/// `1+sleep(5)`) is the numeric-context probe; the number must open the
/// value or directly follow a quote or `&`, where an injected expression
/// starts, so `room 1-sleep(5)` stays clean while the body mirror still sees
/// the probe inside a JSON string (`{"id":"1-sleep(5) and 1=1"}`). The
/// remaining alternatives name database-specific functions that are not
/// general-purpose code.
///
/// That context is tight enough for a query value but not for a request body
/// that carries source code: `foo();\n sleep(1);`, `x = sleep(5)`,
/// `(sleep(1))`, and `benchmark(1000, fn)` are all ordinary code. The body
/// mirror is therefore level 2, and level-1 body coverage comes from
/// `SQLI_TIME_DELAY_SQL_CONTEXT`.
const SQLI_TIME_DELAY: &str = r#"(?i)(?:(?:^|[(,;='"|&]|\b(?:and|or|xor|select|union|where|having|if|then|else|when)\b|(?:^|['"&])[\s(]*-?[0-9]{1,20}(?:\.[0-9]{1,20})?\s*[-+*/%^|&<>=]{1,2}\(*)(?:\s|/\*(?s:.){0,64}?\*/)*(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)|\bbenchmark\s*\(\s*\d+\s*,|\bwaitfor(?:\s|/\*(?s:.){0,64}?\*/)+(?:delay|time)(?:\s|/\*(?s:.){0,64}?\*/)*['"]\d|\bdbms_(?:lock\.sleep|pipe\.receive_message)\s*\(|\brandomblob\s*\(\s*\d{6,})"#;

/// Level-1 body time-delay signature, claimed by `FE-SQLI-010-B`. `sleep(n)`
/// counts only where no general-purpose language puts it: after an SQL
/// keyword (`AND`, `OR`, `XOR`, `SELECT`, `UNION`, `WHERE`, `HAVING`, `THEN`,
/// `RLIKE`, `ORDER BY`), after a closing quote and an SQL operator
/// (`'+sleep(5)+'`, `'||sleep(5)`), or as a branch of `IF(…, sleep(n), …)`.
///
/// Three unquoted shapes are also level 1, each anchored where source code
/// does not put a delay call:
///
/// * a later item of an `ORDER BY` / `GROUP BY` list (`ORDER BY 1,sleep(5)`,
///   `ORDER/**/BY 1/**/,sleep(5)`);
/// * a value that is nothing but a number, an arithmetic, comparison, or
///   bitwise operator, and the call (`1-sleep(5)`, `"1*sleep(5)"`,
///   `"1=sleep(5)"`): it opens the body, a quoted string, or an `&`-separated
///   field, and ends at the closing quote, `&`, the end of the body, or an SQL
///   comment (`--`, `#`, `/*`);
/// * a form-encoded pair whose whole value is the call, optionally behind the
///   same number and operator (`id=sleep(5)`, `id=1-sleep(5)`,
///   `a=1&id=sleep(5)&b=2`): the pair must open the body or follow `&`, and the
///   value must end at `&`, the end of the body, or an SQL comment (`--`, `#`,
///   `/*`). A JSON body never opens with `key=`, and a code line such as
///   `x=sleep(5);` does not end its value there.
///
/// Precision wins over recall here because the level-2 `FE-SQLI-006-B` is the
/// backstop. An assignment inside code (`x = sleep(5)`, compact
/// `x=1+sleep(5)` inside a JSON string), a spreadsheet formula
/// (`"=2*sleep(1)"`), a statement (`foo(); sleep(1);`), and a method call
/// (`time.sleep(1)`) stay clean; so does a JSON string whose whole value is
/// `sleep(5)`, which only the level-2 `FE-SQLI-006-B` claims. A delay call
/// followed by more SQL (`id=sleep(5) and 1=1`, `{"id":"1-sleep(5) and 1=1"}`)
/// is likewise left to level 2.
///
/// `BENCHMARK` needs an SQL function as its expression (`MD5(`, `SHA1(`, a
/// subquery), so `benchmark(1000, fn)` stays clean. `pg_sleep`,
/// `WAITFOR DELAY`, the Oracle `dbms_*` calls, and `randomblob` are
/// database-specific and keep the query rule's shape.
const SQLI_TIME_DELAY_SQL_CONTEXT: &str = r#"(?i)(?:\b(?:and|or|xor|select|union|where|having|then|rlike|by)\b(?:\s|/\*(?s:.){0,64}?\*/|\()*sleep\s*\(\s*\d+(?:\.\d+)?\s*\)|['"](?:\s|/\*(?s:.){0,64}?\*/)*(?:\|\||&&|[-+*=^])(?:\s|/\*(?s:.){0,64}?\*/|\()*sleep\s*\(\s*\d+(?:\.\d+)?\s*\)|\bif\s*\([^;]{0,64}?,(?:\s|/\*(?s:.){0,64}?\*/)*sleep\s*\(\s*\d+(?:\.\d+)?\s*\)|\b(?:order|group)(?:\s|/\*(?s:.){0,64}?\*/)+by(?:\s|/\*(?s:.){0,64}?\*/)[0-9a-z_.`\s,/*]{0,64},(?:\s|/\*(?s:.){0,64}?\*/|\()*sleep\s*\(\s*\d+(?:\.\d+)?\s*\)|(?:^|[&'"])[\s(]*-?[0-9]{1,20}(?:\.[0-9]{1,20})?\s*[-+*/%^|&<>=]{1,2}(?:\s|/\*(?s:.){0,64}?\*/|\()*sleep\s*\(\s*\d+(?:\.\d+)?\s*\)[\s)]*(?:(?:--|#|/\*)[^&'"]{0,32})?(?:[&'"]|$)|(?:^|&)[0-9a-z_.\[\]-]{1,64}=[\s(]*(?:-?[0-9]{1,20}(?:\.[0-9]{1,20})?\s*[-+*/%^|&<>=]{1,2}(?:\s|/\*(?s:.){0,64}?\*/|\()*)?sleep\s*\(\s*\d+(?:\.\d+)?\s*\)[\s)]*(?:(?:--|#|/\*)[^&]{0,32})?(?:&|$)|\bpg_sleep\s*\(\s*\d|\bbenchmark\s*\(\s*\d+\s*,\s*(?:(?:md5|sha1?|sha2|encode|aes_encrypt|compress|concat|rand|char)\s*\(|\(\s*select\b)|\bwaitfor(?:\s|/\*(?s:.){0,64}?\*/)+(?:delay|time)(?:\s|/\*(?s:.){0,64}?\*/)*['"]\d|\bdbms_(?:lock\.sleep|pipe\.receive_message)\s*\(|\brandomblob\s*\(\s*\d{6,})"#;

/// Database catalog enumeration, claimed by `FE-SQLI-007` and its body
/// mirror. Only catalog objects that ordinary application traffic never
/// names: dotted `information_schema.` / `pg_catalog.` access, `pg_shadow`,
/// SQLite's `sqlite_master`, the MSSQL `sys*` system tables and `sys.*`
/// catalog views, and the Oracle dictionary views an attacker enumerates.
/// Bare words that double as ordinary JSON keys (`all_users`, `user_tables`,
/// `mysql.user` as a dotted config key) are deliberately excluded.
const SQLI_SCHEMA_ENUMERATION: &str = r"(?i)(?:\binformation_schema(?:\s|/\*(?s:.){0,64}?\*/)*\.|\bpg_catalog\s*\.|\bpg_shadow\b|\bsqlite_(?:master|schema|temp_master)\b|\b(?:sysobjects|syscolumns|sysdatabases|syslogins|msysobjects)\b|\bsys\.(?:objects|tables|columns|databases|sql_logins|server_principals)\b|\b(?:all_tab_columns|user_tab_columns|dba_users|dba_tables)\b)";

/// Error-based extraction and out-of-band / host-access SQL primitives,
/// claimed by `FE-SQLI-008` and its body mirror: MySQL `extractvalue` /
/// `updatexml` / `load_file` / `INTO OUTFILE`, MSSQL `xp_*` / `sp_OA*` /
/// `OPENROWSET`, Oracle `utl_http` / `utl_inaddr` / `dbms_java`, and
/// PostgreSQL large-object file access.
///
/// `load_file` is also an ordinary function name (`def load_file(path):`,
/// `loader.load_file('/etc/app.conf')`), so it counts only as a bare call
/// whose argument is what MySQL reads: a quoted absolute or UNC path, a hex
/// literal in either spelling (`0x2f65…`, `X'2f65…'`), either of those behind
/// a charset introducer (`_latin1'/etc/passwd'`, `_binary 0x2f65…`), or a
/// `CHAR(` / `CONCAT(` / `CONCAT_WS(` / `UNHEX(` / `FROM_BASE64(` expression.
/// The argument may follow the level-1 whitespace-or-bounded-comment
/// separator, so `load_file(/**/'/etc/passwd')` counts. A method or
/// associated-function call (`.load_file(`, `->load_file(`, `::load_file(`)
/// never qualifies. A user-variable argument (`load_file(@v)`) is not matched:
/// Ruby writes `load_file(@path)` as ordinary code.
const SQLI_ERROR_OR_OOB_FUNCTION: &str = r#"(?i)(?:\b(?:extractvalue|updatexml)\s*\(|(?:^|[^.\w$>:])load_file\s*\((?:\s|/\*(?s:.){0,64}?\*/)*(?:(?:_[a-z0-9]{2,16}\s*)?(?:0x[0-9a-f]{2,}|x'[0-9a-f]{2,}|['"](?:/|\\\\|[a-z]:[\\/]))|(?:char|concat(?:_ws)?|unhex|from_base64)\s*\()|\binto(?:\s|/\*(?s:.){0,64}?\*/)+(?:out|dump)file\b|\bxp_(?:cmdshell|dirtree|regread|fileexist|subdirs)\b|\bsp_(?:oacreate|oamethod|execute_external_script)\b|\bopenrowset\s*\(|\butl_(?:http\.request|inaddr\.get_host_(?:address|name)|file\.fopen)\b|\bdbms_(?:java\.runjava|xmlquery|scheduler\.create_job)\b|\blo_(?:import|export)\s*\()"#;

/// Quoted-string tautology (`' or 'a'='a`, `'or'1'='1`, `" || ""="`),
/// claimed by `FE-SQLI-009` and its body mirror. `FE-SQLI-002` covers the
/// numeric form; this is the string-literal shape, including the unspaced
/// variant that `FE-SQLI-002`'s mandatory separator after `or` cannot see.
/// Uses the level-1 whitespace-or-bounded-comment separator.
///
/// The `=` comparison is SQL-only syntax, but `like` is an English word:
/// `'soda' or 'pop' like 'grandma'` is prose. A `like` comparison therefore
/// counts only when its right-hand string has the shape of an injection
/// rather than a closed quotation: it opens with a `%` / `_` wildcard
/// (`' or 'a' like '%`), it is left unterminated for the application's own
/// closing quote — the value ends inside it, or a JSON string closes it
/// (`' or 'a' like 'a`) — or it is followed by an SQL comment
/// (`' or 'a' like 'a'--`). Closing parentheses, a statement `;`, and a
/// `LIMIT n` / `LIMIT n, m` clause may sit between the string and the comment
/// (`' or 'a' like 'a')--`, `' or 'a' like 'a';--`,
/// `' or 'a' like 'a' limit 1--`).
///
/// A closed right operand may also continue into a boolean tail that ends in
/// one of those injection-shaped strings: an `and` / `or` / `xor` / `&&` /
/// `||` operator, then up to six further operators, `not`s, closed strings,
/// numbers, or `true` / `false` / `null` (parentheses and bounded comments
/// may separate them), then optionally a `column <op>` comparison, and
/// finally an unterminated or comment-terminated string
/// (`' or 'a' like 'a' or 'x`, `' or 'a' like 'a' or 'b' or 1 or 'x`,
/// `' or 'a' like 'a' and user<>'x`, `' or 'a' like 'a') or ('x`). A tail
/// whose last string is closed (`'pop' like 'grandma' or 'grandpa' says?`)
/// remains prose.
const SQLI_STRING_TAUTOLOGY: &str = r#"(?i)['"](?:\s|/\*(?s:.){0,64}?\*/)*(?:\bor\b|\|\|)(?:\s|/\*(?s:.){0,64}?\*/)*['"][^'"]{0,32}['"](?:\s|/\*(?s:.){0,64}?\*/)*(?:=(?:\s|/\*(?s:.){0,64}?\*/)*['"]|\blike\b(?:\s|/\*(?s:.){0,64}?\*/)*(?:['"][%_]|'[^'"]{0,32}(?:"|$|'?[\s);]*(?:\blimit\s+\d+(?:\s*,\s*\d+)?[\s);]*)?(?:--|#|/\*))|"[^'"]{0,32}(?:$|"?[\s);]*(?:\blimit\s+\d+(?:\s*,\s*\d+)?[\s);]*)?(?:--|#|/\*))|(?:'[^'"]{0,32}'|"[^'"]{0,32}")(?:[\s()]|/\*(?s:.){0,64}?\*/)*(?:\band\b|\bor\b|\bxor\b|&&|\|\|)(?:(?:[\s()]|/\*(?s:.){0,64}?\*/)*(?:(?:\band\b|\bor\b|\bxor\b|&&|\|\|)|\bnot\b|'[^'"]{0,32}'|"[^'"]{0,32}"|\d{1,16}\b|\b(?:true|false|null)\b)){0,6}(?:[\s()]|/\*(?s:.){0,64}?\*/)*(?:\w{1,32}\s*(?:<>|[<>!]?=|[<>]|\blike\b)\s*)?(?:'[^'"]{0,32}(?:"|$|'?[\s);]*(?:\blimit\s+\d+(?:\s*,\s*\d+)?[\s);]*)?(?:--|#|/\*))|"[^'"]{0,32}(?:$|"?[\s);]*(?:\blimit\s+\d+(?:\s*,\s*\d+)?[\s);]*)?(?:--|#|/\*)))))"#;

/// Script-capable URL schemes, claimed by `FE-XSS-002` and its body / cookie
/// mirrors. Browsers delete ASCII tab, LF, and CR anywhere inside a URL before
/// parsing its scheme (WHATWG URL "remove all ASCII tab or newline"), so
/// `java&#x09;script:` and `jav%0Aascript:` both execute; the character class
/// between letters is exactly that set, not general whitespace, so prose such
/// as "java script: a primer" is not widened into a match. `vbscript:` is the
/// legacy IE equivalent.
const SCRIPT_URL_SCHEME: &str = r"(?i)(?:j[\t\n\r]*a[\t\n\r]*v[\t\n\r]*a[\t\n\r]*s[\t\n\r]*c[\t\n\r]*r[\t\n\r]*i[\t\n\r]*p[\t\n\r]*t|v[\t\n\r]*b[\t\n\r]*s[\t\n\r]*c[\t\n\r]*r[\t\n\r]*i[\t\n\r]*p[\t\n\r]*t)[\t\n\r]*\s*:";

/// Active-content HTML elements that have no place in a query parameter,
/// claimed by `FE-XSS-006-Q` (level 1) and its body mirror (level 2, where
/// CMS and rich-text APIs legitimately carry markup). Complements the
/// script-tag, event-handler, and URL-scheme signatures: `<base href>`
/// hijacks relative URLs, `<meta http-equiv=refresh>` redirects, and
/// `<svg>`/`<math>`/`<object>`/`<embed>`/frames are the usual script-less
/// XSS carriers. The element name must follow `<` directly, exactly as an
/// HTML tokenizer requires, so prose such as `a < svg` is not a tag.
const HTML_ACTIVE_CONTENT_ELEMENT: &str =
    r"(?i)<(?:iframe|frame|frameset|object|embed|applet|base|meta|link|svg|math|isindex)\b";

/// Command execution without a classic `;cmd` chain, claimed by
/// `FE-CMD-004` (query values). Each shape is chosen so that ordinary
/// delimited lists (`tags=linux;bash`, `skills=bash|pwsh`,
/// `fields=id|uname`) and multi-line prose (`Order%0AID: 12345`,
/// `%0ACat food`) stay clean:
///
/// * a backtick or `$(` subshell running a common command;
/// * a CR/LF command separator (`%0a`) followed by a Windows tool name in
///   all-lower or all-upper case (`whoami`, `IPCONFIG`). `cmd.exe` and
///   PowerShell resolve commands in any case, so a mixed-case `Whoami`,
///   `Ipconfig`, `Certutil`, or `Systeminfo` also counts when it ends the
///   value, carries `.exe`, takes a flag (`Certutil /urlcache`), or is
///   followed by one of the shell operators listed below other than `#`. A
///   mixed-case `PowerShell` / `Pwsh` counts only with `.exe`, a flag
///   (`PowerShell -nop`), or `iex` / `invoke-` (`Powershell IEX(…)`): a bare
///   launch runs no attacker command, so a prose list ending in
///   `PowerShell`, a table row `PowerShell | …`,
///   `PowerShell is great`, and `PowerShell - a primer` stay clean. Being
///   piped into (`x | PowerShell -c …`) is covered by the operator shapes
///   below;
/// * the same separator followed by a Unix tool name in the lower case a Unix
///   shell requires, or by a short command word (`cat`, `id`, `sh`, `nc`,
///   `bash`, `python`, `perl`) in lower case that then ends the value, takes
///   an argument shaped like a flag, path, variable, or quoted string, or is
///   followed by a shell operator. The operator must be one prose does not
///   write after a word: `;`, `|`, `&`, `<`, `>`, or a backtick directly
///   against the word (`cat|nc`); `&&`, `|`, `||`, `;`, or a backtick after a
///   space; a `#` comment, against the word or after a space, that ends the
///   value or is followed by a non-digit (`id#`, `id #`, `id #x`, the form a
///   POSIX shell treats as a comment); a spaced `&` that ends the value
///   (`id &`); or a redirect onto a path, descriptor, or variable
///   (`cat > /tmp/x`). A spaced `&` followed by more text (`cat & dog`,
///   `cat &amp; dog`) and a numbered item (`cat #1`) are prose;
/// * `;`, `|`, `&&`, or `||` followed by a reconnaissance tool that never
///   names a list item (`whoami`, `ifconfig`, `certutil`, `mkfifo`, …);
/// * `&&` or `||` — which lists do not use — followed by a tool that can also
///   be a list item (`uname`, `busybox`, `powershell`, `pwsh`, `socat`, `id`,
///   `ls`, `sleep`, `ping`, …), or `;` / `|` followed by one of those tools
///   only when it takes a flag, path, or quoted argument, redirects, or
///   chains again;
/// * `;` or `|` followed by an argument shape a list never has: `busybox`
///   running a network or shell applet (`nc`, `wget`, `sh`, `ash`,
///   `telnet`), `socat` with a `tcp` / `udp` / `exec` / `-` address, or
///   `ncat` / `netcat` / `nc` given a host and a port;
///
/// plus the `$IFS` field-separator trick used to smuggle spaces. A bare
/// `x;uname` at the end of a value is indistinguishable from the list
/// `fields=id;uname` and is deliberately not matched.
const CMD_EXTENDED_EXECUTION: &str = r#"(?i)(?:(?:`|\$\()\s*(?:cat|tac|head|tail|ls|id|echo|printf|rm|ping|sleep|env|pwd|uname|whoami|curl|wget|nc|ncat|bash|sh|zsh|python[23]?|perl|ruby|php|base64|xxd|nslookup|dig|ifconfig)\b|[\r\n]\s*(?:(?-i:whoami|ipconfig|certutil|powershell|pwsh|systeminfo|WHOAMI|IPCONFIG|CERTUTIL|POWERSHELL|PWSH|SYSTEMINFO)\b|(?:whoami|ipconfig|certutil|systeminfo)(?:\.exe\b|\s*$|[;|&<>`]|\s*(?:&&|\|\|?|;|`)|\s*&\s*$|\s*[<>]{1,2}\s*[/~.$&]|\s+[-/][a-z])|(?:powershell|pwsh)(?:\.exe\b|\s+[-/][a-z]|\s+(?:iex\b|invoke-))|(?-i:uname|ifconfig|nslookup|wget|curl|ncat)\b|(?-i:cat|id|sh|nc|bash|python[23]?|perl)(?:\s*$|[;|&<>`]|\s*(?:&&|\|\|?|;|`)|\s*#(?:[^0-9]|$)|\s*&\s*$|\s*[<>]{1,2}\s*[/~.$&]|\s+[-/.~$'"]))|(?:[;|]|&&)\s*(?:whoami|ifconfig|ipconfig|nslookup|certutil|bitsadmin|systeminfo|tasklist|mkfifo)\b|(?:&&|\|\|)\s*(?:uname|busybox|ncat|netcat|socat|powershell|pwsh|id|ls|sleep|ping)\b|[;|]\s*(?:uname|busybox|ncat|netcat|socat|powershell|pwsh)(?:\s+[-/$'"]|\s*[<>`]|\s*&&|\s*\|\|)|[;|]\s*(?:busybox\s+(?:nc|wget|sh|ash|telnet)\b|socat\s+(?:tcp|udp|exec|-)|(?:ncat|netcat|nc)\s+\S+\s+\d{1,5}\b)|\$\{?IFS\}?)"#;

/// Explicit shell / interpreter invocation, claimed by `FE-CMD-005-Q`
/// (level 1) and `FE-CMD-005-B` (level 2, because deployment and CI APIs
/// legitimately carry scripts): absolute shell paths, `cmd /c`,
/// `powershell -enc`, and `sh -c` / `python -c` / `perl -e` one-liners.
const CMD_INTERPRETER_INVOCATION: &str = r"(?i)(?:/bin/(?:ba|z|da|k|c|tc)?sh\b|/usr/bin/(?:env|perl|python[23]?|ruby|php|wget|curl|nc|ncat|socat|id|whoami)\b|\bcmd(?:\.exe)?\s+/[ck]\s|\bpowershell(?:\.exe)?\s+[-/](?:e(?:nc(?:odedcommand)?)?|c(?:ommand)?|nop(?:rofile)?|w(?:indowstyle)?|ep|exec(?:utionpolicy)?|noni(?:nteractive)?)\b|\b(?:ba|z)?sh\s+-c\s|\bpython[23]?\s+-c\s|\b(?:perl|ruby)\s+-e\s|\bphp\s+-r\s)";

/// Shellshock (CVE-2014-6271): bash imports an environment variable whose
/// value *begins* with a function definition. CGI copies each header into an
/// `HTTP_*` variable and the query string into `QUERY_STRING`, so the value
/// must start with `() {`; anchoring on the start keeps ordinary JavaScript
/// (`function() {`) out of it.
const SHELLSHOCK_FUNCTION_DEFINITION: &str = r"^\s*\(\s*\)\s*\{";

/// OGNL expression injection (Apache Struts 2: CVE-2017-5638 via the
/// `Content-Type` header, CVE-2018-11776, and the S2-0xx family), claimed by
/// `FE-OGNL-001-{B,Q,H}`. Every alternative is an OGNL-only construct:
/// `#_memberAccess`, the `OgnlContext` default-member-access handle, static
/// `@java.lang.X@` calls, `#context['…']`, and the `%{(#` expression opener.
const OGNL_EXPRESSION: &str = r#"(?i)(?:#_?memberaccess\b|\bognl\s*\.\s*ognlcontext\b|@java\.lang\.[a-z]+@|#context\s*\[\s*['"]|%\{\s*\(\s*#)"#;

/// PHP code injection, claimed by `FE-PHP-001-Q` (level 1) and
/// `FE-PHP-001-B` (level 2): an opening `<?php` / `<?=` tag, or a
/// code-execution function called on request superglobals, a decoding
/// helper, or a string literal.
const PHP_CODE_INJECTION: &str = r#"(?i)(?:<\?(?:php\b|=)|\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|create_function|call_user_func(?:_array)?)\s*\(\s*(?:\$_(?:get|post|request|cookie|server|files|env)\b|(?:base64_decode|str_rot13|gzinflate|gzuncompress|hex2bin|chr)\s*\(|['"`]))"#;

/// PHP stream wrappers that turn file-access sinks into code execution or
/// arbitrary reads (`php://input`, `phar://` deserialization, `zip://`,
/// `data://text/plain`), claimed by `FE-PHP-002-Q` (level 1) and
/// `FE-PHP-002-B` (level 2, because PHP source reads its own request body
/// through `file_get_contents('php://input')` and buffers through
/// `php://temp` / `php://memory`). `php://filter` and `expect://` are already
/// claimed by `FE-LFI-001`.
const PHP_STREAM_WRAPPER: &str = r"(?i)\b(?:php://(?:input|fd|memory|temp|stdin)|phar://|zip://|compress\.(?:zlib|bzip2)://|glob://|data://text/plain)";

/// Node.js code execution / sandbox escape, claimed by `FE-NODE-001-Q`
/// (level 1) and `FE-NODE-001-B` (level 2, where code-hosting APIs
/// legitimately carry source).
const NODE_CODE_INJECTION: &str = r#"(?i)(?:\brequire\s*\(\s*['"`](?:node:)?(?:child_process|vm)['"`]\s*\)|\bprocess\s*\.\s*(?:mainmodule\b|binding\s*\(|dlopen\s*\()|\bchild_process\s*\)?\s*\.\s*(?:exec|execsync|execfile|spawn|spawnsync|fork)\s*\(|\bconstructor\s*\.\s*constructor\s*\(\s*['"`]|\bglobal\s*\.\s*process\s*\.\s*mainmodule\b)"#;

/// HTTP response splitting / header injection through a query value that an
/// application reflects into a response header (redirect targets, download
/// names), claimed by `FE-CRLF-001`. Query values are percent-decoded before
/// matching, so `%0d%0aSet-Cookie:` is seen as CR LF `Set-Cookie:`.
const CRLF_HEADER_INJECTION: &str = r"(?i)[\r\n][\t ]*(?:set-cookie|location|refresh|link|content-(?:type|length|disposition|security-policy)|access-control-allow-[a-z-]+|transfer-encoding|x-xss-protection)[\t ]*:|[\r\n][\t ]*http/\d(?:\.\d)?[\t ]+\d{3}\b";

/// Requests for version-control metadata, credential stores, and server
/// configuration files, claimed by `FE-RESTRICTED-001`. Matched against the
/// canonical policy path, which has already decoded `%2e` and refused dot
/// segments, so `/%2egit/config` is seen as `/.git/config`. `wp-config.php`
/// matches together with its backup and editor-swap copies
/// (`wp-config.php.bak`, `wp-config.php~`, `.wp-config.php.swp`), because
/// those serve the database password as plain text. `.well-known`,
/// `.github`, and `.gitignore` are deliberately not matched.
const RESTRICTED_FILE_ACCESS: &str = r"(?i)/(?:\.(?:git|svn|hg|bzr|cvs)(?:/|$)|\.env(?:\.[a-z0-9_-]+)*$|\.ht(?:access|passwd|digest)$|\.(?:aws|ssh|docker|kube|gnupg|azure)/|\.config/gcloud/|\.(?:npmrc|pypirc|netrc|pgpass|git-credentials|gitconfig|bash_history|zsh_history|mysql_history|psql_history|ds_store)$|web\.config$|\.?wp-config\.php(?:[.~_-][a-z0-9~._-]*)?$|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$)";

/// Backup, editor-swap, and database-dump artifacts, claimed by
/// `FE-RESTRICTED-002` at level 2 (file-serving applications legitimately
/// publish `.sql` or `.db` downloads).
const RESTRICTED_BACKUP_ARTIFACT: &str =
    r"(?i)(?:\.(?:bak|backup|old|orig|save|sav|swp|swo|tmp|sql|sqlite3?|db|dump|mdb|accdb)|~)$";

/// A multipart `Content-Disposition` `filename` / `filename*` parameter naming
/// a server-executable script, including double extensions (`shell.php.jpg`)
/// that permissive handler mappings still execute. Claimed by
/// `FE-UPLOAD-001`; it only sees multipart bodies when `inspect_multipart` is
/// enabled.
///
/// The parameter must sit on a `Content-Disposition:` line, so a form or JSON
/// field that merely names a file (`filename=index.php`) is not an upload.
/// An RFC 8187 `filename*` value opens with a charset and an optional
/// language tag (`UTF-8''shell.php`, `ISO-8859-1''shell.php`,
/// `UTF-8'en_US'shell.php`). Lenient parsers split that prefix on `'` without
/// checking the charset or tag, so the pattern skips a charset of any length
/// and a tag of any length, each made of any characters except a quote, `;`,
/// or a line break — a looser shape than the RFC token grammar, and no charset
/// name list. A percent-encoded name (`UTF-8''shell%2Ephp`) matches through
/// the decoded body view the layered decoder already scans.
/// Windows and IIS strip trailing dots and spaces and treat `::$DATA` as the
/// file's default stream, and a NUL (raw or `%00`) truncates the name in
/// C-backed handlers, so `shell.php.`, `shell.php `, `shell.php::$DATA`, and
/// `shell.php%00.jpg` all land as `shell.php` and all match. The header-line,
/// `filename*` prefix, and parameter-token repeats are unbounded but each is
/// confined by its class: an unbounded class loop compiles to a single
/// automaton state where a counted `{0,N}` repeat compiles to N, and a length
/// bound would let a padded name slip past.
const EXECUTABLE_UPLOAD_FILENAME: &str = r#"(?i)\bcontent-disposition\s*:[^\r\n]*?\bfilename\*?\s*=\s*(?:[^'"\r\n;]+'[^'"\r\n;]*'|["'])?[^"';\r\n]*?\.(?:php[3-8s]?|pht(?:ml)?|phar|jspx?|jspf|jsw|jsv|aspx?|asa|asax|ascx|ashx|asmx|cshtml|vbhtml|cgi|shtml|htaccess)(?:\.[a-z0-9]{1,8})*[. ]*(?:::\$data)?(?:["';\r\n\x00]|%00|$)"#;

/// Unsafe YAML / serializer language tags that instantiate arbitrary types
/// (PyYAML `!!python/object/apply`, SnakeYAML CVE-2022-1471 gadgets, Psych
/// `!ruby/object`), claimed by `FE-DESER-004`.
const YAML_GADGET_TAG: &str = r"(?i)(?:!!(?:python/(?:object(?:/apply|/new)?|name|module)|javax\.script\.scriptenginemanager|java\.net\.urlclassloader|com\.sun\.rowset\.jdbcrowsetimpl|org\.springframework\.)|!ruby/(?:object|hash|struct):|\btag:yaml\.org,2002:python/)";

/// A polymorphic-type discriminator (`@type`, `$type`, `@class`, `__type`)
/// naming a JDK / framework / .NET gadget namespace, claimed by
/// `FE-DESER-005` (Fastjson autoType, Jackson default typing, Json.NET
/// `TypeNameHandling`). JSON-LD's `"@type": "Person"` and application-owned
/// type names are unaffected; only the known gadget namespaces are listed.
///
/// Fastjson's autoType check is bypassed by JVM descriptor spellings it
/// strips before loading the class (`"Lcom.sun.rowset.JdbcRowSetImpl;"`,
/// `"LLcom…;;"`, and the array form `"[com…"`), so up to three leading `L` /
/// `[` characters are accepted before the namespace. The second branch is
/// Jackson's `WRAPPER_ARRAY` default typing, `["com.sun…", {…}]`, which carries
/// no discriminator key: a gadget class name as the first array element
/// followed by the object it types. Keep the namespace lists of the
/// discriminator branch and this object form identical.
///
/// The same wrapper also types a gadget built from one string through its
/// single-String constructor — the CVE-2017-17485 Spring payload
/// `["org.springframework.context.support.FileSystemXmlApplicationContext",
/// "http://…/spel.xml"]`. That string form counts only when the array is
/// exactly `[class, string]` and the first element ends in a capitalised class
/// name; the string may be double-quoted and hold a `'`, or single-quoted and
/// hold a `"` (`"http://x/it's.xml"`, `'http://x/"a.xml'`). A list of
/// package names (`["org.apache.commons","org.apache.http"]`) or of three
/// class names stays clean. It leaves out the `java.*` and .NET
/// namespaces: Jackson wraps JDK value types with a string as ordinary data
/// (`["java.net.URL","https://…"]`), and Json.NET never writes this array form.
///
/// Spring is listed by the packages that hold its known gadgets (`aop`,
/// `beans`, `context`, `jndi`, `transaction`, `web.context.support`, …), not by
/// the whole `org.springframework.` namespace. Spring Session's and Spring
/// Security's Jackson modules write their own types with a discriminator
/// (`"@class":"org.springframework.security.core.context.SecurityContextImpl"`),
/// and an application that switches default typing to `WRAPPER_ARRAY` writes
/// `["org.springframework.security…SimpleGrantedAuthority",{…}]` — the same
/// shape as the array branch. Neither is a gadget. The `java.util.*`
/// collection wrappers those modules also emit (`["java.util.ArrayList",[…]]`)
/// are outside both lists, and a `java.lang.*` wrapper such as
/// `["java.lang.Long",1]` wraps a scalar, not an object.
const JSON_POLYMORPHIC_GADGET: &str = r#"(?i)(?:["'](?:@type|\$type|@class|__type)["']\s*:\s*["'](?-i:[\[L]){0,3}(?:com\.sun\.|java\.(?:net|lang|rmi|util\.logging)\.|javax\.(?:naming|management|script|swing)\.|org\.apache\.|org\.springframework\.(?:aop|beans|context|jndi|transaction|expression|jdbc|jms|jmx|remoting|scripting|web\.context\.support)\.|org\.hibernate\.|org\.codehaus\.groovy\.|com\.mchange\.|com\.zaxxer\.|com\.alibaba\.|ch\.qos\.logback\.|system\.(?:windows\.data\.objectdataprovider|diagnostics\.process|configuration\.install|management\.automation|web\.security|windows\.forms))|\[\s*["'](?:(?:com\.sun\.|java\.(?:net|lang|rmi|util\.logging)\.|javax\.(?:naming|management|script|swing)\.|org\.apache\.|org\.springframework\.(?:aop|beans|context|jndi|transaction|expression|jdbc|jms|jmx|remoting|scripting|web\.context\.support)\.|org\.hibernate\.|org\.codehaus\.groovy\.|com\.mchange\.|com\.zaxxer\.|com\.alibaba\.|ch\.qos\.logback\.|system\.(?:windows\.data\.objectdataprovider|diagnostics\.process|configuration\.install|management\.automation|web\.security|windows\.forms))[\w.$]*["']\s*,\s*\{|(?:com\.sun\.|javax\.(?:naming|management|script|swing)\.|org\.apache\.|org\.springframework\.(?:aop|beans|context|jndi|transaction|expression|jdbc|jms|jmx|remoting|scripting|web\.context\.support)\.|org\.hibernate\.|org\.codehaus\.groovy\.|com\.mchange\.|com\.zaxxer\.|com\.alibaba\.|ch\.qos\.logback\.)(?:[\w.$]*\.)?(?-i:[A-Z])[\w$]*["']\s*,\s*(?:"[^"\r\n]*"|'[^'\r\n]*')\s*\]))"#;

/// Cloud-metadata endpoints and dotted IPv4 private/loopback/link-local forms
/// claimed by `FE-SSRF-001` / `FE-SSRF-001-Q`. Body and query share this
/// pattern so coverage stays in lockstep. Beyond the AWS/GCP/Azure/OCI IMDS
/// address `169.254.169.254` it names the AWS ECS task-credential endpoint
/// (`169.254.170.2`), the AWS IPv6 IMDS (`fd00:ec2::254`), and Alibaba Cloud's
/// `100.100.100.200`. Alternative textual IP forms (decimal, hex, octal,
/// `[::1]`) and `localhost` are claimed at paranoia level 2 by
/// `FE-SSRF-003`.
const SSRF_METADATA_OR_PRIVATE_IP: &str = r"(?i)(?:169\.254\.169\.254|169\.254\.170\.2\b|fd00:ec2::254|100\.100\.100\.200\b|metadata\.google\.internal|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})";

/// Dangerous schemes claimed by `FE-SSRF-002` / `FE-SSRF-002-Q`. Word-bounded
/// so tokens like `profile://` are not substring matches.
const SSRF_DANGEROUS_SCHEME: &str = r"(?i)\b(?:file|gopher|dict|jar|ldap)://";

/// Loopback, unspecified, and link-local hosts spelled in forms that a
/// dotted-quad signature cannot see — `localhost` (and the fully-qualified
/// `localhost.`), `0`, `0.0.0.0`, short dotted loopback (`127.1`,
/// `127.0.1`), mixed dotted hex/octal (`0x7f.1`), and bracketed IPv6
/// (`[::1]`, `[::ffff:127.0.0.1]`, `[fe80::…]`). A host written as one
/// decimal (`2130706433`), hex (`0x7f000001`), or octal (`017700000001`)
/// integer matches whatever address it encodes: nothing legitimate spells a
/// host that way, and the encoded address is exactly what the dotted-quad
/// rules cannot see. Claimed by `FE-SSRF-003` at paranoia level 2: it
/// requires a URL scheme in front, but development tooling legitimately
/// passes `http://localhost:…` around.
const SSRF_ALTERNATE_LOOPBACK_FORM: &str = r"(?i)\b(?:https?|ftp|gopher|dict|ldap|tftp)://(?:[^/@\s]*@)?(?:localhost\.?|0|0\.0\.0\.0|127(?:\.\d{1,3}){1,2}|0x[0-9a-f]{1,8}|0[0-7]{1,11}|[1-9]\d{7,9}|(?:0x[0-9a-f]{1,2}|0[0-7]{1,3})(?:\.(?:0x[0-9a-f]{1,2}|0[0-7]{0,3}|\d{1,3})){1,3}|\[(?:[0:]*:1|::|::ffff:[0-9a-f.:]+|fe80:[0-9a-f:%.]*)\])(?::\d{1,5})?(?:[/?#]|$)";

pub fn default_rules() -> Vec<WafRule> {
    vec![
        r("FE-SQLI-001", "UNION SELECT SQL injection", "sqli", Severity::High, RuleTarget::QueryValues, SQLI_UNION_SELECT),
        r("FE-SQLI-002", "Boolean tautology SQL injection", "sqli", Severity::High, RuleTarget::QueryValues, SQLI_BOOLEAN_TAUTOLOGY),
        r("FE-SQLI-003", "Stacked SQL statement", "sqli", Severity::High, RuleTarget::QueryValues, SQLI_STACKED_STATEMENT),
        rp("FE-SQLI-004", "SQL comment token", "sqli", Severity::Medium, RuleTarget::QueryValues, r"(?i)(?:--[\s-]|/\*|\*/)", 2),
        r("FE-SQLI-005", "SQLSTATE token", "sqli", Severity::Medium, RuleTarget::BodyText, r"(?i)\bSQLSTATE(?:\[[0-9A-Z]{5}\]|[0-9A-Z]{5})\b"),
        r("FE-NOSQL-001", "NoSQL operator key", "nosqli", Severity::High, RuleTarget::BodyText, r#"(?i)"\$(?:ne|gt|where|regex|exists)"\s*:"#),
        r("FE-CMD-001", "Shell metacharacter command chain", "command_injection", Severity::High, RuleTarget::QueryValues, r"(?i)(?:;|\||&&|\|\|)\s*(?:cat|sh|bash|cmd|powershell|nc|wget|curl)\b"),
        r("FE-CMD-002", "Interactive shell or network fetch", "command_injection", Severity::High, RuleTarget::BodyText, r"(?i)\b(?:bash\s+-i|nc\s+-e|wget\s+https?://|curl\s+https?://)\b"),
        r("FE-CMD-003", "Shell substitution expression", "command_injection", Severity::Medium, RuleTarget::BodyText, r"(?:`[^`]{1,200}`|\$\([^)]{1,200}\))"),
        r("FE-LDAP-001", "LDAP wildcard injection", "ldap_injection", Severity::Medium, RuleTarget::QueryValues, r"(?i)\*\)\s*\(\s*uid\s*=\s*\*"),
        r("FE-LDAP-002", "LDAP OR injection", "ldap_injection", Severity::Medium, RuleTarget::BodyText, r"(?i)\(\|\s*\(\s*uid\s*=\s*\*\s*\)\s*\)"),
        r("FE-XPATH-001", "XPath tautology", "xpath_injection", Severity::Medium, RuleTarget::QueryValues, r#"(?i)['"]\s+or\s+['"]?1['"]?\s*=\s*['"]?1"#),
        r("FE-XPATH-002", "XPath function probe", "xpath_injection", Severity::Low, RuleTarget::BodyText, r"(?i)\b(?:count|string-length)\s*\("),
        r("FE-SSTI-001", "Template expression marker", "ssti", Severity::High, RuleTarget::BodyText, r"(?:\{\{[^}]{1,200}\}\}|\$\{[^}]{1,200}\}|<%[^%]{1,200}%>)"),
        r("FE-XSS-001", "Script tag", "xss", Severity::High, RuleTarget::QueryValues, r"(?i)<\s*script\b"),
        r("FE-XSS-002", "Script URL scheme", "xss", Severity::High, RuleTarget::QueryValues, SCRIPT_URL_SCHEME),
        r("FE-XSS-003", "HTML event handler", "xss", Severity::Medium, RuleTarget::BodyText, EVENT_HANDLER),
        r("FE-XSS-004", "Iframe srcdoc payload", "xss", Severity::High, RuleTarget::BodyText, r"(?i)<\s*iframe\b[^>]*\bsrcdoc\s*="),
        r("FE-XSS-005", "HTML data URL", "xss", Severity::Medium, RuleTarget::QueryValues, r"(?i)data\s*:\s*text/html"),
        // Built-in FullUrl PATHTRAV/LFI signatures opt into a compile-time
        // canonical-query-value mirror (`%2f` decoded). Category labels do not.
        r_canonical_query("FE-PATHTRAV-001", "Dot-dot path traversal", "path_traversal", Severity::High, RuleTarget::FullUrl, r"(?:\.\./|\.\.\\)"),
        r_canonical_query("FE-PATHTRAV-002", "Encoded path traversal", "path_traversal", Severity::High, RuleTarget::FullUrl, r"(?i)%25?2e%25?2e(?:%25?2f|%25?5c|/|\\)"),
        r_canonical_query("FE-PATHTRAV-003", "Encoded null byte", "path_traversal", Severity::Medium, RuleTarget::FullUrl, r"(?i)%00"),
        r_canonical_query("FE-LFI-001", "Local file inclusion target", "lfi", Severity::High, RuleTarget::FullUrl, r"(?i)(?:/etc/passwd|/proc/self/|c:\\windows\\|php://filter|expect://|file:///)"),
        r("FE-RFI-001", "Remote URL in request parameter", "rfi", Severity::Medium, RuleTarget::QueryValues, r"(?i)\b(?:https?|ftp)://[^\s/?#]+"),
        r("FE-XXE-001", "XML external entity marker", "xxe", Severity::High, RuleTarget::BodyText, r#"(?i)(?:<!ENTITY|\bSYSTEM\s+["']|\bPUBLIC\s+["'])"#),
        // Base64 (`rO0AB`) or hex (`aced0005`) encoding of the Java
        // serialization stream magic `AC ED 00 05`.
        r("FE-DESER-001", "Java serialized object marker", "deserialization", Severity::High, RuleTarget::BodyText, r"(?:\brO0AB[A-Za-z0-9+/=]{8,}|(?i:\baced0005[0-9a-f]{8,}))"),
        r("FE-DESER-002", ".NET BinaryFormatter marker", "deserialization", Severity::High, RuleTarget::BodyText, r"AAEAAAD/////"),
        r("FE-DESER-003", "PHP serialized object marker", "deserialization", Severity::High, RuleTarget::BodyText, r#"O:\d+:"[^"]+":"#),
        r("FE-SSRF-001", "Cloud metadata or private IP URL", "ssrf", Severity::High, RuleTarget::BodyText, SSRF_METADATA_OR_PRIVATE_IP),
        r("FE-SSRF-002", "Dangerous URL scheme", "ssrf", Severity::High, RuleTarget::BodyText, SSRF_DANGEROUS_SCHEME),
        r("FE-HEADER-001", "Header control character", "header_anomaly", Severity::Medium, RuleTarget::HeaderValues(None), r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),
        r("FE-HEADER-002", "HTTP method override header", "header_anomaly", Severity::Low, RuleTarget::HeaderNames, r"(?i)^x-http-method-override$"),
        r("FE-COOKIE-001", "Cookie control character", "cookie_attack", Severity::Medium, RuleTarget::Cookies, r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),
        r("FE-COOKIE-002", "Session fixation cookie name", "cookie_attack", Severity::Low, RuleTarget::Cookies, r"(?i)\b(?:jsessionid|phpsessid|asp\.net_sessionid)\s*="),
        r("FE-HPP-001", "Conflicting duplicate query key", "parameter_pollution", Severity::Medium, RuleTarget::FullUrl, r"$^"),
        r("FE-ENCODING-001", "Double URL encoding", "encoding_evasion", Severity::Medium, RuleTarget::FullUrl, r"(?i)%25(?:25|2e|2f|5c|00)"),
        r("FE-ENCODING-002", "Overlong UTF-8 marker", "encoding_evasion", Severity::Medium, RuleTarget::FullUrl, r"(?i)%(?:c0|e0|f0)%"),
        r("FE-METHOD-001", "Disallowed method", "method_abuse", Severity::Medium, RuleTarget::Method, r"$^"),
        r("FE-RESP-STACK-001", "Java stack trace disclosure", "stack_trace", Severity::Medium, RuleTarget::ResponseBody, r"(?m)\bat\s+[A-Za-z0-9_.$]+\([^)]*\.java:\d+\)"),
        r("FE-RESP-STACK-002", "Python traceback disclosure", "stack_trace", Severity::Medium, RuleTarget::ResponseBody, r"Traceback \(most recent call last\)"),
        r("FE-RESP-STACK-003", ".NET stack trace disclosure", "stack_trace", Severity::Medium, RuleTarget::ResponseBody, r"(?i)System\.[A-Za-z.]*Exception:.*\bat\s+"),
        r("FE-RESP-DB-001", "Verbose database error", "database_error", Severity::Medium, RuleTarget::ResponseBody, r"(?i)(?:SQLSTATE|MySQL server version|PostgreSQL.*ERROR|ORA-\d{5}|Mongo(?:DB)?Error|near\s+'WHERE')"),
        r("FE-RESP-SOURCE-001", "Server-side source disclosure", "source_disclosure", Severity::High, RuleTarget::ResponseBody, r"(?i)(?:<\?php|<%[@=]?)"),
        r("FE-RESP-FP-001", "X-Powered-By version disclosure", "fingerprinting", Severity::Low, RuleTarget::ResponseHeaders, r"(?i)\bx-powered-by\s*:\s*[A-Za-z]+/[0-9]"),
        r("FE-DATA-LEAK-001", "Credit card number with valid Luhn checksum (long digit runs are capped)", "data_leak", Severity::High, RuleTarget::ResponseBody, ""),
        r("FE-DATA-LEAK-002", "AWS access key", "data_leak", Severity::High, RuleTarget::ResponseBody, r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        r("FE-DATA-LEAK-003", "Stripe live secret key", "data_leak", Severity::High, RuleTarget::ResponseBody, r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        r("FE-DATA-LEAK-004", "GitHub personal access token", "data_leak", Severity::High, RuleTarget::ResponseBody, r"\bghp_[A-Za-z0-9]{36}\b"),
        r("FE-DATA-LEAK-005", "JWT-shaped token", "data_leak", Severity::Medium, RuleTarget::ResponseBody, r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        r("FE-DATA-LEAK-006", "Private key PEM header", "data_leak", Severity::Critical, RuleTarget::ResponseBody, r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        // --- Log4Shell / JNDI lookup injection (CVE-2021-44228). Delivered via
        // headers (User-Agent, X-Forwarded-For), query, and body. ---
        rp("FE-JNDI-001-B", "JNDI lookup expression (body)", "jndi_injection", Severity::Critical, RuleTarget::BodyText, r"(?i)\$\{(?:jndi|ldap|ldaps|rmi|dns|nis|iiop|corba|nds):", 1),
        rp("FE-JNDI-001-Q", "JNDI lookup expression (query)", "jndi_injection", Severity::Critical, RuleTarget::QueryValues, r"(?i)\$\{(?:jndi|ldap|ldaps|rmi|dns|nis|iiop|corba|nds):", 1),
        rp("FE-JNDI-001-H", "JNDI lookup expression (header)", "jndi_injection", Severity::Critical, RuleTarget::HeaderValues(None), r"(?i)\$\{(?:jndi|ldap|ldaps|rmi|dns|nis|iiop|corba|nds):", 1),
        rp("FE-JNDI-002-B", "Nested lookup obfuscation (body)", "jndi_injection", Severity::High, RuleTarget::BodyText, r"(?i)\$\{[^}]{0,80}\$\{", 2),
        rp("FE-JNDI-002-Q", "Nested lookup obfuscation (query)", "jndi_injection", Severity::High, RuleTarget::QueryValues, r"(?i)\$\{[^}]{0,80}\$\{", 2),
        rp("FE-JNDI-002-H", "Nested lookup obfuscation (header)", "jndi_injection", Severity::High, RuleTarget::HeaderValues(None), r"(?i)\$\{[^}]{0,80}\$\{", 2),
        // --- Spring4Shell class-loader manipulation (CVE-2022-22965) ---
        rp("FE-SPRING4SHELL-001-B", "Class loader manipulation (body)", "rce", Severity::High, RuleTarget::BodyText, r"(?i)class\.(?:module\.)?classloader", 1),
        rp("FE-SPRING4SHELL-001-Q", "Class loader manipulation (query)", "rce", Severity::High, RuleTarget::QueryValues, r"(?i)class\.(?:module\.)?classloader", 1),
        // --- Prototype pollution (JS backends) ---
        rp("FE-PROTO-001", "Prototype pollution __proto__ key", "prototype_pollution", Severity::High, RuleTarget::BodyText, r"(?i)__proto__", 1),
        rp("FE-PROTO-002", "Prototype pollution constructor.prototype", "prototype_pollution", Severity::High, RuleTarget::BodyText, r#"(?i)(?:constructor\s*\.\s*prototype|"constructor"\s*:\s*\{)"#, 2),
        rp("FE-PROTO-001-Q", "Prototype pollution __proto__ (query key)", "prototype_pollution", Severity::High, RuleTarget::QueryKeys, PROTOTYPE_POLLUTION_PROTO, 1),
        rp("FE-PROTO-002-Q", "Prototype pollution constructor[prototype] (query key)", "prototype_pollution", Severity::High, RuleTarget::QueryKeys, PROTOTYPE_POLLUTION_CONSTRUCTOR, 1),
        rp("FE-PROTO-001-QV", "Prototype pollution __proto__ (query value)", "prototype_pollution", Severity::High, RuleTarget::QueryValues, PROTOTYPE_POLLUTION_PROTO, 1),
        rp("FE-PROTO-002-QV", "Prototype pollution constructor[prototype] (query value)", "prototype_pollution", Severity::High, RuleTarget::QueryValues, PROTOTYPE_POLLUTION_CONSTRUCTOR, 1),
        // --- NoSQL bracket-operator injection (form/query encoded) ---
        rp("FE-NOSQL-002", "NoSQL bracket operator", "nosqli", Severity::Medium, RuleTarget::QueryValues, r"(?i)\[\$(?:ne|gt|gte|lt|lte|in|nin|where|regex|exists|or|and)\]", 2),
        // --- Header-borne injection (strong, low-FP signatures only) ---
        rp("FE-HEADER-003", "Injection payload in header value", "header_anomaly", Severity::High, RuleTarget::HeaderValues(None), r"(?i)(?:<\s*script\b|\bunion\s+(?:all\s+)?select\b|\.\./|\.\.\\)", 2),
        // --- SSTI: tightened arithmetic probe + Java/Spring EL ---
        rp("FE-SSTI-002", "Template arithmetic probe", "ssti", Severity::High, RuleTarget::BodyText, r"(?:\{\{\s*\d+\s*[-+*/%]\s*\d+|\$\{\s*\d+\s*[-+*/%]\s*\d+|<%=?\s*\d+\s*[-+*/%]\s*\d+)", 1),
        rp("FE-SSTI-003", "Java/Spring EL expression", "ssti", Severity::High, RuleTarget::BodyText, r"(?i)(?:\$\{T\(|\$\{[^}]*\.getclass\(|#\{[^}]*\})", 2),
        // --- XSS body/query symmetry (the original rules covered only one side) ---
        rp("FE-XSS-001-B", "Script tag (body)", "xss", Severity::High, RuleTarget::BodyText, r"(?i)<\s*script\b", 1),
        rp("FE-XSS-002-B", "Script URL scheme (body)", "xss", Severity::High, RuleTarget::BodyText, SCRIPT_URL_SCHEME, 1),
        rp("FE-XSS-003-Q", "HTML event handler (query)", "xss", Severity::Medium, RuleTarget::QueryValues, EVENT_HANDLER, 1),
        rp("FE-XSS-005-B", "HTML data URL (body)", "xss", Severity::Medium, RuleTarget::BodyText, r"(?i)data\s*:\s*text/html", 1),
        // --- Level-1 SQLi body/query symmetry. Body mirrors intentionally use
        // the exact established query patterns above, without broadening. ---
        rp("FE-SQLI-001-B", "UNION SELECT SQL injection (body)", "sqli", Severity::High, RuleTarget::BodyText, SQLI_UNION_SELECT, 1),
        rp("FE-SQLI-002-B", "Boolean tautology SQL injection (body)", "sqli", Severity::High, RuleTarget::BodyText, SQLI_BOOLEAN_TAUTOLOGY, 1),
        rp("FE-SQLI-003-B", "Stacked SQL statement (body)", "sqli", Severity::High, RuleTarget::BodyText, SQLI_STACKED_STATEMENT, 1),
        // Body-side "any comment token" catch-all mirroring `FE-SQLI-004`.
        // The bounded `{0,64}` comment body in the level-1 signatures above
        // leaves a residual evasion behind a longer comment; the query side
        // already had this backstop at paranoia 2 and the body side had none.
        rp("FE-SQLI-004-B", "SQL comment token (body)", "sqli", Severity::Medium, RuleTarget::BodyText, r"(?i)(?:--[\s-]|/\*|\*/)", 2),
        // --- Traversal / LFI / SSRF parity across body and query ---
        // SSRF query mirrors stay on QueryValues (decoded parameter values),
        // not FullUrl, so a path token like `/v10.1.2.3` is not a substring
        // hit. They ship at paranoia 1 with the body rules: the documented
        // pack covers metadata/private-IP and dangerous schemes on both
        // sides at the recommended enforce/L1 posture.
        rp("FE-PATHTRAV-001-B", "Dot-dot path traversal (body)", "path_traversal", Severity::High, RuleTarget::BodyText, r"(?:\.\./|\.\.\\)", 1),
        rp("FE-LFI-001-B", "Local file inclusion target (body)", "lfi", Severity::High, RuleTarget::BodyText, r"(?i)(?:/etc/passwd|/proc/self/|c:\\windows\\|php://filter|expect://|file:///)", 1),
        rp("FE-SSRF-001-Q", "Cloud metadata or private IP URL (query)", "ssrf", Severity::High, RuleTarget::QueryValues, SSRF_METADATA_OR_PRIVATE_IP, 1),
        rp("FE-SSRF-002-Q", "Dangerous URL scheme (query)", "ssrf", Severity::High, RuleTarget::QueryValues, SSRF_DANGEROUS_SCHEME, 1),
        rp("FE-SSRF-003-Q", "Alternate loopback or link-local host form (query)", "ssrf", Severity::Medium, RuleTarget::QueryValues, SSRF_ALTERNATE_LOOPBACK_FORM, 2),
        rp("FE-SSRF-003-B", "Alternate loopback or link-local host form (body)", "ssrf", Severity::Medium, RuleTarget::BodyText, SSRF_ALTERNATE_LOOPBACK_FORM, 2),
        // --- SQL injection: blind, enumeration, error-based, string
        // tautology. Query and body mirrors share one pattern each. ---
        rp("FE-SQLI-006", "Time-delay SQL injection", "sqli", Severity::High, RuleTarget::QueryValues, SQLI_TIME_DELAY, 1),
        rp("FE-SQLI-006-B", "Time-delay SQL injection (body)", "sqli", Severity::High, RuleTarget::BodyText, SQLI_TIME_DELAY, 2),
        rp("FE-SQLI-007", "Database catalog enumeration", "sqli", Severity::High, RuleTarget::QueryValues, SQLI_SCHEMA_ENUMERATION, 1),
        rp("FE-SQLI-007-B", "Database catalog enumeration (body)", "sqli", Severity::High, RuleTarget::BodyText, SQLI_SCHEMA_ENUMERATION, 1),
        rp("FE-SQLI-008", "Error-based or out-of-band SQL function", "sqli", Severity::High, RuleTarget::QueryValues, SQLI_ERROR_OR_OOB_FUNCTION, 1),
        rp("FE-SQLI-008-B", "Error-based or out-of-band SQL function (body)", "sqli", Severity::High, RuleTarget::BodyText, SQLI_ERROR_OR_OOB_FUNCTION, 1),
        rp("FE-SQLI-009", "Quoted string tautology SQL injection", "sqli", Severity::High, RuleTarget::QueryValues, SQLI_STRING_TAUTOLOGY, 1),
        rp("FE-SQLI-009-B", "Quoted string tautology SQL injection (body)", "sqli", Severity::High, RuleTarget::BodyText, SQLI_STRING_TAUTOLOGY, 1),
        // Level-1 body time-delay coverage: the query pattern's context
        // accepts code shapes, so its exact body mirror above is level 2.
        rp("FE-SQLI-010-B", "Time-delay SQL injection in SQL context (body)", "sqli", Severity::High, RuleTarget::BodyText, SQLI_TIME_DELAY_SQL_CONTEXT, 1),
        // --- Cookie mirrors. Cookie values are an injection channel for
        // every server framework that binds them to handler parameters.
        // `FE-SQLI-003-C` needs a `;`, and the Cookie header is split into
        // crumbs on `;` before matching, so a raw crumb never contains one:
        // the rule fires on a percent-encoded `%3B` through the decoded
        // cookie views. ---
        rp("FE-SQLI-001-C", "UNION SELECT SQL injection (cookie)", "sqli", Severity::High, RuleTarget::Cookies, SQLI_UNION_SELECT, 1),
        rp("FE-SQLI-002-C", "Boolean tautology SQL injection (cookie)", "sqli", Severity::High, RuleTarget::Cookies, SQLI_BOOLEAN_TAUTOLOGY, 1),
        rp("FE-SQLI-003-C", "Stacked SQL statement (cookie)", "sqli", Severity::High, RuleTarget::Cookies, SQLI_STACKED_STATEMENT, 1),
        rp("FE-XSS-001-C", "Script tag (cookie)", "xss", Severity::High, RuleTarget::Cookies, r"(?i)<\s*script\b", 1),
        rp("FE-XSS-002-C", "Script URL scheme (cookie)", "xss", Severity::High, RuleTarget::Cookies, SCRIPT_URL_SCHEME, 1),
        rp("FE-PATHTRAV-001-C", "Dot-dot path traversal (cookie)", "path_traversal", Severity::High, RuleTarget::Cookies, r"(?:\.\./|\.\.\\)", 1),
        // --- XSS: active-content elements. ---
        rp("FE-XSS-006-Q", "Active-content HTML element (query)", "xss", Severity::Medium, RuleTarget::QueryValues, HTML_ACTIVE_CONTENT_ELEMENT, 1),
        rp("FE-XSS-006-B", "Active-content HTML element (body)", "xss", Severity::Medium, RuleTarget::BodyText, HTML_ACTIVE_CONTENT_ELEMENT, 2),
        // --- Command injection and interpreter invocation. ---
        rp("FE-CMD-004", "Subshell, newline, or tool command execution", "command_injection", Severity::High, RuleTarget::QueryValues, CMD_EXTENDED_EXECUTION, 1),
        rp("FE-CMD-005-Q", "Shell or interpreter invocation (query)", "command_injection", Severity::High, RuleTarget::QueryValues, CMD_INTERPRETER_INVOCATION, 1),
        rp("FE-CMD-005-B", "Shell or interpreter invocation (body)", "command_injection", Severity::High, RuleTarget::BodyText, CMD_INTERPRETER_INVOCATION, 2),
        // --- Shellshock (CVE-2014-6271): header values and the CGI query
        // string, whose leading pair is the query KEY. ---
        rp("FE-SHELLSHOCK-001-H", "Shellshock function definition (header)", "rce", Severity::Critical, RuleTarget::HeaderValues(None), SHELLSHOCK_FUNCTION_DEFINITION, 1),
        rp("FE-SHELLSHOCK-001-Q", "Shellshock function definition (query key)", "rce", Severity::Critical, RuleTarget::QueryKeys, SHELLSHOCK_FUNCTION_DEFINITION, 1),
        rp("FE-SHELLSHOCK-001-QV", "Shellshock function definition (query value)", "rce", Severity::Critical, RuleTarget::QueryValues, SHELLSHOCK_FUNCTION_DEFINITION, 1),
        // --- OGNL / Apache Struts 2 expression injection. ---
        rp("FE-OGNL-001-B", "OGNL expression injection (body)", "rce", Severity::Critical, RuleTarget::BodyText, OGNL_EXPRESSION, 1),
        rp("FE-OGNL-001-Q", "OGNL expression injection (query)", "rce", Severity::Critical, RuleTarget::QueryValues, OGNL_EXPRESSION, 1),
        rp("FE-OGNL-001-H", "OGNL expression injection (header)", "rce", Severity::Critical, RuleTarget::HeaderValues(None), OGNL_EXPRESSION, 1),
        // --- PHP and Node.js code injection. ---
        rp("FE-PHP-001-Q", "PHP code injection (query)", "rce", Severity::High, RuleTarget::QueryValues, PHP_CODE_INJECTION, 1),
        rp("FE-PHP-001-B", "PHP code injection (body)", "rce", Severity::High, RuleTarget::BodyText, PHP_CODE_INJECTION, 2),
        rp("FE-PHP-002-B", "PHP stream wrapper (body)", "rce", Severity::High, RuleTarget::BodyText, PHP_STREAM_WRAPPER, 2),
        rp("FE-PHP-002-Q", "PHP stream wrapper (query)", "rce", Severity::High, RuleTarget::QueryValues, PHP_STREAM_WRAPPER, 1),
        rp("FE-NODE-001-Q", "Node.js code execution (query)", "rce", Severity::High, RuleTarget::QueryValues, NODE_CODE_INJECTION, 1),
        rp("FE-NODE-001-B", "Node.js code execution (body)", "rce", Severity::High, RuleTarget::BodyText, NODE_CODE_INJECTION, 2),
        // --- Response splitting through reflected query values. ---
        rp("FE-CRLF-001", "CRLF header injection", "http_response_splitting", Severity::High, RuleTarget::QueryValues, CRLF_HEADER_INJECTION, 1),
        // --- Restricted files on the canonical path. ---
        rp("FE-RESTRICTED-001", "Version-control, credential, or server config file access", "restricted_file", Severity::High, RuleTarget::UrlPath, RESTRICTED_FILE_ACCESS, 1),
        rp("FE-RESTRICTED-002", "Backup or database dump artifact access", "restricted_file", Severity::Medium, RuleTarget::UrlPath, RESTRICTED_BACKUP_ARTIFACT, 2),
        // --- Uploads and deserialization gadgets. ---
        rp("FE-UPLOAD-001", "Executable script upload filename", "file_upload", Severity::High, RuleTarget::BodyText, EXECUTABLE_UPLOAD_FILENAME, 1),
        rp("FE-DESER-004", "Unsafe YAML type tag", "deserialization", Severity::High, RuleTarget::BodyText, YAML_GADGET_TAG, 1),
        rp("FE-DESER-005", "Polymorphic JSON gadget type", "deserialization", Severity::High, RuleTarget::BodyText, JSON_POLYMORPHIC_GADGET, 1),
    ]
    .into_iter()
    .map(|mut rule| {
        if rule.id == "FE-DATA-LEAK-001" {
            rule.match_kind = MatchKind::Luhn;
        }
        // Retune loud / low-value rules: keep them available but gate them
        // behind a higher paranoia_level so they no longer dominate the
        // monitor signal (or block) at the default level 1.
        match rule.id.as_str() {
            // High false-positive at level 1: broad template markers, SQL
            // comment tokens, shell substitution, any-URL-in-param, JWT-shaped
            // response tokens, SQLSTATE in request bodies. The broad SSTI
            // marker is superseded at level 1 by FE-SSTI-002/003.
            "FE-SSTI-001" | "FE-SQLI-004" | "FE-SQLI-004-B" | "FE-SQLI-005"
            | "FE-CMD-003" | "FE-RFI-001" | "FE-DATA-LEAK-005" => {
                rule.paranoia_min = rule.paranoia_min.max(2)
            }
            // Very loud / low signal: bare XPath function probe.
            "FE-XPATH-002" => rule.paranoia_min = 3,
            // Sending a session cookie is normal, not an attack. Demote to
            // informational and gate behind the highest paranoia level.
            "FE-COOKIE-002" => {
                rule.severity = Severity::Info;
                rule.paranoia_min = 3;
            }
            _ => {}
        }
        // Encoding-evasion heuristics false-positive on benign percent-encoded
        // text (coupon codes like SAVE50%25, pasted `%00` / overlong UTF-8).
        // They stay Monitor under bulk `default_rule_action: enforce`; only an
        // explicit per-rule action promotes them. Other built-in specials
        // (HPP, method abuse, encoded path-traversal `%00`) inherit bulk
        // enforce — they are attack-shaped rather than encoding-heuristic.
        if matches!(rule.id.as_str(), "FE-ENCODING-001" | "FE-ENCODING-002") {
            rule.default_action_policy = DefaultActionPolicy::OptInEnforce;
        }
        rule
    })
    .collect()
}

fn r(
    id: &str,
    name: &str,
    category: &str,
    severity: Severity,
    target: RuleTarget,
    pattern: &str,
) -> WafRule {
    rp(id, name, category, severity, target, pattern, 1)
}

/// Built-in FullUrl PATHTRAV/LFI helper: same as [`r`], plus the canonical
/// query-value mirror. Must not be used for custom rules or other built-ins.
fn r_canonical_query(
    id: &str,
    name: &str,
    category: &str,
    severity: Severity,
    target: RuleTarget,
    pattern: &str,
) -> WafRule {
    let mut rule = r(id, name, category, severity, target, pattern);
    debug_assert!(
        matches!(rule.target, RuleTarget::FullUrl),
        "canonical query-value mirror is FullUrl-only"
    );
    rule.query_scan_mirror = QueryScanMirror::CanonicalQueryValues;
    rule
}

/// Like [`r`] but with an explicit `paranoia_min`. Rules above the configured
/// `paranoia_level` are compiled out, so loud/broad signatures live at 2–3.
#[allow(clippy::too_many_arguments)]
fn rp(
    id: &str,
    name: &str,
    category: &str,
    severity: Severity,
    target: RuleTarget,
    pattern: &str,
    paranoia_min: u8,
) -> WafRule {
    WafRule {
        id: id.to_string(),
        name: name.to_string(),
        category: category.to_string(),
        severity,
        target,
        match_kind: MatchKind::Regex,
        pattern: pattern.to_string(),
        conditions: None,
        action: RuleAction::Monitor,
        default_action_policy: DefaultActionPolicy::Inherit,
        fp_filters: Vec::new(),
        paranoia_min,
        score: None,
        query_scan_mirror: QueryScanMirror::None,
    }
}
