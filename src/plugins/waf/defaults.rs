use super::rules::{MatchKind, RuleAction, RuleTarget, Severity, WafRule};

pub fn default_rules() -> Vec<WafRule> {
    vec![
        r("FE-SQLI-001", "UNION SELECT SQL injection", "sqli", Severity::High, RuleTarget::QueryValues, r"(?i)\bunion\s+(?:all\s+)?select\b"),
        r("FE-SQLI-002", "Boolean tautology SQL injection", "sqli", Severity::High, RuleTarget::QueryValues, r#"(?i)(?:\bor\b|\|\|)\s+['"]?\d+['"]?\s*=\s*['"]?\d+"#),
        r("FE-SQLI-003", "Stacked SQL statement", "sqli", Severity::High, RuleTarget::QueryValues, r"(?i);\s*(?:drop|insert|update|delete|alter)\b"),
        r("FE-SQLI-004", "SQL comment token", "sqli", Severity::Medium, RuleTarget::QueryValues, r"(?i)(?:--|/\*|\*/|#)"),
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
        r("FE-XSS-002", "JavaScript URL", "xss", Severity::High, RuleTarget::QueryValues, r"(?i)javascript\s*:"),
        r("FE-XSS-003", "HTML event handler", "xss", Severity::Medium, RuleTarget::BodyText, r"(?i)\bon[a-z]{3,32}\s*="),
        r("FE-XSS-004", "Iframe srcdoc payload", "xss", Severity::High, RuleTarget::BodyText, r"(?i)<\s*iframe\b[^>]*\bsrcdoc\s*="),
        r("FE-XSS-005", "HTML data URL", "xss", Severity::Medium, RuleTarget::QueryValues, r"(?i)data\s*:\s*text/html"),
        r("FE-PATHTRAV-001", "Dot-dot path traversal", "path_traversal", Severity::High, RuleTarget::FullUrl, r"(?:\.\./|\.\.\\)"),
        r("FE-PATHTRAV-002", "Encoded path traversal", "path_traversal", Severity::High, RuleTarget::FullUrl, r"(?i)%25?2e%25?2e(?:%25?2f|%25?5c|/|\\)"),
        r("FE-PATHTRAV-003", "Encoded null byte", "path_traversal", Severity::Medium, RuleTarget::FullUrl, r"(?i)%00"),
        r("FE-LFI-001", "Local file inclusion target", "lfi", Severity::High, RuleTarget::FullUrl, r"(?i)(?:/etc/passwd|/proc/self/|c:\\windows\\|php://filter|expect://|file:///)"),
        r("FE-RFI-001", "Remote URL in request parameter", "rfi", Severity::Medium, RuleTarget::QueryValues, r"(?i)\b(?:https?|ftp)://[^\s/?#]+"),
        r("FE-XXE-001", "XML external entity marker", "xxe", Severity::High, RuleTarget::BodyText, r#"(?i)(?:<!DOCTYPE|<!ENTITY|\bSYSTEM\s+["']|\bPUBLIC\s+["'])"#),
        r("FE-DESER-001", "Java serialized object marker", "deserialization", Severity::High, RuleTarget::BodyText, r"\brO0AB[A-Za-z0-9+/=]{8,}"),
        r("FE-DESER-002", ".NET BinaryFormatter marker", "deserialization", Severity::High, RuleTarget::BodyText, r"AAEAAAD/////"),
        r("FE-DESER-003", "PHP serialized object marker", "deserialization", Severity::High, RuleTarget::BodyText, r#"O:\d+:"[^"]+":"#),
        r("FE-SSRF-001", "Cloud metadata or private IP URL", "ssrf", Severity::High, RuleTarget::BodyText, r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"),
        r("FE-SSRF-002", "Dangerous URL scheme", "ssrf", Severity::High, RuleTarget::BodyText, r"(?i)\b(?:file|gopher|dict|jar|ldap)://"),
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
    ]
    .into_iter()
    .map(|mut rule| {
        if rule.id == "FE-DATA-LEAK-001" {
            rule.match_kind = MatchKind::Luhn;
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
        fp_filters: Vec::new(),
        paranoia_min: 1,
    }
}
