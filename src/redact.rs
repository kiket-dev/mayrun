//! Secret-safe redaction for receipt command fields.

use regex::Regex;
use std::sync::OnceLock;

/// Redact tokens, KEY=value secrets, bearer headers, and private-key blocks.
/// Keeps enough structure for rule provenance; residual risk remains for novel formats.
pub fn redact_command(s: &str) -> String {
    let mut out = s.to_string();
    out = private_key_re().replace_all(&out, "[REDACTED_PRIVATE_KEY]").into_owned();
    out = bearer_re().replace_all(&out, "$1[REDACTED_TOKEN]").into_owned();
    out = assignment_re().replace_all(&out, "$1=[REDACTED]").into_owned();
    out = token_like_re().replace_all(&out, "[REDACTED_TOKEN]").into_owned();
    out
}

fn private_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
            .expect("private key regex")
    })
}

fn bearer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(Authorization:\s*Bearer\s+|Bearer\s+)([A-Za-z0-9._\-+/=]{8,})")
            .expect("bearer regex")
    })
}

fn assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Match common secret-ish env assignments (API_KEY=…, FOO_SECRET=…).
        Regex::new(concat!(
            r"(?i)\b(",
            r"(?:[A-Z][A-Z0-9_]*_)?(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|AUTH)",
            r"[A-Z0-9_]*",
            r")=",
            r#"([^\s'"\\]+|'[^']*'|"[^"]*")"#
        ))
        .expect("assignment regex")
    })
}

fn token_like_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Common cloud/token prefixes (fake values in tests only).
        Regex::new(r"\b(ghp_|gho_|github_pat_|sk-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{10,})\S*")
            .expect("token regex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_assignment_and_bearer() {
        let s = "curl -H 'Authorization: Bearer supersecrettoken123' -d API_KEY=abc123xyz";
        let r = redact_command(s);
        assert!(!r.contains("supersecrettoken123"), "{r}");
        assert!(!r.contains("abc123xyz"), "{r}");
        assert!(r.contains("[REDACTED"));
    }

    #[test]
    fn redacts_private_key_block() {
        // Build marker at runtime so secret scanners do not flag the test fixture.
        let pem = format!(
            "-----BEGIN {k}-----\nMIIEfake\n-----END {k}-----",
            k = "RSA PRIVATE KEY"
        );
        let s = format!("cat <<EOF\n{pem}\nEOF");
        let r = redact_command(&s);
        assert!(!r.contains("MIIEfake"), "{r}");
        assert!(r.contains("[REDACTED_PRIVATE_KEY]"));
    }

    #[test]
    fn redacts_github_token_prefix() {
        // Assemble token-like string at runtime to avoid secret-scanner false positives.
        let fake = format!("{}{}", "ghp_", "abcdefghijklmnopqrstuvwxyz012345");
        let s = format!("export TOKEN={fake}");
        let r = redact_command(&s);
        assert!(!r.contains(&fake), "{r}");
    }

    #[test]
    fn leaves_benign_command() {
        let s = "cargo test --package mayrun";
        assert_eq!(redact_command(s), s);
    }
}
