//! Actionable CLI / MCP user-facing messages.

/// Escape a command for reuse inside single quotes: `mayrun run '…'`.
pub fn shell_single_quote(s: &str) -> String {
    // POSIX: close quote, insert escaped quote, reopen.
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn approve_cli_hint(command: &str) -> String {
    format!(
        "Re-run after confirming:\n  mayrun run {} --approve",
        shell_single_quote(command)
    )
}

pub fn approve_mcp_next_steps(command: &str) -> serde_json::Value {
    serde_json::json!({
        "ask_human": true,
        "retry_mcp": {
            "tool": "mayrun_run",
            "approved": true,
            "command": command,
        },
        "or_cli": format!("mayrun run {} --approve", shell_single_quote(command)),
    })
}

pub fn deny_policy_adjust_hint() -> &'static str {
    "To adjust policy: edit mayrun.policy.yaml (or a pack under extends), then `mayrun check '<cmd>'`. Never grant Allow via AI — only deterministic rules or human --approve."
}

pub fn format_denial(rule_id: Option<&str>, reason: Option<&str>) -> String {
    let mut out = String::from("mayrun: denied by policy");
    if let Some(id) = rule_id {
        out.push_str(&format!("\n  rule_id: {id}"));
    }
    if let Some(r) = reason {
        out.push_str(&format!("\n  reason:  {r}"));
    }
    out.push('\n');
    out.push_str(deny_policy_adjust_hint());
    out
}

pub fn format_approval_required(
    command: &str,
    receipt_id: &str,
    rule_id: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut out = format!("mayrun: approval required (receipt {receipt_id})");
    if let Some(id) = rule_id {
        out.push_str(&format!("\n  rule_id: {id}"));
    }
    if let Some(r) = reason {
        out.push_str(&format!("\n  reason:  {r}"));
    }
    out.push('\n');
    out.push_str(&approve_cli_hint(command));
    out
}

pub fn format_receipt_line(r: &crate::receipts::Receipt) -> String {
    let id_short = &r.id[..8.min(r.id.len())];
    let rule = r.rule_id.as_deref().unwrap_or("-");
    let reason = r.reason.as_deref().unwrap_or("-");
    let exit = r
        .exit_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".into());
    format!(
        "- {id_short} {:?} rule_id={rule} reason={reason} executed={} exit={exit} cmd={}",
        r.decision, r.executed, r.command
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_quote_escapes() {
        assert_eq!(shell_single_quote("echo hi"), "'echo hi'");
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn approve_hint_contains_flag() {
        let h = approve_cli_hint("git push");
        assert!(h.contains("--approve"));
        assert!(h.contains("mayrun run"));
    }
}
