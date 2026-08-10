//! Offline governance metrics from local receipt logs.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::policy::Decision;
use crate::receipts::Receipt;

#[derive(Debug, Serialize)]
pub struct MetricsReport {
    pub since_ms: Option<u128>,
    pub total: usize,
    pub decisions: DecisionMix,
    pub top_rule_ids: Vec<RuleCount>,
    pub approval_friction: ApprovalFriction,
    pub sandbox_rate: f64,
    pub session_deny_rate: f64,
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DecisionMix {
    pub allow: usize,
    pub deny: usize,
    pub require_approval: usize,
}

#[derive(Debug, Serialize)]
pub struct RuleCount {
    pub rule_id: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct ApprovalFriction {
    /// require_approval receipts that were not approved.
    pub pending_or_blocked: usize,
    /// Later executed+approved receipts whose command matches a prior require_approval.
    pub later_approved: usize,
}

/// Parse duration like `7d`, `24h`, `60m`.
pub fn parse_since(s: &str) -> Result<u128, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty --since".into());
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u128 = num.parse().map_err(|_| format!("invalid --since number in `{s}`"))?;
    let ms = match unit {
        "d" => n.saturating_mul(86_400_000),
        "h" => n.saturating_mul(3_600_000),
        "m" => n.saturating_mul(60_000),
        "s" => n.saturating_mul(1_000),
        _ => return Err(format!("invalid --since unit in `{s}` (use d/h/m/s)")),
    };
    Ok(ms)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn compute(receipts: &[Receipt], since: Option<&str>) -> Result<MetricsReport, String> {
    let cutoff = match since {
        Some(s) => Some(now_ms().saturating_sub(parse_since(s)?)),
        None => None,
    };
    let filtered: Vec<&Receipt> = receipts
        .iter()
        .filter(|r| cutoff.map(|c| r.ts_unix_ms >= c).unwrap_or(true))
        .collect();

    let mut mix = DecisionMix {
        allow: 0,
        deny: 0,
        require_approval: 0,
    };
    let mut rule_counts: HashMap<String, usize> = HashMap::new();
    let mut sandboxed = 0usize;
    for r in &filtered {
        match r.decision {
            Decision::Allow => mix.allow += 1,
            Decision::Deny => mix.deny += 1,
            Decision::RequireApproval => mix.require_approval += 1,
        }
        if let Some(id) = &r.rule_id {
            *rule_counts.entry(id.clone()).or_default() += 1;
        }
        if r.sandbox.as_ref().is_some_and(|s| !s.is_empty()) {
            sandboxed += 1;
        }
    }

    let mut top: Vec<RuleCount> = rule_counts
        .into_iter()
        .map(|(rule_id, count)| RuleCount { rule_id, count })
        .collect();
    top.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.rule_id.cmp(&b.rule_id)));
    top.truncate(10);

    let friction = approval_friction(&filtered);
    let total = filtered.len();
    let deny_rate = if total == 0 {
        0.0
    } else {
        mix.deny as f64 / total as f64
    };
    let sandbox_rate = if total == 0 {
        0.0
    } else {
        sandboxed as f64 / total as f64
    };

    Ok(MetricsReport {
        since_ms: cutoff,
        total,
        decisions: mix,
        top_rule_ids: top,
        approval_friction: friction,
        sandbox_rate,
        session_deny_rate: deny_rate,
        note: "Offline metrics from local receipts only — not agent APM; no network telemetry.",
    })
}

fn approval_friction(receipts: &[&Receipt]) -> ApprovalFriction {
    let mut pending = 0usize;
    let mut later = 0usize;
    for (i, r) in receipts.iter().enumerate() {
        if r.decision != Decision::RequireApproval || r.approved {
            continue;
        }
        if !r.executed {
            pending += 1;
        }
        let found = receipts[i + 1..].iter().any(|later_r| {
            later_r.command == r.command && later_r.approved && later_r.executed
        });
        if found {
            later += 1;
        }
    }
    ApprovalFriction {
        pending_or_blocked: pending,
        later_approved: later,
    }
}

pub fn format_human(m: &MetricsReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("receipts: {}\n", m.total));
    out.push_str(&format!(
        "decisions: allow={} deny={} require_approval={}\n",
        m.decisions.allow, m.decisions.deny, m.decisions.require_approval
    ));
    out.push_str(&format!(
        "session_deny_rate: {:.1}%\n",
        m.session_deny_rate * 100.0
    ));
    out.push_str(&format!("sandbox_rate: {:.1}%\n", m.sandbox_rate * 100.0));
    out.push_str(&format!(
        "approval_friction: pending={} later_approved={}\n",
        m.approval_friction.pending_or_blocked, m.approval_friction.later_approved
    ));
    if !m.top_rule_ids.is_empty() {
        out.push_str("top_rule_ids:\n");
        for r in &m.top_rule_ids {
            out.push_str(&format!("  {} {}\n", r.count, r.rule_id));
        }
    }
    out.push_str(m.note);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_since_days() {
        assert_eq!(parse_since("7d").unwrap(), 7 * 86_400_000);
    }
}
