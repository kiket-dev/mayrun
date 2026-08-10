//! Offline pack scoreboard over pinned corpus fixtures.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::policy::{CompiledPolicy, Decision, PolicyDocument, PolicyError};

#[derive(Debug, Deserialize)]
pub struct CorpusFile {
    #[serde(default)]
    pub cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorpusCase {
    pub command: String,
    pub expect: ExpectDecision,
    #[serde(default)]
    pub rule_prefix: Option<String>,
    #[serde(default)]
    pub packs: Option<Vec<String>>,
    /// Optional label: unsafe (default for deny/require_approval) or safe (allow).
    #[serde(default)]
    pub class: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectDecision {
    Allow,
    Deny,
    RequireApproval,
}

impl From<ExpectDecision> for Decision {
    fn from(e: ExpectDecision) -> Self {
        match e {
            ExpectDecision::Allow => Decision::Allow,
            ExpectDecision::Deny => Decision::Deny,
            ExpectDecision::RequireApproval => Decision::RequireApproval,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScoreboardReport {
    pub total: usize,
    pub unsafe_cases: usize,
    pub safe_cases: usize,
    pub recall_unsafe: f64,
    pub false_positive_rate_safe: f64,
    pub misses: Vec<Miss>,
    pub false_positives: Vec<Miss>,
}

#[derive(Debug, Serialize)]
pub struct Miss {
    pub command: String,
    pub expect: String,
    pub got: String,
    pub rule_id: Option<String>,
}

pub fn load_corpus(path: &Path) -> Result<CorpusFile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_yaml::from_str(&text).map_err(|e| format!("corpus YAML: {e}"))
}

fn policy_for_case(case: &CorpusCase) -> Result<CompiledPolicy, PolicyError> {
    let packs = case.packs.clone().unwrap_or_else(|| {
        crate::packs::PACK_NAMES
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    });
    let doc = PolicyDocument {
        api_version: Some("mayrun.dev/v1".into()),
        default: Decision::Deny,
        extends: packs
            .into_iter()
            .map(crate::policy::ExtendSpec::PackName)
            .collect(),
        ..PolicyDocument::default()
    };
    CompiledPolicy::compile(doc)
}

fn is_unsafe(case: &CorpusCase) -> bool {
    if let Some(c) = &case.class {
        return c == "unsafe";
    }
    !matches!(case.expect, ExpectDecision::Allow)
}

pub fn evaluate(corpus: &CorpusFile) -> Result<ScoreboardReport, String> {
    let mut unsafe_total = 0usize;
    let mut unsafe_hit = 0usize;
    let mut safe_total = 0usize;
    let mut safe_fp = 0usize;
    let mut misses = Vec::new();
    let mut false_positives = Vec::new();

    for case in &corpus.cases {
        let policy = policy_for_case(case).map_err(|e| e.to_string())?;
        let ev = policy.evaluate_detailed(&case.command);
        let expect: Decision = case.expect.into();
        let decision_ok = ev.decision == expect;
        let rule_id = ev.rule_id.as_deref().unwrap_or("");
        let reason = ev.reason.as_deref().unwrap_or("");
        let prefix_ok = match &case.rule_prefix {
            Some(p) if p == "default" => {
                rule_id.is_empty() || reason.starts_with("default:")
            }
            Some(p) => rule_id.starts_with(p) || rule_id == p,
            None => true,
        };
        let ok = decision_ok && prefix_ok;

        if is_unsafe(case) {
            unsafe_total += 1;
            if ok {
                unsafe_hit += 1;
            } else {
                misses.push(Miss {
                    command: case.command.clone(),
                    expect: format!("{expect:?}").to_ascii_lowercase(),
                    got: format!("{:?}", ev.decision).to_ascii_lowercase(),
                    rule_id: ev.rule_id.clone(),
                });
            }
        } else {
            safe_total += 1;
            // FP: safe command not allowed (over-blocked)
            if ev.decision != Decision::Allow {
                safe_fp += 1;
                false_positives.push(Miss {
                    command: case.command.clone(),
                    expect: "allow".into(),
                    got: format!("{:?}", ev.decision).to_ascii_lowercase(),
                    rule_id: ev.rule_id.clone(),
                });
            } else if !ok {
                // allow but wrong rule prefix — count as miss for pack lockstep
                misses.push(Miss {
                    command: case.command.clone(),
                    expect: format!("{expect:?}").to_ascii_lowercase(),
                    got: format!("{:?}", ev.decision).to_ascii_lowercase(),
                    rule_id: ev.rule_id.clone(),
                });
            }
        }
    }

    let recall = if unsafe_total == 0 {
        1.0
    } else {
        unsafe_hit as f64 / unsafe_total as f64
    };
    let fpr = if safe_total == 0 {
        0.0
    } else {
        safe_fp as f64 / safe_total as f64
    };

    Ok(ScoreboardReport {
        total: corpus.cases.len(),
        unsafe_cases: unsafe_total,
        safe_cases: safe_total,
        recall_unsafe: recall,
        false_positive_rate_safe: fpr,
        misses,
        false_positives,
    })
}

pub fn format_markdown(r: &ScoreboardReport) -> String {
    let mut out = String::new();
    out.push_str("# mayrun pack scoreboard\n\n");
    out.push_str(&format!("- cases: {}\n", r.total));
    out.push_str(&format!("- unsafe: {}\n", r.unsafe_cases));
    out.push_str(&format!("- safe: {}\n", r.safe_cases));
    out.push_str(&format!(
        "- recall (unsafe): {:.1}%\n",
        r.recall_unsafe * 100.0
    ));
    out.push_str(&format!(
        "- false positive rate (safe): {:.1}%\n",
        r.false_positive_rate_safe * 100.0
    ));
    if !r.misses.is_empty() {
        out.push_str("\n## Misses\n\n");
        for m in &r.misses {
            out.push_str(&format!(
                "- `{}` expect={} got={} rule={}\n",
                m.command,
                m.expect,
                m.got,
                m.rule_id.as_deref().unwrap_or("-")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoreboard_on_repo_corpus() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus.yaml");
        if !path.is_file() {
            return;
        }
        let corpus = load_corpus(&path).unwrap();
        let report = evaluate(&corpus).unwrap();
        assert!(report.total > 0);
        assert!(
            report.recall_unsafe >= 0.99,
            "recall regressed: {} misses: {:?}",
            report.misses.len(),
            report.misses
        );
    }
}
