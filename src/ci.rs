//! `mayrun ci` — policy compile + advisory scoreboard (Free) / receipt gate (Pro).

use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use crate::license::{self, LicenseError};
use crate::policy::{self, PolicyError};
use crate::receipts::{self, Receipt};
use crate::scoreboard;

#[derive(Debug, Error)]
pub enum CiError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Receipt(#[from] receipts::ReceiptError),
    #[error(transparent)]
    License(#[from] LicenseError),
    #[error("{0}")]
    Msg(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiTier {
    Free,
    Pro,
}

#[derive(Debug, Clone, Serialize)]
pub struct CiAnnotation {
    pub level: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CiReport {
    pub tier: CiTier,
    pub ok: bool,
    pub policy_path: String,
    pub rule_count: usize,
    pub receipt_count: usize,
    pub receipt_chain_ok: bool,
    pub scoreboard_recall: Option<f64>,
    pub annotations: Vec<CiAnnotation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_sub: Option<String>,
}

pub struct CiOpts {
    pub policy: PathBuf,
    pub receipts: PathBuf,
    pub corpus: Option<PathBuf>,
    pub license: Option<String>,
    pub repo_sub: Option<String>,
    /// When true (or license valid), enforce Pro receipt gate.
    pub force_pro: bool,
}

pub fn run(opts: CiOpts) -> Result<CiReport, CiError> {
    let mut annotations = Vec::new();

    let compiled = policy::load_policy(&opts.policy)?;
    let (allow, deny, require_approval) = compiled.counts_by_effect();
    annotations.push(CiAnnotation {
        level: "notice".into(),
        message: format!(
            "policy ok: {} rules (allow={allow} deny={deny} require_approval={require_approval})",
            compiled.rule_count()
        ),
        rule_id: None,
    });

    let mut scoreboard_recall = None;
    if let Some(corpus) = &opts.corpus {
        if corpus.is_file() {
            match scoreboard::load_corpus(corpus).and_then(|f| scoreboard::evaluate(&f)) {
                Ok(report) => {
                    scoreboard_recall = Some(report.recall_unsafe);
                    annotations.push(CiAnnotation {
                        level: "notice".into(),
                        message: format!(
                            "scoreboard advisory: recall_unsafe={:.3} fp_rate={:.3} ({} misses)",
                            report.recall_unsafe,
                            report.false_positive_rate_safe,
                            report.misses.len()
                        ),
                        rule_id: None,
                    });
                    for m in report.misses.iter().take(5) {
                        annotations.push(CiAnnotation {
                            level: "warning".into(),
                            message: format!(
                                "scoreboard miss: {} (expect {} got {})",
                                m.command, m.expect, m.got
                            ),
                            rule_id: m.rule_id.clone(),
                        });
                    }
                }
                Err(e) => {
                    annotations.push(CiAnnotation {
                        level: "warning".into(),
                        message: format!("scoreboard advisory skipped: {e}"),
                        rule_id: None,
                    });
                }
            }
        }
    }

    let (receipts, chain_ok, chain_err) = load_receipts_checked(&opts.receipts)?;
    if let Some(ref err) = chain_err {
        annotations.push(CiAnnotation {
            level: "error".into(),
            message: format!("receipt chain invalid: {err}"),
            rule_id: None,
        });
    } else if receipts.is_empty() {
        annotations.push(CiAnnotation {
            level: "notice".into(),
            message: format!(
                "no receipts at {} (local gate not exercised in this checkout)",
                opts.receipts.display()
            ),
            rule_id: None,
        });
    } else {
        annotations.push(CiAnnotation {
            level: "notice".into(),
            message: format!(
                "receipt chain ok ({} entries at {})",
                receipts.len(),
                opts.receipts.display()
            ),
            rule_id: None,
        });
    }

    let mut tier = CiTier::Free;
    let mut license_sub = None;
    let mut pro = opts.force_pro;

    if let Some(lic) = opts.license.as_deref().filter(|s| !s.trim().is_empty()) {
        let verified = license::verify(lic, opts.repo_sub.as_deref(), None)?;
        tier = CiTier::Pro;
        license_sub = Some(verified.payload.sub.clone());
        pro = true;
        annotations.push(CiAnnotation {
            level: "notice".into(),
            message: format!(
                "Pro license ok (sub={}, tier={})",
                verified.payload.sub, verified.payload.tier
            ),
            rule_id: None,
        });
    } else if opts.force_pro {
        return Err(CiError::Msg(
            "Pro mode requested but MAYRUN_LICENSE / --license missing".into(),
        ));
    }

    let mut ok = chain_err.is_none();
    if pro {
        tier = CiTier::Pro;
        // Pro receipt gate: chain must be valid AND at least one receipt present
        // as evidence the local gate was used for this change set / workspace.
        if receipts.is_empty() {
            ok = false;
            annotations.push(CiAnnotation {
                level: "error".into(),
                message: "Pro receipt gate: required evidence missing — no receipts found. Run gated commands via mayrun (shell-hook/mcp/mcp-proxy) so `.mayrun/receipts.jsonl` is committed or uploaded as a CI artifact.".into(),
                rule_id: None,
            });
        } else if !chain_ok {
            ok = false;
        } else {
            // Surface recent denials as annotations (informational; chain validity is the gate).
            for r in receipts.iter().rev().take(20) {
                if matches!(r.decision, crate::policy::Decision::Deny) {
                    annotations.push(CiAnnotation {
                        level: "warning".into(),
                        message: format!(
                            "recent deny receipt: {} ({})",
                            r.command,
                            r.reason.as_deref().unwrap_or("no reason")
                        ),
                        rule_id: r.rule_id.clone(),
                    });
                }
            }
            annotations.push(CiAnnotation {
                level: "notice".into(),
                message: "Pro receipt gate passed".into(),
                rule_id: None,
            });
        }
    }

    Ok(CiReport {
        tier,
        ok,
        policy_path: opts.policy.display().to_string(),
        rule_count: compiled.rule_count(),
        receipt_count: receipts.len(),
        receipt_chain_ok: chain_ok,
        scoreboard_recall,
        annotations,
        license_sub,
    })
}

fn load_receipts_checked(
    path: &Path,
) -> Result<(Vec<Receipt>, bool, Option<String>), CiError> {
    if !path.is_file() {
        return Ok((Vec::new(), true, None));
    }
    let text = std::fs::read_to_string(path).map_err(|e| CiError::Msg(e.to_string()))?;
    let mut receipts = Vec::new();
    let mut prev = "genesis".to_string();
    for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let r: Receipt = serde_json::from_str(line).map_err(|e| {
            CiError::Msg(format!("receipt parse error line {}: {e}", i + 1))
        })?;
        if r.prev_hash != prev {
            return Ok((
                receipts,
                false,
                Some(format!(
                    "broken chain at receipt {} (expected prev_hash {prev}, got {})",
                    r.id, r.prev_hash
                )),
            ));
        }
        // Re-hash check: trust stored hash linkage for v1; prev_hash continuity is the gate.
        prev = r.hash.clone();
        receipts.push(r);
    }
    Ok((receipts, true, None))
}

/// Emit GitHub Actions workflow commands for annotations.
pub fn emit_github_annotations(report: &CiReport) {
    for a in &report.annotations {
        let level = match a.level.as_str() {
            "error" => "error",
            "warning" => "warning",
            _ => "notice",
        };
        let mut msg = a.message.clone();
        if let Some(rid) = &a.rule_id {
            msg = format!("[{rid}] {msg}");
        }
        // Sanitize so annotations stay on one line.
        let msg = msg.replace('\n', " ").replace('%', "%25").replace('\r', "");
        println!("::{level}::{msg}");
    }
}

pub fn format_human(report: &CiReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "mayrun ci [{}] ok={} policy={} rules={} receipts={} chain_ok={}\n",
        match report.tier {
            CiTier::Free => "free",
            CiTier::Pro => "pro",
        },
        report.ok,
        report.policy_path,
        report.rule_count,
        report.receipt_count,
        report.receipt_chain_ok,
    ));
    for a in &report.annotations {
        out.push_str(&format!("  - {}: {}\n", a.level, a.message));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::{self, DOGFOOD_SIGNING_KEY_HEX};
    use tempfile::tempdir;

    #[test]
    fn free_tier_ok_without_receipts() {
        let dir = tempdir().unwrap();
        let policy = dir.path().join("mayrun.policy.yaml");
        std::fs::write(
            &policy,
            r#"
default: deny
extends:
  - pack: dangerous-defaults
  - pack: git-safe
"#,
        )
        .unwrap();
        let report = run(CiOpts {
            policy,
            receipts: dir.path().join("missing.jsonl"),
            corpus: None,
            license: None,
            repo_sub: None,
            force_pro: false,
        })
        .unwrap();
        assert!(report.ok);
        assert_eq!(report.tier, CiTier::Free);
    }

    #[test]
    fn pro_fails_without_receipts() {
        let dir = tempdir().unwrap();
        let policy = dir.path().join("mayrun.policy.yaml");
        std::fs::write(
            &policy,
            "default: deny\nextends:\n  - pack: dangerous-defaults\n",
        )
        .unwrap();
        let key = license::mint_with_key(DOGFOOD_SIGNING_KEY_HEX, "*", None).unwrap();
        // Ensure verify uses dogfood verifying key (default).
        let report = run(CiOpts {
            policy,
            receipts: dir.path().join("missing.jsonl"),
            corpus: None,
            license: Some(key),
            repo_sub: Some("acme/app".into()),
            force_pro: false,
        })
        .unwrap();
        assert!(!report.ok);
        assert_eq!(report.tier, CiTier::Pro);
        assert!(
            report
                .annotations
                .iter()
                .any(|a| a.level == "error" && a.message.contains("receipt")),
            "{:?}",
            report.annotations
        );
    }

    #[test]
    fn pro_passes_with_valid_receipt_chain() {
        let dir = tempdir().unwrap();
        let policy = dir.path().join("mayrun.policy.yaml");
        std::fs::write(
            &policy,
            "default: deny\nextends:\n  - pack: dangerous-defaults\n  - pack: git-safe\n",
        )
        .unwrap();
        let receipts_path = dir.path().join("receipts.jsonl");
        let mut log = receipts::ReceiptLog::open(&receipts_path).unwrap();
        log.append(receipts::AppendOpts {
            command: "git status".into(),
            decision: crate::policy::Decision::Allow,
            rule_id: Some("pack.git.status".into()),
            reason: Some("ok".into()),
            approved: false,
            executed: true,
            exit_code: Some(0),
            stdout_preview: None,
            stderr_preview: None,
            sandbox: None,
        })
        .unwrap();
        let key = license::mint_with_key(DOGFOOD_SIGNING_KEY_HEX, "*", None).unwrap();
        let report = run(CiOpts {
            policy,
            receipts: receipts_path,
            corpus: None,
            license: Some(key),
            repo_sub: None,
            force_pro: false,
        })
        .unwrap();
        assert!(report.ok, "{:?}", report.annotations);
        assert_eq!(report.receipt_count, 1);
    }
}
