//! Command execution under policy.

use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::process::Command;
use tokio::time::timeout;

use crate::policy::{CompiledPolicy, Decision, Evaluation};
use crate::receipts::{AppendOpts, Receipt, ReceiptLog};

const PREVIEW_CHARS: usize = 2_000;
const DEFAULT_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Error)]
pub enum RunError {
    #[error("denied by policy")]
    Denied {
        rule_id: Option<String>,
        reason: Option<String>,
    },
    #[error("approval required (id={id})")]
    ApprovalRequired {
        id: String,
        rule_id: Option<String>,
        reason: Option<String>,
    },
    #[error("session run budget exceeded ({max})")]
    BudgetExceeded { max: u32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("receipt error: {0}")]
    Receipt(#[from] crate::receipts::ReceiptError),
    #[error("command timed out after {0}s")]
    TimedOut(u64),
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub receipt: Receipt,
    pub evaluation: Evaluation,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub struct Runner {
    policy: CompiledPolicy,
    receipts: ReceiptLog,
    runs: AtomicU32,
    timeout_secs: u64,
}

impl Runner {
    pub fn new(policy: CompiledPolicy, receipts: ReceiptLog) -> Self {
        Self {
            policy,
            receipts,
            runs: AtomicU32::new(0),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }

    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }

    pub fn receipts(&self) -> &ReceiptLog {
        &self.receipts
    }

    #[allow(dead_code)]
    pub fn evaluate(&self, command: &str) -> Decision {
        self.policy.evaluate(command)
    }

    pub fn evaluate_detailed(&self, command: &str) -> Evaluation {
        self.policy.evaluate_detailed(command)
    }

    pub async fn run(&mut self, command: &str, force_approve: bool) -> Result<RunResult, RunError> {
        if let Some(max) = self.policy.raw.max_runs_per_session {
            let n = self.runs.load(Ordering::Relaxed);
            if n >= max {
                let _ = self.receipts.append(AppendOpts {
                    command: command.into(),
                    decision: Decision::Deny,
                    rule_id: None,
                    reason: Some(format!("budget exceeded ({max})")),
                    approved: false,
                    executed: false,
                    exit_code: None,
                    stdout_preview: None,
                    stderr_preview: None,
                })?;
                return Err(RunError::BudgetExceeded { max });
            }
        }

        let evaluation = self.policy.evaluate_detailed(command);
        match evaluation.decision {
            Decision::Deny => {
                let _ = self.receipts.append(AppendOpts {
                    command: command.into(),
                    decision: Decision::Deny,
                    rule_id: evaluation.rule_id.clone(),
                    reason: evaluation.reason.clone(),
                    approved: false,
                    executed: false,
                    exit_code: None,
                    stdout_preview: None,
                    stderr_preview: None,
                })?;
                Err(RunError::Denied {
                    rule_id: evaluation.rule_id,
                    reason: evaluation.reason,
                })
            }
            Decision::RequireApproval if !force_approve => {
                let receipt = self.receipts.append(AppendOpts {
                    command: command.into(),
                    decision: Decision::RequireApproval,
                    rule_id: evaluation.rule_id.clone(),
                    reason: evaluation.reason.clone(),
                    approved: false,
                    executed: false,
                    exit_code: None,
                    stdout_preview: None,
                    stderr_preview: None,
                })?;
                Err(RunError::ApprovalRequired {
                    id: receipt.id,
                    rule_id: evaluation.rule_id,
                    reason: evaluation.reason,
                })
            }
            Decision::Allow | Decision::RequireApproval => {
                self.runs.fetch_add(1, Ordering::Relaxed);
                let approved = matches!(evaluation.decision, Decision::RequireApproval) && force_approve;
                self.execute(command, evaluation, approved).await
            }
        }
    }

    async fn execute(
        &mut self,
        command: &str,
        evaluation: Evaluation,
        approved: bool,
    ) -> Result<RunResult, RunError> {
        let child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let output = match timeout(
            Duration::from_secs(self.timeout_secs),
            child.wait_with_output(),
        )
        .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => return Err(RunError::Io(e)),
            Err(_) => {
                let _ = self.receipts.append(AppendOpts {
                    command: command.into(),
                    decision: evaluation.decision,
                    rule_id: evaluation.rule_id.clone(),
                    reason: Some(format!("timed out after {}s", self.timeout_secs)),
                    approved,
                    executed: false,
                    exit_code: None,
                    stdout_preview: None,
                    stderr_preview: None,
                })?;
                return Err(RunError::TimedOut(self.timeout_secs));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);
        let receipt = self.receipts.append(AppendOpts {
            command: command.into(),
            decision: evaluation.decision,
            rule_id: evaluation.rule_id.clone(),
            reason: evaluation.reason.clone(),
            approved,
            executed: true,
            exit_code: Some(exit_code),
            stdout_preview: Some(preview(&stdout)),
            stderr_preview: Some(preview(&stderr)),
        })?;

        Ok(RunResult {
            receipt,
            evaluation,
            stdout,
            stderr,
            exit_code,
        })
    }
}

fn preview(s: &str) -> String {
    if s.chars().count() <= PREVIEW_CHARS {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(PREVIEW_CHARS).collect();
        format!("{truncated}…")
    }
}
