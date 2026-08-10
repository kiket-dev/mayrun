//! MCP stdio server exposing mayrun tools.

use std::path::PathBuf;
use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars,
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::policy::{Decision, find_policy_path, load_policy};
use crate::receipts::{ReceiptLog, default_receipt_path};
use crate::shell::Runner;
use crate::ux;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RunArgs {
    /// Shell command to evaluate and possibly execute.
    pub command: String,
    /// Set true only after a human explicitly approved a require_approval command.
    #[serde(default)]
    pub approved: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StatusArgs {
    /// How many recent receipts to include (default 10).
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DraftArgs {
    /// Natural-language intent for a policy draft (review before applying).
    pub intent: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TightenArgs {
    /// Minimum times a pattern must appear (default 2).
    #[serde(default = "default_min_count")]
    pub min_count: usize,
}

fn default_limit() -> usize {
    10
}

fn default_min_count() -> usize {
    2
}

#[derive(Clone)]
pub struct MayrunServer {
    runner: Arc<Mutex<Runner>>,
    policy_path: PathBuf,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl MayrunServer {
    pub fn try_new(policy_path: Option<PathBuf>, receipt_path: Option<PathBuf>) -> anyhow::Result<Self> {
        let policy_path = policy_path
            .or_else(|| find_policy_path(None))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no policy file found; run `mayrun init` or pass --policy mayrun.policy.yaml"
                )
            })?;
        let policy = load_policy(&policy_path)?;
        let receipts = ReceiptLog::open(receipt_path.unwrap_or_else(default_receipt_path))?;
        let runner = Runner::new(policy, receipts);
        Ok(Self {
            runner: Arc::new(Mutex::new(runner)),
            policy_path,
            tool_router: Self::tool_router(),
        })
    }

    #[tool(
        description = "Evaluate policy and run a shell command if allowed. Prefer this over unrestricted shell. If require_approval, ask the human to approve then retry with approved=true."
    )]
    async fn mayrun_run(
        &self,
        Parameters(args): Parameters<RunArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut runner = self.runner.lock().await;
        match runner.run(&args.command, args.approved).await {
            Ok(result) => {
                let body = serde_json::json!({
                    "ok": true,
                    "decision": result.receipt.decision,
                    "rule_id": result.receipt.rule_id,
                    "reason": result.receipt.reason,
                    "capabilities": result.evaluation.capabilities,
                    "approved": result.receipt.approved,
                    "exit_code": result.exit_code,
                    "receipt_id": result.receipt.id,
                    "receipt_hash": result.receipt.hash,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                });
                Ok(CallToolResult::success(vec![Content::text(
                    body.to_string(),
                )]))
            }
            Err(crate::shell::RunError::Denied { rule_id, reason }) => {
                Ok(CallToolResult::error(vec![Content::text(
                    serde_json::json!({
                        "ok": false,
                        "decision": Decision::Deny,
                        "rule_id": rule_id,
                        "reason": reason,
                        "error": "denied by policy",
                        "command": args.command,
                        "how_to_adjust": ux::deny_policy_adjust_hint(),
                        "next_steps": [
                            "Do not retry with approved=true — Deny cannot be bypassed by approval.",
                            "Edit mayrun.policy.yaml or pack rules, then mayrun_check before retrying.",
                        ],
                    })
                    .to_string(),
                )]))
            }
            Err(crate::shell::RunError::ApprovalRequired { id, rule_id, reason }) => {
                Ok(CallToolResult::error(vec![Content::text(
                    serde_json::json!({
                        "ok": false,
                        "decision": Decision::RequireApproval,
                        "rule_id": rule_id,
                        "reason": reason,
                        "error": "approval required",
                        "receipt_id": id,
                        "hint": "Ask the human to confirm, then call mayrun_run again with approved=true",
                        "next_steps": ux::approve_mcp_next_steps(&args.command),
                        "command": args.command,
                    })
                    .to_string(),
                )]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "{{\"ok\":false,\"error\":{}}}",
                serde_json::to_string(&e.to_string()).unwrap_or_else(|_| "\"error\"".into())
            ))])),
        }
    }

    #[tool(description = "Show active mayrun policy path, default decision, and recent receipts.")]
    async fn mayrun_status(
        &self,
        Parameters(args): Parameters<StatusArgs>,
    ) -> Result<CallToolResult, McpError> {
        let runner = self.runner.lock().await;
        let recent = runner
            .receipts()
            .recent(args.limit.max(1).min(100))
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let (allow, deny, require_approval) = runner.policy().counts_by_effect();
        let body = serde_json::json!({
            "policy_path": self.policy_path,
            "default": runner.policy().raw.default,
            "rule_count": runner.policy().rule_count(),
            "allow_rules": allow,
            "deny_rules": deny,
            "require_approval_rules": require_approval,
            "extends": runner.policy().raw.extends.iter().map(|e| e.pack_name()).collect::<Vec<_>>(),
            "receipt_path": runner.receipts().path(),
            "recent_receipts": recent,
        });
        Ok(CallToolResult::success(vec![Content::text(
            body.to_string(),
        )]))
    }

    #[tool(description = "Evaluate a command against policy without executing it. Returns decision, rule_id, reason, and capabilities.")]
    async fn mayrun_check(
        &self,
        Parameters(args): Parameters<RunArgs>,
    ) -> Result<CallToolResult, McpError> {
        let runner = self.runner.lock().await;
        let ev = runner.evaluate_detailed(&args.command);
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::json!({
                "command": args.command,
                "decision": ev.decision,
                "rule_id": ev.rule_id,
                "reason": ev.reason,
                "capabilities": ev.capabilities,
            })
            .to_string(),
        )]))
    }

    #[tool(
        description = "Draft a mayrun policy YAML from natural-language intent. Output is a proposal only — never auto-applies. Human must review and write the file."
    )]
    async fn mayrun_policy_suggest(
        &self,
        Parameters(args): Parameters<DraftArgs>,
    ) -> Result<CallToolResult, McpError> {
        let yaml = crate::author::draft_policy(&args.intent)
            .map_err(|e| McpError::internal_error(e, None))?;
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::json!({
                "proposal_only": true,
                "warning": "Review YAML before writing to mayrun.policy.yaml. AI never grants runtime Allow.",
                "yaml": yaml,
            })
            .to_string(),
        )]))
    }

    #[tool(
        description = "Propose policy rule snippets from recent receipt history (deterministic). Proposal only — never auto-applies."
    )]
    async fn mayrun_policy_tighten(
        &self,
        Parameters(args): Parameters<TightenArgs>,
    ) -> Result<CallToolResult, McpError> {
        let runner = self.runner.lock().await;
        let all = runner
            .receipts()
            .all()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let yaml = crate::author::tighten_from_receipts(&all, args.min_count.max(1));
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::json!({
                "proposal_only": true,
                "yaml": yaml,
            })
            .to_string(),
        )]))
    }
}

#[tool_handler]
impl ServerHandler for MayrunServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "mayrun gates shell side effects for coding agents. Use mayrun_check or mayrun_run instead of unrestricted shell. Respect deny and require_approval decisions. Policy suggest/tighten tools only propose YAML for human review."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
