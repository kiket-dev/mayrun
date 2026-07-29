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

use crate::policy::{CompiledPolicy, Decision, find_policy_path, load_policy};
use crate::receipts::{ReceiptLog, default_receipt_path};
use crate::shell::Runner;

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

fn default_limit() -> usize {
    10
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
            Err(crate::shell::RunError::Denied) => Ok(CallToolResult::error(vec![Content::text(
                serde_json::json!({
                    "ok": false,
                    "decision": Decision::Deny,
                    "error": "denied by policy",
                    "command": args.command,
                })
                .to_string(),
            )])),
            Err(crate::shell::RunError::ApprovalRequired { id }) => {
                Ok(CallToolResult::error(vec![Content::text(
                    serde_json::json!({
                        "ok": false,
                        "decision": Decision::RequireApproval,
                        "error": "approval required",
                        "receipt_id": id,
                        "hint": "Ask the human to confirm, then call mayrun_run again with approved=true",
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
        let body = serde_json::json!({
            "policy_path": self.policy_path,
            "default": runner.policy().raw.default,
            "allow_rules": runner.policy().raw.allow.len(),
            "deny_rules": runner.policy().raw.deny.len(),
            "require_approval_rules": runner.policy().raw.require_approval.len(),
            "receipt_path": runner.receipts().path(),
            "recent_receipts": recent,
        });
        Ok(CallToolResult::success(vec![Content::text(
            body.to_string(),
        )]))
    }

    #[tool(description = "Evaluate a command against policy without executing it.")]
    async fn mayrun_check(
        &self,
        Parameters(args): Parameters<RunArgs>,
    ) -> Result<CallToolResult, McpError> {
        let runner = self.runner.lock().await;
        let decision = runner.evaluate(&args.command);
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::json!({
                "command": args.command,
                "decision": decision,
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
                "mayrun gates shell side effects for coding agents. Use mayrun_check or mayrun_run instead of unrestricted shell. Respect deny and require_approval decisions."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

/// Re-export for type visibility in tests.
#[allow(dead_code)]
pub type PolicyRef = CompiledPolicy;
