//! Thin MCP stdio proxy — gate upstream `tools/call` with policy + receipts.
//!
//! Non-goals: mTLS mesh, marketplace scanning, hosted control plane.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Value, json};
use thiserror::Error;

use crate::policy::{CompiledPolicy, Decision, McpCall, load_policy};
use crate::receipts::{AppendOpts, ReceiptLog};
use crate::ux;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy error: {0}")]
    Policy(#[from] crate::policy::PolicyError),
    #[error("receipt error: {0}")]
    Receipt(#[from] crate::receipts::ReceiptError),
    #[error("upstream exited unexpectedly")]
    UpstreamExit,
    #[error("{0}")]
    Msg(String),
}

pub struct ProxyOpts {
    pub policy_path: PathBuf,
    pub receipts_path: PathBuf,
    pub server_name: String,
    pub approve_file: Option<PathBuf>,
    pub upstream: Vec<String>,
}

/// Run the stdio proxy until client stdin EOF or upstream exit.
pub fn run_proxy(opts: ProxyOpts) -> Result<(), ProxyError> {
    if opts.upstream.is_empty() {
        return Err(ProxyError::Msg(
            "mcp-proxy requires an upstream command after `--`".into(),
        ));
    }

    let policy = load_policy(&opts.policy_path)?;
    let receipts = ReceiptLog::open(&opts.receipts_path)?;
    let state = Arc::new(Mutex::new(ProxyState {
        policy,
        receipts,
        server_name: opts.server_name,
        approve_file: opts.approve_file,
    }));

    let mut child = spawn_upstream(&opts.upstream)?;
    let mut upstream_in = child.stdin.take().ok_or_else(|| {
        ProxyError::Msg("failed to open upstream stdin".into())
    })?;
    let upstream_out = child.stdout.take().ok_or_else(|| {
        ProxyError::Msg("failed to open upstream stdout".into())
    })?;

    // Upstream → client (pass-through responses/notifications).
    let forward = thread::spawn(move || {
        let mut reader = BufReader::new(upstream_out);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let mut stdout = std::io::stdout().lock();
                    if writeln!(stdout, "{}", line.trim_end()).is_err() {
                        break;
                    }
                    if stdout.flush().is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Client → proxy → upstream (intercept tools/call).
    let stdin = std::io::stdin();
    let mut client_in = BufReader::new(stdin.lock());
    let mut line = String::new();
    loop {
        line.clear();
        let n = client_in.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = serde_json::from_str(line.trim())?;
        if let Some(blocked) = intercept_tools_call(&state, &msg)? {
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{}", serde_json::to_string(&blocked)?)?;
            stdout.flush()?;
            continue;
        }
        writeln!(upstream_in, "{}", line.trim_end())?;
        upstream_in.flush()?;
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = forward.join();
    Ok(())
}

struct ProxyState {
    policy: CompiledPolicy,
    receipts: ReceiptLog,
    server_name: String,
    approve_file: Option<PathBuf>,
}

fn spawn_upstream(argv: &[String]) -> Result<Child, ProxyError> {
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| ProxyError::Msg("empty upstream".into()))?;
    Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(ProxyError::Io)
}

/// If this is a gated `tools/call`, return a JSON-RPC error/result to send to the client
/// instead of forwarding. `None` means forward unchanged.
fn intercept_tools_call(
    state: &Arc<Mutex<ProxyState>>,
    msg: &Value,
) -> Result<Option<Value>, ProxyError> {
    let method = msg.get("method").and_then(|m| m.as_str());
    if method != Some("tools/call") {
        return Ok(None);
    }
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let tool = params
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    let mut guard = state.lock().map_err(|_| ProxyError::Msg("proxy lock".into()))?;
    let call = McpCall {
        server: guard.server_name.clone(),
        tool: tool.clone(),
        arguments: arguments.clone(),
    };
    let ev = guard.policy.evaluate_mcp(&call);
    let synthetic = call.synthetic_command();

    match ev.decision {
        Decision::Allow => {
            guard.receipts.append(AppendOpts {
                command: synthetic,
                decision: Decision::Allow,
                rule_id: ev.rule_id.clone(),
                reason: ev.reason.clone(),
                approved: false,
                executed: true,
                exit_code: None,
                stdout_preview: None,
                stderr_preview: None,
                sandbox: None,
            })?;
            // Forward to upstream — return None.
            Ok(None)
        }
        Decision::Deny => {
            guard.receipts.append(AppendOpts {
                command: synthetic,
                decision: Decision::Deny,
                rule_id: ev.rule_id.clone(),
                reason: ev.reason.clone(),
                approved: false,
                executed: false,
                exit_code: None,
                stdout_preview: None,
                stderr_preview: None,
                sandbox: None,
            })?;
            Ok(Some(jsonrpc_tool_error(
                id,
                json!({
                    "ok": false,
                    "decision": "deny",
                    "rule_id": ev.rule_id,
                    "reason": ev.reason,
                    "tool": tool,
                    "error": "denied by mayrun mcp-proxy policy",
                    "how_to_adjust": ux::deny_policy_adjust_hint(),
                }),
            )))
        }
        Decision::RequireApproval => {
            let approved = approval_granted(
                guard.approve_file.as_deref(),
                &tool,
                &synthetic,
            )?;
            if approved {
                guard.receipts.append(AppendOpts {
                    command: synthetic,
                    decision: Decision::RequireApproval,
                    rule_id: ev.rule_id.clone(),
                    reason: ev.reason.clone(),
                    approved: true,
                    executed: true,
                    exit_code: None,
                    stdout_preview: None,
                    stderr_preview: None,
                    sandbox: None,
                })?;
                Ok(None)
            } else {
                guard.receipts.append(AppendOpts {
                    command: synthetic,
                    decision: Decision::RequireApproval,
                    rule_id: ev.rule_id.clone(),
                    reason: ev.reason.clone(),
                    approved: false,
                    executed: false,
                    exit_code: None,
                    stdout_preview: None,
                    stderr_preview: None,
                    sandbox: None,
                })?;
                Ok(Some(jsonrpc_tool_error(
                    id,
                    json!({
                        "ok": false,
                        "decision": "require_approval",
                        "rule_id": ev.rule_id,
                        "reason": ev.reason,
                        "tool": tool,
                        "error": "approval required (fail closed)",
                        "hint": "Approve via TTY prompt or write the tool name to --approve-file, then retry",
                    }),
                )))
            }
        }
    }
}

fn jsonrpc_tool_error(id: Value, body: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": body.to_string() }],
            "isError": true
        }
    })
}

fn approval_granted(
    approve_file: Option<&Path>,
    tool: &str,
    synthetic: &str,
) -> Result<bool, ProxyError> {
    if let Some(path) = approve_file {
        if path.is_file() {
            let text = std::fs::read_to_string(path)?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line == tool || line == "*" || synthetic.contains(line) {
                    return Ok(true);
                }
            }
        }
    }
    // TTY approval (stdin is the MCP client — use /dev/tty).
    if let Ok(mut tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")
    {
        let _ = writeln!(
            tty,
            "mayrun mcp-proxy: approval required for `{tool}`\n  {synthetic}\nApprove? [y/N] "
        );
        let _ = tty.flush();
        let mut reader = BufReader::new(tty);
        let mut answer = String::new();
        if reader.read_line(&mut answer).is_ok() {
            let a = answer.trim().to_ascii_lowercase();
            if a == "y" || a == "yes" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyDocument, CompiledPolicy};
    use tempfile::tempdir;

    fn policy_mcp() -> CompiledPolicy {
        let doc: PolicyDocument = serde_yaml::from_str(
            r#"
default: deny
extends:
  - pack: mcp-safe
"#,
        )
        .unwrap();
        CompiledPolicy::compile(doc).unwrap()
    }

    #[test]
    fn intercept_denies_delete_without_forward() {
        let dir = tempdir().unwrap();
        let receipts = dir.path().join("receipts.jsonl");
        let state = Arc::new(Mutex::new(ProxyState {
            policy: policy_mcp(),
            receipts: ReceiptLog::open(&receipts).unwrap(),
            server_name: "filesystem".into(),
            approve_file: None,
        }));
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "delete_file", "arguments": { "path": "x" } }
        });
        let out = intercept_tools_call(&state, &msg).unwrap();
        assert!(out.is_some());
        let body = out.unwrap();
        assert_eq!(body["result"]["isError"], true);
        let text = body["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("deny"), "{text}");
        let log = std::fs::read_to_string(&receipts).unwrap();
        assert!(log.contains("delete_file"));
    }

    #[test]
    fn intercept_allows_read_file_forward() {
        let dir = tempdir().unwrap();
        let receipts = dir.path().join("receipts.jsonl");
        let state = Arc::new(Mutex::new(ProxyState {
            policy: policy_mcp(),
            receipts: ReceiptLog::open(&receipts).unwrap(),
            server_name: "filesystem".into(),
            approve_file: None,
        }));
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "README.md" } }
        });
        let out = intercept_tools_call(&state, &msg).unwrap();
        assert!(out.is_none(), "allow should forward");
        let log = std::fs::read_to_string(&receipts).unwrap();
        assert!(log.contains("read_file"));
        assert!(log.contains("allow"));
    }

    #[test]
    fn non_tools_call_passthrough() {
        let dir = tempdir().unwrap();
        let state = Arc::new(Mutex::new(ProxyState {
            policy: policy_mcp(),
            receipts: ReceiptLog::open(dir.path().join("r.jsonl")).unwrap(),
            server_name: "fs".into(),
            approve_file: None,
        }));
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        assert!(intercept_tools_call(&state, &msg).unwrap().is_none());
    }
}
