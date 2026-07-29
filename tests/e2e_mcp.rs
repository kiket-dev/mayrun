//! Deterministic MCP stdio e2e — speaks JSON-RPC NDJSON (rmcp framing) to `mayrun mcp`.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::tempdir;

fn mayrun_bin() -> PathBuf {
    env!("CARGO_BIN_EXE_mayrun").into()
}

struct McpClient {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl McpClient {
    fn spawn(policy: &PathBuf, receipts: &PathBuf, cwd: &std::path::Path) -> Self {
        let mut child = Command::new(mayrun_bin())
            .args([
                "mcp",
                "--policy",
                policy.to_str().unwrap(),
                "--receipts",
                receipts.to_str().unwrap(),
            ])
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mayrun mcp");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    fn write_msg(&mut self, msg: &Value) {
        let line = serde_json::to_string(msg).unwrap();
        writeln!(self.stdin, "{line}").expect("write mcp frame");
        self.stdin.flush().expect("flush mcp");
    }

    fn read_msg(&mut self) -> Value {
        let mut line = String::new();
        // Skip blank lines; rmcp uses newline-delimited JSON.
        loop {
            line.clear();
            self.stdout
                .read_line(&mut line)
                .expect("read mcp stdout");
            if line.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(line.trim()).unwrap_or_else(|e| {
                panic!("invalid mcp json ({e}): {line}");
            });
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.write_msg(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        // Read until we get a response with matching id (ignore notifications).
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let msg = self.read_msg();
            if msg.get("id").and_then(|v| v.as_u64()) == Some(id) {
                return msg;
            }
        }
        panic!("timeout waiting for response id={id} method={method}");
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.write_msg(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }));
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let resp = self.request(
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments,
            }),
        );
        resp["result"].clone()
    }

    fn tool_text_json(&mut self, name: &str, arguments: Value) -> Value {
        let result = self.call_tool(name, arguments);
        let text = result["content"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or_else(|| panic!("missing tool text content: {result}"));
        serde_json::from_str(text).unwrap_or_else(|e| panic!("tool text not json ({e}): {text}"))
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_policy(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("mayrun.policy.yaml");
    std::fs::write(
        &path,
        r#"
apiVersion: mayrun.dev/v1
default: deny
extends:
  - pack: dangerous-defaults
  - pack: secrets-safe
  - pack: exec-escapes
  - pack: git-safe
  - pack: rust-dev
"#,
    )
    .unwrap();
    path
}

#[test]
fn mcp_protocol_check_run_approve_and_receipts() {
    let dir = tempdir().unwrap();
    let policy = write_policy(dir.path());
    let receipts = dir.path().join(".mayrun").join("receipts.jsonl");
    std::fs::create_dir_all(receipts.parent().unwrap()).unwrap();

    let mut client = McpClient::spawn(&policy, &receipts, dir.path());

    // initialize
    let init = client.request(
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "mayrun-e2e", "version": "0.0.0" }
        }),
    );
    assert!(init.get("result").is_some(), "initialize failed: {init}");
    client.notify("notifications/initialized", json!({}));

    // tools/list — expect 5 mayrun tools
    let listed = client.request("tools/list", json!({}));
    let tools = listed["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert_eq!(tools.len(), 5, "tools: {tools:?}");
    let names: Vec<_> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    for need in [
        "mayrun_check",
        "mayrun_run",
        "mayrun_status",
        "mayrun_policy_suggest",
        "mayrun_policy_tighten",
    ] {
        assert!(names.contains(&need), "missing tool {need} in {names:?}");
    }

    // mayrun_check — deny
    let deny = client.tool_text_json(
        "mayrun_check",
        json!({ "command": "rm -rf /" }),
    );
    assert_eq!(deny["decision"], "deny");
    assert!(
        deny["rule_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("pack.dangerous"),
        "{deny}"
    );

    // mayrun_check — require_approval
    let appr = client.tool_text_json(
        "mayrun_check",
        json!({ "command": "git push origin main" }),
    );
    assert_eq!(appr["decision"], "require_approval");

    // mayrun_check — allow
    let allow = client.tool_text_json(
        "mayrun_check",
        json!({ "command": "git status" }),
    );
    assert_eq!(allow["decision"], "allow");

    // mayrun_run allow path
    let run_ok = client.tool_text_json(
        "mayrun_run",
        json!({ "command": "git status" }),
    );
    assert_eq!(run_ok["ok"], true);
    assert_eq!(run_ok["decision"], "allow");
    assert!(run_ok["receipt_hash"].as_str().is_some_and(|h| !h.is_empty()));

    // mayrun_run require_approval without approved → error payload
    let need = client.call_tool(
        "mayrun_run",
        json!({ "command": "git push origin main" }),
    );
    assert_eq!(need["isError"], true);
    let need_body: Value = serde_json::from_str(
        need["content"][0]["text"]
            .as_str()
            .expect("error text"),
    )
    .unwrap();
    assert_eq!(need_body["decision"], "require_approval");
    assert_eq!(need_body["ok"], false);

    // retry with approved=true (executes; exit code may be non-zero without a remote)
    let approved = client.tool_text_json(
        "mayrun_run",
        json!({ "command": "git push", "approved": true }),
    );
    assert_eq!(approved["ok"], true, "{approved}");
    assert!(approved["receipt_hash"].as_str().is_some_and(|h| !h.is_empty()));
    assert_eq!(approved["approved"], true);

    // policy suggest / tighten are proposal_only
    let suggest = client.tool_text_json(
        "mayrun_policy_suggest",
        json!({ "intent": "allow cargo test" }),
    );
    assert_eq!(suggest["proposal_only"], true);
    assert!(suggest["yaml"].as_str().is_some_and(|y| y.contains("extends")));

    let tighten = client.tool_text_json(
        "mayrun_policy_tighten",
        json!({ "min_count": 1 }),
    );
    assert_eq!(tighten["proposal_only"], true);

    // Receipt chain
    let text = std::fs::read_to_string(&receipts).expect("receipts file");
    let lines: Vec<_> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(lines.len() >= 2, "expected multiple receipts, got {}", lines.len());
    let mut prev = "genesis".to_string();
    for line in &lines {
        let r: Value = serde_json::from_str(line).unwrap();
        assert_eq!(r["prev_hash"], prev, "broken chain at {line}");
        assert!(r.get("rule_id").is_some(), "missing rule_id: {line}");
        prev = r["hash"].as_str().unwrap().to_string();
    }
}
