//! e2e: mayrun mcp-proxy denies dangerous tools/call and allows benign ones.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::tempdir;

fn mayrun_bin() -> PathBuf {
    env!("CARGO_BIN_EXE_mayrun").into()
}

fn mock_upstream() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mock_mcp_upstream.py")
}

struct ProxyClient {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl ProxyClient {
    fn spawn(policy: &PathBuf, receipts: &PathBuf) -> Self {
        let mock = mock_upstream();
        assert!(mock.is_file(), "missing mock at {}", mock.display());
        let mut child = Command::new(mayrun_bin())
            .args([
                "mcp-proxy",
                "--policy",
                policy.to_str().unwrap(),
                "--receipts",
                receipts.to_str().unwrap(),
                "--server-name",
                "filesystem",
                "--",
                "python3",
                mock.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("PYTHONUNBUFFERED", "1")
            .spawn()
            .expect("spawn mcp-proxy");
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
        writeln!(self.stdin, "{line}").expect("write");
        self.stdin.flush().expect("flush");
    }

    fn read_msg(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            match self.stdout.read_line(&mut line) {
                Ok(0) => {
                    let status = self.child.try_wait();
                    panic!("proxy stdout EOF; status={status:?}");
                }
                Ok(_) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    return serde_json::from_str(line.trim()).unwrap_or_else(|e| {
                        panic!("invalid json ({e}): {line}");
                    });
                }
                Err(e) => panic!("read error: {e}"),
            }
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
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let msg = self.read_msg();
            if msg.get("id").and_then(|v| v.as_u64()) == Some(id) {
                return msg;
            }
        }
        panic!("timeout waiting for {method}");
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.write_msg(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }));
    }
}

impl Drop for ProxyClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn mcp_proxy_denies_delete_allows_read() {
    let dir = tempdir().unwrap();
    let policy = dir.path().join("mayrun.policy.yaml");
    std::fs::write(
        &policy,
        r#"
apiVersion: mayrun.dev/v1
default: deny
extends:
  - pack: mcp-safe
"#,
    )
    .unwrap();
    let receipts = dir.path().join("receipts.jsonl");

    let mut client = ProxyClient::spawn(&policy, &receipts);

    let init = client.request(
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "proxy-e2e", "version": "0.0.0" }
        }),
    );
    assert!(init.get("result").is_some(), "{init}");
    client.notify("notifications/initialized", json!({}));

    // Benign read — forwarded to upstream.
    let allow = client.request(
        "tools/call",
        json!({
            "name": "read_file",
            "arguments": { "path": "README.md" }
        }),
    );
    let text = allow["result"]["content"][0]["text"].as_str().unwrap_or("");
    let body: Value = serde_json::from_str(text).unwrap_or(json!({}));
    assert_eq!(body["ok"], true, "{allow}");
    assert_eq!(body["upstream"], true, "{allow}");
    assert_ne!(allow["result"]["isError"], true);

    // Dangerous delete — denied by proxy (never reaches upstream success).
    let deny = client.request(
        "tools/call",
        json!({
            "name": "delete_file",
            "arguments": { "path": "secret.txt" }
        }),
    );
    assert_eq!(deny["result"]["isError"], true, "{deny}");
    let deny_text = deny["result"]["content"][0]["text"].as_str().unwrap();
    let deny_body: Value = serde_json::from_str(deny_text).unwrap();
    assert_eq!(deny_body["decision"], "deny");
    assert!(
        deny_body["rule_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("pack.mcp"),
        "{deny_body}"
    );

    // Receipts: allow + deny
    let log = std::fs::read_to_string(&receipts).expect("receipts");
    assert!(log.contains("read_file"), "{log}");
    assert!(log.contains("delete_file"), "{log}");
    assert!(log.contains("deny"), "{log}");
}
