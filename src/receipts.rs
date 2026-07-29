//! Append-only hash-chained receipt log.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::policy::Decision;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub id: String,
    pub ts_unix_ms: u128,
    pub command: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub approved: bool,
    pub executed: bool,
    pub exit_code: Option<i32>,
    pub stdout_preview: Option<String>,
    pub stderr_preview: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

pub struct AppendOpts {
    pub command: String,
    pub decision: Decision,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub approved: bool,
    pub executed: bool,
    pub exit_code: Option<i32>,
    pub stdout_preview: Option<String>,
    pub stderr_preview: Option<String>,
}

pub struct ReceiptLog {
    path: PathBuf,
    last_hash: String,
}

impl ReceiptLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ReceiptError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let last_hash = read_last_hash(&path)?.unwrap_or_else(|| "genesis".to_string());
        Ok(Self { path, last_hash })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, opts: AppendOpts) -> Result<Receipt, ReceiptError> {
        let id = uuid::Uuid::new_v4().to_string();
        let ts_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let prev_hash = self.last_hash.clone();
        let mut receipt = Receipt {
            id,
            ts_unix_ms,
            command: opts.command,
            decision: opts.decision,
            rule_id: opts.rule_id,
            reason: opts.reason,
            approved: opts.approved,
            executed: opts.executed,
            exit_code: opts.exit_code,
            stdout_preview: opts.stdout_preview,
            stderr_preview: opts.stderr_preview,
            prev_hash: prev_hash.clone(),
            hash: String::new(),
        };
        receipt.hash = hash_receipt(&receipt, &prev_hash);
        let line = serde_json::to_string(&receipt)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{line}")?;
        self.last_hash = receipt.hash.clone();
        Ok(receipt)
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<Receipt>, ReceiptError> {
        if !self.path.is_file() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&self.path)?;
        let mut out: Vec<Receipt> = Vec::new();
        for line in text.lines().rev() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line)?);
            if out.len() >= limit {
                break;
            }
        }
        out.reverse();
        Ok(out)
    }

    pub fn all(&self) -> Result<Vec<Receipt>, ReceiptError> {
        if !self.path.is_file() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&self.path)?;
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line)?);
        }
        Ok(out)
    }
}

fn hash_receipt(receipt: &Receipt, prev_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(receipt.id.as_bytes());
    hasher.update(receipt.ts_unix_ms.to_string().as_bytes());
    hasher.update(receipt.command.as_bytes());
    hasher.update(format!("{:?}", receipt.decision).as_bytes());
    if let Some(ref id) = receipt.rule_id {
        hasher.update(id.as_bytes());
    }
    hasher.update([u8::from(receipt.approved)]);
    hasher.update([u8::from(receipt.executed)]);
    if let Some(code) = receipt.exit_code {
        hasher.update(code.to_string().as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn read_last_hash(path: &Path) -> Result<Option<String>, ReceiptError> {
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)?;
    let last = text.lines().rev().find(|l| !l.trim().is_empty());
    match last {
        Some(line) => {
            let receipt: Receipt = serde_json::from_str(line)?;
            Ok(Some(receipt.hash))
        }
        None => Ok(None),
    }
}

pub fn default_receipt_path() -> PathBuf {
    PathBuf::from(".mayrun/receipts.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn chain_links_hashes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("receipts.jsonl");
        let mut log = ReceiptLog::open(&path).unwrap();
        let r1 = log
            .append(AppendOpts {
                command: "ls".into(),
                decision: Decision::Allow,
                rule_id: Some("allow-ls".into()),
                reason: None,
                approved: false,
                executed: true,
                exit_code: Some(0),
                stdout_preview: None,
                stderr_preview: None,
            })
            .unwrap();
        let r2 = log
            .append(AppendOpts {
                command: "pwd".into(),
                decision: Decision::Allow,
                rule_id: None,
                reason: None,
                approved: false,
                executed: true,
                exit_code: Some(0),
                stdout_preview: None,
                stderr_preview: None,
            })
            .unwrap();
        assert_eq!(r2.prev_hash, r1.hash);
        assert_ne!(r1.hash, r2.hash);
        assert_eq!(r1.rule_id.as_deref(), Some("allow-ls"));
    }
}
