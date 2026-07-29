//! Policy loading and evaluation for mayrun.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy file not found: {0}")]
    NotFound(PathBuf),
    #[error("failed to read policy: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid policy YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid regex in policy: {0}")]
    Regex(#[from] regex::Error),
}

/// Decision for a proposed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// When no rule matches. Default: deny.
    #[serde(default = "default_default_decision")]
    pub default: Decision,
    /// Patterns that are always denied (checked first).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Patterns that require human approval before run.
    #[serde(default)]
    pub require_approval: Vec<String>,
    /// Patterns that are allowed without approval.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Optional cap on shell invocations per process session.
    #[serde(default)]
    pub max_runs_per_session: Option<u32>,
}

fn default_default_decision() -> Decision {
    Decision::Deny
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub raw: Policy,
    deny: Vec<Regex>,
    require_approval: Vec<Regex>,
    allow: Vec<Regex>,
}

impl CompiledPolicy {
    pub fn compile(policy: Policy) -> Result<Self, PolicyError> {
        Ok(Self {
            deny: compile_patterns(&policy.deny)?,
            require_approval: compile_patterns(&policy.require_approval)?,
            allow: compile_patterns(&policy.allow)?,
            raw: policy,
        })
    }

    pub fn evaluate(&self, command: &str) -> Decision {
        let cmd = command.trim();
        if matches_any(&self.deny, cmd) {
            return Decision::Deny;
        }
        if matches_any(&self.require_approval, cmd) {
            return Decision::RequireApproval;
        }
        if matches_any(&self.allow, cmd) {
            return Decision::Allow;
        }
        self.raw.default
    }
}

fn compile_patterns(patterns: &[String]) -> Result<Vec<Regex>, PolicyError> {
    patterns
        .iter()
        .map(|p| Regex::new(p).map_err(PolicyError::from))
        .collect()
}

fn matches_any(patterns: &[Regex], command: &str) -> bool {
    patterns.iter().any(|re| re.is_match(command))
}

/// Resolve policy path: explicit, then `./mayrun.policy.yaml`, then `./.mayrun/policy.yaml`.
pub fn find_policy_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let candidates = [
        PathBuf::from("mayrun.policy.yaml"),
        PathBuf::from(".mayrun/policy.yaml"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

pub fn load_policy(path: &Path) -> Result<CompiledPolicy, PolicyError> {
    if !path.is_file() {
        return Err(PolicyError::NotFound(path.to_path_buf()));
    }
    let text = fs::read_to_string(path)?;
    let policy: Policy = serde_yaml::from_str(&text)?;
    CompiledPolicy::compile(policy)
}

pub fn default_policy_yaml() -> &'static str {
    include_str!("../examples/policy.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_from_yaml(yaml: &str) -> CompiledPolicy {
        let policy: Policy = serde_yaml::from_str(yaml).expect("yaml");
        CompiledPolicy::compile(policy).expect("compile")
    }

    #[test]
    fn deny_beats_allow() {
        let p = policy_from_yaml(
            r#"
default: deny
deny:
  - "rm\\s+-rf"
allow:
  - ".*"
"#,
        );
        assert_eq!(p.evaluate("rm -rf /"), Decision::Deny);
        assert_eq!(p.evaluate("ls"), Decision::Allow);
    }

    #[test]
    fn require_approval_before_allow() {
        let p = policy_from_yaml(
            r#"
default: deny
require_approval:
  - "^git push"
allow:
  - "^git "
"#,
        );
        assert_eq!(p.evaluate("git push origin main"), Decision::RequireApproval);
        assert_eq!(p.evaluate("git status"), Decision::Allow);
        assert_eq!(p.evaluate("curl evil"), Decision::Deny);
    }

    #[test]
    fn default_deny_when_unmatched() {
        let p = policy_from_yaml(
            r#"
default: deny
allow:
  - "^cargo test"
"#,
        );
        assert_eq!(p.evaluate("cargo build"), Decision::Deny);
        assert_eq!(p.evaluate("cargo test"), Decision::Allow);
    }
}
