//! Agent harness setup snippets (`mayrun setup cursor|claude|opencode`).

use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    Cursor,
    Claude,
    OpenCode,
}

impl AgentKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "cursor" => Some(Self::Cursor),
            "claude" | "claude-code" => Some(Self::Claude),
            "opencode" => Some(Self::OpenCode),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cursor => "cursor",
            Self::Claude => "claude",
            Self::OpenCode => "opencode",
        }
    }
}

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("{0}")]
    Msg(String),
}

#[derive(Debug)]
pub struct SetupSnippet {
    pub path_hint: &'static str,
    pub body: String,
    pub format: SnippetFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnippetFormat {
    Json,
    Shell,
}

pub fn render_snippet(agent: AgentKind) -> SetupSnippet {
    match agent {
        AgentKind::Cursor => SetupSnippet {
            path_hint: ".cursor/mcp.json (project) or ~/.cursor/mcp.json",
            format: SnippetFormat::Json,
            body: r#"{
  "mcpServers": {
    "mayrun": {
      "command": "mayrun",
      "args": ["mcp"]
    }
  }
}
"#
            .into(),
        },
        AgentKind::Claude => SetupSnippet {
            path_hint: ".mcp.json (project) or Claude Code MCP settings",
            format: SnippetFormat::Json,
            body: r#"{
  "mcpServers": {
    "mayrun": {
      "command": "mayrun",
      "args": ["mcp"]
    }
  }
}
"#
            .into(),
        },
        AgentKind::OpenCode => SetupSnippet {
            path_hint: "opencode.json (project)",
            format: SnippetFormat::Json,
            body: r#"{
  "mcp": {
    "mayrun": {
      "type": "local",
      "command": ["mayrun", "mcp"]
    }
  }
}
"#
            .into(),
        },
    }
}

/// Default write path for `--write` (project-local).
pub fn default_write_path(agent: AgentKind, root: &Path) -> PathBuf {
    match agent {
        AgentKind::Cursor => root.join(".cursor/mcp.json"),
        AgentKind::Claude => root.join(".mcp.json"),
        AgentKind::OpenCode => root.join("opencode.json"),
    }
}

/// Reject paths that contain `..` components (user-supplied `--path`).
fn ensure_safe_path(path: &Path) -> Result<(), SetupError> {
    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(SetupError::Msg(format!(
            "refusing path with '..': {}",
            path.display()
        )));
    }
    Ok(())
}

/// Merge mayrun MCP entry into an existing JSON file (or create). Writes `.bak` backup first.
pub fn write_snippet(agent: AgentKind, path: &Path) -> Result<(), SetupError> {
    ensure_safe_path(path)?;
    let snippet = render_snippet(agent);
    if path.is_file() {
        let bak_path = backup_path(path);
        fs::copy(path, &bak_path)?;
        let text = fs::read_to_string(path)?;
        let merged = merge_json(agent, &text).map_err(|source| SetupError::Json {
            path: path.to_path_buf(),
            source,
        })?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, merged)?;
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, snippet.body)?;
    }
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    path.parent().unwrap_or(Path::new(".")).join(format!(
        "{}.bak",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config.json")
    ))
}

fn merge_json(agent: AgentKind, existing: &str) -> Result<String, serde_json::Error> {
    let mut root: serde_json::Value = if existing.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(existing)?
    };
    if !root.is_object() {
        root = serde_json::json!({});
    }
    match agent {
        AgentKind::Cursor | AgentKind::Claude => {
            let servers = root
                .as_object_mut()
                .unwrap()
                .entry("mcpServers")
                .or_insert_with(|| serde_json::json!({}));
            if !servers.is_object() {
                *servers = serde_json::json!({});
            }
            servers.as_object_mut().unwrap().insert(
                "mayrun".into(),
                serde_json::json!({
                    "command": "mayrun",
                    "args": ["mcp"]
                }),
            );
        }
        AgentKind::OpenCode => {
            let mcp = root
                .as_object_mut()
                .unwrap()
                .entry("mcp")
                .or_insert_with(|| serde_json::json!({}));
            if !mcp.is_object() {
                *mcp = serde_json::json!({});
            }
            mcp.as_object_mut().unwrap().insert(
                "mayrun".into(),
                serde_json::json!({
                    "type": "local",
                    "command": ["mayrun", "mcp"]
                }),
            );
        }
    }
    Ok(format!("{}\n", serde_json::to_string_pretty(&root)?))
}

/// Light validation for CI smoke: JSON snippets parse; shell is non-empty.
pub fn validate_snippet(snippet: &SetupSnippet) -> Result<(), SetupError> {
    match snippet.format {
        SnippetFormat::Json => {
            let _: serde_json::Value = serde_json::from_str(&snippet.body).map_err(|source| {
                SetupError::Json {
                    path: PathBuf::from(snippet.path_hint),
                    source,
                }
            })?;
            Ok(())
        }
        SnippetFormat::Shell => {
            if snippet.body.trim().is_empty() {
                return Err(SetupError::Msg("empty shell snippet".into()));
            }
            // shellcheck-light: no unquoted dangerous expansions required in our snippets
            if snippet.body.contains("$(curl") || snippet.body.contains("`curl") {
                return Err(SetupError::Msg("snippet must not curl|sh".into()));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn snippets_are_valid_json() {
        for a in [AgentKind::Cursor, AgentKind::Claude, AgentKind::OpenCode] {
            let s = render_snippet(a);
            validate_snippet(&s).unwrap();
        }
    }

    #[test]
    fn write_merges_cursor() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".cursor/mcp.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            r#"{"mcpServers":{"other":{"command":"x"}}}"#,
        )
        .unwrap();
        write_snippet(AgentKind::Cursor, &path).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v["mcpServers"]["mayrun"]["command"].as_str() == Some("mayrun"));
        assert!(v["mcpServers"]["other"]["command"].as_str() == Some("x"));
        assert!(dir.path().join(".cursor/mcp.json.bak").is_file());
    }

    #[test]
    fn rejects_parent_dir_path() {
        let err = write_snippet(AgentKind::Cursor, Path::new("../evil/mcp.json")).unwrap_err();
        assert!(err.to_string().contains(".."), "{err}");
    }
}
