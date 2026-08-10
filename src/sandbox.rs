//! Local OS sandbox primitives (bubblewrap / Seatbelt) — defense in depth under policy.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::Command;

use crate::capabilities::Capability;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// Do not sandbox.
    Off,
    /// Sandbox when available; warn and continue if unavailable.
    Soft,
    /// Fail closed if sandbox cannot be applied.
    Required,
}

impl SandboxMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" | "false" | "0" => Some(Self::Off),
            "soft" | "true" | "1" | "" => Some(Self::Soft),
            "required" => Some(Self::Required),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxProfile {
    pub backend: String,
    pub workspace: PathBuf,
    pub network: bool,
    pub writable_paths: Vec<PathBuf>,
    pub deny_read_paths: Vec<String>,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox required but no supported backend (install bubblewrap on Linux)")]
    Unavailable,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn backend_available() -> Option<&'static str> {
    if cfg!(target_os = "linux") && which("bwrap") {
        return Some("bubblewrap");
    }
    if cfg!(target_os = "macos") && which("sandbox-exec") {
        return Some("seatbelt");
    }
    None
}

fn which(name: &str) -> bool {
    env::var_os("PATH")
        .map(|p| env::split_paths(&p).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

/// Map capabilities + workspace into a sandbox profile.
/// Network deny-by-default unless `net.egress` is present.
/// `secrets.exfil` paths are denied for read even when broader FS is allowed.
pub fn profile_for(
    workspace: &Path,
    capabilities: &[String],
) -> SandboxProfile {
    let has_net = capabilities.iter().any(|c| c == Capability::NetEgress.as_str());
    let deny_read = vec![
        "$HOME/.ssh".into(),
        "$HOME/.aws".into(),
        "$HOME/.gnupg".into(),
        "$HOME/.kube".into(),
        "$HOME/.netrc".into(),
        "$HOME/.npmrc".into(),
    ];
    SandboxProfile {
        backend: backend_available().unwrap_or("none").into(),
        workspace: workspace.to_path_buf(),
        network: has_net,
        writable_paths: vec![workspace.to_path_buf()],
        deny_read_paths: deny_read,
    }
}

/// Resolve sandbox mode from CLI flag value (`None` = off).
pub fn resolve_mode(flag: Option<&str>) -> Result<SandboxMode, String> {
    match flag {
        None => Ok(SandboxMode::Off),
        Some(s) => SandboxMode::parse(s).ok_or_else(|| {
            format!("invalid --sandbox value `{s}` (use soft, required, or omit)")
        }),
    }
}

/// Build a tokio Command that runs `sh -c <command>` inside the sandbox when possible.
pub fn sandboxed_command(
    mode: SandboxMode,
    profile: &SandboxProfile,
    command: &str,
) -> Result<(Command, Option<SandboxProfile>), SandboxError> {
    if mode == SandboxMode::Off {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        return Ok((c, None));
    }

    match backend_available() {
        Some("bubblewrap") => Ok((bwrap_command(profile, command), Some(profile.clone()))),
        Some("seatbelt") => Ok((seatbelt_command(profile, command)?, Some(profile.clone()))),
        _ => match mode {
            SandboxMode::Soft => {
                eprintln!(
                    "mayrun: warning: --sandbox requested but no backend available; running unsandboxed"
                );
                let mut c = Command::new("sh");
                c.arg("-c").arg(command);
                Ok((c, None))
            }
            SandboxMode::Required => Err(SandboxError::Unavailable),
            SandboxMode::Off => unreachable!(),
        },
    }
}

fn bwrap_command(profile: &SandboxProfile, command: &str) -> Command {
    let mut c = Command::new("bwrap");
    c.arg("--ro-bind").arg("/").arg("/");
    c.arg("--dev").arg("/dev");
    c.arg("--proc").arg("/proc");
    c.arg("--tmpfs").arg("/tmp");
    // Workspace writable
    c.arg("--bind")
        .arg(&profile.workspace)
        .arg(&profile.workspace);
    c.arg("--chdir").arg(&profile.workspace);
    if !profile.network {
        c.arg("--unshare-net");
    }
    for p in &profile.deny_read_paths {
        // Best-effort: expand $HOME
        let expanded = if let Some(rest) = p.strip_prefix("$HOME") {
            env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(rest.trim_start_matches('/')))
                .unwrap_or_else(|| PathBuf::from(p))
        } else {
            PathBuf::from(p)
        };
        if expanded.exists() {
            c.arg("--ro-bind-try")
                .arg("/var/empty")
                .arg(&expanded);
        }
    }
    // Prefer a known-empty dir; if missing, skip bind (soft).
    c.arg("--").arg("sh").arg("-c").arg(command);
    c.stdin(Stdio::null());
    c
}

fn seatbelt_command(profile: &SandboxProfile, command: &str) -> Result<Command, SandboxError> {
    let ws = profile.workspace.display();
    let net = if profile.network {
        "(allow network*)"
    } else {
        "(deny network*)"
    };
    let profile_text = format!(
        r#"(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow file-read*)
(allow file-write* (subpath "{ws}"))
{net}
"#
    );
    let tmp = env::temp_dir().join(format!("mayrun-seatbelt-{}.sb", std::process::id()));
    std::fs::write(&tmp, profile_text)?;
    let mut c = Command::new("sandbox-exec");
    c.arg("-f").arg(&tmp);
    c.arg("sh").arg("-c").arg(command);
    c.stdin(Stdio::null());
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_denied_by_default() {
        let p = profile_for(Path::new("/tmp/ws"), &[]);
        assert!(!p.network);
        let p2 = profile_for(Path::new("/tmp/ws"), &["net.egress".into()]);
        assert!(p2.network);
    }

    #[test]
    fn parse_modes() {
        assert_eq!(SandboxMode::parse("required"), Some(SandboxMode::Required));
        assert_eq!(SandboxMode::parse("soft"), Some(SandboxMode::Soft));
        assert_eq!(SandboxMode::parse("true"), Some(SandboxMode::Soft));
    }
}
