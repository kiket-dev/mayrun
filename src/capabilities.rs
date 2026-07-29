//! Deterministic capability / risk tags for commands.

use std::collections::BTreeSet;

use crate::argv::ParsedCommand;
use serde::{Deserialize, Serialize};

/// Risk / capability labels used by packs and capability matchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsRead,
    FsWrite,
    FsDestroy,
    NetEgress,
    ScmRead,
    ScmWrite,
    ScmPublish,
    BuildLocal,
    PkgInstall,
    PkgPublish,
    ClusterRead,
    ClusterMutate,
    PrivEscalate,
    SecretsExfil,
    ContainerMutate,
    InfraDestroy,
    InfraApply,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::FsDestroy => "fs.destroy",
            Self::NetEgress => "net.egress",
            Self::ScmRead => "scm.read",
            Self::ScmWrite => "scm.write",
            Self::ScmPublish => "scm.publish",
            Self::BuildLocal => "build.local",
            Self::PkgInstall => "pkg.install",
            Self::PkgPublish => "pkg.publish",
            Self::ClusterRead => "cluster.read",
            Self::ClusterMutate => "cluster.mutate",
            Self::PrivEscalate => "priv.escalate",
            Self::SecretsExfil => "secrets.exfil",
            Self::ContainerMutate => "container.mutate",
            Self::InfraDestroy => "infra.destroy",
            Self::InfraApply => "infra.apply",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "fs.read" => Self::FsRead,
            "fs.write" => Self::FsWrite,
            "fs.destroy" => Self::FsDestroy,
            "net.egress" => Self::NetEgress,
            "scm.read" => Self::ScmRead,
            "scm.write" => Self::ScmWrite,
            "scm.publish" => Self::ScmPublish,
            "build.local" => Self::BuildLocal,
            "pkg.install" => Self::PkgInstall,
            "pkg.publish" => Self::PkgPublish,
            "cluster.read" => Self::ClusterRead,
            "cluster.mutate" => Self::ClusterMutate,
            "priv.escalate" => Self::PrivEscalate,
            "secrets.exfil" => Self::SecretsExfil,
            "container.mutate" => Self::ContainerMutate,
            "infra.destroy" => Self::InfraDestroy,
            "infra.apply" => Self::InfraApply,
            _ => return None,
        })
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Infer capability tags from a peeled command (deterministic heuristics).
pub fn infer_capabilities(parsed: &ParsedCommand) -> BTreeSet<Capability> {
    let mut caps = BTreeSet::new();
    if parsed.elevated {
        caps.insert(Capability::PrivEscalate);
    }
    let bin = parsed.binary.as_str();
    let args = parsed.args();

    match bin {
        "ls" | "pwd" | "echo" | "cat" | "head" | "tail" | "rg" | "grep" | "find" | "wc"
        | "date" | "whoami" | "uname" | "file" | "stat" | "tree" | "less" | "more" | "base64" => {
            caps.insert(Capability::FsRead);
            if bin == "find" && args.iter().any(|a| a == "-delete" || a == "-exec") {
                caps.insert(Capability::FsDestroy);
            }
            if is_read_or_copy_binary(bin) && args.iter().any(|a| looks_like_secret_path(a)) {
                caps.insert(Capability::SecretsExfil);
            }
        }
        "rm" | "rmdir" | "unlink" => {
            caps.insert(Capability::FsDestroy);
        }
        "mv" | "cp" | "chmod" | "chown" | "mkdir" | "touch" | "ln" | "truncate" | "install"
        | "tar" => {
            caps.insert(Capability::FsWrite);
            if is_read_or_copy_binary(bin) && args.iter().any(|a| looks_like_secret_path(a)) {
                caps.insert(Capability::SecretsExfil);
            }
            if bin == "chmod"
                && args
                    .iter()
                    .any(|a| a.contains("+s") || a.contains("4755") || a.contains("u+s"))
            {
                caps.insert(Capability::PrivEscalate);
            }
        }
        "dd" | "mkfs" | "mkfs.ext4" | "mkfs.xfs" | "wipefs" => {
            caps.insert(Capability::FsDestroy);
        }
        "curl" | "wget" | "http" | "ssh" | "scp" | "rsync" | "nc" | "ncat" => {
            caps.insert(Capability::NetEgress);
            if is_read_or_copy_binary(bin) && args.iter().any(|a| looks_like_secret_path(a)) {
                caps.insert(Capability::SecretsExfil);
            }
            if looks_like_pipe_to_shell(&parsed.raw) {
                caps.insert(Capability::PrivEscalate);
            }
        }
        "git" => classify_git(args, &mut caps),
        "cargo" => classify_cargo(args, &mut caps),
        "npm" | "pnpm" | "yarn" | "bun" => classify_node(bin, args, &mut caps),
        "pip" | "pip3" | "uv" => {
            if args.first().is_some_and(|a| a == "install") {
                caps.insert(Capability::PkgInstall);
                caps.insert(Capability::NetEgress);
            } else {
                caps.insert(Capability::BuildLocal);
            }
        }
        "kubectl" | "helm" => classify_k8s(bin, args, &mut caps),
        "docker" | "podman" => classify_container(args, &mut caps),
        "terraform" | "tofu" | "opentofu" => classify_terraform(args, &mut caps),
        "sudo" | "doas" | "su" | "pkexec" => {
            caps.insert(Capability::PrivEscalate);
        }
        "printenv" | "env" => {
            caps.insert(Capability::SecretsExfil);
        }
        "mayrun" => {
            caps.insert(Capability::FsRead);
        }
        _ => {}
    }

    // Redirection / destructive shell patterns on raw string.
    if parsed.raw.contains(" > ") || parsed.raw.contains(">>") {
        caps.insert(Capability::FsWrite);
    }
    if looks_like_pipe_to_shell(&parsed.raw) {
        caps.insert(Capability::NetEgress);
        caps.insert(Capability::PrivEscalate);
    }

    caps
}

fn classify_git(args: &[String], caps: &mut BTreeSet<Capability>) {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "status" | "diff" | "log" | "show" | "branch" | "rev-parse" | "describe" | "remote"
        | "tag" | "stash" | "blame" | "ls-files" | "ls-remote" => {
            caps.insert(Capability::ScmRead);
        }
        "add" | "commit" | "checkout" | "switch" | "restore" | "reset" | "merge" | "rebase"
        | "cherry-pick" | "mv" | "rm" => {
            caps.insert(Capability::ScmWrite);
        }
        "push" => {
            caps.insert(Capability::ScmPublish);
            if args.iter().any(|a| a == "--force" || a == "-f" || a.starts_with("--force")) {
                caps.insert(Capability::FsDestroy); // treat force-push as high risk
            }
        }
        "pull" | "fetch" | "clone" => {
            caps.insert(Capability::ScmRead);
            caps.insert(Capability::NetEgress);
        }
        _ => {
            caps.insert(Capability::ScmRead);
        }
    }
}

fn classify_cargo(args: &[String], caps: &mut BTreeSet<Capability>) {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "check" | "test" | "clippy" | "fmt" | "build" | "doc" | "tree" | "metadata" => {
            caps.insert(Capability::BuildLocal);
        }
        "run" | "bench" => {
            caps.insert(Capability::BuildLocal);
        }
        "publish" => {
            caps.insert(Capability::PkgPublish);
            caps.insert(Capability::NetEgress);
        }
        "install" | "add" | "update" | "fetch" => {
            caps.insert(Capability::PkgInstall);
            caps.insert(Capability::NetEgress);
        }
        _ => {
            caps.insert(Capability::BuildLocal);
        }
    }
}

fn classify_node(_bin: &str, args: &[String], caps: &mut BTreeSet<Capability>) {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "test" | "run" | "lint" | "exec" | "dlx" => {
            caps.insert(Capability::BuildLocal);
            if sub == "run" {
                let script = args.get(1).map(String::as_str).unwrap_or("");
                if matches!(script, "test" | "lint" | "build" | "typecheck" | "check") {
                    caps.insert(Capability::BuildLocal);
                }
            }
        }
        "publish" => {
            caps.insert(Capability::PkgPublish);
            caps.insert(Capability::NetEgress);
        }
        "install" | "add" | "i" | "ci" | "update" => {
            caps.insert(Capability::PkgInstall);
            caps.insert(Capability::NetEgress);
        }
        _ => {
            caps.insert(Capability::BuildLocal);
        }
    }
}

fn classify_k8s(bin: &str, args: &[String], caps: &mut BTreeSet<Capability>) {
    let sub = if bin == "helm" {
        args.first().map(String::as_str).unwrap_or("")
    } else {
        args.first().map(String::as_str).unwrap_or("")
    };
    match sub {
        "get" | "describe" | "logs" | "top" | "api-resources" | "explain" | "status" | "list" => {
            caps.insert(Capability::ClusterRead);
        }
        "apply" | "create" | "patch" | "replace" | "scale" | "rollout" | "expose" | "upgrade"
        | "install" => {
            caps.insert(Capability::ClusterMutate);
        }
        "delete" | "drain" | "cordon" | "uninstall" => {
            caps.insert(Capability::ClusterMutate);
            caps.insert(Capability::FsDestroy);
        }
        "exec" | "port-forward" | "cp" | "attach" => {
            caps.insert(Capability::ClusterMutate);
            caps.insert(Capability::PrivEscalate);
        }
        _ => {
            caps.insert(Capability::ClusterRead);
        }
    }
}

fn classify_container(args: &[String], caps: &mut BTreeSet<Capability>) {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "ps" | "images" | "logs" | "inspect" | "version" | "info" => {
            caps.insert(Capability::FsRead);
        }
        "build" | "pull" | "run" | "start" | "stop" | "rm" | "rmi" | "compose" | "push"
        | "tag" | "exec" => {
            caps.insert(Capability::ContainerMutate);
            if sub == "push" || sub == "pull" {
                caps.insert(Capability::NetEgress);
            }
            if sub == "push" {
                caps.insert(Capability::PkgPublish);
            }
        }
        _ => {
            caps.insert(Capability::ContainerMutate);
        }
    }
}

fn classify_terraform(args: &[String], caps: &mut BTreeSet<Capability>) {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "plan" | "validate" | "fmt" | "init" | "show" | "state" | "output" => {
            caps.insert(Capability::BuildLocal);
        }
        "apply" => {
            caps.insert(Capability::InfraApply);
        }
        "destroy" => {
            caps.insert(Capability::InfraDestroy);
        }
        _ => {
            caps.insert(Capability::BuildLocal);
        }
    }
}

/// Binaries that can read or copy file contents (secret exfil surface).
fn is_read_or_copy_binary(bin: &str) -> bool {
    matches!(
        bin,
        "cat"
            | "head"
            | "tail"
            | "less"
            | "more"
            | "grep"
            | "rg"
            | "cp"
            | "mv"
            | "tar"
            | "rsync"
            | "scp"
            | "base64"
    )
}

/// Heuristic: path looks like credentials, keys, history, or cookie stores.
///
/// Known miss: `$HOME/.ssh/...` is not expanded and may not match `~/.ssh/` forms.
pub fn looks_like_secret_path(p: &str) -> bool {
    let lower = p.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(lower.as_str());

    // Directory / path fragments
    if lower.contains("/.ssh/")
        || lower.starts_with("~/.ssh/")
        || lower.contains("/.aws/")
        || lower.starts_with("~/.aws/")
        || lower.contains("/.gnupg/")
        || lower.contains(".gnupg")
        || lower.contains("/.kube/config")
        || lower.ends_with(".kube/config")
        || lower.contains("/.netrc")
        || lower.ends_with(".netrc")
        || lower.contains("/.npmrc")
        || lower.ends_with(".npmrc")
    {
        return true;
    }

    // Keys (project-local .env* is handled by packs as require_approval, not exfil)
    if lower.ends_with(".pem")
        || base.starts_with("id_rsa")
        || base.starts_with("id_ed25519")
        || lower.ends_with("id_rsa")
        || lower.ends_with("id_ed25519")
    {
        return true;
    }

    // Shell history
    if base == ".bash_history" || base == ".zsh_history" || base == ".history" {
        return true;
    }

    // Browser cookie DBs (common absolute/home-relative names)
    if base == "cookies" || base == "cookies.sqlite" || lower.contains("/cookies.sqlite") {
        return true;
    }

    false
}

fn looks_like_pipe_to_shell(raw: &str) -> bool {
    let re = regex::Regex::new(r"\|\s*(ba)?sh\b").ok();
    re.map(|r| r.is_match(raw)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argv::ParsedCommand;

    #[test]
    fn git_push_is_publish() {
        let p = ParsedCommand::parse("git push origin main");
        let c = infer_capabilities(&p);
        assert!(c.contains(&Capability::ScmPublish));
    }

    #[test]
    fn rm_is_destroy() {
        let p = ParsedCommand::parse("rm -rf /tmp/x");
        let c = infer_capabilities(&p);
        assert!(c.contains(&Capability::FsDestroy));
    }

    #[test]
    fn cargo_test_is_build() {
        let p = ParsedCommand::parse("cargo test");
        let c = infer_capabilities(&p);
        assert!(c.contains(&Capability::BuildLocal));
    }

    #[test]
    fn secret_path_on_read_binaries() {
        for cmd in [
            "cat ~/.ssh/id_rsa",
            "head ~/.aws/credentials",
            "cp ~/.netrc /tmp/x",
            "base64 id_ed25519.pem",
            "grep secret .bash_history",
            "tar cf - .gnupg",
        ] {
            let p = ParsedCommand::parse(cmd);
            let c = infer_capabilities(&p);
            assert!(
                c.contains(&Capability::SecretsExfil),
                "expected secrets.exfil for {cmd:?}, got {c:?}"
            );
        }
        let safe = ParsedCommand::parse("cat README.md");
        assert!(!infer_capabilities(&safe).contains(&Capability::SecretsExfil));
    }

    #[test]
    fn looks_like_secret_path_covers_common_forms() {
        assert!(looks_like_secret_path("~/.ssh/id_rsa"));
        assert!(looks_like_secret_path("/home/u/.kube/config"));
        assert!(looks_like_secret_path("Cookies.sqlite"));
        assert!(!looks_like_secret_path(".env.local"));
        assert!(!looks_like_secret_path("src/main.rs"));
    }
}
