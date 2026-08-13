//! Shell integration: `shell-hook` eval scripts and `shell-wrap` for agent shells.

use std::env;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
}

impl ShellKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }
}

/// Detect shell from `$SHELL` basename, defaulting to bash.
pub fn detect_shell() -> ShellKind {
    env::var_os("SHELL")
        .and_then(|s| {
            let p = PathBuf::from(s);
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(ShellKind::parse)
        })
        .unwrap_or(ShellKind::Bash)
}

/// Absolute path to this mayrun binary (best effort).
pub fn mayrun_bin() -> String {
    env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "mayrun".into())
}

/// Print shell-specific eval that installs a preexec/DEBUG gate.
///
/// Allow (exit 0): shell executes the command (check-only gate).
/// Deny (3) / require_approval (2): call `mayrun run` for actionable UX + receipt, then abort.
/// No policy (4) / other errors: pass through — do not brick shells outside a mayrun project.
pub fn render_hook(shell: ShellKind, bin: &str) -> String {
    let bin_q = shell_escape_double(bin);
    match shell {
        ShellKind::Zsh => format!(
            r#"# mayrun shell-hook (zsh) — eval "$(mayrun shell-hook)"
# Gate only when a policy is present (exit 2/3). No policy (4) → pass through.
mayrun_preexec() {{
  local cmd="$1" ec
  case "$cmd" in
    ''|mayrun\ *|*\ mayrun\ shell-hook*|*\ mayrun\ shell-wrap*) return 0 ;;
  esac
  if [[ -n "${{MAYRUN_HOOK_ACTIVE:-}}" ]]; then return 0; fi
  export MAYRUN_HOOK_ACTIVE=1
  "{bin}" check "$cmd" >/dev/null 2>&1
  ec=$?
  case "$ec" in
    0) unset MAYRUN_HOOK_ACTIVE; return 0 ;;
    2|3)
      "{bin}" run "$cmd"
      unset MAYRUN_HOOK_ACTIVE
      kill -INT $$ 2>/dev/null || return 1
      ;;
    *) unset MAYRUN_HOOK_ACTIVE; return 0 ;;
  esac
}}
autoload -Uz add-zsh-hook 2>/dev/null || true
add-zsh-hook -d preexec mayrun_preexec 2>/dev/null || true
add-zsh-hook preexec mayrun_preexec
"#,
            bin = bin_q
        ),
        ShellKind::Bash => format!(
            r#"# mayrun shell-hook (bash) — eval "$(mayrun shell-hook)"
# Gate only when a policy is present (exit 2/3). No policy (4) → pass through.
mayrun_debug_trap() {{
  local cmd="$BASH_COMMAND" ec
  case "$cmd" in
    ''|mayrun\ *|*\ mayrun\ shell-hook*|*\ mayrun\ shell-wrap*|mayrun_debug_trap*) return 0 ;;
  esac
  if [[ -n "${{MAYRUN_HOOK_ACTIVE:-}}" ]]; then return 0; fi
  export MAYRUN_HOOK_ACTIVE=1
  "{bin}" check "$cmd" >/dev/null 2>&1
  ec=$?
  case "$ec" in
    0) unset MAYRUN_HOOK_ACTIVE; return 0 ;;
    2|3)
      "{bin}" run "$cmd"
      unset MAYRUN_HOOK_ACTIVE
      echo "mayrun: blocked (exit $ec)" >&2
      kill -INT $$ 2>/dev/null || return $ec
      ;;
    *) unset MAYRUN_HOOK_ACTIVE; return 0 ;;
  esac
}}
trap 'mayrun_debug_trap' DEBUG
"#,
            bin = bin_q
        ),
        ShellKind::Fish => format!(
            r#"# mayrun shell-hook (fish) — mayrun shell-hook | source
# Gate only when a policy is present (exit 2/3). No policy (4) → pass through.
function mayrun_preexec --on-event fish_preexec
  set -l cmd $argv[1]
  if test -z "$cmd"; or string match -qr '^mayrun ' -- $cmd
    return
  end
  if set -q MAYRUN_HOOK_ACTIVE
    return
  end
  set -gx MAYRUN_HOOK_ACTIVE 1
  "{bin}" check $cmd >/dev/null 2>&1
  set -l ec $status
  switch $ec
    case 0
      set -e MAYRUN_HOOK_ACTIVE
      return
    case 2 3
      "{bin}" run $cmd
      set -e MAYRUN_HOOK_ACTIVE
      echo "mayrun: blocked" >&2
      return 1
    case '*'
      set -e MAYRUN_HOOK_ACTIVE
      return
  end
end
"#,
            bin = bin_q
        ),
    }
}

fn shell_escape_double(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Debug, Error)]
pub enum ShellWrapError {
    #[error("shell-wrap requires a program to exec (e.g. mayrun shell-wrap -- bash -lc 'cmd')")]
    MissingProgram,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Gate agent shells: if argv is `sh|bash|zsh … -c <cmd>`, run through `mayrun run`
/// (policy + execute + receipt) and exit with that status. Otherwise exec unchanged.
pub fn shell_wrap(argv: &[OsString]) -> Result<(), ShellWrapError> {
    if argv.is_empty() {
        return Err(ShellWrapError::MissingProgram);
    }

    validate_exec_program(&argv[0])?;

    let prog = argv[0].to_string_lossy();
    let prog_base = PathBuf::from(prog.as_ref())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(prog.as_ref())
        .to_string();

    if matches!(prog_base.as_str(), "bash" | "sh" | "zsh" | "dash") {
        if let Some(cmd) = extract_c_command(argv) {
            let status = StdCommand::new(mayrun_bin())
                .arg("run")
                .arg(&cmd)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    // argv is passed as an execve-style array (no shell). Program must pass
    // validate_exec_program above; args are not interpolated into a shell string.
    // Use execvp directly (not Command::new) so argv stays a structured C array.
    exec_passthrough(argv)
}

/// execvp with validated OsString argv (NUL-free). Does not invoke a shell.
fn exec_passthrough(argv: &[OsString]) -> Result<(), ShellWrapError> {
    let c_args: Vec<CString> = argv
        .iter()
        .map(|a| {
            CString::new(a.as_bytes()).map_err(|_| ShellWrapError::MissingProgram)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut ptrs: Vec<*const std::ffi::c_char> = c_args.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: ptrs is NUL-terminated; pointed-to CStrings live in `c_args`.
    let _ = unsafe { execvp(ptrs[0], ptrs.as_ptr()) };
    Err(ShellWrapError::Io(std::io::Error::last_os_error()))
}

unsafe extern "C" {
    fn execvp(file: *const std::ffi::c_char, argv: *const *const std::ffi::c_char) -> i32;
}

/// Reject empty / NUL / newline program paths before execve-style passthrough.
fn validate_exec_program(prog: &OsString) -> Result<(), ShellWrapError> {
    let s = prog.to_string_lossy();
    if s.is_empty() || s.contains('\0') || s.contains('\n') || s.contains('\r') {
        return Err(ShellWrapError::MissingProgram);
    }
    // Disallow shell metacharacters in the program path (args stay separate argv).
    if s.chars().any(|c| matches!(c, ';' | '|' | '&' | '`' | '$' | '>' | '<' | '\n')) {
        return Err(ShellWrapError::MissingProgram);
    }
    Ok(())
}

/// Parse `-c <cmd>` / `-lc <cmd>` from shell argv.
fn extract_c_command(argv: &[OsString]) -> Option<String> {
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].to_string_lossy();
        if a == "-c" || a == "--command" {
            return Some(argv.get(i + 1)?.to_string_lossy().into_owned());
        }
        // Combined short options: -lc, -ic, -c, etc.
        if a.starts_with('-') && !a.starts_with("--") && a.contains('c') && a != "-" {
            // `-c` as last char in cluster takes next arg as command (bash/zsh).
            if a.ends_with('c') {
                return Some(argv.get(i + 1)?.to_string_lossy().into_owned());
            }
        }
        if !a.starts_with('-') {
            break;
        }
        if matches!(
            a.as_ref(),
            "-o" | "-O" | "--rcfile" | "--init-file"
        ) {
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bash_c() {
        let argv: Vec<OsString> = ["bash", "-c", "echo hi"]
            .into_iter()
            .map(OsString::from)
            .collect();
        assert_eq!(extract_c_command(&argv).as_deref(), Some("echo hi"));
    }

    #[test]
    fn extract_bash_lc() {
        let argv: Vec<OsString> = ["bash", "-lc", "rm -rf /tmp/x"]
            .into_iter()
            .map(OsString::from)
            .collect();
        assert_eq!(extract_c_command(&argv).as_deref(), Some("rm -rf /tmp/x"));
    }

    #[test]
    fn hook_mentions_check_and_run() {
        let h = render_hook(ShellKind::Zsh, "/usr/bin/mayrun");
        assert!(h.contains("preexec"));
        assert!(h.contains("check"));
        assert!(h.contains("run"));
        assert!(h.contains("2|3"), "hook must gate only deny/approve exits");
        let b = render_hook(ShellKind::Bash, "mayrun");
        assert!(b.contains("DEBUG"));
        assert!(b.contains("2|3"));
    }

    #[test]
    fn rejects_metachar_program() {
        let bad = OsString::from("bash;id");
        assert!(validate_exec_program(&bad).is_err());
        assert!(validate_exec_program(&OsString::from("/bin/bash")).is_ok());
    }
}
