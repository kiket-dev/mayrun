//! Project signal detection for `mayrun init --detect`.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub packs: Vec<&'static str>,
    pub signals: Vec<String>,
}

/// Detect packs from workspace signals. Always includes the baseline safety packs;
/// never weakens `dangerous-defaults`.
pub fn detect_packs(root: &Path) -> Detection {
    let mut packs = vec![
        "dangerous-defaults",
        "secrets-safe",
        "exec-escapes",
        "shell-basics",
    ];
    let mut signals = vec!["baseline safety packs + shell-basics".into()];

    if root.join(".git").exists() {
        packs.push("git-safe");
        signals.push(".git → git-safe".into());
    }
    if root.join("Cargo.toml").is_file() {
        packs.push("rust-dev");
        signals.push("Cargo.toml → rust-dev".into());
    }
    if root.join("package.json").is_file()
        || root.join("package-lock.json").is_file()
        || root.join("pnpm-lock.yaml").is_file()
        || root.join("yarn.lock").is_file()
        || root.join("bun.lockb").is_file()
        || root.join("bun.lock").is_file()
    {
        packs.push("node-dev");
        signals.push("Node lockfile / package.json → node-dev".into());
    }
    if root.join("pyproject.toml").is_file()
        || root.join("requirements.txt").is_file()
        || root.join("Pipfile").is_file()
        || root.join("poetry.lock").is_file()
        || root.join("uv.lock").is_file()
    {
        packs.push("python-dev");
        signals.push("Python project files → python-dev".into());
    }
    if root.join("go.mod").is_file() {
        packs.push("go-dev");
        signals.push("go.mod → go-dev".into());
    }
    if root.join("pom.xml").is_file()
        || root.join("build.gradle").is_file()
        || root.join("build.gradle.kts").is_file()
    {
        // Prefer kotlin-dev when Kotlin DSL / sources are present.
        if root.join("build.gradle.kts").is_file()
            || walk_shallow_match(root, |name| name.ends_with(".kt") || name.ends_with(".kts"))
        {
            packs.push("kotlin-dev");
            signals.push("Kotlin/Gradle KTS → kotlin-dev".into());
        } else {
            packs.push("java-dev");
            signals.push("pom.xml / build.gradle → java-dev".into());
        }
    }
    if walk_shallow_match(root, |name| {
        name.ends_with(".csproj") || name.ends_with(".sln") || name.ends_with(".fsproj")
    }) {
        packs.push("dotnet-dev");
        signals.push(".csproj / .sln → dotnet-dev".into());
    }
    if root.join("CMakeLists.txt").is_file()
        || root.join("meson.build").is_file()
        || root.join("compile_commands.json").is_file()
    {
        packs.push("cpp-dev");
        signals.push("CMake/meson → cpp-dev".into());
    }
    if root.join("composer.json").is_file() {
        packs.push("php-dev");
        signals.push("composer.json → php-dev".into());
    }
    if root.join("Gemfile").is_file() {
        packs.push("ruby-dev");
        signals.push("Gemfile → ruby-dev".into());
    }
    if has_ops_signals(root) {
        packs.push("ops-approve");
        signals.push("Dockerfile / .tf / k8s manifests → ops-approve".into());
    }

    Detection { packs, signals }
}

fn has_ops_signals(root: &Path) -> bool {
    if root.join("Dockerfile").is_file() || root.join("dockerfile").is_file() {
        return true;
    }
    if walk_shallow_match(root, |name| {
        name.ends_with(".tf")
            || name == "docker-compose.yml"
            || name == "docker-compose.yaml"
            || name == "compose.yml"
            || name == "compose.yaml"
            || looks_like_k8s(name)
    }) {
        return true;
    }
    false
}

fn looks_like_k8s(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.ends_with(".yaml") || lower.ends_with(".yml"))
        && (lower.contains("deployment")
            || lower.contains("kustomization")
            || lower.contains("helm")
            || lower.starts_with("values"))
}

/// Shallow dir walk (root + one level) for common ops files.
fn walk_shallow_match(root: &Path, pred: impl Fn(&str) -> bool) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if pred(&name) {
            return true;
        }
        if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            let Ok(sub) = std::fs::read_dir(ent.path()) else {
                continue;
            };
            for child in sub.flatten() {
                let n = child.file_name();
                if pred(&n.to_string_lossy()) {
                    return true;
                }
            }
        }
    }
    false
}

/// Render a starter policy YAML with the given extends packs.
pub fn policy_yaml_for_packs(packs: &[&str]) -> String {
    let mut out = String::from(
        r#"# mayrun policy v1 — generated by `mayrun init --detect`
# Evaluation: deny → require_approval → allow → default.
# Only deterministic rules can Allow. AI draft/tighten proposes YAML only.

apiVersion: mayrun.dev/v1
default: deny

extends:
"#,
    );
    for p in packs {
        out.push_str(&format!("  - pack: {p}\n"));
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn always_has_baseline() {
        let dir = tempdir().unwrap();
        let d = detect_packs(dir.path());
        assert!(d.packs.contains(&"dangerous-defaults"));
        assert!(d.packs.contains(&"secrets-safe"));
        assert!(d.packs.contains(&"exec-escapes"));
        assert!(d.packs.contains(&"shell-basics"));
        assert!(!d.packs.contains(&"rust-dev"));
    }

    #[test]
    fn rust_sample() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let d = detect_packs(dir.path());
        assert!(d.packs.contains(&"rust-dev"));
        assert!(d.packs.contains(&"git-safe"));
        assert!(d.packs.contains(&"shell-basics"));
        assert_eq!(d.packs.first().copied(), Some("dangerous-defaults"));
    }

    #[test]
    fn node_sample() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}\n").unwrap();
        let d = detect_packs(dir.path());
        assert!(d.packs.contains(&"node-dev"));
    }

    #[test]
    fn python_go_samples() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), "[project]\nname=\"x\"\n").unwrap();
        std::fs::write(dir.path().join("go.mod"), "module example.com/x\n").unwrap();
        let d = detect_packs(dir.path());
        assert!(d.packs.contains(&"python-dev"));
        assert!(d.packs.contains(&"go-dev"));
    }

    #[test]
    fn ops_dockerfile() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let d = detect_packs(dir.path());
        assert!(d.packs.contains(&"ops-approve"));
    }
}
