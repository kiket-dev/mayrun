//! Built-in policy packs shipped with the binary.

use crate::policy::{PolicyDocument, PolicyError, Rule};

pub const PACK_NAMES: &[&str] = &[
    "dangerous-defaults",
    "shell-basics",
    "git-safe",
    "rust-dev",
    "node-dev",
    "python-dev",
    "go-dev",
    "java-dev",
    "dotnet-dev",
    "cpp-dev",
    "php-dev",
    "ruby-dev",
    "kotlin-dev",
    "ops-approve",
    "secrets-safe",
    "exec-escapes",
    "network-exfil",
    "mcp-safe",
    "read-only",
];

pub fn pack_yaml(name: &str) -> Option<&'static str> {
    match name {
        "dangerous-defaults" => Some(include_str!("../packs/dangerous-defaults.yaml")),
        "shell-basics" => Some(include_str!("../packs/shell-basics.yaml")),
        "git-safe" => Some(include_str!("../packs/git-safe.yaml")),
        "rust-dev" => Some(include_str!("../packs/rust-dev.yaml")),
        "node-dev" => Some(include_str!("../packs/node-dev.yaml")),
        "python-dev" => Some(include_str!("../packs/python-dev.yaml")),
        "go-dev" => Some(include_str!("../packs/go-dev.yaml")),
        "java-dev" => Some(include_str!("../packs/java-dev.yaml")),
        "dotnet-dev" => Some(include_str!("../packs/dotnet-dev.yaml")),
        "cpp-dev" => Some(include_str!("../packs/cpp-dev.yaml")),
        "php-dev" => Some(include_str!("../packs/php-dev.yaml")),
        "ruby-dev" => Some(include_str!("../packs/ruby-dev.yaml")),
        "kotlin-dev" => Some(include_str!("../packs/kotlin-dev.yaml")),
        "ops-approve" => Some(include_str!("../packs/ops-approve.yaml")),
        "secrets-safe" => Some(include_str!("../packs/secrets-safe.yaml")),
        "exec-escapes" => Some(include_str!("../packs/exec-escapes.yaml")),
        "network-exfil" => Some(include_str!("../packs/network-exfil.yaml")),
        "mcp-safe" => Some(include_str!("../packs/mcp-safe.yaml")),
        "read-only" => Some(include_str!("../packs/read-only.yaml")),
        _ => None,
    }
}

/// All rule IDs across every built-in pack (for corpus lockstep tests).
pub fn all_pack_rule_ids() -> Result<Vec<String>, PolicyError> {
    let mut ids = Vec::new();
    for name in PACK_NAMES {
        for rule in load_pack_rules(name)? {
            ids.push(rule.id);
        }
    }
    Ok(ids)
}

pub fn load_pack_rules(name: &str) -> Result<Vec<Rule>, PolicyError> {
    let yaml = pack_yaml(name).ok_or_else(|| PolicyError::UnknownPack(name.to_string()))?;
    let doc: PolicyDocument = serde_yaml::from_str(yaml).map_err(|source| PolicyError::Yaml {
        path: std::path::PathBuf::from(format!("pack:{name}")),
        source,
    })?;
    Ok(doc.rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_packs_parse() {
        for name in PACK_NAMES {
            load_pack_rules(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }
}
