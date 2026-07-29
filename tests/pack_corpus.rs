//! Table-driven pack corpus — lockstep with built-in pack rule IDs.

use std::collections::HashSet;

use mayrun::packs::{self, PACK_NAMES};
use mayrun::policy::{CompiledPolicy, Decision, PolicyDocument};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CorpusFile {
    cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
struct CorpusCase {
    command: String,
    expect: ExpectDecision,
    rule_prefix: String,
    #[serde(default)]
    packs: Option<Vec<String>>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum ExpectDecision {
    Allow,
    Deny,
    RequireApproval,
}

impl From<ExpectDecision> for Decision {
    fn from(e: ExpectDecision) -> Self {
        match e {
            ExpectDecision::Allow => Decision::Allow,
            ExpectDecision::Deny => Decision::Deny,
            ExpectDecision::RequireApproval => Decision::RequireApproval,
        }
    }
}

fn policy_for(packs: &[String]) -> CompiledPolicy {
    let doc = PolicyDocument {
        api_version: Some("mayrun.dev/v1".into()),
        default: Decision::Deny,
        extends: packs
            .iter()
            .map(|p| mayrun::policy::ExtendSpec::PackName(p.clone()))
            .collect(),
        ..Default::default()
    };
    CompiledPolicy::compile(doc).expect("compile corpus policy")
}

fn all_packs() -> Vec<String> {
    PACK_NAMES.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn corpus_cases_match_expected_decisions() {
    let corpus: CorpusFile =
        serde_yaml::from_str(include_str!("corpus.yaml")).expect("parse corpus.yaml");

    for (i, case) in corpus.cases.iter().enumerate() {
        let packs = case.packs.clone().unwrap_or_else(all_packs);
        let policy = policy_for(&packs);
        let ev = policy.evaluate_detailed(&case.command);
        let expect: Decision = case.expect.into();
        assert_eq!(
            ev.decision, expect,
            "case {i} command={:?}: decision {:?} != {:?}; rule_id={:?} reason={:?}",
            case.command, ev.decision, expect, ev.rule_id, ev.reason
        );
        let rule_id = ev.rule_id.as_deref().unwrap_or("");
        let reason = ev.reason.as_deref().unwrap_or("");
        let matches_prefix = rule_id.starts_with(&case.rule_prefix)
            || (case.rule_prefix == "default"
                && (rule_id.is_empty() || reason.starts_with("default:")));
        assert!(
            matches_prefix,
            "case {i} command={:?}: rule_id={rule_id:?} reason={reason:?} does not start with {:?}",
            case.command, case.rule_prefix
        );
    }
}

#[test]
fn every_pack_rule_id_has_corpus_entry() {
    let corpus: CorpusFile =
        serde_yaml::from_str(include_str!("corpus.yaml")).expect("parse corpus.yaml");
    let covered: HashSet<&str> = corpus
        .cases
        .iter()
        .map(|c| c.rule_prefix.as_str())
        .collect();

    let ids = packs::all_pack_rule_ids().expect("load pack rule ids");
    let missing: Vec<_> = ids
        .iter()
        .filter(|id| !covered.contains(id.as_str()))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "pack rule IDs missing from corpus.yaml rule_prefix coverage:\n  {}",
        missing.join("\n  ")
    );
}
