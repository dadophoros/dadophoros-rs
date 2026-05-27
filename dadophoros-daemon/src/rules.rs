use std::fmt;
use std::path::Path;

use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Deserialize, Debug, Clone)]
pub struct Rule {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub action: Action,
    #[serde(default)]
    pub duration: Duration,
    #[serde(rename = "match", default)]
    pub matches: Vec<Match>,
}

fn default_true() -> bool {
    true
}
fn default_priority() -> u32 {
    100
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
        })
    }
}

#[derive(Deserialize, Debug, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
pub enum Duration {
    Once,
    Session,
    #[default]
    Persistent,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Match {
    #[serde(rename = "type")]
    pub field: MatchField,
    pub op: MatchOp,
    pub value: MatchValue,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum MatchField {
    ProcessPath,
    DestHost,
    DestPort,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum MatchOp {
    Exact,
    Prefix,
    Suffix,
    Contains,
    In,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum MatchValue {
    Num(u16),
    Str(String),
    NumList(Vec<u16>),
    StrList(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub action: Action,
    pub rule_id: String,
}

pub fn load_dir(dir: &Path) -> Vec<Rule> {
    let mut rules = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Common at first start; logged once during startup, no need to
            // re-warn on subsequent reloads.
            return rules;
        }
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "rules directory unreadable");
            return rules;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "could not read rule file");
                continue;
            }
        };
        match toml::from_str::<Rule>(&contents) {
            Ok(mut r) => {
                if !r.enabled {
                    debug!(path = %path.display(), "rule disabled");
                    continue;
                }
                if r.id.is_none() {
                    r.id = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .map(str::to_owned);
                }
                rules.push(r);
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "rule parse failed");
            }
        }
    }
    rules.sort_by_key(|r| r.priority);
    rules
}

pub fn evaluate(
    rules: &[Rule],
    exe: Option<&str>,
    host: Option<&str>,
    dport: u16,
) -> Option<Verdict> {
    for rule in rules {
        if rule.matches.iter().all(|m| matches_one(m, exe, host, dport)) {
            return Some(Verdict {
                action: rule.action,
                rule_id: rule.id.clone().unwrap_or_else(|| "?".to_string()),
            });
        }
    }
    None
}

fn matches_one(m: &Match, exe: Option<&str>, host: Option<&str>, dport: u16) -> bool {
    match m.field {
        MatchField::ProcessPath => match_string(m.op, &m.value, exe.unwrap_or("")),
        MatchField::DestHost => match_string(m.op, &m.value, host.unwrap_or("")),
        MatchField::DestPort => match_port(m.op, &m.value, dport),
    }
}

fn match_string(op: MatchOp, value: &MatchValue, s: &str) -> bool {
    match (op, value) {
        (MatchOp::Exact, MatchValue::Str(v)) => s == v,
        (MatchOp::Prefix, MatchValue::Str(v)) => s.starts_with(v.as_str()),
        (MatchOp::Suffix, MatchValue::Str(v)) => s.ends_with(v.as_str()),
        (MatchOp::Contains, MatchValue::Str(v)) => s.contains(v.as_str()),
        (MatchOp::In, MatchValue::StrList(vs)) => vs.iter().any(|v| v == s),
        _ => false,
    }
}

fn match_port(op: MatchOp, value: &MatchValue, port: u16) -> bool {
    match (op, value) {
        (MatchOp::Exact, MatchValue::Num(v)) => port == *v,
        (MatchOp::In, MatchValue::NumList(vs)) => vs.contains(&port),
        _ => false,
    }
}
