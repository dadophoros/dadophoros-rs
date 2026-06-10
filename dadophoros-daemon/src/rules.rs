use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
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
    // Carried forward for step 6's once/session/persistent semantics; the
    // current observe-mode code path never reads it.
    #[allow(dead_code)]
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
    DestIp,
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
                    r.id = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned);
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

/// A parsed rule paired with the file it came from and its effective id.
/// Unlike [`load_dir`], `list_all` keeps disabled rules — the Rules view needs
/// to show them so the user can flip them back on.
#[derive(Debug, Clone)]
pub struct LoadedRule {
    pub id: String,
    pub rule: Rule,
    pub path: PathBuf,
}

/// The id a rule is addressed by: its explicit `id` field, or the file stem.
fn effective_id(rule: &Rule, path: &Path) -> String {
    rule.id.clone().unwrap_or_else(|| {
        path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_owned()
    })
}

/// Every parsable rule under `dir`, disabled included, sorted by priority then
/// id for a stable display order. Unparsable files are skipped (and warned),
/// matching [`load_dir`]'s leniency.
pub fn list_all(dir: &Path) -> Vec<LoadedRule> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "rules directory unreadable");
            return out;
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
            Ok(rule) => {
                let id = effective_id(&rule, &path);
                out.push(LoadedRule { id, rule, path });
            }
            Err(e) => warn!(path = %path.display(), error = %e, "rule parse failed"),
        }
    }
    out.sort_by(|a, b| {
        a.rule
            .priority
            .cmp(&b.rule.priority)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

/// Rewrite the `enabled` flag of the rule with the given effective id, leaving
/// the rest of the file (comments, ordering, formatting) intact. The daemon's
/// notify watcher then reloads the active set. Returns the file touched.
pub fn set_enabled(dir: &Path, id: &str, enabled: bool) -> Result<PathBuf> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let Ok(rule) = toml::from_str::<Rule>(&contents) else {
            continue;
        };
        if effective_id(&rule, &path) != id {
            continue;
        }
        let mut doc = contents
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("parsing {} for edit", path.display()))?;
        doc["enabled"] = toml_edit::value(enabled);
        std::fs::write(&path, doc.to_string())
            .with_context(|| format!("writing {}", path.display()))?;
        return Ok(path);
    }
    Err(anyhow!("no rule with id {id}"))
}

impl Duration {
    pub fn as_str(&self) -> &'static str {
        match self {
            Duration::Once => "once",
            Duration::Session => "session",
            Duration::Persistent => "persistent",
        }
    }
}

impl Match {
    /// A compact human-readable summary, e.g. `dest_host suffix .example.com`.
    pub fn summary(&self) -> String {
        let field = match self.field {
            MatchField::ProcessPath => "process_path",
            MatchField::DestHost => "dest_host",
            MatchField::DestIp => "dest_ip",
            MatchField::DestPort => "dest_port",
        };
        let op = match self.op {
            MatchOp::Exact => "exact",
            MatchOp::Prefix => "prefix",
            MatchOp::Suffix => "suffix",
            MatchOp::Contains => "contains",
            MatchOp::In => "in",
        };
        let value = match &self.value {
            MatchValue::Num(n) => n.to_string(),
            MatchValue::Str(s) => s.clone(),
            MatchValue::NumList(v) => v
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(","),
            MatchValue::StrList(v) => v.join(","),
        };
        format!("{field} {op} {value}")
    }
}

pub fn evaluate(
    rules: &[Rule],
    exe: Option<&str>,
    host: Option<&str>,
    ip: Option<&str>,
    dport: u16,
) -> Option<Verdict> {
    for rule in rules {
        if rule
            .matches
            .iter()
            .all(|m| matches_one(m, exe, host, ip, dport))
        {
            return Some(Verdict {
                action: rule.action,
                rule_id: rule.id.clone().unwrap_or_else(|| "?".to_string()),
            });
        }
    }
    None
}

fn matches_one(
    m: &Match,
    exe: Option<&str>,
    host: Option<&str>,
    ip: Option<&str>,
    dport: u16,
) -> bool {
    match m.field {
        MatchField::ProcessPath => match_string(m.op, &m.value, exe.unwrap_or("")),
        MatchField::DestHost => match_string(m.op, &m.value, host.unwrap_or("")),
        MatchField::DestIp => match_string(m.op, &m.value, ip.unwrap_or("")),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, priority: u32, action: Action, matches: Vec<Match>) -> Rule {
        Rule {
            id: Some(id.into()),
            priority,
            enabled: true,
            action,
            duration: Duration::Persistent,
            matches,
        }
    }

    fn m(field: MatchField, op: MatchOp, value: MatchValue) -> Match {
        Match { field, op, value }
    }

    fn host_suffix(s: &str) -> Match {
        m(
            MatchField::DestHost,
            MatchOp::Suffix,
            MatchValue::Str(s.into()),
        )
    }

    #[test]
    fn no_rules_yields_no_verdict() {
        assert!(evaluate(&[], Some("/usr/bin/curl"), Some("github.com"), None, 443).is_none());
    }

    #[test]
    fn host_suffix_deny() {
        let rules = vec![rule(
            "block-dc",
            100,
            Action::Deny,
            vec![host_suffix(".doubleclick.net")],
        )];
        let v = evaluate(&rules, None, Some("ad.doubleclick.net"), None, 443).unwrap();
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.rule_id, "block-dc");
    }

    #[test]
    fn host_suffix_no_match() {
        let rules = vec![rule(
            "block-dc",
            100,
            Action::Deny,
            vec![host_suffix(".doubleclick.net")],
        )];
        assert!(evaluate(&rules, None, Some("github.com"), None, 443).is_none());
    }

    #[test]
    fn match_clauses_are_anded() {
        let rules = vec![rule(
            "apt-https",
            100,
            Action::Allow,
            vec![
                m(
                    MatchField::ProcessPath,
                    MatchOp::Exact,
                    MatchValue::Str("/usr/bin/apt".into()),
                ),
                m(
                    MatchField::DestPort,
                    MatchOp::In,
                    MatchValue::NumList(vec![80, 443]),
                ),
            ],
        )];
        // both clauses satisfied
        assert!(evaluate(&rules, Some("/usr/bin/apt"), None, None, 80).is_some());
        assert!(evaluate(&rules, Some("/usr/bin/apt"), None, None, 443).is_some());
        // process matches, port does not
        assert!(evaluate(&rules, Some("/usr/bin/apt"), None, None, 22).is_none());
        // port matches, process does not
        assert!(evaluate(&rules, Some("/usr/bin/curl"), None, None, 80).is_none());
    }

    #[test]
    fn first_match_wins_in_priority_order() {
        // The caller is responsible for passing rules sorted by priority
        // ascending — load_dir does that. Here we simulate the sorted slice.
        let rules = vec![
            rule("hi", 1, Action::Allow, vec![host_suffix(".example.com")]),
            rule("lo", 10, Action::Deny, vec![host_suffix(".example.com")]),
        ];
        let v = evaluate(&rules, None, Some("a.example.com"), None, 443).unwrap();
        assert_eq!(v.rule_id, "hi");
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn empty_matches_is_catch_all() {
        let rules = vec![rule("default-deny", 1000, Action::Deny, vec![])];
        let v = evaluate(&rules, None, None, None, 443).unwrap();
        assert_eq!(v.action, Action::Deny);
    }

    #[test]
    fn string_op_variants() {
        let exact = m(
            MatchField::ProcessPath,
            MatchOp::Exact,
            MatchValue::Str("/usr/bin/curl".into()),
        );
        let prefix = m(
            MatchField::ProcessPath,
            MatchOp::Prefix,
            MatchValue::Str("/usr/bin/".into()),
        );
        let suffix = m(
            MatchField::ProcessPath,
            MatchOp::Suffix,
            MatchValue::Str("/curl".into()),
        );
        let contains = m(
            MatchField::ProcessPath,
            MatchOp::Contains,
            MatchValue::Str("bin".into()),
        );
        let in_list = m(
            MatchField::ProcessPath,
            MatchOp::In,
            MatchValue::StrList(vec!["/usr/bin/curl".into(), "/usr/bin/wget".into()]),
        );
        for one in [exact, prefix, suffix, contains, in_list] {
            let r = vec![rule("t", 1, Action::Allow, vec![one])];
            assert!(
                evaluate(&r, Some("/usr/bin/curl"), None, None, 0).is_some(),
                "expected match"
            );
        }
    }

    #[test]
    fn port_op_variants() {
        let exact = m(MatchField::DestPort, MatchOp::Exact, MatchValue::Num(443));
        let in_list = m(
            MatchField::DestPort,
            MatchOp::In,
            MatchValue::NumList(vec![80, 443, 8080]),
        );
        for one in [exact, in_list] {
            let r = vec![rule("t", 1, Action::Allow, vec![one])];
            assert!(evaluate(&r, None, None, None, 443).is_some());
        }
        // miss
        let r = vec![rule(
            "t",
            1,
            Action::Allow,
            vec![m(
                MatchField::DestPort,
                MatchOp::Exact,
                MatchValue::Num(443),
            )],
        )];
        assert!(evaluate(&r, None, None, None, 80).is_none());
    }

    #[test]
    fn missing_host_or_exe_treated_as_empty_string() {
        // A suffix rule on .example.com against a None host should miss.
        let r = vec![rule(
            "h",
            1,
            Action::Deny,
            vec![host_suffix(".example.com")],
        )];
        assert!(evaluate(&r, None, None, None, 443).is_none());
    }

    // --- load_dir: filesystem-backed integration tests ---------------------

    fn write_rule(dir: &std::path::Path, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn load_dir_missing_returns_empty() {
        let nonexistent = std::path::PathBuf::from("/tmp/dadophoros-nonexistent-xyzzy-12345");
        assert!(load_dir(&nonexistent).is_empty());
    }

    #[test]
    fn load_dir_parses_basic_rule_with_filename_as_id() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "block-doubleclick.toml",
            r#"
priority = 100
action = "deny"

[[match]]
type = "dest_host"
op = "suffix"
value = ".doubleclick.net"
"#,
        );
        let rules = load_dir(dir.path());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, Action::Deny);
        // No explicit id field -> the file's stem becomes the id.
        assert_eq!(rules[0].id.as_deref(), Some("block-doubleclick"));
        assert_eq!(rules[0].matches.len(), 1);
    }

    #[test]
    fn load_dir_preserves_explicit_id() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "rule.toml",
            r#"
id = "my-uuid-or-whatever"
action = "allow"
"#,
        );
        let rules = load_dir(dir.path());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id.as_deref(), Some("my-uuid-or-whatever"));
    }

    #[test]
    fn load_dir_filters_disabled_rules() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "on.toml",
            r#"
priority = 50
enabled = true
action = "allow"
"#,
        );
        write_rule(
            dir.path(),
            "off.toml",
            r#"
priority = 10
enabled = false
action = "deny"
"#,
        );
        let rules = load_dir(dir.path());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, Action::Allow);
    }

    #[test]
    fn load_dir_sorts_by_priority_ascending() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "low-prio.toml",
            r#"
priority = 100
action = "allow"
"#,
        );
        write_rule(
            dir.path(),
            "high-prio.toml",
            r#"
priority = 10
action = "deny"
"#,
        );
        write_rule(
            dir.path(),
            "mid-prio.toml",
            r#"
priority = 50
action = "allow"
"#,
        );
        let rules = load_dir(dir.path());
        let priorities: Vec<u32> = rules.iter().map(|r| r.priority).collect();
        assert_eq!(priorities, vec![10, 50, 100]);
    }

    #[test]
    fn load_dir_skips_invalid_toml_and_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "good.toml",
            r#"
action = "allow"
"#,
        );
        write_rule(
            dir.path(),
            "broken.toml",
            "::: this is not valid TOML at all :::",
        );
        write_rule(
            dir.path(),
            "missing-action.toml",
            r#"
priority = 1
"#,
        ); // action is required; should fail to parse and be skipped
        let rules = load_dir(dir.path());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, Action::Allow);
    }

    #[test]
    fn list_all_includes_disabled_and_carries_path() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "off.toml",
            r#"
priority = 10
enabled = false
action = "deny"
"#,
        );
        write_rule(
            dir.path(),
            "on.toml",
            r#"
priority = 5
action = "allow"
"#,
        );
        let all = list_all(dir.path());
        assert_eq!(all.len(), 2);
        // Sorted by priority ascending: on (5) before off (10).
        assert_eq!(all[0].id, "on");
        assert_eq!(all[1].id, "off");
        assert!(!all[1].rule.enabled);
        assert!(all[1].path.ends_with("off.toml"));
    }

    #[test]
    fn list_all_uses_explicit_id_over_stem() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "file-stem.toml",
            r#"
id = "explicit-id"
action = "allow"
"#,
        );
        let all = list_all(dir.path());
        assert_eq!(all[0].id, "explicit-id");
    }

    #[test]
    fn set_enabled_flips_flag_and_preserves_file() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "r.toml",
            r#"# keep this comment
id = "r"
priority = 50
enabled = true
action = "deny"

[[match]]
type = "dest_host"
op = "suffix"
value = ".example.com"
"#,
        );
        let path = set_enabled(dir.path(), "r", false).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("enabled = false"));
        // Untouched content survives.
        assert!(body.contains("# keep this comment"));
        assert!(body.contains(".example.com"));
        // load_dir now filters it out; list_all still sees it.
        assert!(load_dir(dir.path()).is_empty());
        assert_eq!(list_all(dir.path()).len(), 1);

        // And back on.
        set_enabled(dir.path(), "r", true).unwrap();
        assert_eq!(load_dir(dir.path()).len(), 1);
    }

    #[test]
    fn set_enabled_adds_flag_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        // No `enabled` key -> defaults to true. Disabling must insert one.
        write_rule(
            dir.path(),
            "r.toml",
            r#"
id = "r"
action = "allow"
"#,
        );
        set_enabled(dir.path(), "r", false).unwrap();
        assert!(load_dir(dir.path()).is_empty());
    }

    #[test]
    fn set_enabled_matches_by_file_stem_when_no_explicit_id() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "stem-id.toml",
            r#"
action = "deny"
"#,
        );
        set_enabled(dir.path(), "stem-id", false).unwrap();
        assert!(load_dir(dir.path()).is_empty());
    }

    #[test]
    fn set_enabled_unknown_id_errors() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(dir.path(), "r.toml", "action = \"allow\"\n");
        let err = set_enabled(dir.path(), "nope", false).unwrap_err();
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn match_summary_formats_each_value_kind() {
        let s = m(
            MatchField::DestHost,
            MatchOp::Suffix,
            MatchValue::Str(".example.com".into()),
        )
        .summary();
        assert_eq!(s, "dest_host suffix .example.com");
        let p = m(
            MatchField::DestPort,
            MatchOp::In,
            MatchValue::NumList(vec![80, 443]),
        )
        .summary();
        assert_eq!(p, "dest_port in 80,443");
    }

    #[test]
    fn load_dir_ignores_non_toml_files() {
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "rule.toml",
            r#"
action = "allow"
"#,
        );
        write_rule(dir.path(), "README.md", "# Some operator notes\n");
        write_rule(dir.path(), "rule.toml.bak", "garbage");
        write_rule(dir.path(), "rule.yaml", "action: allow");
        let rules = load_dir(dir.path());
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn load_dir_end_to_end_with_evaluate() {
        // Round-trip the full SPEC example: parse it, then make sure the
        // resulting rule matches/misses the right traffic.
        let dir = tempfile::tempdir().unwrap();
        write_rule(
            dir.path(),
            "apt-https.toml",
            r#"
id = "apt-https"
priority = 50
action = "allow"
duration = "persistent"

[[match]]
type = "process_path"
op = "exact"
value = "/usr/bin/apt"

[[match]]
type = "dest_host"
op = "suffix"
value = ".ubuntu.com"

[[match]]
type = "dest_port"
op = "in"
value = [80, 443]
"#,
        );
        let rules = load_dir(dir.path());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].matches.len(), 3);

        // Matches: right exe, right host, allowed port.
        let v = evaluate(
            &rules,
            Some("/usr/bin/apt"),
            Some("archive.ubuntu.com"),
            None,
            443,
        )
        .unwrap();
        assert_eq!(v.action, Action::Allow);
        assert_eq!(v.rule_id, "apt-https");

        // Misses: wrong port.
        assert!(evaluate(
            &rules,
            Some("/usr/bin/apt"),
            Some("archive.ubuntu.com"),
            None,
            22
        )
        .is_none());
        // Misses: wrong exe.
        assert!(evaluate(
            &rules,
            Some("/usr/bin/curl"),
            Some("archive.ubuntu.com"),
            None,
            443,
        )
        .is_none());
        // Misses: wrong host suffix.
        assert!(evaluate(&rules, Some("/usr/bin/apt"), Some("example.com"), None, 443).is_none());
    }
}
