use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use dadophoros_proto::{
    read_message, write_message, ClientMessage, DenyRuleKind, RuleAction, RuleInfo, ServerMessage,
    Stats, SOCKET_PATH,
};
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};

use crate::rules;

pub fn spawn_server(
    events: broadcast::Sender<ServerMessage>,
    rules_dir: PathBuf,
    stats: watch::Receiver<Stats>,
) -> Result<()> {
    let path = Path::new(SOCKET_PATH);
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path).with_context(|| format!("binding {SOCKET_PATH}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    info!(path = SOCKET_PATH, "IPC listening");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let tx = events.clone();
                    let dir = rules_dir.clone();
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, tx, dir, stats).await {
                            debug!(error = %e, "client disconnected");
                        }
                    });
                }
                Err(e) => warn!(error = %e, "accept failed"),
            }
        }
    });
    Ok(())
}

async fn handle_client(
    stream: UnixStream,
    events: broadcast::Sender<ServerMessage>,
    rules_dir: PathBuf,
    stats: watch::Receiver<Stats>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    write_message(
        &mut writer,
        &ServerMessage::Hello {
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await
    .context("hello")?;

    let first: ClientMessage = read_message(&mut reader).await.context("subscribe read")?;
    let filter = match first {
        ClientMessage::Subscribe { filter } => filter,
        other => {
            write_message(
                &mut writer,
                &ServerMessage::Error(format!("expected Subscribe, got {:?}", other_kind(&other))),
            )
            .await?;
            return Ok(());
        }
    };
    write_message(&mut writer, &ServerMessage::Ok).await?;
    debug!(filter = ?filter, "client subscribed");

    let mut rx = events.subscribe();
    loop {
        tokio::select! {
            biased;
            msg = read_message::<_, ClientMessage>(&mut reader) => {
                match msg {
                    Ok(ClientMessage::CreateDenyRule { exe_path, hostname, dest_ip, dport, by }) => {
                        let ack = match write_deny_rule(&rules_dir, exe_path, hostname, dest_ip, dport, by) {
                            Ok(path) => {
                                info!(path = %path.display(), "wrote deny rule");
                                ServerMessage::Ok
                            }
                            Err(e) => {
                                warn!(error = %e, "deny rule write failed");
                                ServerMessage::Error(e.to_string())
                            }
                        };
                        if write_message(&mut writer, &ack).await.is_err() {
                            break;
                        }
                    }
                    Ok(ClientMessage::ListRules) => {
                        let infos = list_rule_infos(&rules_dir);
                        if write_message(&mut writer, &ServerMessage::Rules(infos)).await.is_err() {
                            break;
                        }
                    }
                    Ok(ClientMessage::SetRuleEnabled { id, enabled }) => {
                        let ack = match rules::set_enabled(&rules_dir, &id, enabled) {
                            Ok(path) => {
                                info!(path = %path.display(), id = %id, enabled, "toggled rule");
                                ServerMessage::Ok
                            }
                            Err(e) => {
                                warn!(error = %e, id = %id, "rule toggle failed");
                                ServerMessage::Error(e.to_string())
                            }
                        };
                        if write_message(&mut writer, &ack).await.is_err() {
                            break;
                        }
                    }
                    Ok(ClientMessage::GetStats) => {
                        let snap = stats.borrow().clone();
                        if write_message(&mut writer, &ServerMessage::Stats(snap)).await.is_err() {
                            break;
                        }
                    }
                    Ok(ClientMessage::Unsubscribe) => break,
                    Ok(ClientMessage::Subscribe { .. }) => {
                        // Re-subscribe not supported.
                    }
                    Err(_) => break,
                }
            }
            ev = rx.recv() => {
                match ev {
                    Ok(msg) => {
                        if !matches_filter(&msg, filter.as_ref()) {
                            continue;
                        }
                        if write_message(&mut writer, &msg).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        debug!(skipped = n, "client lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}

fn other_kind(m: &ClientMessage) -> &'static str {
    match m {
        ClientMessage::Subscribe { .. } => "Subscribe",
        ClientMessage::Unsubscribe => "Unsubscribe",
        ClientMessage::CreateDenyRule { .. } => "CreateDenyRule",
        ClientMessage::ListRules => "ListRules",
        ClientMessage::SetRuleEnabled { .. } => "SetRuleEnabled",
        ClientMessage::GetStats => "GetStats",
    }
}

/// Build the wire-facing rule list (disabled rules included) for the TUI.
fn list_rule_infos(dir: &Path) -> Vec<RuleInfo> {
    rules::list_all(dir)
        .into_iter()
        .map(|loaded| RuleInfo {
            id: loaded.id,
            priority: loaded.rule.priority,
            enabled: loaded.rule.enabled,
            action: match loaded.rule.action {
                rules::Action::Allow => RuleAction::Allow,
                rules::Action::Deny => RuleAction::Deny,
            },
            duration: loaded.rule.duration.as_str().to_string(),
            matches: loaded.rule.matches.iter().map(|m| m.summary()).collect(),
            path: loaded.path.to_string_lossy().into_owned(),
        })
        .collect()
}

fn matches_filter(msg: &ServerMessage, filter: Option<&dadophoros_proto::EventFilter>) -> bool {
    let Some(f) = filter else {
        return true;
    };
    let ev = match msg {
        ServerMessage::Event(e) => e,
        _ => return true,
    };
    if let Some(needle) = &f.process_path_contains {
        if !ev
            .exe_path
            .as_deref()
            .map(|p| p.contains(needle.as_str()))
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(needle) = &f.host_contains {
        if !ev
            .hostname
            .as_deref()
            .map(|h| h.contains(needle.as_str()))
            .unwrap_or(false)
        {
            return false;
        }
    }
    true
}

fn write_deny_rule(
    dir: &Path,
    exe_path: Option<String>,
    hostname: Option<String>,
    dest_ip: Option<String>,
    dport: u16,
    by: DenyRuleKind,
) -> Result<PathBuf> {
    // Validate that the requested rule kind has the data it needs.
    let (need_host, need_exe, need_ip) = match by {
        DenyRuleKind::Host => (true, false, false),
        DenyRuleKind::Process => (false, true, false),
        DenyRuleKind::Ip => (false, false, true),
        DenyRuleKind::Both => (true, true, false),
    };
    if need_host && hostname.as_deref().unwrap_or("").is_empty() {
        return Err(anyhow!("requested deny-by-host but no hostname on the row"));
    }
    if need_exe && exe_path.as_deref().unwrap_or("").is_empty() {
        return Err(anyhow!(
            "requested deny-by-process but no exe path on the row"
        ));
    }
    if need_ip && dest_ip.as_deref().unwrap_or("").is_empty() {
        return Err(anyhow!("requested deny-by-ip but no dest_ip on the row"));
    }

    if !dir.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    let mut matches = Vec::with_capacity(2);
    if need_exe {
        let exe = exe_path.as_deref().unwrap();
        matches.push(format!(
            "[[match]]\ntype = \"process_path\"\nop = \"exact\"\nvalue = \"{}\"\n",
            toml_escape(exe)
        ));
    }
    if need_host {
        let host = hostname.as_deref().unwrap();
        // Suffix match so subdomains of the row's hostname are covered too.
        // If the user wanted exact, they can edit the file.
        matches.push(format!(
            "[[match]]\ntype = \"dest_host\"\nop = \"suffix\"\nvalue = \"{}\"\n",
            toml_escape(host)
        ));
    }
    if need_ip {
        let ip = dest_ip.as_deref().unwrap();
        matches.push(format!(
            "[[match]]\ntype = \"dest_ip\"\nop = \"exact\"\nvalue = \"{}\"\n",
            toml_escape(ip)
        ));
    }

    let stem = naming_stem(&exe_path, &hostname, &dest_ip, dport, by);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let filename = format!("auto-deny-{stem}-{ts}.toml");
    let path = dir.join(filename);
    let body = format!(
        "# Auto-generated by dadophoros TUI rule picker.\n\
         id = \"auto-deny-{stem}-{ts}\"\n\
         priority = 100\n\
         action = \"deny\"\n\
         \n\
         {}",
        matches.join("\n")
    );

    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn naming_stem(
    exe: &Option<String>,
    host: &Option<String>,
    ip: &Option<String>,
    _dport: u16,
    by: DenyRuleKind,
) -> String {
    let host_part = host.as_deref().map(sanitize);
    let ip_part = ip.as_deref().map(sanitize);
    let exe_part = exe.as_deref().and_then(|p| {
        std::path::Path::new(p)
            .file_name()
            .and_then(|s| s.to_str())
            .map(sanitize)
    });
    match by {
        DenyRuleKind::Host => host_part.unwrap_or_else(|| "unknown".into()),
        DenyRuleKind::Process => exe_part.unwrap_or_else(|| "unknown".into()),
        DenyRuleKind::Ip => ip_part.unwrap_or_else(|| "unknown".into()),
        DenyRuleKind::Both => {
            let e = exe_part.unwrap_or_else(|| "unknown".into());
            let h = host_part.unwrap_or_else(|| "unknown".into());
            format!("{e}-{h}")
        }
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn toml_escape(s: &str) -> String {
    // Cheap escape: backslashes and double quotes. Hostnames and Linux
    // file paths only legitimately need this much.
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_keeps_alphanumerics_and_dashes() {
        assert_eq!(sanitize("github.com"), "github_com");
        assert_eq!(sanitize("api-test.example.com"), "api-test_example_com");
        assert_eq!(sanitize("/usr/bin/curl"), "_usr_bin_curl");
    }

    #[test]
    fn write_deny_rule_host_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_deny_rule(
            dir.path(),
            Some("/usr/bin/curl".into()),
            Some("github.com".into()),
            Some("1.2.3.4".into()),
            443,
            DenyRuleKind::Host,
        )
        .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("action = \"deny\""));
        assert!(body.contains("type = \"dest_host\""));
        assert!(body.contains("op = \"suffix\""));
        assert!(body.contains("\"github.com\""));
        assert!(!body.contains("process_path"));
    }

    #[test]
    fn write_deny_rule_process_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_deny_rule(
            dir.path(),
            Some("/usr/bin/curl".into()),
            Some("github.com".into()),
            Some("1.2.3.4".into()),
            443,
            DenyRuleKind::Process,
        )
        .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("type = \"process_path\""));
        assert!(body.contains("op = \"exact\""));
        assert!(body.contains("/usr/bin/curl"));
        assert!(!body.contains("dest_host"));
    }

    #[test]
    fn write_deny_rule_both_includes_both_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_deny_rule(
            dir.path(),
            Some("/usr/bin/curl".into()),
            Some("github.com".into()),
            Some("1.2.3.4".into()),
            443,
            DenyRuleKind::Both,
        )
        .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("process_path"));
        assert!(body.contains("dest_host"));
    }

    #[test]
    fn write_deny_rule_host_without_hostname_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = write_deny_rule(
            dir.path(),
            Some("/usr/bin/curl".into()),
            None,
            Some("1.2.3.4".into()),
            443,
            DenyRuleKind::Host,
        )
        .unwrap_err();
        assert!(err.to_string().contains("hostname"));
    }

    #[test]
    fn write_deny_rule_process_without_exe_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = write_deny_rule(
            dir.path(),
            None,
            Some("github.com".into()),
            Some("1.2.3.4".into()),
            443,
            DenyRuleKind::Process,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exe"));
    }

    #[test]
    fn write_deny_rule_ip_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_deny_rule(
            dir.path(),
            None,
            None,
            Some("140.82.112.4".into()),
            443,
            DenyRuleKind::Ip,
        )
        .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("type = \"dest_ip\""));
        assert!(body.contains("op = \"exact\""));
        assert!(body.contains("140.82.112.4"));
    }

    #[test]
    fn write_deny_rule_ip_without_ip_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = write_deny_rule(dir.path(), None, None, None, 443, DenyRuleKind::Ip).unwrap_err();
        assert!(err.to_string().contains("dest_ip"));
    }

    #[test]
    fn write_deny_rule_creates_directory_if_missing() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("nested/rules.d");
        let path = write_deny_rule(
            &dir,
            None,
            Some("github.com".into()),
            None,
            443,
            DenyRuleKind::Host,
        )
        .unwrap();
        assert!(path.exists());
    }
}
