use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SOCKET_PATH: &str = "/run/dadophoros.sock";
const MAX_FRAME: usize = 1 << 20; // 1 MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    Subscribe {
        filter: Option<EventFilter>,
    },
    Unsubscribe,
    /// Ask the daemon to materialize a deny rule from a row the user picked
    /// in the TUI. The daemon writes a TOML file under the rules directory
    /// and the existing notify watcher reloads. Optional fields let the
    /// daemon decline gracefully if the requested `by` kind requires data
    /// the row didn't have (e.g. asking to deny by host when hostname is
    /// None).
    CreateDenyRule {
        exe_path: Option<String>,
        hostname: Option<String>,
        dest_ip: Option<String>,
        dport: u16,
        by: DenyRuleKind,
    },
    /// Ask the daemon for the full rule set, disabled rules included, so the
    /// TUI's Rules view can browse them. The reply is `ServerMessage::Rules`.
    ListRules,
    /// Flip a rule's `enabled` flag on disk. The daemon rewrites the TOML
    /// file (preserving the rest of it) and its notify watcher reloads the
    /// active rule set. `id` is the rule's effective id (explicit `id` field
    /// or, failing that, the file stem) as reported by `ListRules`.
    SetRuleEnabled {
        id: String,
        enabled: bool,
    },
    /// Ask the daemon for the current aggregate stats snapshot. The reply is
    /// `ServerMessage::Stats`.
    GetStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyRuleKind {
    /// dest_host suffix match on the given hostname.
    Host,
    /// process_path exact match on the given exe.
    Process,
    /// dest_ip exact match on the given address (v4 dotted-quad or v6 compact form).
    Ip,
    /// Host + process_path AND-ed together.
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    Hello {
        daemon_version: String,
    },
    Event(EnrichedEvent),
    Ok,
    Error(String),
    /// Full rule set in priority order, disabled rules included. Reply to
    /// `ClientMessage::ListRules`.
    Rules(Vec<RuleInfo>),
    /// Aggregate snapshot. Reply to `ClientMessage::GetStats`.
    Stats(Stats),
}

/// A rule as the TUI needs to display and act on it. This is a flattened,
/// display-oriented view of the daemon's internal `Rule`; the daemon owns the
/// authoritative parsing and never round-trips through this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Effective id: the explicit `id` field, or the file stem if absent.
    pub id: String,
    pub priority: u32,
    pub enabled: bool,
    pub action: RuleAction,
    /// `once` | `session` | `persistent`, as written in the file.
    pub duration: String,
    /// One human-readable summary per `[[match]]` clause, e.g.
    /// `dest_host suffix .doubleclick.net`. Empty means catch-all.
    pub matches: Vec<String>,
    /// Absolute path to the backing TOML file, so the TUI can open it in
    /// `$EDITOR`.
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
}

/// Aggregate counters maintained by the daemon over the session. Cheap to
/// clone; sent whole in reply to `GetStats`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub total_events: u64,
    pub total_allowed: u64,
    pub total_denied: u64,
    /// Top processes by connection count, descending.
    pub top_processes: Vec<LabeledCount>,
    /// Top destination hosts (or bare IPs) by connection count, descending.
    pub top_hosts: Vec<LabeledCount>,
    /// Per-second connection counts, oldest first, for a sparkline. The
    /// last bucket is the current (still-filling) second.
    pub activity: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabeledCount {
    pub label: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    pub process_path_contains: Option<String>,
    pub host_contains: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Deny,
}

// FlowKey stays on the wire even though DecideVerdict went away — Step 8
// brings it back when start_ns is populated and we want the TUI to be able
// to reference flows directly.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub pid: u32,
    pub start_ns: u64,
    pub family: u8,
    pub daddr_v4: u32,
    pub daddr_v6: [u8; 16],
    pub dport: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub ts_unix_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe_path: Option<String>,
    pub family: u8,
    pub daddr_v4: u32, // network byte order, as stored on the wire
    pub daddr_v6: [u8; 16],
    pub dport: u16,
    pub hostname: Option<String>,
    pub verdict: Verdict,
    pub matched_rule: Option<String>,
}

#[derive(Debug)]
pub enum ProtoError {
    Io(std::io::Error),
    Codec(postcard::Error),
    FrameTooLarge(usize),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Io(e) => write!(f, "io: {e}"),
            ProtoError::Codec(e) => write!(f, "codec: {e}"),
            ProtoError::FrameTooLarge(n) => write!(f, "frame too large: {n}"),
        }
    }
}

impl std::error::Error for ProtoError {}

impl From<std::io::Error> for ProtoError {
    fn from(e: std::io::Error) -> Self {
        ProtoError::Io(e)
    }
}

impl From<postcard::Error> for ProtoError {
    fn from(e: postcard::Error) -> Self {
        ProtoError::Codec(e)
    }
}

pub async fn read_message<R, T>(reader: &mut R) -> Result<T, ProtoError>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}

pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let bytes = postcard::to_allocvec(msg)?;
    if bytes.len() > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge(bytes.len()));
    }
    let len = (bytes.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> EnrichedEvent {
        EnrichedEvent {
            ts_unix_ns: 1_700_000_000_000_000_000,
            pid: 42,
            uid: 1000,
            comm: "curl".into(),
            exe_path: Some("/usr/bin/curl".into()),
            family: 4,
            daddr_v4: 0x0403_02_01,
            daddr_v6: [0; 16],
            dport: 443,
            hostname: Some("github.com".into()),
            verdict: Verdict::Deny,
            matched_rule: Some("block-github".into()),
        }
    }

    #[tokio::test]
    async fn roundtrip_subscribe_no_filter() {
        let (mut w, mut r) = tokio::io::duplex(1024);
        let msg = ClientMessage::Subscribe { filter: None };
        write_message(&mut w, &msg).await.unwrap();
        drop(w);
        let got: ClientMessage = read_message(&mut r).await.unwrap();
        assert!(matches!(got, ClientMessage::Subscribe { filter: None }));
    }

    #[tokio::test]
    async fn roundtrip_subscribe_with_filter() {
        let filter = EventFilter {
            process_path_contains: Some("firefox".into()),
            host_contains: Some(".github.com".into()),
        };
        let msg = ClientMessage::Subscribe {
            filter: Some(filter),
        };
        let (mut w, mut r) = tokio::io::duplex(1024);
        write_message(&mut w, &msg).await.unwrap();
        drop(w);
        let got: ClientMessage = read_message(&mut r).await.unwrap();
        let ClientMessage::Subscribe { filter: Some(f) } = got else {
            panic!("expected subscribe with filter");
        };
        assert_eq!(f.process_path_contains.as_deref(), Some("firefox"));
        assert_eq!(f.host_contains.as_deref(), Some(".github.com"));
    }

    #[tokio::test]
    async fn roundtrip_event() {
        let original = sample_event();
        let (mut w, mut r) = tokio::io::duplex(2048);
        write_message(&mut w, &ServerMessage::Event(original.clone()))
            .await
            .unwrap();
        drop(w);
        let got: ServerMessage = read_message(&mut r).await.unwrap();
        let ServerMessage::Event(ev) = got else {
            panic!("expected Event");
        };
        assert_eq!(ev.pid, original.pid);
        assert_eq!(ev.comm, original.comm);
        assert_eq!(ev.exe_path, original.exe_path);
        assert_eq!(ev.dport, original.dport);
        assert_eq!(ev.verdict, original.verdict);
        assert_eq!(ev.matched_rule, original.matched_rule);
        assert_eq!(ev.daddr_v4, original.daddr_v4);
    }

    #[tokio::test]
    async fn roundtrip_multiple_messages_back_to_back() {
        let (mut w, mut r) = tokio::io::duplex(4096);
        write_message(
            &mut w,
            &ServerMessage::Hello {
                daemon_version: "1.2.3".into(),
            },
        )
        .await
        .unwrap();
        write_message(&mut w, &ServerMessage::Ok).await.unwrap();
        write_message(&mut w, &ServerMessage::Event(sample_event()))
            .await
            .unwrap();
        drop(w);

        let m1: ServerMessage = read_message(&mut r).await.unwrap();
        assert!(matches!(m1, ServerMessage::Hello { .. }));
        let m2: ServerMessage = read_message(&mut r).await.unwrap();
        assert!(matches!(m2, ServerMessage::Ok));
        let m3: ServerMessage = read_message(&mut r).await.unwrap();
        assert!(matches!(m3, ServerMessage::Event(_)));
    }

    #[tokio::test]
    async fn roundtrip_list_rules_and_reply() {
        let (mut w, mut r) = tokio::io::duplex(2048);
        write_message(&mut w, &ClientMessage::ListRules)
            .await
            .unwrap();
        let got: ClientMessage = read_message(&mut r).await.unwrap();
        assert!(matches!(got, ClientMessage::ListRules));

        let infos = vec![RuleInfo {
            id: "block-dc".into(),
            priority: 100,
            enabled: false,
            action: RuleAction::Deny,
            duration: "persistent".into(),
            matches: vec!["dest_host suffix .doubleclick.net".into()],
            path: "/etc/dadophoros/rules.d/block-dc.toml".into(),
        }];
        write_message(&mut w, &ServerMessage::Rules(infos.clone()))
            .await
            .unwrap();
        let got: ServerMessage = read_message(&mut r).await.unwrap();
        let ServerMessage::Rules(rs) = got else {
            panic!("expected Rules");
        };
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].id, "block-dc");
        assert!(!rs[0].enabled);
        assert_eq!(rs[0].action, RuleAction::Deny);
        assert_eq!(rs[0].matches, infos[0].matches);
    }

    #[tokio::test]
    async fn roundtrip_set_rule_enabled() {
        let (mut w, mut r) = tokio::io::duplex(1024);
        write_message(
            &mut w,
            &ClientMessage::SetRuleEnabled {
                id: "block-dc".into(),
                enabled: false,
            },
        )
        .await
        .unwrap();
        let got: ClientMessage = read_message(&mut r).await.unwrap();
        let ClientMessage::SetRuleEnabled { id, enabled } = got else {
            panic!("expected SetRuleEnabled");
        };
        assert_eq!(id, "block-dc");
        assert!(!enabled);
    }

    #[tokio::test]
    async fn roundtrip_get_stats_and_reply() {
        let (mut w, mut r) = tokio::io::duplex(2048);
        write_message(&mut w, &ClientMessage::GetStats)
            .await
            .unwrap();
        let got: ClientMessage = read_message(&mut r).await.unwrap();
        assert!(matches!(got, ClientMessage::GetStats));

        let stats = Stats {
            total_events: 10,
            total_allowed: 7,
            total_denied: 3,
            top_processes: vec![LabeledCount {
                label: "/usr/bin/curl".into(),
                count: 4,
            }],
            top_hosts: vec![LabeledCount {
                label: "github.com".into(),
                count: 5,
            }],
            activity: vec![0, 1, 2, 3],
        };
        write_message(&mut w, &ServerMessage::Stats(stats.clone()))
            .await
            .unwrap();
        let got: ServerMessage = read_message(&mut r).await.unwrap();
        let ServerMessage::Stats(s) = got else {
            panic!("expected Stats");
        };
        assert_eq!(s.total_events, 10);
        assert_eq!(s.total_denied, 3);
        assert_eq!(s.top_processes[0].label, "/usr/bin/curl");
        assert_eq!(s.activity, vec![0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn read_short_frame_errors() {
        // 4-byte length prefix says 100 bytes follow; we close after writing none.
        let (mut w, mut r) = tokio::io::duplex(1024);
        use tokio::io::AsyncWriteExt;
        w.write_all(&100u32.to_be_bytes()).await.unwrap();
        drop(w);
        let err = read_message::<_, ServerMessage>(&mut r).await.unwrap_err();
        assert!(matches!(err, ProtoError::Io(_)));
    }
}
