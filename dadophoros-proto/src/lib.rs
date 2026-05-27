use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SOCKET_PATH: &str = "/run/dadophoros.sock";
const MAX_FRAME: usize = 1 << 20; // 1 MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    Subscribe { filter: Option<EventFilter> },
    Unsubscribe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    Hello { daemon_version: String },
    Event(EnrichedEvent),
    Ok,
    Error(String),
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
