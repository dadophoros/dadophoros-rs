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
