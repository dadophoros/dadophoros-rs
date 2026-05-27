use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use dadophoros_proto::{
    read_message, write_message, ClientMessage, EnrichedEvent, ServerMessage, SOCKET_PATH,
};
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

pub fn spawn_server(events: broadcast::Sender<EnrichedEvent>) -> Result<()> {
    let path = Path::new(SOCKET_PATH);
    // Best-effort cleanup of any leftover socket from a prior run.
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding {SOCKET_PATH}"))?;
    // Permissive for local dev; the spec calls for tighter group permissions
    // in step 8 polish.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    info!(path = SOCKET_PATH, "IPC listening");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let tx = events.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, tx).await {
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
    events: broadcast::Sender<EnrichedEvent>,
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

    // Expect the first message from the client to be a Subscribe.
    let first: ClientMessage = read_message(&mut reader).await.context("subscribe read")?;
    let filter = match first {
        ClientMessage::Subscribe { filter } => filter,
        ClientMessage::Unsubscribe => {
            write_message(
                &mut writer,
                &ServerMessage::Error("expected Subscribe".to_string()),
            )
            .await?;
            return Ok(());
        }
    };
    write_message(&mut writer, &ServerMessage::Ok).await?;
    debug!(filter = ?filter, "client subscribed");

    let mut rx = events.subscribe();
    loop {
        match rx.recv().await {
            Ok(ev) => {
                if !matches_filter(&ev, filter.as_ref()) {
                    continue;
                }
                if write_message(&mut writer, &ServerMessage::Event(ev))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                debug!(skipped = n, "client lagged");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

fn matches_filter(ev: &EnrichedEvent, filter: Option<&dadophoros_proto::EventFilter>) -> bool {
    let Some(f) = filter else {
        return true;
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
