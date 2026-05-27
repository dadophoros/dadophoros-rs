use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use dadophoros_proto::{
    read_message, write_message, ClientMessage, EnrichedEvent, ServerMessage, SOCKET_PATH,
};
use futures_util::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::{Frame, Terminal};
use tokio::io::BufReader;
use tokio::net::UnixStream;

const MAX_EVENTS: usize = 10_000;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Connect first so we can fail fast with a clear error before mangling the terminal.
    let stream = UnixStream::connect(SOCKET_PATH)
        .await
        .with_context(|| format!("connecting to {SOCKET_PATH}"))?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Read Hello.
    let hello: ServerMessage = read_message(&mut reader).await.context("reading hello")?;
    let daemon_version = match hello {
        ServerMessage::Hello { daemon_version } => daemon_version,
        other => anyhow::bail!("expected Hello, got {other:?}"),
    };

    write_message(&mut writer, &ClientMessage::Subscribe { filter: None })
        .await
        .context("subscribe")?;
    let ack: ServerMessage = read_message(&mut reader).await.context("subscribe ack")?;
    if !matches!(ack, ServerMessage::Ok) {
        anyhow::bail!("subscribe failed: {ack:?}");
    }

    setup_panic_hook();
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    // We don't enable mouse capture: the terminal's native text selection
    // (and shell copy/paste) keeps working that way.
    execute!(stdout, EnterAlternateScreen).ok();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let result = run(&mut terminal, &mut reader, daemon_version).await;

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

fn setup_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        prev(info);
    }));
}

struct Aggregate {
    event: EnrichedEvent, // latest representative; verdict/rule may shift
    count: u32,
    last_ts: u64,
}

#[derive(Default, PartialEq, Eq, Clone)]
struct AggKey {
    pid: u32,
    comm: String,
    exe: String,
    host_or_ip: String,
    port: u16,
}

impl AggKey {
    fn of(ev: &EnrichedEvent) -> Self {
        Self {
            pid: ev.pid,
            comm: ev.comm.clone(),
            exe: ev.exe_path.clone().unwrap_or_default(),
            host_or_ip: ev.hostname.clone().unwrap_or_else(|| format_addr(ev)),
            port: ev.dport,
        }
    }
}

#[derive(Default)]
struct App {
    events: VecDeque<Aggregate>,
    state: TableState,
    follow: bool,
    filter: String,
    filter_mode: bool,
    daemon_version: String,
    connected: bool,
}

impl App {
    fn new(daemon_version: String) -> Self {
        Self {
            follow: true,
            connected: true,
            daemon_version,
            ..Default::default()
        }
    }

    fn push(&mut self, ev: EnrichedEvent) {
        let key = AggKey::of(&ev);
        let ts = ev.ts_unix_ns;
        if let Some(agg) = self.events.iter_mut().find(|a| AggKey::of(&a.event) == key) {
            agg.count += 1;
            agg.last_ts = ts;
            agg.event = ev;
            return;
        }
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(Aggregate {
            event: ev,
            count: 1,
            last_ts: ts,
        });
    }

    fn filtered_indices(&self) -> Vec<usize> {
        if self.filter.is_empty() {
            (0..self.events.len()).collect()
        } else {
            let needle = self.filter.to_lowercase();
            self.events
                .iter()
                .enumerate()
                .filter(|(_, a)| event_matches(&a.event, &needle))
                .map(|(i, _)| i)
                .collect()
        }
    }

    fn scroll(&mut self, delta: isize) {
        let indices = self.filtered_indices();
        if indices.is_empty() {
            self.state.select(None);
            return;
        }
        let current_pos = self
            .state
            .selected()
            .and_then(|sel| indices.iter().position(|&i| i == sel))
            .unwrap_or_else(|| indices.len().saturating_sub(1));
        let new_pos = (current_pos as isize + delta).clamp(0, indices.len() as isize - 1) as usize;
        self.state.select(Some(indices[new_pos]));
        self.follow = new_pos == indices.len() - 1;
    }

    fn jump_to_end(&mut self) {
        let indices = self.filtered_indices();
        if let Some(&last) = indices.last() {
            self.state.select(Some(last));
        }
        self.follow = true;
    }

    fn jump_to_start(&mut self) {
        let indices = self.filtered_indices();
        if let Some(&first) = indices.first() {
            self.state.select(Some(first));
        }
        self.follow = false;
    }
}

fn event_matches(ev: &EnrichedEvent, needle_lower: &str) -> bool {
    let mut hay = String::new();
    hay.push_str(&ev.comm.to_lowercase());
    hay.push(' ');
    if let Some(p) = &ev.exe_path {
        hay.push_str(&p.to_lowercase());
        hay.push(' ');
    }
    if let Some(h) = &ev.hostname {
        hay.push_str(&h.to_lowercase());
        hay.push(' ');
    }
    hay.push_str(&format_addr(ev));
    hay.contains(needle_lower)
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    daemon_version: String,
) -> Result<()> {
    let mut app = App::new(daemon_version);
    let mut crossterm_events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            msg = read_message::<_, ServerMessage>(reader) => {
                match msg {
                    Ok(ServerMessage::Event(ev)) => {
                        app.push(ev);
                        if app.follow {
                            if !app.events.is_empty() {
                                app.state.select(Some(app.events.len() - 1));
                            }
                        }
                    }
                    Ok(ServerMessage::Hello { .. }) | Ok(ServerMessage::Ok) => {}
                    Ok(ServerMessage::Error(e)) => {
                        app.connected = false;
                        eprintln!("daemon error: {e}");
                        break;
                    }
                    Err(_) => {
                        app.connected = false;
                        break;
                    }
                }
            }
            Some(Ok(event)) = crossterm_events.next() => {
                if handle_input(event, &mut app) {
                    break;
                }
            }
            _ = tick.tick() => {
                terminal.draw(|f| draw(f, &mut app))?;
            }
        }
        // Drain any keyboard burst without waiting for the tick.
        terminal.draw(|f| draw(f, &mut app))?;
    }
    Ok(())
}

fn handle_input(event: Event, app: &mut App) -> bool {
    let Event::Key(key) = event else {
        return false;
    };
    if key.kind != KeyEventKind::Press {
        return false;
    }
    if app.filter_mode {
        match key.code {
            KeyCode::Esc => {
                app.filter.clear();
                app.filter_mode = false;
            }
            KeyCode::Enter => {
                app.filter_mode = false;
            }
            KeyCode::Backspace => {
                app.filter.pop();
            }
            KeyCode::Char(c) => {
                app.filter.push(c);
            }
            _ => {}
        }
        return false;
    }
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
        KeyCode::Up => app.scroll(-1),
        KeyCode::Down => app.scroll(1),
        KeyCode::PageUp => app.scroll(-20),
        KeyCode::PageDown => app.scroll(20),
        KeyCode::Home => app.jump_to_start(),
        KeyCode::End | KeyCode::Char('G') => app.jump_to_end(),
        KeyCode::Char('/') => {
            app.filter.clear();
            app.filter_mode = true;
        }
        _ => {}
    }
    false
}

fn draw(f: &mut Frame, app: &mut App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(f.area());

    draw_table(f, layout[0], app);
    draw_status(f, layout[1], app);
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let indices = app.filtered_indices();
    let rows: Vec<Row> = indices
        .iter()
        .map(|&i| {
            let agg = &app.events[i];
            let ev = &agg.event;
            let host_or_ip = ev
                .hostname
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(|| format_addr(ev));
            let exe = ev
                .exe_path
                .as_deref()
                .map(short_path)
                .unwrap_or_else(|| "?".to_string());
            let verdict = match ev.verdict {
                dadophoros_proto::Verdict::Allow => "allow",
                dadophoros_proto::Verdict::Deny => "deny",
            };
            let rule = ev.matched_rule.clone().unwrap_or_else(|| "-".to_string());
            let count = if agg.count > 1 {
                format!("×{}", agg.count)
            } else {
                String::new()
            };
            let style = if ev.verdict == dadophoros_proto::Verdict::Deny {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(ev.pid.to_string()),
                Cell::from(ev.comm.clone()),
                Cell::from(exe),
                Cell::from(host_or_ip),
                Cell::from(ev.dport.to_string()),
                Cell::from(verdict),
                Cell::from(rule),
                Cell::from(count).style(Style::default().fg(Color::Cyan)),
            ])
            .style(style)
        })
        .collect();

    let header = Row::new(vec![
        "PID", "COMM", "EXE", "HOST", "PORT", "VERDICT", "RULE", "N",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(28),
            Constraint::Min(20),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("dadophoros — live"),
    );

    f.render_stateful_widget(table, area, &mut app.state);
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let conn = if app.connected {
        format!("daemon v{}", app.daemon_version)
    } else {
        "disconnected".to_string()
    };
    let counts = format!("{} events", app.events.len());
    let filter_text = if app.filter_mode {
        format!("/{}", app.filter)
    } else if !app.filter.is_empty() {
        format!("filter: {}", app.filter)
    } else {
        String::new()
    };
    let help = "q quit  ↑↓ scroll  / filter  Esc cancel  End follow";

    let line = Line::from(vec![
        Span::styled(conn, Style::default().fg(Color::Green)),
        Span::raw("  "),
        Span::raw(counts),
        Span::raw("  "),
        Span::styled(filter_text, Style::default().fg(Color::Yellow)),
        Span::raw("  "),
        Span::styled(help, Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn format_addr(ev: &EnrichedEvent) -> String {
    if ev.family == 4 {
        Ipv4Addr::from(ev.daddr_v4.to_ne_bytes()).to_string()
    } else {
        format!("[{}]", Ipv6Addr::from(ev.daddr_v6))
    }
}

fn short_path(p: &str) -> String {
    // Keep the last two path segments to fit narrow columns without losing
    // identity for snap/flatpak-style deep paths.
    let parts: Vec<&str> = p.rsplit('/').collect();
    match parts.as_slice() {
        [last] => (*last).to_string(),
        [last, parent, ..] => format!(".../{parent}/{last}"),
        _ => p.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dadophoros_proto::Verdict;

    fn make_event(
        pid: u32,
        comm: &str,
        host: Option<&str>,
        port: u16,
        verdict: Verdict,
    ) -> EnrichedEvent {
        EnrichedEvent {
            ts_unix_ns: 0,
            pid,
            uid: 1000,
            comm: comm.to_string(),
            exe_path: Some(format!("/usr/bin/{comm}")),
            family: 4,
            // 4.3.2.1 in network-order bytes; LE host reads as 0x01020304.
            daddr_v4: 0x01020304,
            daddr_v6: [0; 16],
            dport: port,
            hostname: host.map(str::to_owned),
            verdict,
            matched_rule: None,
        }
    }

    #[test]
    fn push_appends_first_event() {
        let mut app = App::new("test".into());
        app.push(make_event(
            1,
            "curl",
            Some("github.com"),
            443,
            Verdict::Allow,
        ));
        assert_eq!(app.events.len(), 1);
        assert_eq!(app.events[0].count, 1);
    }

    #[test]
    fn push_dedupes_same_tuple() {
        let mut app = App::new("test".into());
        for _ in 0..5 {
            app.push(make_event(
                1,
                "curl",
                Some("github.com"),
                443,
                Verdict::Allow,
            ));
        }
        assert_eq!(app.events.len(), 1);
        assert_eq!(app.events[0].count, 5);
    }

    #[test]
    fn push_distinguishes_different_ports() {
        let mut app = App::new("test".into());
        app.push(make_event(
            1,
            "curl",
            Some("github.com"),
            443,
            Verdict::Allow,
        ));
        app.push(make_event(
            1,
            "curl",
            Some("github.com"),
            80,
            Verdict::Allow,
        ));
        assert_eq!(app.events.len(), 2);
        assert!(app.events.iter().all(|a| a.count == 1));
    }

    #[test]
    fn push_distinguishes_different_comm_threads() {
        // Firefox's "DNS Res~er #112" vs "DNS Res~er #102" — same pid, same
        // exe, same host/port but different thread names — should remain
        // separate rows.
        let mut app = App::new("test".into());
        app.push(make_event(
            1,
            "DNS Res~er #112",
            Some("127.0.0.53"),
            53,
            Verdict::Allow,
        ));
        app.push(make_event(
            1,
            "DNS Res~er #102",
            Some("127.0.0.53"),
            53,
            Verdict::Allow,
        ));
        assert_eq!(app.events.len(), 2);
    }

    #[test]
    fn push_updates_latest_verdict_on_dedup() {
        let mut app = App::new("test".into());
        app.push(make_event(
            1,
            "curl",
            Some("github.com"),
            443,
            Verdict::Allow,
        ));
        app.push(make_event(
            1,
            "curl",
            Some("github.com"),
            443,
            Verdict::Deny,
        ));
        assert_eq!(app.events.len(), 1);
        assert_eq!(app.events[0].count, 2);
        assert_eq!(app.events[0].event.verdict, Verdict::Deny);
    }

    #[test]
    fn agg_key_falls_back_to_ip_when_no_hostname() {
        let mut ev = make_event(1, "curl", None, 443, Verdict::Allow);
        ev.daddr_v4 = 0x04030201; // 1.2.3.4 in network-order bytes
        let key = AggKey::of(&ev);
        assert_eq!(key.host_or_ip, "1.2.3.4");
    }

    #[test]
    fn agg_key_uses_hostname_when_present() {
        let ev = make_event(1, "curl", Some("github.com"), 443, Verdict::Allow);
        let key = AggKey::of(&ev);
        assert_eq!(key.host_or_ip, "github.com");
    }

    #[test]
    fn short_path_basename_when_no_slash() {
        assert_eq!(short_path("foo"), "foo");
    }

    #[test]
    fn short_path_two_segment_path() {
        assert_eq!(short_path("/usr/bin/curl"), ".../bin/curl");
    }

    #[test]
    fn short_path_deep_path() {
        assert_eq!(
            short_path("/snap/firefox/7901/usr/lib/firefox/firefox"),
            ".../firefox/firefox"
        );
    }

    #[test]
    fn event_matches_substring_case_insensitive() {
        let ev = make_event(1, "Firefox", Some("MAIL.GOOGLE.com"), 443, Verdict::Allow);
        assert!(event_matches(&ev, "google"));
        assert!(event_matches(&ev, "firefox"));
        assert!(!event_matches(&ev, "github"));
    }

    #[test]
    fn filter_narrows_visible_rows() {
        let mut app = App::new("test".into());
        app.push(make_event(
            1,
            "curl",
            Some("github.com"),
            443,
            Verdict::Allow,
        ));
        app.push(make_event(
            2,
            "firefox",
            Some("example.com"),
            443,
            Verdict::Allow,
        ));
        assert_eq!(app.filtered_indices().len(), 2);
        app.filter = "github".into();
        assert_eq!(app.filtered_indices().len(), 1);
    }
}
