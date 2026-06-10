use std::io;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::EventStream;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use dadophoros_proto::{read_message, write_message, ClientMessage, ServerMessage, SOCKET_PATH};
use futures_util::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Tabs};
use ratatui::{Frame, Terminal};
use tokio::io::BufReader;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

mod app;
mod views;

use app::{handle_input, App, InputAction, View};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let stream = UnixStream::connect(SOCKET_PATH)
        .await
        .with_context(|| format!("connecting to {SOCKET_PATH}"))?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

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
    execute!(stdout, EnterAlternateScreen).ok();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let result = run(&mut terminal, &mut reader, &mut writer, daemon_version).await;

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

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut OwnedWriteHalf,
    daemon_version: String,
) -> Result<()> {
    let mut app = App::new(daemon_version);
    let mut crossterm_events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut tick_count: u64 = 0;

    loop {
        tokio::select! {
            msg = read_message::<_, ServerMessage>(reader) => {
                match msg {
                    Ok(ServerMessage::Event(ev)) => {
                        app.push(ev);
                        if app.follow && !app.events.is_empty() {
                            app.state.select(Some(app.events.len() - 1));
                        }
                    }
                    Ok(ServerMessage::Hello { .. }) => {}
                    Ok(ServerMessage::Rules(rules)) => app.set_rules(rules),
                    Ok(ServerMessage::Stats(stats)) => app.stats = Some(stats),
                    Ok(ServerMessage::Ok) => {
                        app.last_ack = Some("ok".into());
                        app.last_ack_is_error = false;
                        // A toggle/write succeeded — refresh the rule list so
                        // the Rules view reflects the new on-disk truth.
                        if app.view == View::Rules
                            && write_message(writer, &ClientMessage::ListRules).await.is_err()
                        {
                            app.connected = false;
                            break;
                        }
                    }
                    Ok(ServerMessage::Error(e)) => {
                        app.last_ack = Some(e);
                        app.last_ack_is_error = true;
                    }
                    Err(_) => {
                        app.connected = false;
                        break;
                    }
                }
            }
            Some(Ok(event)) = crossterm_events.next() => {
                match handle_input(event, &mut app) {
                    InputAction::Quit => break,
                    InputAction::Send(msg) => {
                        if write_message(writer, &msg).await.is_err() {
                            app.connected = false;
                            break;
                        }
                    }
                    InputAction::EditRule(path) => {
                        if edit_rule(terminal, &path, &mut app).is_err() {
                            // Restoring the terminal failed; bail rather than
                            // risk a corrupted screen.
                            break;
                        }
                        if write_message(writer, &ClientMessage::ListRules).await.is_err() {
                            app.connected = false;
                            break;
                        }
                    }
                    InputAction::Nothing => {}
                }
            }
            _ = tick.tick() => {
                tick_count += 1;
                // Refresh stats roughly once a second while the Stats view is
                // open (the daemon republishes its snapshot at the same rate).
                if app.view == View::Stats && tick_count.is_multiple_of(10)
                    && write_message(writer, &ClientMessage::GetStats).await.is_err()
                {
                    app.connected = false;
                    break;
                }
                terminal.draw(|f| draw(f, &mut app))?;
            }
        }
        terminal.draw(|f| draw(f, &mut app))?;
    }
    Ok(())
}

/// Suspend the TUI, open `path` in `$EDITOR` (falling back to `vi`), then
/// restore the alternate screen. The daemon's file watcher reloads the active
/// rule set on save; we re-request the rule list separately to refresh the view.
fn edit_rule(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    path: &str,
    app: &mut App,
) -> Result<()> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);

    let status = std::process::Command::new(&editor).arg(path).status();

    enable_raw_mode().context("re-enable raw mode after editor")?;
    execute!(terminal.backend_mut(), EnterAlternateScreen).context("re-enter alt screen")?;
    terminal.clear().context("clear after editor")?;

    match status {
        Ok(s) if s.success() => {
            app.last_ack = Some("edited; reloading rules".into());
            app.last_ack_is_error = false;
        }
        Ok(s) => {
            app.last_ack = Some(format!("{editor} exited with {s}"));
            app.last_ack_is_error = true;
        }
        Err(e) => {
            app.last_ack = Some(format!("could not launch {editor}: {e}"));
            app.last_ack_is_error = true;
        }
    }
    Ok(())
}

fn draw(f: &mut Frame, app: &mut App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // tab bar
            Constraint::Min(1),    // view body
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    draw_tabs(f, layout[0], app);
    match app.view {
        View::Live => {
            views::live::draw(f, layout[1], app);
            if app.modal.is_some() {
                views::live::draw_modal(f, app);
            }
        }
        View::Rules => views::rules::draw(f, layout[1], app),
        View::Stats => views::stats::draw(f, layout[1], app),
    }
    draw_status(f, layout[2], app);
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App) {
    let titles = ["1 Live", "2 Rules", "3 Stats"];
    let selected = match app.view {
        View::Live => 0,
        View::Rules => 1,
        View::Stats => 2,
    };
    let tabs = Tabs::new(titles.to_vec())
        .select(selected)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(Style::default().fg(Color::White).bg(Color::Blue))
        .divider(" ");
    f.render_widget(tabs, area);
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let conn = if app.connected {
        format!("daemon v{}", app.daemon_version)
    } else {
        "disconnected".to_string()
    };
    let filter_text = if app.view == View::Live {
        if app.filter_mode {
            format!("/{}", app.filter)
        } else if !app.filter.is_empty() {
            format!("filter: {}", app.filter)
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let ack_color = if app.last_ack_is_error {
        Color::Red
    } else {
        Color::Green
    };
    let ack_text = app.last_ack.clone().unwrap_or_default();
    let help = match app.view {
        View::Live => "Tab views  ↑↓ scroll  / filter  d deny-rule  End follow  q quit",
        View::Rules => "Tab views  ↑↓ select  t toggle  e edit($EDITOR)  r refresh  q quit",
        View::Stats => "Tab views  r refresh  q quit",
    };

    let mut spans = vec![
        Span::styled(conn, Style::default().fg(Color::Green)),
        Span::raw("  "),
        Span::styled(filter_text, Style::default().fg(Color::Yellow)),
    ];
    if !ack_text.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(ack_text, Style::default().fg(ack_color)));
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled(help, Style::default().fg(Color::DarkGray)));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
