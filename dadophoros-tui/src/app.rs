use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use dadophoros_proto::{ClientMessage, DenyRuleKind, EnrichedEvent, RuleInfo, Stats, Verdict};
use ratatui::widgets::TableState;

pub const MAX_EVENTS: usize = 10_000;

/// Top-level tabbed views, switched with Tab or the number keys.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Live,
    Rules,
    Stats,
}

pub struct Aggregate {
    pub event: EnrichedEvent,
    pub count: u32,
    pub last_ts: u64,
}

#[derive(Clone)]
pub struct ModalState {
    /// The event the user picked when they pressed 'd'. We keep a snapshot
    /// here so the row scrolling out from under us doesn't change what the
    /// modal applies to.
    pub event: EnrichedEvent,
}

#[derive(Default, PartialEq, Eq, Clone)]
pub struct AggKey {
    pid: u32,
    comm: String,
    exe: String,
    host_or_ip: String,
    port: u16,
}

impl AggKey {
    pub fn of(ev: &EnrichedEvent) -> Self {
        Self {
            pid: ev.pid,
            comm: ev.comm.clone(),
            exe: ev.exe_path.clone().unwrap_or_default(),
            host_or_ip: ev.hostname.clone().unwrap_or_else(|| format_addr(ev)),
            port: ev.dport,
        }
    }
}

pub struct App {
    pub view: View,

    // Live view.
    pub events: VecDeque<Aggregate>,
    pub state: TableState,
    pub follow: bool,
    pub filter: String,
    pub filter_mode: bool,
    pub modal: Option<ModalState>,

    // Rules view.
    pub rules: Vec<RuleInfo>,
    pub rules_state: TableState,

    // Stats view.
    pub stats: Option<Stats>,

    // Shared chrome.
    /// Last message from the daemon about an attempted rule write/toggle, or
    /// an editor result. Shown in the status bar.
    pub last_ack: Option<String>,
    pub last_ack_is_error: bool,
    pub daemon_version: String,
    pub connected: bool,
}

impl App {
    pub fn new(daemon_version: String) -> Self {
        Self {
            view: View::Live,
            events: VecDeque::new(),
            state: TableState::default(),
            follow: true,
            filter: String::new(),
            filter_mode: false,
            modal: None,
            rules: Vec::new(),
            rules_state: TableState::default(),
            stats: None,
            last_ack: None,
            last_ack_is_error: false,
            daemon_version,
            connected: true,
        }
    }

    pub fn push(&mut self, ev: EnrichedEvent) {
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

    pub fn filtered_indices(&self) -> Vec<usize> {
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

    pub fn selected_event(&self) -> Option<EnrichedEvent> {
        let i = self.state.selected()?;
        self.events.get(i).map(|a| a.event.clone())
    }

    pub fn scroll(&mut self, delta: isize) {
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

    pub fn jump_to_end(&mut self) {
        let indices = self.filtered_indices();
        if let Some(&last) = indices.last() {
            self.state.select(Some(last));
        }
        self.follow = true;
    }

    pub fn jump_to_start(&mut self) {
        let indices = self.filtered_indices();
        if let Some(&first) = indices.first() {
            self.state.select(Some(first));
        }
        self.follow = false;
    }

    /// Set every event whose facts would be matched by a deny rule of the
    /// requested kind to verdict=Deny right now. The daemon's authoritative
    /// rule evaluation arrives a few ms later and overwrites the
    /// matched_rule label, but this gives instant visual feedback.
    pub fn optimistically_deny(&mut self, target: &EnrichedEvent, by: DenyRuleKind) {
        let target_ip = ip_string(target);
        for agg in self.events.iter_mut() {
            let matches = match by {
                DenyRuleKind::Host => agg.event.hostname == target.hostname,
                DenyRuleKind::Process => agg.event.exe_path == target.exe_path,
                DenyRuleKind::Ip => ip_string(&agg.event) == target_ip,
                DenyRuleKind::Both => {
                    agg.event.hostname == target.hostname && agg.event.exe_path == target.exe_path
                }
            };
            if matches {
                agg.event.verdict = Verdict::Deny;
                if agg.event.matched_rule.is_none() {
                    agg.event.matched_rule = Some("(pending)".to_string());
                }
            }
        }
    }

    // --- Rules view -------------------------------------------------------

    pub fn set_rules(&mut self, rules: Vec<RuleInfo>) {
        self.rules = rules;
        if self.rules.is_empty() {
            self.rules_state.select(None);
        } else {
            let sel = self
                .rules_state
                .selected()
                .unwrap_or(0)
                .min(self.rules.len() - 1);
            self.rules_state.select(Some(sel));
        }
    }

    pub fn rules_scroll(&mut self, delta: isize) {
        if self.rules.is_empty() {
            self.rules_state.select(None);
            return;
        }
        let cur = self.rules_state.selected().unwrap_or(0);
        let new = (cur as isize + delta).clamp(0, self.rules.len() as isize - 1) as usize;
        self.rules_state.select(Some(new));
    }

    pub fn selected_rule(&self) -> Option<&RuleInfo> {
        self.rules_state.selected().and_then(|i| self.rules.get(i))
    }

    // --- View switching ---------------------------------------------------

    fn next_view(&self) -> View {
        match self.view {
            View::Live => View::Rules,
            View::Rules => View::Stats,
            View::Stats => View::Live,
        }
    }

    /// Switch to `view`, returning the request (if any) the new view needs to
    /// populate itself.
    pub fn switch_to(&mut self, view: View) -> InputAction {
        self.view = view;
        match view {
            View::Live => InputAction::Nothing,
            View::Rules => InputAction::Send(ClientMessage::ListRules),
            View::Stats => InputAction::Send(ClientMessage::GetStats),
        }
    }
}

pub fn event_matches(ev: &EnrichedEvent, needle_lower: &str) -> bool {
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

pub enum InputAction {
    Nothing,
    Quit,
    Send(ClientMessage),
    /// Suspend the TUI and open this rule file in `$EDITOR`.
    EditRule(String),
}

pub fn handle_input(event: Event, app: &mut App) -> InputAction {
    let Event::Key(key) = event else {
        return InputAction::Nothing;
    };
    if key.kind != KeyEventKind::Press {
        return InputAction::Nothing;
    }
    if matches!(key.code, KeyCode::Char('c')) && key.modifiers.contains(KeyModifiers::CONTROL) {
        return InputAction::Quit;
    }
    // Modal and filter prompt (Live view only) capture all other keys.
    if app.modal.is_some() {
        return handle_modal_input(key, app);
    }
    if app.filter_mode {
        handle_filter_input(key, app);
        return InputAction::Nothing;
    }

    // View switching and quit, available from any view.
    match key.code {
        KeyCode::Tab => {
            let v = app.next_view();
            return app.switch_to(v);
        }
        KeyCode::Char('1') => return app.switch_to(View::Live),
        KeyCode::Char('2') => return app.switch_to(View::Rules),
        KeyCode::Char('3') => return app.switch_to(View::Stats),
        KeyCode::Char('q') => return InputAction::Quit,
        _ => {}
    }

    match app.view {
        View::Live => handle_live_input(key, app),
        View::Rules => handle_rules_input(key, app),
        View::Stats => handle_stats_input(key, app),
    }
}

fn handle_live_input(key: KeyEvent, app: &mut App) -> InputAction {
    match key.code {
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
        KeyCode::Char('d') => {
            if let Some(ev) = app.selected_event() {
                app.modal = Some(ModalState { event: ev });
            }
        }
        _ => {}
    }
    InputAction::Nothing
}

fn handle_rules_input(key: KeyEvent, app: &mut App) -> InputAction {
    match key.code {
        KeyCode::Up => app.rules_scroll(-1),
        KeyCode::Down => app.rules_scroll(1),
        KeyCode::Char('r') => return InputAction::Send(ClientMessage::ListRules),
        KeyCode::Char('t') | KeyCode::Char(' ') => {
            if let Some(r) = app.selected_rule() {
                return InputAction::Send(ClientMessage::SetRuleEnabled {
                    id: r.id.clone(),
                    enabled: !r.enabled,
                });
            }
        }
        KeyCode::Char('e') => {
            if let Some(r) = app.selected_rule() {
                return InputAction::EditRule(r.path.clone());
            }
        }
        _ => {}
    }
    InputAction::Nothing
}

fn handle_stats_input(key: KeyEvent, _app: &mut App) -> InputAction {
    if let KeyCode::Char('r') = key.code {
        return InputAction::Send(ClientMessage::GetStats);
    }
    InputAction::Nothing
}

fn handle_modal_input(key: KeyEvent, app: &mut App) -> InputAction {
    let Some(modal) = &app.modal else {
        return InputAction::Nothing;
    };
    let target = modal.event.clone();
    let send = |by: DenyRuleKind| -> InputAction { InputAction::Send(rule_msg(&target, by)) };
    match key.code {
        KeyCode::Esc => app.modal = None,
        KeyCode::Char('h') if target.hostname.is_some() => {
            app.modal = None;
            app.optimistically_deny(&target, DenyRuleKind::Host);
            return send(DenyRuleKind::Host);
        }
        KeyCode::Char('p') if target.exe_path.is_some() => {
            app.modal = None;
            app.optimistically_deny(&target, DenyRuleKind::Process);
            return send(DenyRuleKind::Process);
        }
        KeyCode::Char('i') => {
            app.modal = None;
            app.optimistically_deny(&target, DenyRuleKind::Ip);
            return send(DenyRuleKind::Ip);
        }
        KeyCode::Char('b') if target.hostname.is_some() && target.exe_path.is_some() => {
            app.modal = None;
            app.optimistically_deny(&target, DenyRuleKind::Both);
            return send(DenyRuleKind::Both);
        }
        _ => {}
    }
    InputAction::Nothing
}

fn handle_filter_input(key: KeyEvent, app: &mut App) {
    match key.code {
        KeyCode::Esc => {
            app.filter.clear();
            app.filter_mode = false;
        }
        KeyCode::Enter => app.filter_mode = false,
        KeyCode::Backspace => {
            app.filter.pop();
        }
        KeyCode::Char(c) => app.filter.push(c),
        _ => {}
    }
}

pub fn rule_msg(ev: &EnrichedEvent, by: DenyRuleKind) -> ClientMessage {
    ClientMessage::CreateDenyRule {
        exe_path: ev.exe_path.clone(),
        hostname: ev.hostname.clone(),
        dest_ip: Some(ip_string(ev)),
        dport: ev.dport,
        by,
    }
}

/// Bare destination IP without IPv6 brackets, suitable for rule matching.
pub fn ip_string(ev: &EnrichedEvent) -> String {
    if ev.family == 4 {
        Ipv4Addr::from(ev.daddr_v4.to_ne_bytes()).to_string()
    } else {
        Ipv6Addr::from(ev.daddr_v6).to_string()
    }
}

/// Destination address for display: IPv6 gets bracketed.
pub fn format_addr(ev: &EnrichedEvent) -> String {
    if ev.family == 4 {
        Ipv4Addr::from(ev.daddr_v4.to_ne_bytes()).to_string()
    } else {
        format!("[{}]", Ipv6Addr::from(ev.daddr_v6))
    }
}

pub fn short_path(p: &str) -> String {
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
            daddr_v4: 0x01020304,
            daddr_v6: [0; 16],
            dport: port,
            hostname: host.map(str::to_owned),
            verdict,
            matched_rule: None,
        }
    }

    fn rule_info(id: &str, enabled: bool) -> RuleInfo {
        RuleInfo {
            id: id.to_string(),
            priority: 100,
            enabled,
            action: dadophoros_proto::RuleAction::Deny,
            duration: "persistent".into(),
            matches: vec!["dest_host suffix .example.com".into()],
            path: format!("/etc/dadophoros/rules.d/{id}.toml"),
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
    }

    #[test]
    fn push_distinguishes_different_comm_threads() {
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
        assert_eq!(app.events[0].count, 2);
        assert_eq!(app.events[0].event.verdict, Verdict::Deny);
    }

    #[test]
    fn agg_key_falls_back_to_ip_when_no_hostname() {
        let mut ev = make_event(1, "curl", None, 443, Verdict::Allow);
        ev.daddr_v4 = 0x04030201;
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
    fn optimistically_deny_marks_matching_rows_by_host() {
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
            Some("github.com"),
            443,
            Verdict::Allow,
        ));
        app.push(make_event(
            3,
            "wget",
            Some("example.com"),
            443,
            Verdict::Allow,
        ));
        let target = make_event(1, "curl", Some("github.com"), 443, Verdict::Allow);
        app.optimistically_deny(&target, DenyRuleKind::Host);
        let mut by_host: std::collections::HashMap<String, Verdict> = Default::default();
        for a in &app.events {
            let h = a.event.hostname.clone().unwrap_or_default();
            by_host.insert(h, a.event.verdict);
        }
        assert_eq!(by_host.get("github.com"), Some(&Verdict::Deny));
        assert_eq!(by_host.get("example.com"), Some(&Verdict::Allow));
    }

    #[test]
    fn optimistically_deny_marks_matching_rows_by_ip() {
        let mut app = App::new("test".into());
        app.push(make_event(
            1,
            "curl",
            Some("github.com"),
            443,
            Verdict::Allow,
        ));
        let target = make_event(1, "curl", Some("github.com"), 443, Verdict::Allow);
        app.optimistically_deny(&target, DenyRuleKind::Ip);
        assert_eq!(app.events[0].event.verdict, Verdict::Deny);
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

    #[test]
    fn rule_msg_picks_up_event_fields() {
        let ev = make_event(7, "curl", Some("github.com"), 443, Verdict::Allow);
        let msg = rule_msg(&ev, DenyRuleKind::Both);
        match msg {
            ClientMessage::CreateDenyRule {
                exe_path,
                hostname,
                dest_ip,
                dport,
                by,
            } => {
                assert_eq!(exe_path.as_deref(), Some("/usr/bin/curl"));
                assert_eq!(hostname.as_deref(), Some("github.com"));
                assert!(dest_ip.is_some());
                assert_eq!(dport, 443);
                assert_eq!(by, DenyRuleKind::Both);
            }
            _ => panic!("expected CreateDenyRule"),
        }
    }

    #[test]
    fn set_rules_clamps_selection() {
        let mut app = App::new("test".into());
        app.set_rules(vec![
            rule_info("a", true),
            rule_info("b", false),
            rule_info("c", true),
        ]);
        app.rules_state.select(Some(2));
        // Shrinking the list must not leave a dangling selection.
        app.set_rules(vec![rule_info("a", true)]);
        assert_eq!(app.rules_state.selected(), Some(0));
        app.set_rules(vec![]);
        assert_eq!(app.rules_state.selected(), None);
    }

    #[test]
    fn rules_scroll_clamps_to_bounds() {
        let mut app = App::new("test".into());
        app.set_rules(vec![rule_info("a", true), rule_info("b", false)]);
        app.rules_state.select(Some(0));
        app.rules_scroll(-1);
        assert_eq!(app.rules_state.selected(), Some(0));
        app.rules_scroll(5);
        assert_eq!(app.rules_state.selected(), Some(1));
    }

    #[test]
    fn switch_to_requests_view_data() {
        let mut app = App::new("test".into());
        assert!(matches!(
            app.switch_to(View::Rules),
            InputAction::Send(ClientMessage::ListRules)
        ));
        assert_eq!(app.view, View::Rules);
        assert!(matches!(
            app.switch_to(View::Stats),
            InputAction::Send(ClientMessage::GetStats)
        ));
        assert!(matches!(app.switch_to(View::Live), InputAction::Nothing));
    }

    #[test]
    fn rules_toggle_sends_inverted_enabled() {
        let mut app = App::new("test".into());
        app.view = View::Rules;
        app.set_rules(vec![rule_info("block-dc", true)]);
        app.rules_state.select(Some(0));
        let key = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE);
        match handle_rules_input(key, &mut app) {
            InputAction::Send(ClientMessage::SetRuleEnabled { id, enabled }) => {
                assert_eq!(id, "block-dc");
                assert!(!enabled);
            }
            _ => panic!("expected SetRuleEnabled"),
        }
    }

    #[test]
    fn rules_edit_returns_path() {
        let mut app = App::new("test".into());
        app.view = View::Rules;
        app.set_rules(vec![rule_info("block-dc", true)]);
        app.rules_state.select(Some(0));
        let key = KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE);
        match handle_rules_input(key, &mut app) {
            InputAction::EditRule(p) => assert!(p.ends_with("block-dc.toml")),
            _ => panic!("expected EditRule"),
        }
    }
}
