//! Session-wide aggregate counters for the TUI's Stats view.
//!
//! The main loop owns a single [`Accumulator`], feeds it every enriched event,
//! and advances its activity ring once a second. A cheap [`Accumulator::snapshot`]
//! is published over a `watch` channel so any number of IPC clients can read the
//! latest figures without touching the hot path.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};

use dadophoros_proto::{EnrichedEvent, LabeledCount, Stats, Verdict};

/// Seconds of activity history retained for the sparkline.
const ACTIVITY_BUCKETS: usize = 120;
/// How many processes/hosts the snapshot reports.
const TOP_N: usize = 10;

#[derive(Debug)]
pub struct Accumulator {
    total_events: u64,
    total_allowed: u64,
    total_denied: u64,
    per_process: HashMap<String, u64>,
    per_host: HashMap<String, u64>,
    /// Per-second connection counts, oldest at the front. The back bucket is
    /// the second currently filling.
    activity: VecDeque<u64>,
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Accumulator {
    pub fn new() -> Self {
        let mut activity = VecDeque::with_capacity(ACTIVITY_BUCKETS);
        activity.resize(ACTIVITY_BUCKETS, 0);
        Self {
            total_events: 0,
            total_allowed: 0,
            total_denied: 0,
            per_process: HashMap::new(),
            per_host: HashMap::new(),
            activity,
        }
    }

    pub fn record(&mut self, ev: &EnrichedEvent) {
        self.total_events += 1;
        match ev.verdict {
            Verdict::Allow => self.total_allowed += 1,
            Verdict::Deny => self.total_denied += 1,
        }
        let proc = ev
            .exe_path
            .clone()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| ev.comm.clone());
        *self.per_process.entry(proc).or_insert(0) += 1;
        *self.per_host.entry(host_or_ip(ev)).or_insert(0) += 1;
        if let Some(last) = self.activity.back_mut() {
            *last += 1;
        }
    }

    /// Advance the activity ring by one second. Call on a 1 Hz tick.
    pub fn tick(&mut self) {
        self.activity.push_back(0);
        while self.activity.len() > ACTIVITY_BUCKETS {
            self.activity.pop_front();
        }
    }

    pub fn snapshot(&self) -> Stats {
        Stats {
            total_events: self.total_events,
            total_allowed: self.total_allowed,
            total_denied: self.total_denied,
            top_processes: top_n(&self.per_process),
            top_hosts: top_n(&self.per_host),
            activity: self.activity.iter().copied().collect(),
        }
    }
}

/// Highest-count entries, descending; ties broken by label for stable output.
fn top_n(map: &HashMap<String, u64>) -> Vec<LabeledCount> {
    let mut v: Vec<LabeledCount> = map
        .iter()
        .map(|(label, &count)| LabeledCount {
            label: label.clone(),
            count,
        })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.label.cmp(&b.label)));
    v.truncate(TOP_N);
    v
}

/// Display key for the per-host table: hostname if known, else the bare IP.
fn host_or_ip(ev: &EnrichedEvent) -> String {
    if let Some(h) = &ev.hostname {
        if !h.is_empty() {
            return h.clone();
        }
    }
    if ev.family == 4 {
        Ipv4Addr::from(ev.daddr_v4.to_ne_bytes()).to_string()
    } else {
        Ipv6Addr::from(ev.daddr_v6).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(comm: &str, exe: Option<&str>, host: Option<&str>, verdict: Verdict) -> EnrichedEvent {
        EnrichedEvent {
            ts_unix_ns: 0,
            pid: 1,
            uid: 1000,
            comm: comm.to_string(),
            exe_path: exe.map(str::to_owned),
            family: 4,
            daddr_v4: 0x04030201, // 1.2.3.4 in network order
            daddr_v6: [0; 16],
            dport: 443,
            hostname: host.map(str::to_owned),
            verdict,
            matched_rule: None,
        }
    }

    #[test]
    fn totals_split_allow_and_deny() {
        let mut acc = Accumulator::new();
        acc.record(&ev(
            "curl",
            Some("/usr/bin/curl"),
            Some("github.com"),
            Verdict::Allow,
        ));
        acc.record(&ev(
            "curl",
            Some("/usr/bin/curl"),
            Some("github.com"),
            Verdict::Deny,
        ));
        acc.record(&ev(
            "curl",
            Some("/usr/bin/curl"),
            Some("github.com"),
            Verdict::Allow,
        ));
        let s = acc.snapshot();
        assert_eq!(s.total_events, 3);
        assert_eq!(s.total_allowed, 2);
        assert_eq!(s.total_denied, 1);
    }

    #[test]
    fn top_processes_ranked_by_count() {
        let mut acc = Accumulator::new();
        for _ in 0..3 {
            acc.record(&ev("curl", Some("/usr/bin/curl"), None, Verdict::Allow));
        }
        acc.record(&ev("wget", Some("/usr/bin/wget"), None, Verdict::Allow));
        let s = acc.snapshot();
        assert_eq!(s.top_processes[0].label, "/usr/bin/curl");
        assert_eq!(s.top_processes[0].count, 3);
        assert_eq!(s.top_processes[1].label, "/usr/bin/wget");
    }

    #[test]
    fn process_falls_back_to_comm_without_exe() {
        let mut acc = Accumulator::new();
        acc.record(&ev("mystery", None, None, Verdict::Allow));
        assert_eq!(acc.snapshot().top_processes[0].label, "mystery");
    }

    #[test]
    fn host_falls_back_to_ip() {
        let mut acc = Accumulator::new();
        acc.record(&ev("curl", Some("/usr/bin/curl"), None, Verdict::Allow));
        assert_eq!(acc.snapshot().top_hosts[0].label, "1.2.3.4");
    }

    #[test]
    fn activity_lands_in_current_bucket_then_rotates() {
        let mut acc = Accumulator::new();
        acc.record(&ev("curl", None, Some("h"), Verdict::Allow));
        acc.record(&ev("curl", None, Some("h"), Verdict::Allow));
        let before = acc.snapshot().activity;
        assert_eq!(*before.last().unwrap(), 2);
        acc.tick();
        let after = acc.snapshot().activity;
        // New current bucket is empty; the 2 slid one slot back.
        assert_eq!(*after.last().unwrap(), 0);
        assert_eq!(after[after.len() - 2], 2);
        // Ring stays a fixed width.
        assert_eq!(after.len(), ACTIVITY_BUCKETS);
    }
}
