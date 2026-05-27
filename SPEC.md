# dadophoros

> *δᾳδοφόρος — the torchbearer at Eleusis, who carried the light through
> the procession so others could see where they were going.*

An eBPF-based outbound connection observer and policy engine for Linux.
Watches outbound socket activity (`connect()` for TCP/connected UDP and
`sendmsg`/`sendto` for unconnected UDP), attributes it to a process and a
destination domain, displays it in a TUI, and (eventually) enforces
allow-list policies in-kernel.

## Goals

1. **Casual observability.** Leave the tool running and at any moment see
   what your machine is contacting and which process is responsible.
   Useful for spotting malware C2, errant telemetry, unexpected behavior
   from packages you just installed.
2. **Allow-list enforcement.** Configure a default-deny policy and an
   explicit allow-list of (process, domain) pairs. Block everything else
   in-kernel via the cgroup connect/sendmsg hooks' verdict return.

The two goals share most of an implementation. v1 focuses on goal 1;
goal 2 is staged in deliberately once observation is solid.

## Non-goals

- **TLS interception or payload inspection.** No MITM, no decryption.
  If you want request URLs and bodies, layer `mitmproxy` on top.
- **Cross-platform.** Linux only. eBPF and cgroup v2 required.
- **Container orchestration integration.** No Kubernetes-aware policy,
  no per-container rules beyond what comes free from cgroup-aware hooks.
- **A replacement for OpenSnitch.** Adjacent, opinionated, in Rust, with
  a TUI-first interaction model. Different tool.

## Architectural decisions (settled — do not relitigate)

- **Language: Rust everywhere.** Userspace daemon, kernel-side eBPF
  programs, TUI client.
- **eBPF library: Aya.** Not libbpf-rs. The reason is build-time simplicity
  (no C toolchain dependency) and the pure-Rust eBPF program path.
- **Primary interception: `cgroup/connect4` and `cgroup/connect6` for TCP
  and connected UDP; `cgroup/sendmsg4` and `cgroup/sendmsg6` for
  unconnected UDP egress.** Attached to the root cgroup at
  `/sys/fs/cgroup`. Verdict returned directly from the kernel-side
  program. Events from the sendmsg hooks are deduplicated in userspace by
  `FlowKey`, so a UDP socket that is both `connect()`'d and used with
  `sendmsg` produces only one event per flow. Not NFQUEUE.
- **Event transport: BPF ringbuf.** Not perf event array. Kernel 5.8+ only.
- **Process attribution: `bpf_get_current_pid_tgid()` in the connect and
  sendmsg hooks, enriched by `sys_enter_execve` and `sched_process_fork`
  tracepoints that populate a `pid → ProcessInfo` map.** Not `/proc`
  walking from userspace (except for a one-shot backfill at startup).
- **DNS correlation: userspace, sniffing via `tc/egress` and `tc/ingress`
  programs filtering UDP/53 and TCP/53, parsed with `hickory-proto`.**
  Programs are attached to `lo` (to catch stub-resolver traffic such as
  systemd-resolved on `127.0.0.53`) and to every UP non-virtual
  interface, refreshed on link state changes via an rtnetlink listener.
  Cache lives in userspace, keyed by destination IP, with TTL eviction.
- **Verdict cache: `LruHashMap<FlowKey, Verdict>` in the kernel.**
  Cgroup hook checks cache; cache miss emits event and (in observe mode)
  allows. In enforce mode, cache miss returns deny synchronously (see
  "Enforcement model" below).
- **Enforcement model: synchronous deny + cache + retry.** cgroup/connect
  and cgroup/sendmsg hooks cannot sleep. In enforce mode, a cache miss
  returns deny — the syscall fails with `EPERM` — the daemon emits a
  `PendingVerdict` to subscribed TUIs, and the user's decision is written
  to `VERDICT_CACHE` for next time. The user re-runs the action to test
  the new verdict. There is no transparent retry; applications that don't
  retry on `EPERM` will simply fail until the verdict is cached and the
  action is rerun. This is the OpenSnitch UX model; document it as the
  intended behavior, not a limitation.
- **IPC: Unix socket with length-prefixed binary protocol.** Not gRPC.
  `postcard` serialization (stable wire format, no_std-compatible).
  Daemon owns the socket at `/run/dadophoros.sock`.
- **TUI: `ratatui` + `crossterm`.** Separate binary from the daemon.
- **Rule storage: JSON or TOML files under `/etc/dadophoros/rules.d/`,
  one rule per file.** Grep-able, diff-able, version-controllable.
  Watched via `notify` for live reload.
- **Minimum kernel: 5.15.** Ubuntu 22.04 baseline. Document it; don't
  feature-detect downward.
- **CO-RE via BTF.** Compile-once-run-everywhere; load `vmlinux` BTF
  from `/sys/kernel/btf/vmlinux`. No per-kernel builds.

## Repository layout

```
dadophoros/
├── Cargo.toml                  # workspace root (excludes dadophoros-ebpf)
├── README.md
├── LICENSE                     # MIT OR Apache-2.0 dual
├── docs/
│   ├── architecture.md
│   ├── building.md
│   └── rules.md
├── xtask/                      # build orchestration
│   ├── Cargo.toml
│   └── src/main.rs             # invokes nightly cargo for dadophoros-ebpf
├── dadophoros-common/          # shared types between kernel + userspace
│   └── src/lib.rs
├── dadophoros-ebpf/            # kernel-side BPF programs (built via xtask)
│   ├── .cargo/config.toml      # pins target to bpfel-unknown-none
│   ├── Cargo.toml
│   └── src/main.rs
├── dadophoros-daemon/          # privileged userspace daemon (`dadophorosd`)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── loader.rs           # eBPF program load + attach
│       ├── events.rs           # ringbuf drain, event enrichment
│       ├── dns.rs              # DNS cache and tc-program management
│       ├── process.rs          # ProcessInfo map management
│       ├── rules.rs            # rule loading, matching, watching
│       ├── verdict.rs          # verdict cache writes, pending verdicts
│       └── ipc.rs              # Unix socket server, broadcast channel
├── dadophoros-tui/             # TUI client (`dadophoros`)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── app.rs              # state, event loop
│       ├── ipc.rs              # client side of the IPC protocol
│       ├── views/
│       │   ├── live.rs         # live event stream
│       │   ├── pending.rs      # pending verdict prompts
│       │   ├── rules.rs        # browse/edit rules
│       │   └── stats.rs        # aggregates
│       └── widgets/            # reusable ratatui widgets
└── dadophoros-proto/           # shared IPC types (used by daemon + tui)
    ├── Cargo.toml
    └── src/lib.rs
```

Binary names: `dadophorosd` (daemon), `dadophoros` (TUI). Crate names match.

## Shared types (`dadophoros-common`)

`#[repr(C)]` types passed between kernel and userspace via maps and ringbuf.
Must be `no_std`-compatible by default; a `user` feature gates
`bytemuck::Pod` derives that need std.

```rust
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectEvent {
    pub pid: u32,
    pub uid: u32,
    pub daddr_v4: u32,             // network byte order
    pub daddr_v6: [u8; 16],
    pub dport: u16,                // host byte order
    pub family: u8,                // 4 or 6
    pub _pad: u8,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub start_ns: u64,
    pub exe_inode: u64,            // for cheap identity comparison
    pub comm: [u8; 16],
    // exe path is stored separately in userspace; too variable-length for BPF
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub pid: u32,
    pub _pad0: u32,                // align start_ns to 8 bytes
    pub start_ns: u64,             // task->start_boottime, via CO-RE; defeats PID reuse
    pub daddr_v4: u32,
    pub daddr_v6: [u8; 16],
    pub dport: u16,
    pub family: u8,
    pub _pad: u8,
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow = 1,
    Deny = 0,
    Pending = 2,
}
```

Include `const _: () = assert!(size_of::<ConnectEvent>() == 48);` style
asserts on every shared struct to catch silent layout drift.

## Kernel-side programs (`dadophoros-ebpf`)

Nine programs in seven items (grouped where they share logic), all in
the same eBPF object:

1. **`cgroup/connect4`** — fires on every IPv4 `connect()` (TCP and
   connected UDP). Builds a `FlowKey` — reading `start_ns` from
   `task_struct->start_boottime` via CO-RE so PID reuse cannot alias —
   checks `VERDICT_CACHE`, emits a `ConnectEvent` to `EVENTS` ringbuf
   if uncached. Returns 1 (allow) or 0 (deny) based on cache.
2. **`cgroup/connect6`** — IPv6 equivalent. Shares logic via inlined helper.
3. **`cgroup/sendmsg4` + `cgroup/sendmsg6`** — fire on UDP `sendto`/
   `sendmsg` to unconnected sockets. Same `FlowKey` construction and
   cache check as connect4/6. Required to cover QUIC, mDNS, NTP, and
   other UDP egress that bypasses `connect()`. Userspace deduplicates
   against the connect path by `FlowKey`.
4. **`tracepoint/syscalls/sys_enter_execve`** — populates `PROCESS_INFO`
   with the new process's metadata. Reads exe path via the filename
   argument; truncates to a fixed buffer.
5. **`tracepoint/sched/sched_process_fork`** — copies
   `PROCESS_INFO[parent_pid]` into `PROCESS_INFO[child_pid]`. Required
   so forked workers that `connect()` without `execve` are attributed
   to their parent's exe path rather than left unresolved.
6. **`tracepoint/sched/sched_process_exit`** — marks `PROCESS_INFO`
   entries for deletion with a grace period (don't delete immediately;
   short-lived processes can have pending events in flight).
7. **`tc/egress` + `tc/ingress`** — clone UDP/53 and TCP/53 packets
   into a `DNS_EVENTS` ringbuf for userspace parsing. Attached to `lo`
   (to catch stub-resolver traffic such as systemd-resolved on
   `127.0.0.53`) and to every UP non-virtual interface, refreshed on
   link state changes via an rtnetlink listener in the daemon.

Maps:

| Name             | Type           | Key            | Value           | Size       |
|------------------|----------------|----------------|-----------------|------------|
| `EVENTS`         | RingBuf        | —              | ConnectEvent    | 256 KiB    |
| `DNS_EVENTS`     | RingBuf        | —              | raw DNS packet  | 256 KiB    |
| `VERDICT_CACHE`  | LruHashMap     | FlowKey        | u8 (Verdict)    | 65,536     |
| `PROCESS_INFO`   | HashMap        | u32 (pid)      | ProcessInfo     | 32,768     |

The verifier will reject anything it can't prove safe. Keep loops
bounded and constant; keep map lookups guarded; use the `?` operator
sparingly because each unwind path multiplies verification cost.

## Userspace daemon (`dadophorosd`)

### Process model

Single async runtime (tokio). Top-level tasks:

- **Loader task** — runs at startup, attaches all programs, owns the
  `Ebpf` handle for the program's lifetime.
- **Event drain task** — `AsyncFd`-wrapped ringbuf, drains
  `ConnectEvent`s, enriches with hostname (DNS cache lookup) and exe
  path (`PROCESS_INFO` map lookup), matches against rules, writes
  verdict to `VERDICT_CACHE`, publishes enriched event to broadcast
  channel.
- **DNS drain task** — same pattern for `DNS_EVENTS`, parses with
  `hickory-proto`, updates the userspace DNS cache.
- **Rule watcher task** — `notify` watcher on `/etc/dadophoros/rules.d/`,
  reloads `Vec<Rule>` on changes, swaps via `ArcSwap` so the event
  drain task always sees a consistent ruleset.
- **IPC server task** — accepts Unix socket connections, spawns a
  per-client task that subscribes to the broadcast channel and
  forwards events as IPC frames.
- **Process info backfill task** — runs once at startup, walks `/proc`,
  populates `PROCESS_INFO` for every existing PID. The execve
  tracepoint takes over from there.
- **DNS cache eviction task** — `tokio::time::interval(1s)`, sweeps
  expired entries.

### Rule schema

```toml
# /etc/dadophoros/rules.d/01-allow-package-managers.toml
id = "8c2a..."           # UUID, stable
priority = 100           # lower = higher priority
enabled = true
action = "allow"         # "allow" | "deny"
duration = "persistent"  # "once" | "session" | "persistent"

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
```

Multiple `[[match]]` entries within a rule are AND-ed. Multiple rules
are walked in priority order; first match wins. Default action when no
rule matches is configured globally: `mode = "observe" | "enforce"`.

### IPC protocol

Length-prefixed (4-byte big-endian length, then postcard-serialized
`Message`). Bidirectional. Types live in `dadophoros-proto`:

```rust
pub enum ClientMessage {
    Subscribe { filter: Option<EventFilter> },
    Unsubscribe,
    ListRules,
    GetRule(Uuid),
    PutRule(Rule),
    DeleteRule(Uuid),
    DecideVerdict { flow: FlowKey, verdict: Verdict, persist: bool },
    GetStats,
}

pub enum ServerMessage {
    Event(EnrichedEvent),
    PendingVerdict { flow: FlowKey, event: EnrichedEvent },
    Rules(Vec<Rule>),
    Rule(Option<Rule>),
    Ok,
    Error(String),
    Stats(Stats),
}

pub struct EnrichedEvent {
    pub ts: SystemTime,
    pub raw: ConnectEvent,
    pub exe_path: Option<String>,
    pub hostname: Option<String>,
    pub verdict: Verdict,
    pub matched_rule: Option<Uuid>,
}
```

Multiple concurrent clients supported via `tokio::sync::broadcast`.

## TUI (`dadophoros`)

Four primary views, switched via tab keys:

1. **Live** (default) — scrolling table of recent events. Columns:
   time, pid, comm, exe, host (or IP), port, verdict, rule. Filterable
   by process or domain via `/` prompt. Selecting a row and pressing
   `a` / `d` creates an allow/deny rule for that flow.
2. **Pending** — only populated in enforce mode. Lists connections
   awaiting user verdict. Hotkeys: `a` allow once, `A` allow always,
   `d` deny once, `D` deny always, `i` show details.
3. **Rules** — browse rules in priority order. `e` opens the rule file
   in `$EDITOR` (the daemon picks up the change via `notify`).
4. **Stats** — top processes by connection count, top hosts, blocked
   count, sparkline of activity over time.

State management: single `App` struct, `tokio::select!` over crossterm
input, IPC messages, and a 100ms redraw ticker. Use `ratatui::Terminal`
in alternate screen mode; restore on panic via a custom panic hook.

## Staging plan

Each step ships something useful. Don't skip ahead — the architecture
benefits from real traffic patterns at each layer.

### Step 1 — Minimal observation

`dadophoros-common`, `dadophoros-ebpf` with `connect4`, `connect6`,
`sendmsg4`, `sendmsg6` and the `EVENTS` ringbuf, `dadophoros-daemon`
that loads the program, attaches to root cgroup, drains events, prints
to stdout. No DNS, no enrichment beyond `comm`, no rules, no TUI. (A
connect-only prototype already exists outside this repo; this step
ports it in and adds the sendmsg hooks alongside.)

Acceptance: `sudo dadophorosd` prints lines like
`pid=12453 uid=1000 comm=curl -> 140.82.121.4:443` for every outbound
TCP/connected-UDP connection and every UDP `sendto`/`sendmsg` on the
machine.

### Step 2 — Process attribution

Add `sys_enter_execve`, `sched_process_fork`, and `sched_process_exit`
tracepoints, `PROCESS_INFO` map, `/proc` backfill on startup. Enrich
events in userspace with exe path. Output gains the
`exe=/usr/bin/curl` column.

Acceptance: connections from short-lived processes (e.g.
`bash -c 'curl example.com'`) show the correct exe path, not just
the bash invocation. Fork-without-exec children (e.g. a worker pool
in a long-running Python daemon) are attributed to the parent's
exe path, not left unresolved.

### Step 3 — DNS correlation

`tc/egress` + `tc/ingress` programs filtering port 53. `DNS_EVENTS`
ringbuf. Userspace DNS cache with TTL eviction. Events gain
`host=github.com` when the DNS cache has a match.

Acceptance: a `curl https://github.com` shows the hostname in the
output, not just the resolved IP. DNS via systemd-resolved
(`127.0.0.53`) is also resolved to hostnames.

### Step 4 — Rules and verdict matching (observe mode)

Rule loader, `notify` watcher, in-memory match. Daemon writes verdicts
to `VERDICT_CACHE` but kernel still always allows — we're just logging
what *would have* been blocked. Output gains `verdict=allow` /
`verdict=deny(matched)` column.

Acceptance: a deny rule for `*.doubleclick.net` shows the matching
events as `verdict=deny` in the output, but connections still succeed.

### Step 5 — IPC + TUI shell

`dadophoros-proto`, IPC server in daemon, TUI client with just the Live
view. Daemon still prints to stdout for now; TUI connects and shows
the same stream.

Acceptance: `dadophoros` shows the same events as the daemon's stdout, in a
scrollable table, with filtering.

### Step 6 — Enforcement

Flip a config flag and the cgroup hooks start returning 0 for cached
denies *and* for cache misses (default-deny on unknowns). Add the
pending-verdict flow: cache miss in enforce mode emits event and
returns deny, daemon sends `PendingVerdict` to subscribed TUIs, user
decides, TUI sends `DecideVerdict`, daemon writes the verdict to
`VERDICT_CACHE`. The user then re-runs the action so the cached
verdict applies. There is no in-kernel wait and no transparent retry;
the original `connect()`/`sendmsg()` has already failed with `EPERM`.

Acceptance: a deny rule actually blocks the connection. For unseen
flows, an interactive prompt in the TUI lets the user choose
allow/deny; the decision is cached, and re-running the action
succeeds (allow) or continues to fail (deny). Note: the user must
re-run; there is no transparent retry of the original syscall.

### Step 7 — Rules view + stats

Rules view in TUI (browse, enable/disable, edit in `$EDITOR`).
Stats view with the aggregates. Persist session rules to disk on
daemon shutdown if the user opts in.

### Step 8 — Polish

Binary hashing of exe on first sight, hash-change detection across
sessions, configurable log destination, systemd unit file, packaging
hints for Debian/Fedora/Arch, install script. Documentation pass.

## Constraints and conventions

- **MSRV: stable Rust for daemon and TUI, nightly for the eBPF crate.**
  The eBPF crate needs `-Z build-std=core`; everything else builds on
  stable. Document the nightly requirement only for `dadophoros-ebpf`.
- **No `unwrap()` in long-running paths.** `expect()` is acceptable
  at startup for unrecoverable conditions with a clear message.
  Event-loop code uses `?` and logs errors via `tracing`.
- **`tracing` everywhere, never `println!` except in the step-1 stdout
  path which gets removed in step 5.**
- **Async via tokio.** Spawn long-lived tasks with `tokio::spawn`;
  use `JoinSet` when tasks need to be cancelled together.
- **State sharing across tasks: `Arc<ArcSwap<T>>` for read-mostly state
  (rules, config), `tokio::sync::RwLock` for read-heavy mutable state
  (DNS cache), `tokio::sync::broadcast` for fan-out (events to TUI
  subscribers).** Avoid `Mutex` on hot paths.
- **Error type: `anyhow::Error` for application errors at task
  boundaries; `thiserror`-derived enums for library-style errors that
  callers need to match on (`RuleError`, `IpcError`).**
- **Tests: unit tests inline in modules. Integration tests under
  `tests/` in each crate. eBPF programs tested via `aya`'s
  `EbpfLoader::load_file` against a goldenfile of expected map
  contents after a synthetic event sequence.**
- **No `.unwrap()` on lock acquisition in async code; always `?` or
  handle the poisoned case explicitly.**
- **Logging conventions: `tracing::info!` for steady-state events
  worth seeing once per occurrence, `debug!` for per-event chatter,
  `warn!` for recoverable anomalies, `error!` for things that
  should page someone (which, for a local tool, just means a
  prominent log line).**

## Build, packaging, install

### Build prerequisites

```sh
# Nightly toolchain for the eBPF crate
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
rustup target add bpfel-unknown-none --toolchain nightly

# bpf-linker handles the BPF-target link step
cargo install bpf-linker
```

### Build

```sh
cargo xtask build-ebpf --release
cargo build --release
```

`cargo xtask build-ebpf` invokes the nightly toolchain to compile
`dadophoros-ebpf` for `bpfel-unknown-none` and writes the ELF where
the daemon's `include_bytes!` expects it. `cargo build --release`
then builds the daemon and TUI on stable. `cargo xtask build` chains
both. The `dadophoros-ebpf` crate is intentionally excluded from the
workspace `members` so the stable parent build does not try to
compile it with the wrong target.

### Runtime requirements

- Linux kernel ≥ 5.15
- cgroup v2 mounted at `/sys/fs/cgroup`
- BTF available at `/sys/kernel/btf/vmlinux`
- Capabilities for the daemon: `CAP_BPF`, `CAP_NET_ADMIN`,
  `CAP_SYS_RESOURCE` (for memlock bump on old systems).
  Not full root — install as a systemd service with
  `AmbientCapabilities=`.

### systemd unit (shipped)

```ini
[Unit]
Description=dadophoros — outbound connection observer
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/dadophorosd
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/dadophoros /run
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## What to defer

Things that will tempt you but should not land in v1:

- **Web UI.** TUI only. A web UI is a much bigger surface area (auth,
  CSRF, packaging static assets) for marginal benefit on a local tool.
- **Remote daemon access.** Local Unix socket only. Don't expose IPC
  over TCP; if a user wants remote, they can SSH and run `dadophoros` there.
- **Per-container rules / Kubernetes integration.** The cgroup hook
  gives container awareness for free at the kernel level, but the
  rule schema doesn't need first-class container concepts yet.
- **eBPF program updates without daemon restart.** Possible with
  `bpf_link` re-attach but adds complexity. Restart is fine.
- **DoH/DoT awareness.** The DNS sniffer sees plain UDP/53 and
  TCP/53. Document that DoH bypasses the hostname cache; rules
  against bare IPs still work; in step 8 consider hooking
  `getaddrinfo` via uprobe as a supplement.
- **Custom kernels.** Target stock distro kernels. Don't add
  workarounds for unusual configurations until someone asks.

## Naming

The project name is `dadophoros`. Crate names use `dadophoros-` prefix.
Binary names are: `dadophorosd` (daemon), `dadophoros` (TUI). Config
goes in `/etc/dadophoros/`; runtime state in `/run/dadophoros/`; logs
follow the system convention via `journald` when run under systemd.

The full name appears in `--version` output, the systemd unit
description, and documentation headers. Code identifiers use the short
forms freely.