# dadophoros

> *δᾳδοφόρος — the torchbearer at Eleusis, who carried the light through
> the procession so others could see where they were going.*

A Linux-only outbound-connection observer with a TUI front end. Watches every
outbound `connect()` and unconnected UDP `sendmsg()` on the host, attributes
each to a process and (when possible) a resolved hostname, and lets you write
deny rules that block matching flows in-kernel. The current design philosophy is *casual observability first*: by default
every flow is allowed and logged.

## What you see

Two binaries. One needs root, one doesn't.

```sh
sudo dadophorosd      # privileged daemon
dadophoros            # unprivileged TUI client
```

The TUI shows a live table of `(PID, COMM, EXE, HOST, PORT, VERDICT, RULE)`.
Repeated identical flows collapse into a single row with a `×N` counter.
`/` filters by substring. `d` on a selected row opens a modal that turns
that row's facts into a deny rule, written as a TOML file under
`/etc/dadophoros/rules.d/` and reloaded automatically.

## Data flow

```
┌─────────────┐  EVENTS / DNS_EVENTS   ┌────────────────┐  ┌──────────┐
│ kernel BPF  │  ────  ringbufs  ────► │ dadophorosd    │  │ TOML     │
│ programs    │                        │ (userspace)    │ ◄┤ rules.d/ │
│             │ ◄──── VERDICT_CACHE ── │                │  └──────────┘
└─────────────┘    (deny flowkeys)     │ DNS cache,     │      ▲
       ▲                               │ rules engine,  │      │ writes new
       │ loaded + attached             │ /proc lookup,  │      │ rule files
       │ at startup                    │ IPC server     │      │
       │                               └────────────────┘      │
                                              │                │
                                              │ Unix socket    │
                                              ▼                │
                                       ┌──────────────┐        │
                                       │ dadophoros   │────────┘
                                       │ (TUI)        │ CreateDenyRule
                                       └──────────────┘
```

Two ringbufs run kernel → userspace:
- `EVENTS` — every outbound flow seen by a cgroup connect/sendmsg hook
- `DNS_EVENTS` — every plaintext DNS packet seen by tc filters on `lo` and
  the physical interfaces (UDP/53 only at the moment)

One LRU hashmap goes userspace → kernel:
- `VERDICT_CACHE` — the daemon inserts a `FlowKey` here whenever a deny
  rule matches. The kernel hook checks this map before emitting and returns
  EPERM on hit, with no further round trip to userspace.

## eBPF

eBPF programs are typically compiled with LLVM/Clang into eBPF bytecode. This is a generic, highly optimized instruction set that the kernel understands. When a user-space application loads the bytecode into the kernel (via the bpf() system call), the kernel passes it through the eBPF Verifier. Once verified, the kernel uses a Just-In-Time (JIT) Compiler to translate the generic eBPF bytecode into the native machine code of your specific CPU (e.g., x86_64, ARM64). This means eBPF runs at native hardware speeds, with zero interpretation overhead. An eBPF program is event-driven. You attach ("hook") it to a specific point in the kernel.

Because eBPF programs live in the isolated kernel space, they need a way to send data back to user-space applications. They do this using eBPF Maps. Maps are efficient key-value data structures stored in the kernel. Both the eBPF program (in the kernel) and the controller application (in user-space) can read and write to these maps simultaneously. Common map types include hash tables, arrays, and ring buffers (used for streaming perf events).



## Workspace layout

The repo is a Cargo workspace with five member crates plus a build
orchestrator. The eBPF crate is intentionally **excluded** from the workspace
because it targets a different triple with a different toolchain.

| Crate                | Role                                   | `std`?   |
| ---                  | ---                                    | ---      |
| `dadophoros-common`  | shared types (kernel ↔ userspace ABI)  | `no_std` |
| `dadophoros-ebpf`    | kernel-side BPF programs               | `no_std` |
| `dadophoros-daemon`  | privileged userspace daemon            | std      |
| `dadophoros-proto`   | daemon ↔ TUI wire protocol             | std      |
| `dadophoros-tui`     | unprivileged TUI client                | std      |
| `xtask`              | build orchestration                    | std      |

### `dadophoros-common`

A tiny `no_std` crate holding the `#[repr(C)]` structs that cross the kernel
boundary byte-for-byte: `ConnectEvent`, `DnsEvent`, `ProcessInfo`,
`FlowKey`, `Verdict`. Each carries a
`const _: () = assert!(size_of::<T>() == N)` so a stray field reordering
fails at compile time on both sides.

A `user` feature gates the std-only derives (`bytemuck::Pod`, `aya::Pod`)
so the same crate links cleanly into both the eBPF object (`no_std`) and
the daemon (where the `Pod` markers are required to construct typed map
handles).

### `dadophoros-ebpf`

The kernel side. Compiles to a single Executable and Linkable Format (ELF) object for `bpfel-unknown-none`
using nightly Rust + `-Z build-std=core` + `bpf-linker`. Excluded from the
workspace `members` list so the stable parent build never tries to compile
it; only `cargo xtask build-ebpf` ever touches it.

Programs in the object:

- **`cgroup/connect4`, `cgroup/connect6`** — fire on every outbound TCP and
  connected UDP `connect()`. Build a `FlowKey` from the destination, look
  it up in `VERDICT_CACHE`; if found, return 0 (deny, no event). Otherwise
  emit a `ConnectEvent` to the `EVENTS` ringbuf and return 1 (allow).
- **`cgroup/sendmsg4`, `cgroup/sendmsg6`** — same logic for unconnected UDP
  `sendto`/`sendmsg`. Also skips loopback destinations (so we don't see
  every systemd-resolved reply to a local ephemeral port).
- **`tracepoint/syscalls/sys_enter_execve`** — populates `PROCESS_INFO` with
  the executing task's metadata.
- **`tracepoint/sched/sched_process_fork`** — copies `PROCESS_INFO` from
  parent to child so forked workers that never `execve` still attribute to
  their parent's exe path.
- **`tracepoint/sched/sched_process_exit`** — removes the entry.
- **`tc/egress` + `tc/ingress`** (`dns_egress`, `dns_ingress`) — attached
  by the daemon to `lo` and every UP non-virtual interface; copy UDP/53
  payloads into the `DNS_EVENTS` ringbuf for userspace parsing.

The resulting ELF is embedded into the daemon binary at compile time via
`include_bytes_aligned!`, so deployment is one binary; there's no separate
`.o` file to install.

### `dadophoros-daemon` (binary: `dadophorosd`)

The privileged process. Needs `CAP_BPF` + `CAP_NET_ADMIN` (or root). At
startup it:

1. Loads the embedded eBPF object and attaches every program to its proper
   hook point (`/sys/fs/cgroup` for the cgroup hooks; every UP interface
   for tc; the named tracepoints for the rest).
2. Walks `/proc` to backfill exe paths for processes that already exist.
3. Loads rules from `/etc/dadophoros/rules.d/*.toml` and starts a `notify`
   watcher on the directory.
4. Binds `/run/dadophoros.sock` (chmod 0666 so the unprivileged TUI can
   connect) and spawns the IPC server.

Then it enters a tokio `select!` loop multiplexing:

- **EVENTS ringbuf drains** → enrich each `ConnectEvent` with exe path
  (from cached `/proc/<pid>/exe`) and hostname (from the DNS cache) →
  match against the rule set → if a deny rule fires, insert the FlowKey
  into `VERDICT_CACHE` so the kernel blocks the next attempt → broadcast a
  `ServerMessage::Event` to subscribed IPC clients.
- **DNS_EVENTS ringbuf drains** → parse with `hickory-proto` → populate a
  userspace `IpAddr → (hostname, expires_at)` cache used during event
  enrichment.
- **Filesystem notifications** → reload rules.
- **1 Hz tick** → evict expired DNS cache entries.

Module split:

- `main.rs` — startup, the main event loop, and all the small enrichment helpers
- `rules.rs` — TOML schema, file loader, and the
  `evaluate(rules, exe, host, ip, port)` matcher (priority-ordered, first match wins, `[[match]]` clauses AND-ed)
- `ipc.rs` — Unix socket server. Each per-client task `select!`s between
  incoming `ClientMessage`s and the outgoing broadcast stream. Also handles
  `CreateDenyRule` by writing a TOML file straight into the rules directory
  (the notify watcher reloads it automatically a few ms later).

### `dadophoros-proto`

The wire-protocol crate. Two halves:

1. The serde-derived message types: `ClientMessage` (`Subscribe`,
   `Unsubscribe`, `CreateDenyRule`), `ServerMessage` (`Hello`, `Event`,
   `Ok`, `Error`), `EnrichedEvent`, `EventFilter`, `Verdict`, `FlowKey`,
   `DenyRuleKind`.
2. A 4-byte big-endian length prefix + `postcard` framing layer
   (`read_message` / `write_message`) generic over any
   `tokio::io::AsyncRead`/`AsyncWrite`.

Why a separate crate? Both the daemon (server side) and the TUI (client
side) depend on this without depending on each other. Future clients (a
CLI, a metrics exporter, a desktop applet) would link against `proto` and
nothing else. Bumping `proto`'s version cleanly signals an IPC-breaking
change distinct from a daemon implementation bump.

### `dadophoros-tui` (binary: `dadophoros`)

Unprivileged client built on `ratatui` + `crossterm`. Connects to
`/run/dadophoros.sock`, sends `Subscribe`, then enters a `select!` loop
over the IPC reader, a `crossterm::event::EventStream`, and a 100 ms
redraw timer.

The view is a scrollable table with aggregation: identical
`(pid, comm, exe, host, port)` tuples collapse onto one row with a `×N`
count column whose verdict + matched-rule labels update in place. `/`
enters substring filter mode. `d` on the selected row opens a centered
modal:

```
┌─create deny rule─────────────────────┐
│ Selected: pid=12453 comm=curl        │
│           -> github.com:443          │
│                                      │
│ [h] deny by host (suffix github.com) │
│ [p] deny by process (exact …/curl)   │
│ [i] deny by IP (exact 140.82.114.4)  │
│ [b] deny by host AND process         │
│                                      │
│ Esc: cancel                          │
└──────────────────────────────────────┘
```

Picking one sends a `CreateDenyRule` to the daemon; the daemon writes
`auto-deny-<sanitized>-<ts>.toml` into the rules directory. The TUI also
**optimistically** marks every matching row red right then, so the user
sees instant feedback. The daemon's authoritative rule-id label arrives a
few ms later with the next real event for the flow.

### `xtask`

Tiny binary that orchestrates the eBPF build. The eBPF crate needs nightly
cargo, the `bpfel-unknown-none` target, `-Z build-std=core`, and
`bpf-linker` — none of which the stable parent build wants to deal with.
`cargo xtask build-ebpf` shells out a child cargo invocation in
`dadophoros-ebpf/` after **scrubbing `RUSTC`, `CARGO`, and
`RUSTUP_TOOLCHAIN`** from the env (the parent leaks these, and without
the scrub the child silently picks up stable and fails with "can't find
crate for `core`").

## Build

One-time prerequisites:

```sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

Then:

```sh
cargo xtask build-ebpf --release
cargo build --release
```

The first command produces `target/bpfel-unknown-none/release/dadophoros-ebpf`
(the BPF ELF). The second embeds that ELF into `target/release/dadophorosd`
and also produces `target/release/dadophoros`.

## Run

```sh
sudo target/release/dadophorosd       # one terminal
target/release/dadophoros             # another terminal, no sudo
```

In the TUI: `↑↓` scroll, `PgUp/PgDn` page, `Home`/`End` jump, `/` filter,
`d` deny-rule modal, `q` quit.

Rules live as TOML files under `/etc/dadophoros/rules.d/`. Manual example:

```toml
priority = 100
action = "deny"

[[match]]
type = "dest_host"
op = "suffix"
value = ".doubleclick.net"
```

Multiple `[[match]]` clauses within a rule are AND-ed. Multiple rule files
are walked in priority order; the first match wins. Supported match
fields: `process_path`, `dest_host`, `dest_ip`, `dest_port`. Supported
ops: `exact`, `prefix`, `suffix`, `contains`, `in`.

## Status

What works today:

- Per-process attribution for every outbound flow (TCP + connected and
  unconnected UDP)
- DNS hostname enrichment via plaintext UDP/53 sniffing on `lo` and every
  UP interface
- TOML deny rules with `process_path`, `dest_host`, `dest_ip`, and
  `dest_port` matchers, hot-reloaded on file changes
- Per-flow kernel-side deny enforcement via `VERDICT_CACHE`
- TUI with live view, aggregation, filtering, and a modal that turns
  observations into rule files in place

Known limitations (Step 8 polish territory, see [SPEC.md](SPEC.md)):

- **DoH / DoT bypass.** Firefox and Chrome default to DNS-over-HTTPS, which
  our tc DNS sniffer doesn't see. Host-based rules won't fire for traffic
  from those browsers unless DoH is disabled (Firefox:
  `about:config` → `network.trr.mode = 5`) or the rule is written against
  the destination IPs.
- **`FlowKey.start_ns` is currently zero.** PID reuse can briefly alias
  cached verdicts. The CO-RE fix described in SPEC #3 is planned.
- **No rules-management view in the TUI yet.** Browse / disable / edit
  rules by editing TOML files directly.
- **TCP/53 DNS is not captured.** UDP/53 only for now.

## Tests

```sh
cargo test
```

53 unit and integration tests cover: rule parsing and evaluation, IPC
frame round-trips, TOML rule-file writing, TUI aggregation, and the
TUI's optimistic-deny logic. The eBPF crate is exercised by the kernel
verifier at load time rather than by unit tests.

## License

MIT OR Apache-2.0
