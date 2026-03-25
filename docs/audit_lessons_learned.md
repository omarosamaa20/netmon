# Phase I Lessons Learned Audit (Phase II Codebase)

Date: 2026-03-25
Scope: netmon workspace (capture, resolver, aggregator, controller, gui)

## WS-1
Lesson: Apply BPF filtering as early as possible to reduce user-space work.
Status: YES
Checked files:
- crates/capture/src/lib.rs
- crates/gui/src/main.rs
Evidence:
- Runtime BPF updates are routed from GUI to capture thread.
- Capture thread applies kernel filter using libpcap filter API.
Actions taken:
- Added trace comment: Phase I Lesson WS-1 at filter application site in capture crate.

## WS-2
Lesson: Use bounded queues and decoupled workers to prevent unbounded memory growth under bursts.
Status: YES
Checked files:
- crates/gui/src/main.rs
- crates/aggregator/src/lib.rs
Evidence:
- Flow transport uses sync_channel(1024).
- Aggregation runs on a dedicated worker thread.
Actions taken:
- Added trace comment: Phase I Lesson WS-2 at channel creation site in GUI crate.

## WS-3
Lesson: Track direction (TX/RX) explicitly for accurate bandwidth accounting.
Status: YES
Checked files:
- crates/capture/src/lib.rs
- crates/aggregator/src/lib.rs
Evidence:
- Direction enum is attached per FlowRecord.
- Aggregator updates directional totals and histories separately.
Actions taken:
- Added trace comment: Phase I Lesson WS-3 at direction classifier site.

## WS-4
Lesson: Keep protocol split visible for operator interpretation.
Status: YES
Checked files:
- crates/aggregator/src/lib.rs
- crates/gui/src/main.rs
Evidence:
- Connection entries preserve protocol.
- Process table now includes Proto Mix (TCP/UDP/OTHER counts) and sortable column.
Actions taken:
- Added protocol mix column and helper logic in GUI process table.
- Added trace comment: Phase I Lesson WS-4 near table render site.

## TC-1
Lesson: Control actions should be available directly from live telemetry context.
Status: YES
Checked files:
- crates/gui/src/main.rs
- crates/controller/src/lib.rs
Evidence:
- Connection row context menu exposes block/unblock actions.
- Controller provides block_process and unblock_process API.
Actions taken:
- Added trace comment: Phase I Lesson TC-1 at controller block entry point.

## TC-2
Lesson: Incomplete control features must remain explicit and operator-visible (no silent omission).
Status: YES
Checked files:
- crates/gui/src/main.rs
Evidence:
- GUI now exposes Export PCAP (TODO) action with explicit status message.
Actions taken:
- Added export_pcap_todo function and toolbar button.
- Added trace comment: Phase I Lesson TC-2 at TODO entry point.

## TC-3
Lesson: Control operations must be reversible and safe to clean up.
Status: YES
Checked files:
- crates/controller/src/lib.rs
- crates/gui/src/main.rs
Evidence:
- unblock_process removes rules by tracked handles.
- unblock_all is called on app shutdown.
Actions taken:
- Added trace comment: Phase I Lesson TC-3 at controller unblock entry point.

## NS-1
Lesson: Prefer Netlink SOCK_DIAG over /proc parsing for socket ownership resolution.
Status: YES
Checked files:
- crates/resolver/src/lib.rs
- crates/resolver/src/netlink.rs
Evidence:
- Resolver refresh uses Netlink query as primary path.
Actions taken:
- Added trace comment: Phase I Lesson NS-1 at strategy selection point.

## NS-2
Lesson: Keep /proc fallback for environments where Netlink is unavailable.
Status: YES
Checked files:
- crates/resolver/src/lib.rs
- crates/resolver/src/proc_fallback.rs
Evidence:
- Resolver logs warning and falls back to proc parser on Netlink failure.
Actions taken:
- Added trace comment: Phase I Lesson NS-2 at fallback branch.

## NS-3
Lesson: Avoid expensive resolver refresh on every packet; use timed refresh windows.
Status: YES
Checked files:
- crates/resolver/src/lib.rs
- crates/aggregator/src/lib.rs
Evidence:
- Resolver has refresh_if_needed with refresh period.
- Aggregator refreshes connection cache on interval gate.
Actions taken:
- Added trace comments: Phase I Lesson NS-3 in resolver and aggregator gating points.

## IF-1
Lesson: Show both fast and stable throughput indicators.
Status: YES
Checked files:
- crates/gui/src/main.rs
Evidence:
- Process table now shows TX/RX 2s and 10s rolling averages.
- CSV export now includes 2s and 10s average columns.
Actions taken:
- Added ten_second_avg helper and new table columns.
- Added export columns for 10s averages.
- Added trace comment: Phase I Lesson IF-1 at table and export sites.

## IF-2
Lesson: Provide short-horizon trend visualization for quick situational awareness.
Status: YES
Checked files:
- crates/gui/src/main.rs
- crates/aggregator/src/lib.rs
Evidence:
- Histories keep 40 samples and chart renders last 40 seconds.
Actions taken:
- Added trace comment: Phase I Lesson IF-2 at chart computation site.

## IF-3
Lesson: Surface anomalous heavy traffic visually.
Status: YES
Checked files:
- crates/gui/src/main.rs
Evidence:
- Process rows are color-coded using warning and critical thresholds.
Actions taken:
- Added trace comment: Phase I Lesson IF-3 at hotspot color logic.

## IF-4
Lesson: Keep UI responsive via non-blocking snapshot reads and controlled repaint cadence.
Status: YES
Checked files:
- crates/gui/src/main.rs
- crates/aggregator/src/lib.rs
Evidence:
- GUI reads immutable snapshots via RwLock and requests periodic repaint.
- Aggregator computes in worker thread and publishes snapshots.
Actions taken:
- Added trace comment: Phase I Lesson IF-4 at repaint cadence site.

## Build Verification
- Command: cargo check (WSL Linux path)
- Result: PASS
- Crates verified: capture, controller, resolver, aggregator, gui
