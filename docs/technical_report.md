# Technical Report
## CSCE 3401 — Linux Network Monitor & Controller

## Section 1 — Project Overview
The Linux Network Monitor & Controller is a desktop application that observes live network activity and attributes that activity to the process and user account that owns each socket. It combines passive monitoring and active control in one workflow: packets are captured in real time, mapped to PID and username, aggregated into per-process bandwidth timelines, and then exposed in a GUI where the operator can block selected processes. The target user is a system administrator or advanced Linux user who needs process-aware traffic visibility during troubleshooting, auditing, or incident response.

The project addresses a practical tooling gap that appears in coursework and operations alike. Packet analyzers provide deep packet visibility but usually do not show owner identity in a direct real-time dashboard, while host-level traffic tools often summarize usage without precise process-to-user context and in-place control actions. This implementation closes that loop by keeping ownership attribution and blocking controls directly adjacent to monitoring output.

The implementation is written in Rust (edition 2021), while the default language in the guidelines is C++. Per the project rules, this language choice is intended to claim the Rust +5% bonus credit. Rust was selected for its memory safety model and zero-cost abstractions in a system that manipulates raw packet bytes, virtual filesystem state under /proc, kernel IPC through Netlink, and multi-threaded shared state.

## Section 2 — OS Concepts Demonstrated
The project demonstrates Linux virtual filesystem mechanics through direct reads of /proc. Socket ownership fallback data is parsed from /proc/net files in resolver/src/proc_fallback.rs via read_proc_net and read_proc_file, while process-level ownership is derived by scanning /proc/<PID>/fd symlinks in resolver/src/pid_map.rs using build_inode_pid_map and parse_socket_inode. Process identity is completed by reading /proc/<PID>/comm in read_process_name and UID metadata from /proc/<PID>/status in read_process_effective_uid. Together, these functions show how process and socket state is surfaced by the kernel without persistent on-disk files.

The resolver also demonstrates kernel-to-user IPC using Netlink SOCK_DIAG. The primary query path in resolver/src/netlink.rs is implemented by query_sockets and query_family_protocol, which send SOCK_DIAG_BY_FAMILY requests and parse multipart replies into structured socket records. Compared to text parsing under /proc, the Netlink path is atomic for each dump, structured, and directly aligned with the interface used by ss, so it is the preferred mechanism.

Packet capture behavior demonstrates AF_PACKET and libpcap integration at OS boundaries. In capture/src/lib.rs, spawn_capture_thread configures a live capture handle in promiscuous mode and run_capture_loop continuously consumes packets from capture.next_packet with timeout-based blocking. Promiscuous mode is required so the interface can expose all frames visible on the link layer to the monitor path instead of only traffic addressed to local sockets.

Kernel packet filtering is demonstrated through BPF filter application in capture/src/lib.rs inside handle_pending_commands, where capture.filter applies a user-entered expression at the kernel capture layer. This matters for efficiency because packets that do not match are discarded before user-space transfer and parsing, reducing copy overhead and downstream CPU work compared to filtering after packet delivery.

OS thread scheduling and synchronization are exercised through a three-thread model. The capture thread focuses on packet ingestion, the aggregator thread performs ownership resolution and statistics maintenance, and the GUI thread renders immutable snapshots. The bounded mpsc::sync_channel(1024) between capture and aggregator provides explicit back-pressure, while the capture thread relies on pcap timeout blocking and the aggregator thread uses a controlled sleep interval to avoid busy waiting.

Netfilter and nftables integration is implemented in controller/src/lib.rs, primarily in block_process and unblock_process. When the operator blocks a process from the GUI, the controller constructs nft rules in the inet filter output chain and applies them through the nft CLI, causing packets to be dropped in kernel networking hooks before transmission. This demonstrates practical control-plane interaction with Linux packet filtering infrastructure.

## Section 3 — Architecture
The workspace uses five crates with explicit responsibilities. The capture crate ingests packets and produces normalized FlowRecord values containing endpoint, protocol, direction, and byte-count metadata. Its public API exports capture lifecycle controls and packet event structs, and its main OS resource touchpoints are libpcap handles and a worker thread bound to interface traffic.

The resolver crate maps transport flows to process identity. It exposes Resolver, ProcessInfo, and connection listing helpers used by the aggregator. Its OS resource surface includes Netlink SOCK_DIAG sockets for primary socket enumeration and /proc reads as fallback and ownership join data, including fd symlink traversal and passwd-based UID-to-username mapping.

The aggregator crate consumes flow events and publishes snapshot state. It exports process and interface snapshot models, plus thread startup and join control. Its OS-facing behavior is primarily scheduling and synchronization: bounded channel receive, timed refresh, periodic history rotation, and Arc/RwLock publication for lock-scoped read access from the GUI.

The controller crate provides process traffic control operations through nftables. It exports setup, block, unblock, and cleanup functions and interacts with OS process execution and netfilter state via nft subprocess calls. This crate intentionally remains focused on kernel rule manipulation and does not perform flow capture or PID resolution logic.

The gui crate is the executable composition root. It wires all other crates, drives user interaction, renders process and connection tables plus charts, and mediates control actions such as BPF apply and process block/unblock confirmation. It touches OS resources indirectly through crate APIs and directly through privilege checks and user-facing status handling.

```text
  NIC
   |
   | raw frames via libpcap
   v
[capture thread]
   |
   | FlowRecord over mpsc::sync_channel(1024)
   v
[aggregator thread] <---- resolver cache using Netlink or /proc as a fallback (refresh <= 1/s)
   |
   | Arc<RwLock<Vec<ProcessRow>>> + Arc<RwLock<InterfaceStats>>
   v
[GUI thread / eframe]
   |
   | block/unblock actions
   v
[nftables via nft CLI]
```

## Section 4 — Design Decisions and Trade-offs
The first major decision was implementing the project in Rust rather than C++. In this network-monitoring context, raw byte parsing, multi-threaded state handoff, and long-lived worker loops are all common sources of memory and synchronization defects in unmanaged code. Rust’s ownership and borrowing model removes broad classes of use-after-free and data-race bugs at compile time, which is particularly valuable in a student project expected to run continuously during live demonstrations. The trade-off is a steeper learning curve and fewer Linux systems examples than legacy C++ resources.

The second key decision was Netlink-first resolution with /proc fallback. Netlink SOCK_DIAG provides structured, kernel-native socket listings and aligns with production tooling semantics used by ss. It improves consistency and performance compared to repeatedly parsing text snapshots from /proc/net. The fallback path was still retained because some restricted environments can block or limit Netlink capabilities, and the project must remain operational in broader lab and VM conditions. The trade-off is maintaining two code paths and ensuring their outputs stay behaviorally consistent.

The third decision was to use libpcap instead of a direct AF_PACKET ring-buffer implementation. libpcap reduces implementation complexity, provides mature capture abstractions, and handles BPF filter compilation/application cleanly, which allowed the project to focus on process correlation and control features. The trade-off is an external C dependency and potentially higher overhead than an optimized PACKET_MMAP ring in a high-throughput production-grade sensor.

## Section 5 — Limitations and Future Work
The current blocking implementation is port-based rather than PID-native. In standard nftables matching, there is no universally available direct PID match in the output path, so the project identifies active source ports for a selected process and inserts drop rules for those ports. This can lead to overblocking if a different process later reuses a blocked port. A future refinement would use cgroup-oriented classification and control to bind network policy to process groups more robustly.

Virtualized capture remains constrained by hypervisor behavior. In VirtualBox environments, promiscuous mode may still be limited by host NIC and VM adapter settings such that only traffic to or from the VM is observable. This project detects likely VirtualBox execution and warns the operator, but it cannot override hardware or hypervisor policies from user space.

Per-process rate limiting is intentionally not complete in this phase. The controller crate currently includes a placeholder API for tc/HTB integration, but the final implementation scope focused on robust block/unblock operations, cleanup behavior, and ownership-aware monitoring. Future work can add tc qdisc and class orchestration for configurable shaping and ceilings.

IPv6 handling currently focuses on address and transport identification from the fixed header. Extension-header chains are not deeply parsed in this version, so packets requiring full extension traversal for transport discovery may be under-classified. Extending the parser to walk extension headers is a clear next iteration for protocol completeness.

## Section 6 — Phase I Lessons Applied
The Wireshark lessons were applied by adopting packet-level observability with protocol-aware parsing and by emphasizing clear visualization of traffic evolution over time. In this project, that appears in capture parsing decisions and the GUI chart/table presentation that keeps transport behavior legible during troubleshooting.

The tcpdump lessons were applied through kernel-side BPF usage and interface-scoped capture discipline. Runtime filter changes are pushed directly to libpcap so filtering occurs before user-space parsing, reflecting the performance and selectivity principles observed in packet-capture CLI tooling.

The netstat and ss lessons were applied most directly in the resolver architecture. Ownership correlation follows socket-centric diagnostics using Netlink SOCK_DIAG as the preferred path and /proc joins as fallback, mirroring how modern Linux tooling maps sockets to process identity while balancing compatibility constraints.

The iftop lessons were applied in the continuous bandwidth-oriented interface design. The process table, rolling averages, trend chart, and top-level interface counters were designed to support immediate operator interpretation and action, while the detailed lesson-by-lesson traceability is documented in docs/audit_lessons_learned.md.
