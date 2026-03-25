# Architecture

The workspace is split into five crates. The capture crate opens a libpcap handle and emits parsed flow records. The resolver crate reads /proc data and maps socket inodes to process and user metadata. The aggregator crate consumes flow records and builds shared snapshots for rendering. The controller crate inserts and removes nftables rules for blocking. The gui crate is the executable that wires everything together and handles user interaction.

## Threading and Data Flow

The application uses OS threads instead of async because it keeps the mental model straightforward for this project: one thread captures, one aggregates, and the GUI thread renders. The capture and aggregator threads communicate through a bounded mpsc::sync_channel, and the GUI reads Arc<RwLock<...>> snapshots published by the aggregator.

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
