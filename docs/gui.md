# GUI

eframe and egui use immediate-mode rendering, which means the update() function rebuilds visible UI every frame from current state. This fits well with live monitoring because the screen naturally reflects the newest snapshot without maintaining complex widget state.

The toolbar contains interface selection, start/stop capture controls, BPF input, display toggles, and CSV export. It also shows interface-level totals and current and peak bandwidth values. The process table presents sortable per-process rows with traffic-based color highlighting. The chart shows TX and RX history over the last 40 seconds. The connection table lists socket-level details and offers a right-click block/unblock context menu. The status bar shows operational feedback such as capture state or BPF errors.

The GUI reads snapshots from Arc<RwLock<Vec<ProcessRow>>> and Arc<RwLock<InterfaceStats>> each frame. Reads are cloned quickly and locks are released immediately so the aggregator thread is not blocked for long writes.

Actions are dispatched through direct calls and lightweight state flags. Filter changes send commands to the capture control handle, interface changes restart capture, block/unblock triggers controller functions, and a pending_block state value opens a confirmation dialog before rule insertion.

VirtualBox detection reads hostname and DMI product fields and shows a warning banner when virtualization is detected. This reminds users that promiscuous capture in VirtualBox may only show VM-originated or VM-destined traffic depending on adapter mode.
