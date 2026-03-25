# Aggregator

The aggregator thread receives FlowRecord messages from the capture thread and converts them into per-process statistics suitable for UI rendering. It is the part of the pipeline that turns packet events into time-series counters and total byte counts.

Each ProcessRow contains process identity (PID, name, uid, username), total tx/rx bytes, tx/rx history arrays, a blocked flag, and the current connection list. The row is intentionally GUI-ready so the UI can read and display with minimal per-frame processing.

The history arrays are fixed-size circular-style buffers with newest data at index 0. Every second, values shift right by one slot and the current-second counters are written into slot 0. Rolling averages are then direct slice computations: 2 second average uses history[0..2], 10 second average uses history[0..10], and 40 second average uses all slots.

Snapshots are published through Arc<RwLock<Vec<ProcessRow>>> and Arc<RwLock<InterfaceStats>>. The aggregator prepares new vectors first, then holds a write lock only long enough to replace the snapshot, which keeps GUI read lock contention low.
