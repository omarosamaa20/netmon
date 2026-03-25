#![deny(warnings)]

//! Aggregates captured flow records into per-process counters and history
//! snapshots that the GUI can read each frame.
//!
//! This crate owns a background thread that receives `FlowRecord` items from a
//! bounded mpsc channel, resolves ownership via the resolver cache, and updates
//! process and interface statistics. The thread publishes read-friendly data
//! through `Arc<RwLock<...>>` snapshots so the UI can render without touching
//! mutable internal state. History values use a fixed-size ring-like array with
//! the newest second at index zero.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use capture::{Direction, FlowRecord, Protocol};
use resolver::{ProcessInfo, ResolvedConnection, Resolver};

/// Number of per-second samples kept for charts and rolling averages.
const HISTORY_SLOTS: usize = 40;

/// Channel receive timeout used by the aggregator loop.
const CHANNEL_RECV_TIMEOUT: Duration = Duration::from_millis(100);

/// Delay between expensive resolver `/proc` scans.
const RESOLVER_SCAN_INTERVAL: Duration = Duration::from_millis(800);

/// Sleep duration at the end of each loop iteration to cap CPU usage.
const LOOP_SLEEP_INTERVAL: Duration = Duration::from_millis(10);

/// Placeholder process label when resolver cannot map a flow.
const UNKNOWN_PROCESS_LABEL: &str = "[unknown]";

#[derive(Debug, Clone)]
pub struct ProcessRow {
    pub info: ProcessInfo,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_history: [u64; HISTORY_SLOTS],
    pub rx_history: [u64; HISTORY_SLOTS],
    pub is_blocked: bool,
    pub connections: Vec<ConnectionEntry>,
}

#[derive(Debug, Clone)]
pub struct ConnectionEntry {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: Protocol,
    pub state: String,
    pub pid: u32,
    pub process: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub tx_bytes_total: u64,
    pub rx_bytes_total: u64,
    pub current_bandwidth_bytes_per_sec: u64,
    pub peak_bandwidth_bytes_per_sec: u64,
    pub tx_history: [u64; HISTORY_SLOTS],
    pub rx_history: [u64; HISTORY_SLOTS],
}

impl Default for InterfaceStats {
    // Builds a zeroed interface statistics snapshot.
    fn default() -> Self {
        Self {
            tx_bytes_total: 0,
            rx_bytes_total: 0,
            current_bandwidth_bytes_per_sec: 0,
            peak_bandwidth_bytes_per_sec: 0,
            tx_history: [0; HISTORY_SLOTS],
            rx_history: [0; HISTORY_SLOTS],
        }
    }
}

#[derive(Debug)]
pub struct AggregatorControl {
    join_handle: Option<JoinHandle<()>>,
}

impl AggregatorControl {
    /// Joins the aggregator thread and returns an error if it panicked.
    pub fn join(&mut self) -> Result<(), String> {
        if let Some(handle) = self.join_handle.take() {
            handle
                .join()
                .map_err(|_| "aggregator thread panicked".to_string())?;
        }
        Ok(())
    }

    /// Joins the aggregator thread with a timeout to avoid hanging shutdown.
    pub fn join_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        if let Some(handle) = self.join_handle.take() {
            let (result_sender, result_receiver) = std::sync::mpsc::channel();
            thread::spawn(move || {
                let result = handle.join();
                let _ = result_sender.send(result);
            });

            match result_receiver.recv_timeout(timeout) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err("aggregator thread panicked".to_string()),
                Err(_) => Err("aggregator thread join timed out".to_string()),
            }
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
struct ProcessStats {
    info: ProcessInfo,
    tx_bytes_total: u64,
    rx_bytes_total: u64,
    tx_current_second: u64,
    rx_current_second: u64,
    tx_history: [u64; HISTORY_SLOTS],
    rx_history: [u64; HISTORY_SLOTS],
}

impl ProcessStats {
    // Creates zeroed counters for one process.
    fn new(info: ProcessInfo) -> Self {
        Self {
            info,
            tx_bytes_total: 0,
            rx_bytes_total: 0,
            tx_current_second: 0,
            rx_current_second: 0,
            tx_history: [0; HISTORY_SLOTS],
            rx_history: [0; HISTORY_SLOTS],
        }
    }

    // Rotates per-second histories so index 0 always holds the newest second.
    fn rotate_second(&mut self) {
        for idx in (1..HISTORY_SLOTS).rev() {
            self.tx_history[idx] = self.tx_history[idx - 1];
            self.rx_history[idx] = self.rx_history[idx - 1];
        }
        self.tx_history[0] = self.tx_current_second;
        self.rx_history[0] = self.rx_current_second;
        self.tx_current_second = 0;
        self.rx_current_second = 0;
    }
}

/// Spawns the aggregator thread that merges captured flow records into snapshots.
pub fn spawn_aggregator_thread(
    rx: Receiver<FlowRecord>,
    running: Arc<AtomicBool>,
    rows_snapshot: Arc<RwLock<Vec<ProcessRow>>>,
    interface_snapshot: Arc<RwLock<InterfaceStats>>,
    status_snapshot: Arc<RwLock<String>>,
    blocked_pids: Arc<RwLock<HashSet<u32>>>,
) -> AggregatorControl {
    let join_handle = thread::spawn(move || {
        run_aggregator_loop(
            rx,
            running,
            rows_snapshot,
            interface_snapshot,
            status_snapshot,
            blocked_pids,
        );
    });

    AggregatorControl {
        join_handle: Some(join_handle),
    }
}

// Runs the main aggregator lifecycle from channel reads to snapshot publication.
fn run_aggregator_loop(
    rx: Receiver<FlowRecord>,
    running: Arc<AtomicBool>,
    rows_snapshot: Arc<RwLock<Vec<ProcessRow>>>,
    interface_snapshot: Arc<RwLock<InterfaceStats>>,
    status_snapshot: Arc<RwLock<String>>,
    blocked_pids: Arc<RwLock<HashSet<u32>>>,
) {
    let mut resolver = match Resolver::new() {
        Ok(resolver) => resolver,
        Err(error) => {
            if let Ok(mut status) = status_snapshot.write() {
                *status = format!("Resolver initialization failed: {error}");
            }
            return;
        }
    };

    let mut stats_by_pid: HashMap<u32, ProcessStats> = HashMap::new();
    let mut last_rotation = Instant::now();
    let mut last_proc_scan = Instant::now() - Duration::from_secs(1);
    let mut connection_cache: Vec<ResolvedConnection> = Vec::new();

    let mut if_tx_total: u64 = 0;
    let mut if_rx_total: u64 = 0;
    let mut if_tx_current_second: u64 = 0;
    let mut if_rx_current_second: u64 = 0;
    let mut if_tx_history: [u64; HISTORY_SLOTS] = [0; HISTORY_SLOTS];
    let mut if_rx_history: [u64; HISTORY_SLOTS] = [0; HISTORY_SLOTS];
    let mut peak_bw: u64 = 0;

    while running.load(Ordering::Relaxed) {
        drain_flow_channel(
            &rx,
            &mut resolver,
            &mut stats_by_pid,
            &mut if_tx_total,
            &mut if_rx_total,
            &mut if_tx_current_second,
            &mut if_rx_current_second,
        );
        refresh_connection_cache_if_due(&mut resolver, &mut connection_cache, &mut last_proc_scan);
        rotate_histories_if_due(
            &mut stats_by_pid,
            &mut if_tx_history,
            &mut if_rx_history,
            &mut if_tx_current_second,
            &mut if_rx_current_second,
            &mut peak_bw,
            &mut last_rotation,
        );
        publish_snapshots(
            &stats_by_pid,
            &connection_cache,
            &rows_snapshot,
            &interface_snapshot,
            &blocked_pids,
            if_tx_total,
            if_rx_total,
            peak_bw,
            if_tx_history,
            if_rx_history,
        );
        thread::sleep(LOOP_SLEEP_INTERVAL);
    }
}

// Drains available flow records from the channel and applies them to counters.
fn drain_flow_channel(
    rx: &Receiver<FlowRecord>,
    resolver: &mut Resolver,
    stats_by_pid: &mut HashMap<u32, ProcessStats>,
    if_tx_total: &mut u64,
    if_rx_total: &mut u64,
    if_tx_current_second: &mut u64,
    if_rx_current_second: &mut u64,
) {
    match rx.recv_timeout(CHANNEL_RECV_TIMEOUT) {
        Ok(first_record) => {
            process_record(
                first_record,
                resolver,
                stats_by_pid,
                if_tx_total,
                if_rx_total,
                if_tx_current_second,
                if_rx_current_second,
            );

            while let Ok(next_record) = rx.try_recv() {
                process_record(
                    next_record,
                    resolver,
                    stats_by_pid,
                    if_tx_total,
                    if_rx_total,
                    if_tx_current_second,
                    if_rx_current_second,
                );
            }
        }
        Err(RecvTimeoutError::Timeout) => {}
        Err(RecvTimeoutError::Disconnected) => {}
    }
}

// Refreshes connection metadata from resolver cache at most once per interval.
fn refresh_connection_cache_if_due(
    resolver: &mut Resolver,
    connection_cache: &mut Vec<ResolvedConnection>,
    last_proc_scan: &mut Instant,
) {
    // Phase I Lesson NS-3: avoid per-packet resolver scans by using a timed refresh window.
    if last_proc_scan.elapsed() >= RESOLVER_SCAN_INTERVAL {
        let _ = resolver.refresh_if_needed();
        *connection_cache = resolver.list_connections();
        *last_proc_scan = Instant::now();
    }
}

// Rotates per-second histories and updates interface peak bandwidth.
fn rotate_histories_if_due(
    stats_by_pid: &mut HashMap<u32, ProcessStats>,
    if_tx_history: &mut [u64; HISTORY_SLOTS],
    if_rx_history: &mut [u64; HISTORY_SLOTS],
    if_tx_current_second: &mut u64,
    if_rx_current_second: &mut u64,
    peak_bw: &mut u64,
    last_rotation: &mut Instant,
) {
    if last_rotation.elapsed() < Duration::from_secs(1) {
        return;
    }

    for process_stats in stats_by_pid.values_mut() {
        process_stats.rotate_second();
    }

    rotate_interface_second(
        if_tx_history,
        if_rx_history,
        if_tx_current_second,
        if_rx_current_second,
    );

    let current_bandwidth = if_tx_history[0] + if_rx_history[0];
    if current_bandwidth > *peak_bw {
        *peak_bw = current_bandwidth;
    }
    *last_rotation = Instant::now();
}

// Applies one flow record to process-level and interface-level counters.
fn process_record(
    record: FlowRecord,
    resolver: &mut Resolver,
    stats_by_pid: &mut HashMap<u32, ProcessStats>,
    if_tx_total: &mut u64,
    if_rx_total: &mut u64,
    if_tx_current_second: &mut u64,
    if_rx_current_second: &mut u64,
) {
    let info = resolver
        .resolve_flow_owner(&record.key)
        .unwrap_or(ProcessInfo {
            pid: 0,
            name: UNKNOWN_PROCESS_LABEL.to_string(),
            uid: 0,
            username: UNKNOWN_PROCESS_LABEL.to_string(),
        });

    let bytes = u64::from(record.byte_count);
    let entry = stats_by_pid
        .entry(info.pid)
        .or_insert_with(|| ProcessStats::new(info.clone()));
    entry.info = info;

    match record.direction {
        Direction::Tx => {
            entry.tx_bytes_total = entry.tx_bytes_total.saturating_add(bytes);
            entry.tx_current_second = entry.tx_current_second.saturating_add(bytes);
            *if_tx_total = if_tx_total.saturating_add(bytes);
            *if_tx_current_second = if_tx_current_second.saturating_add(bytes);
        }
        Direction::Rx => {
            entry.rx_bytes_total = entry.rx_bytes_total.saturating_add(bytes);
            entry.rx_current_second = entry.rx_current_second.saturating_add(bytes);
            *if_rx_total = if_rx_total.saturating_add(bytes);
            *if_rx_current_second = if_rx_current_second.saturating_add(bytes);
        }
    }
}

// Rotates interface history arrays and resets the current-second accumulators.
fn rotate_interface_second(
    tx_history: &mut [u64; HISTORY_SLOTS],
    rx_history: &mut [u64; HISTORY_SLOTS],
    tx_current_second: &mut u64,
    rx_current_second: &mut u64,
) {
    for idx in (1..HISTORY_SLOTS).rev() {
        tx_history[idx] = tx_history[idx - 1];
        rx_history[idx] = rx_history[idx - 1];
    }
    tx_history[0] = *tx_current_second;
    rx_history[0] = *rx_current_second;
    *tx_current_second = 0;
    *rx_current_second = 0;
}

// Publishes process and interface snapshots to shared `Arc<RwLock<...>>` state.
fn publish_snapshots(
    stats_by_pid: &HashMap<u32, ProcessStats>,
    connection_cache: &[ResolvedConnection],
    rows_snapshot: &Arc<RwLock<Vec<ProcessRow>>>,
    interface_snapshot: &Arc<RwLock<InterfaceStats>>,
    blocked_pids: &Arc<RwLock<HashSet<u32>>>,
    if_tx_total: u64,
    if_rx_total: u64,
    peak_bw: u64,
    if_tx_history: [u64; HISTORY_SLOTS],
    if_rx_history: [u64; HISTORY_SLOTS],
) {
    let blocked = blocked_pids
        .read()
        .map(|g| g.clone())
        .unwrap_or_else(|_| HashSet::new());

    let mut conn_by_pid: HashMap<u32, Vec<ConnectionEntry>> = HashMap::new();
    for conn in connection_cache {
        conn_by_pid
            .entry(conn.pid)
            .or_default()
            .push(ConnectionEntry {
                local_addr: conn.local_addr,
                remote_addr: conn.remote_addr,
                protocol: conn.protocol,
                state: conn.state.clone(),
                pid: conn.pid,
                process: conn.process.clone(),
                tx_bytes: 0,
                rx_bytes: 0,
            });
    }

    let mut rows = Vec::with_capacity(stats_by_pid.len());
    for (pid, stats) in stats_by_pid {
        rows.push(ProcessRow {
            info: stats.info.clone(),
            tx_bytes: stats.tx_bytes_total,
            rx_bytes: stats.rx_bytes_total,
            tx_history: stats.tx_history,
            rx_history: stats.rx_history,
            is_blocked: blocked.contains(pid),
            connections: conn_by_pid.remove(pid).unwrap_or_default(),
        });
    }

    rows.sort_by_key(|r| r.info.pid);

    if let Ok(mut guard) = rows_snapshot.write() {
        *guard = rows;
    }

    if let Ok(mut iface) = interface_snapshot.write() {
        iface.tx_bytes_total = if_tx_total;
        iface.rx_bytes_total = if_rx_total;
        iface.current_bandwidth_bytes_per_sec = if_tx_history[0].saturating_add(if_rx_history[0]);
        iface.peak_bandwidth_bytes_per_sec = peak_bw;
        iface.tx_history = if_tx_history;
        iface.rx_history = if_rx_history;
    }
}
