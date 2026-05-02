#![deny(warnings)]

//! Aggregates captured flow records into per-thread counters and history
//! snapshots that the GUI can read each frame.
//!
//! Traffic is now attributed to individual OS threads (PID + TID) rather than
//! processes, giving finer-grained visibility into multi-threaded applications.
//!
//! Historical CSV export appends one timestamped row per active thread every
//! second to a persistent file at ~/netmon_history_<timestamp>.csv, so the
//! full capture session is preserved without manual exports.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use capture::{Direction, FlowRecord, Protocol};
use resolver::{ProcessInfo, ResolvedConnection, Resolver};

/// Number of per-second samples kept for charts and rolling averages.
const HISTORY_SLOTS: usize = 300;

/// Channel receive timeout used by the aggregator loop.
const CHANNEL_RECV_TIMEOUT: Duration = Duration::from_millis(100);

/// Delay between expensive resolver `/proc` scans.
const RESOLVER_SCAN_INTERVAL: Duration = Duration::from_millis(800);

/// Sleep duration at the end of each loop iteration to cap CPU usage.
const LOOP_SLEEP_INTERVAL: Duration = Duration::from_millis(10);

/// Evict inactive thread rows after this idle period to bound memory.
const PROCESS_EVICTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Placeholder label when resolver cannot map a flow.
const UNKNOWN_PROCESS_LABEL: &str = "[unknown]";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    pid: u32,
    tid: u32,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    protocol: Protocol,
}

#[derive(Debug, Clone)]
struct ConnectionStats {
    tx_bytes: u64,
    rx_bytes: u64,
    last_seen: Instant,
}

/// One per-thread CSV row captured for session export.
#[derive(Debug, Clone)]
pub struct HistoryCsvRow {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub process: String,
    pub thread: String,
    pub user: String,
    pub uid: u32,
    pub tx_bytes_total: u64,
    pub rx_bytes_total: u64,
    pub tx_2s_avg: u64,
    pub rx_2s_avg: u64,
    pub tx_10s_avg: u64,
    pub rx_10s_avg: u64,
}

/// Key used to track per-thread statistics: (pid, tid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadKey {
    pub pid: u32,
    pub tid: u32,
}

#[derive(Debug, Clone)]
pub struct ProcessRow {
    pub info: ProcessInfo,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_seen: Instant,
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
    pub tid: u32,
    pub process: String,
    pub thread_name: String,
    pub username: String,
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
struct ThreadStats {
    info: ProcessInfo,
    tx_bytes_total: u64,
    rx_bytes_total: u64,
    last_seen: Instant,
    tx_current_second: u64,
    rx_current_second: u64,
    tx_history: [u64; HISTORY_SLOTS],
    rx_history: [u64; HISTORY_SLOTS],
}

impl ThreadStats {
    fn new(info: ProcessInfo) -> Self {
        Self {
            info,
            tx_bytes_total: 0,
            rx_bytes_total: 0,
            last_seen: Instant::now(),
            tx_current_second: 0,
            rx_current_second: 0,
            tx_history: [0; HISTORY_SLOTS],
            rx_history: [0; HISTORY_SLOTS],
        }
    }

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
    session_history_snapshot: Arc<RwLock<Vec<HistoryCsvRow>>>,
) -> AggregatorControl {
    let join_handle = thread::spawn(move || {
        run_aggregator_loop(
            rx,
            running,
            rows_snapshot,
            interface_snapshot,
            status_snapshot,
            blocked_pids,
            session_history_snapshot,
        );
    });

    AggregatorControl {
        join_handle: Some(join_handle),
    }
}

// Opens the historical CSV file and writes the header row.
fn open_history_csv() -> Option<File> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = format!("{home}/netmon_history_{ts}.csv");

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()?;

    let header = "timestamp,pid,tid,process,thread,user,uid,\
                  tx_bytes_total,rx_bytes_total,\
                  tx_2s_avg,rx_2s_avg,tx_10s_avg,rx_10s_avg\n";
    file.write_all(header.as_bytes()).ok()?;

    log::info!("Historical CSV opened at {path}");
    Some(file)
}

// Appends one row per active thread to the history CSV on each second tick.
fn append_history_csv(
    file: &mut File,
    stats_map: &HashMap<ThreadKey, ThreadStats>,
    session_history_snapshot: &Arc<RwLock<Vec<HistoryCsvRow>>>,
) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut exported_rows = Vec::with_capacity(stats_map.len());

    for stats in stats_map.values() {
        let tx_2s = two_second_avg(stats.tx_history);
        let rx_2s = two_second_avg(stats.rx_history);
        let tx_10s = ten_second_avg(stats.tx_history);
        let rx_10s = ten_second_avg(stats.rx_history);

        exported_rows.push(HistoryCsvRow {
            timestamp: ts,
            pid: stats.info.pid,
            tid: stats.info.tid,
            process: stats.info.name.clone(),
            thread: stats.info.thread_name.clone(),
            user: stats.info.username.clone(),
            uid: stats.info.uid,
            tx_bytes_total: stats.tx_bytes_total,
            rx_bytes_total: stats.rx_bytes_total,
            tx_2s_avg: tx_2s,
            rx_2s_avg: rx_2s,
            tx_10s_avg: tx_10s,
            rx_10s_avg: rx_10s,
        });

        let line = format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            ts,
            stats.info.pid,
            stats.info.tid,
            sanitize_csv(&stats.info.name),
            sanitize_csv(&stats.info.thread_name),
            sanitize_csv(&stats.info.username),
            stats.info.uid,
            stats.tx_bytes_total,
            stats.rx_bytes_total,
            tx_2s,
            rx_2s,
            tx_10s,
            rx_10s,
        );

        let _ = file.write_all(line.as_bytes());
    }

    if let Ok(mut history) = session_history_snapshot.write() {
        history.extend(exported_rows);
    }
}

fn two_second_avg(history: [u64; HISTORY_SLOTS]) -> u64 {
    (history[0] + history[1]) / 2
}

fn ten_second_avg(history: [u64; HISTORY_SLOTS]) -> u64 {
    history[0..10].iter().copied().sum::<u64>() / 10
}

fn sanitize_csv(value: &str) -> String {
    value.replace('"', "'").replace(',', " ")
}

// Runs the main aggregator lifecycle from channel reads to snapshot publication.
fn run_aggregator_loop(
    rx: Receiver<FlowRecord>,
    running: Arc<AtomicBool>,
    rows_snapshot: Arc<RwLock<Vec<ProcessRow>>>,
    interface_snapshot: Arc<RwLock<InterfaceStats>>,
    status_snapshot: Arc<RwLock<String>>,
    blocked_pids: Arc<RwLock<HashSet<u32>>>,
    session_history_snapshot: Arc<RwLock<Vec<HistoryCsvRow>>>,
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

    // Keyed by (pid, tid) for per-thread attribution.
    let mut stats_by_thread: HashMap<ThreadKey, ThreadStats> = HashMap::new();
    let mut connection_stats: HashMap<ConnectionKey, ConnectionStats> = HashMap::new();
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

    let mut history_csv = open_history_csv();
    if history_csv.is_none() {
        log::warn!("Could not open historical CSV file; history will not be saved.");
    }

    while running.load(Ordering::Relaxed) {
        refresh_connection_cache_if_due(&mut resolver, &mut connection_cache, &mut last_proc_scan);
        drain_flow_channel(
            &rx,
            &mut resolver,
            &connection_cache,
            &mut stats_by_thread,
            &mut connection_stats,
            &mut if_tx_total,
            &mut if_rx_total,
            &mut if_tx_current_second,
            &mut if_rx_current_second,
        );
        mark_exited_threads(&mut stats_by_thread, &mut resolver);
        evict_stale_threads(&mut stats_by_thread);
        prune_connection_stats(&mut connection_stats, &stats_by_thread);

        let rotated = rotate_histories_if_due(
            &mut stats_by_thread,
            &mut if_tx_history,
            &mut if_rx_history,
            &mut if_tx_current_second,
            &mut if_rx_current_second,
            &mut peak_bw,
            &mut last_rotation,
        );

        // Append one CSV snapshot per second tick.
        if rotated {
            if let Some(ref mut csv_file) = history_csv {
                append_history_csv(csv_file, &stats_by_thread, &session_history_snapshot);
            }
        }

        publish_snapshots(
            &stats_by_thread,
            &connection_cache,
            &connection_stats,
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
    connection_cache: &[ResolvedConnection],
    stats_by_thread: &mut HashMap<ThreadKey, ThreadStats>,
    connection_stats: &mut HashMap<ConnectionKey, ConnectionStats>,
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
                connection_cache,
                stats_by_thread,
                connection_stats,
                if_tx_total,
                if_rx_total,
                if_tx_current_second,
                if_rx_current_second,
            );

            while let Ok(next_record) = rx.try_recv() {
                process_record(
                    next_record,
                    resolver,
                    connection_cache,
                    stats_by_thread,
                    connection_stats,
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

// Marks rows as exited when the PID no longer resolves.
fn mark_exited_threads(
    stats_by_thread: &mut HashMap<ThreadKey, ThreadStats>,
    resolver: &mut Resolver,
) {
    for (key, stats) in stats_by_thread.iter_mut() {
        if key.pid == 0 {
            continue;
        }
        if resolver.process_by_pid(key.pid).is_none()
            && !stats.info.name.ends_with(" [exited]")
        {
            stats.info.name = format!("{} [exited]", stats.info.name);
        }
    }
}

// Removes stale thread entries to keep the map memory-bounded.
fn evict_stale_threads(stats_by_thread: &mut HashMap<ThreadKey, ThreadStats>) {
    stats_by_thread.retain(|_, stats| stats.last_seen.elapsed() <= PROCESS_EVICTION_TIMEOUT);
}

// Refreshes connection metadata from resolver cache at most once per interval.
fn refresh_connection_cache_if_due(
    resolver: &mut Resolver,
    connection_cache: &mut Vec<ResolvedConnection>,
    last_proc_scan: &mut Instant,
) {
    if last_proc_scan.elapsed() >= RESOLVER_SCAN_INTERVAL {
        let _ = resolver.refresh_if_needed();
        *connection_cache = resolver.list_connections();
        *last_proc_scan = Instant::now();
    }
}

// Rotates per-second histories and returns true when a rotation occurred.
fn rotate_histories_if_due(
    stats_by_thread: &mut HashMap<ThreadKey, ThreadStats>,
    if_tx_history: &mut [u64; HISTORY_SLOTS],
    if_rx_history: &mut [u64; HISTORY_SLOTS],
    if_tx_current_second: &mut u64,
    if_rx_current_second: &mut u64,
    peak_bw: &mut u64,
    last_rotation: &mut Instant,
) -> bool {
    if last_rotation.elapsed() < Duration::from_secs(1) {
        return false;
    }

    for thread_stats in stats_by_thread.values_mut() {
        thread_stats.rotate_second();
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
    true
}

// Applies one flow record to thread-level and interface-level counters.
fn process_record(
    record: FlowRecord,
    resolver: &mut Resolver,
    connection_cache: &[ResolvedConnection],
    stats_by_thread: &mut HashMap<ThreadKey, ThreadStats>,
    connection_stats: &mut HashMap<ConnectionKey, ConnectionStats>,
    if_tx_total: &mut u64,
    if_rx_total: &mut u64,
    if_tx_current_second: &mut u64,
    if_rx_current_second: &mut u64,
) {
    let info = resolver
        .resolve_flow_owner(&record.key)
        .or_else(|| lookup_process_from_connections(&record.key, connection_cache))
        .unwrap_or(ProcessInfo {
            pid: 0,
            tid: 0,
            name: UNKNOWN_PROCESS_LABEL.to_string(),
            thread_name: UNKNOWN_PROCESS_LABEL.to_string(),
            uid: 0,
            username: UNKNOWN_PROCESS_LABEL.to_string(),
        });

    let key = ThreadKey { pid: info.pid, tid: info.tid };
    let bytes = u64::from(record.byte_count);
    let info_for_connections = info.clone();
    let entry = stats_by_thread
        .entry(key)
        .or_insert_with(|| ThreadStats::new(info.clone()));
    entry.info = info;
    entry.last_seen = Instant::now();

    match record.direction {
        Direction::Tx => {
            entry.tx_bytes_total = entry.tx_bytes_total.saturating_add(bytes);
            entry.tx_current_second = entry.tx_current_second.saturating_add(bytes);
            *if_tx_total = if_tx_total.saturating_add(bytes);
            *if_tx_current_second = if_tx_current_second.saturating_add(bytes);
            update_connection_stats(connection_stats, &record, &info_for_connections, bytes, true);
        }
        Direction::Rx => {
            entry.rx_bytes_total = entry.rx_bytes_total.saturating_add(bytes);
            entry.rx_current_second = entry.rx_current_second.saturating_add(bytes);
            *if_rx_total = if_rx_total.saturating_add(bytes);
            *if_rx_current_second = if_rx_current_second.saturating_add(bytes);
            update_connection_stats(connection_stats, &record, &info_for_connections, bytes, false);
        }
    }
}

fn update_connection_stats(
    connection_stats: &mut HashMap<ConnectionKey, ConnectionStats>,
    record: &FlowRecord,
    info: &ProcessInfo,
    bytes: u64,
    is_tx: bool,
) {
    let (local_ip, local_port, remote_ip, remote_port) = if is_tx {
        (
            record.key.src_ip,
            record.key.src_port,
            record.key.dst_ip,
            record.key.dst_port,
        )
    } else {
        (
            record.key.dst_ip,
            record.key.dst_port,
            record.key.src_ip,
            record.key.src_port,
        )
    };

    let key = ConnectionKey {
        pid: info.pid,
        tid: info.tid,
        local_addr: SocketAddr::new(local_ip, local_port),
        remote_addr: SocketAddr::new(remote_ip, remote_port),
        protocol: record.key.protocol,
    };

    let entry = connection_stats.entry(key).or_insert(ConnectionStats {
        tx_bytes: 0,
        rx_bytes: 0,
        last_seen: Instant::now(),
    });
    entry.last_seen = Instant::now();
    if is_tx {
        entry.tx_bytes = entry.tx_bytes.saturating_add(bytes);
    } else {
        entry.rx_bytes = entry.rx_bytes.saturating_add(bytes);
    }
}

fn lookup_process_from_connections(
    flow: &capture::FlowKey,
    connection_cache: &[ResolvedConnection],
) -> Option<ProcessInfo> {
    for conn in connection_cache {
        if conn.protocol != flow.protocol {
            continue;
        }

        let forward_match = conn.local_addr.ip() == flow.src_ip
            && conn.local_addr.port() == flow.src_port
            && conn.remote_addr.ip() == flow.dst_ip
            && conn.remote_addr.port() == flow.dst_port;

        let reverse_match = conn.local_addr.ip() == flow.dst_ip
            && conn.local_addr.port() == flow.dst_port
            && conn.remote_addr.ip() == flow.src_ip
            && conn.remote_addr.port() == flow.src_port;

        if !forward_match && !reverse_match {
            continue;
        }

        return Some(ProcessInfo {
            pid: conn.pid,
            tid: conn.tid,
            name: conn.process.clone(),
            thread_name: conn.thread_name.clone(),
            uid: conn.uid,
            username: conn.username.clone(),
        });
    }

    None
}

fn prune_connection_stats(
    connection_stats: &mut HashMap<ConnectionKey, ConnectionStats>,
    stats_by_thread: &HashMap<ThreadKey, ThreadStats>,
) {
    connection_stats.retain(|key, stats| {
        if stats.last_seen.elapsed() > PROCESS_EVICTION_TIMEOUT {
            return false;
        }
        stats_by_thread.contains_key(&ThreadKey {
            pid: key.pid,
            tid: key.tid,
        })
    });
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

// Publishes thread and interface snapshots to shared Arc<RwLock<...>> state.
fn publish_snapshots(
    stats_by_thread: &HashMap<ThreadKey, ThreadStats>,
    connection_cache: &[ResolvedConnection],
    connection_stats: &HashMap<ConnectionKey, ConnectionStats>,
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

    // Build connection list keyed by (pid, tid).
    let mut conn_by_thread: HashMap<ThreadKey, Vec<ConnectionEntry>> = HashMap::new();
    for conn in connection_cache {
        let key = ThreadKey { pid: conn.pid, tid: conn.tid };
        let stats_key = ConnectionKey {
            pid: conn.pid,
            tid: conn.tid,
            local_addr: conn.local_addr,
            remote_addr: conn.remote_addr,
            protocol: conn.protocol,
        };
        let reverse_key = ConnectionKey {
            pid: conn.pid,
            tid: conn.tid,
            local_addr: conn.remote_addr,
            remote_addr: conn.local_addr,
            protocol: conn.protocol,
        };

        let (tx_bytes, rx_bytes) = if let Some(stats) = connection_stats.get(&stats_key) {
            (stats.tx_bytes, stats.rx_bytes)
        } else if let Some(stats) = connection_stats.get(&reverse_key) {
            (stats.rx_bytes, stats.tx_bytes)
        } else {
            (0, 0)
        };

        conn_by_thread
            .entry(key)
            .or_default()
            .push(ConnectionEntry {
                local_addr: conn.local_addr,
                remote_addr: conn.remote_addr,
                protocol: conn.protocol,
                state: conn.state.clone(),
                pid: conn.pid,
                tid: conn.tid,
                process: conn.process.clone(),
                thread_name: conn.thread_name.clone(),
                username: conn.username.clone(),
                tx_bytes,
                rx_bytes,
            });
    }

    let mut rows = Vec::with_capacity(stats_by_thread.len());
    for (key, stats) in stats_by_thread {
        rows.push(ProcessRow {
            info: stats.info.clone(),
            tx_bytes: stats.tx_bytes_total,
            rx_bytes: stats.rx_bytes_total,
            last_seen: stats.last_seen,
            tx_history: stats.tx_history,
            rx_history: stats.rx_history,
            is_blocked: blocked.contains(&key.pid),
            connections: conn_by_thread.remove(key).unwrap_or_default(),
        });
    }

    // Sort by PID then TID for consistent ordering.
    rows.sort_by_key(|r| (r.info.pid, r.info.tid));

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