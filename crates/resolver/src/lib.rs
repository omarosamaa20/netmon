#![deny(warnings)]

//! Resolves captured socket flows to owning processes by preferring a Netlink
//! SOCK_DIAG query and falling back to `/proc/net` parsing when needed.
//!
//! This crate is used by the aggregator to annotate `FlowRecord` values with
//! process and user information. The primary strategy asks the kernel for
//! socket metadata through Netlink in one dump, then joins socket inodes with
//! `/proc/<PID>/fd` symlinks to obtain PIDs. The fallback path keeps behavior
//! available in restricted environments where Netlink queries are blocked.

mod netlink;
mod pid_map;
mod proc_fallback;

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use capture::{FlowKey, Protocol};
use thiserror::Error;

use netlink::SocketEntry;
use pid_map::InodePidEntry;

/// Refresh interval cap for expensive resolver scans.
const RESOLVER_REFRESH_PERIOD: Duration = Duration::from_secs(1);

/// Name used when a flow cannot be mapped to a process.
const UNKNOWN_LABEL: &str = "[unknown]";

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub uid: u32,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedConnection {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: Protocol,
    pub state: String,
    pub inode: u64,
    pub pid: u32,
    pub process: String,
    pub uid: u32,
    pub username: String,
}

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("fallback resolver error: {0}")]
    Fallback(String),
}

pub struct ResolverCache {
    uid_map: HashMap<u32, String>,
    inode_to_process: HashMap<u64, ProcessInfo>,
    socket_entries: HashMap<u64, SocketEntry>,
    connections: Vec<ResolvedConnection>,
    last_refresh: Instant,
}

impl ResolverCache {
    /// Creates an empty cache and loads UID to username mapping from `/etc/passwd`.
    pub fn new() -> Result<Self, ResolverError> {
        Ok(Self {
            uid_map: load_uid_map()?,
            inode_to_process: HashMap::new(),
            socket_entries: HashMap::new(),
            connections: Vec::new(),
            last_refresh: Instant::now() - Duration::from_secs(5),
        })
    }

    // Refreshes the inode-to-process map using the best available strategy.
    //
    // Preferred path: Netlink SOCK_DIAG (see netlink.rs). This is the approach
    // used internally by the `ss` command and recommended in our Phase I survey
    // report. It queries the kernel atomically in a single round-trip and is
    // significantly faster than /proc parsing on systems with many open sockets.
    //
    // Fallback path: /proc/net/ text parsing (see proc_fallback.rs). Used only
    // when Netlink is unavailable. Slower and non-atomic, but works in all
    // Linux environments.
    pub fn refresh(&mut self) -> Result<(), ResolverError> {
        // Phase I Lesson NS-1: prefer Netlink SOCK_DIAG over /proc text scanning.
        let socket_inodes = match netlink::query_sockets() {
            Ok(inodes) => {
                log::debug!("Netlink SOCK_DIAG query succeeded ({} sockets)", inodes.len());
                inodes
            }
            Err(e) => {
                // Phase I Lesson NS-2: keep a robust /proc fallback path when Netlink fails.
                log::warn!(
                    "Netlink SOCK_DIAG unavailable ({}), falling back to /proc/net/ parsing. \
                     This is slower and produces point-in-time snapshots rather than \
                     atomic kernel-side dumps.",
                    e
                );
                proc_fallback::read_proc_net().map_err(|fallback_error| {
                    ResolverError::Fallback(fallback_error.to_string())
                })?
            }
        };

        let inode_pid_map = pid_map::build_inode_pid_map();
        let inode_to_process = build_inode_process_map(&socket_inodes, &inode_pid_map, &self.uid_map);
        let connections = build_connections(&socket_inodes, &inode_pid_map, &self.uid_map);

        self.socket_entries = socket_inodes;
        self.inode_to_process = inode_to_process;
        self.connections = connections;
        self.last_refresh = Instant::now();
        Ok(())
    }

    /// Returns process info for a socket inode if present in the current cache.
    pub fn lookup(&self, inode: u64) -> Option<&ProcessInfo> {
        self.inode_to_process.get(&inode)
    }

    /// Refreshes cache only when stale according to the configured refresh period.
    pub fn refresh_if_needed(&mut self) -> Result<(), ResolverError> {
        // Phase I Lesson NS-3: throttle expensive ownership refresh operations.
        if self.last_refresh.elapsed() < RESOLVER_REFRESH_PERIOD {
            return Ok(());
        }
        self.refresh()
    }

    /// Finds process ownership for a flow by matching endpoints to cached sockets.
    pub fn resolve_flow_owner(&mut self, flow: &FlowKey) -> Option<ProcessInfo> {
        let _ = self.refresh_if_needed();

        for socket_entry in self.socket_entries.values() {
            if socket_entry.protocol != flow.protocol {
                continue;
            }

            let forward_match = socket_entry.local_addr.ip() == flow.src_ip
                && socket_entry.local_addr.port() == flow.src_port
                && socket_entry.remote_addr.ip() == flow.dst_ip
                && socket_entry.remote_addr.port() == flow.dst_port;

            let reverse_match = socket_entry.local_addr.ip() == flow.dst_ip
                && socket_entry.local_addr.port() == flow.dst_port
                && socket_entry.remote_addr.ip() == flow.src_ip
                && socket_entry.remote_addr.port() == flow.src_port;

            if !forward_match && !reverse_match {
                continue;
            }

            if let Some(info) = self.lookup(socket_entry.inode) {
                return Some(info.clone());
            }
        }

        None
    }

    /// Returns the latest connection snapshot that powers the GUI table.
    pub fn list_connections(&mut self) -> Vec<ResolvedConnection> {
        let _ = self.refresh_if_needed();
        self.connections.clone()
    }

    /// Returns process metadata for one PID from the current cache snapshot.
    pub fn process_by_pid(&mut self, pid: u32) -> Option<ProcessInfo> {
        let _ = self.refresh_if_needed();
        self.inode_to_process
            .values()
            .find(|info| info.pid == pid)
            .cloned()
    }
}

pub struct Resolver {
    cache: ResolverCache,
}

impl Resolver {
    /// Creates a resolver instance with an empty cache.
    pub fn new() -> Result<Self, ResolverError> {
        Ok(Self {
            cache: ResolverCache::new()?,
        })
    }

    /// Refreshes cache only when stale, preserving existing caller behavior.
    pub fn refresh_if_needed(&mut self) -> Result<(), ResolverError> {
        self.cache.refresh_if_needed()
    }

    /// Resolves one captured flow to process ownership metadata.
    pub fn resolve_flow_owner(&mut self, flow: &FlowKey) -> Option<ProcessInfo> {
        self.cache.resolve_flow_owner(flow)
    }

    /// Lists resolved connections from the current cache snapshot.
    pub fn list_connections(&mut self) -> Vec<ResolvedConnection> {
        self.cache.list_connections()
    }

    /// Looks up process info by PID from the current cache snapshot.
    pub fn process_by_pid(&mut self, pid: u32) -> Option<ProcessInfo> {
        self.cache.process_by_pid(pid)
    }
}

/// Resolves one flow by creating a short-lived resolver instance.
///
/// This helper keeps compatibility with call sites that use function-style
/// resolution instead of storing a long-lived `Resolver`.
pub fn resolve(flow: &FlowKey) -> Option<ProcessInfo> {
    let mut resolver = Resolver::new().ok()?;
    let _ = resolver.refresh_if_needed();
    resolver.resolve_flow_owner(flow)
}

/// Scans and returns all currently resolved sockets belonging to one PID.
pub fn scan_connections_for_pid(pid: u32) -> Vec<ResolvedConnection> {
    let mut resolver = match Resolver::new() {
        Ok(v) => v,
        Err(e) => {
            log::warn!("resolver init failed while scanning pid connections: {e}");
            return Vec::new();
        }
    };

    let _ = resolver.refresh_if_needed();
    resolver
        .list_connections()
        .into_iter()
        .filter(|connection| connection.pid == pid)
        .collect()
}

// Builds inode-to-process rows by joining sockets with inode->PID scan results.
fn build_inode_process_map(
    socket_entries: &HashMap<u64, SocketEntry>,
    inode_pid_map: &HashMap<u64, InodePidEntry>,
    uid_map: &HashMap<u32, String>,
) -> HashMap<u64, ProcessInfo> {
    let mut inode_to_process = HashMap::with_capacity(socket_entries.len());

    for inode in socket_entries.keys() {
        if let Some((pid, process_name, uid)) = inode_pid_map.get(inode) {
            let username = uid_map
                .get(uid)
                .cloned()
                .unwrap_or_else(|| UNKNOWN_LABEL.to_string());

            inode_to_process.insert(
                *inode,
                ProcessInfo {
                    pid: *pid,
                    name: process_name.clone(),
                    uid: *uid,
                    username,
                },
            );
        } else {
            inode_to_process.insert(
                *inode,
                ProcessInfo {
                    pid: 0,
                    name: UNKNOWN_LABEL.to_string(),
                    uid: 0,
                    username: UNKNOWN_LABEL.to_string(),
                },
            );
        }
    }

    inode_to_process
}

// Builds connection rows for GUI consumers from socket and PID metadata.
fn build_connections(
    socket_entries: &HashMap<u64, SocketEntry>,
    inode_pid_map: &HashMap<u64, InodePidEntry>,
    uid_map: &HashMap<u32, String>,
) -> Vec<ResolvedConnection> {
    let mut connections = Vec::with_capacity(socket_entries.len());

    for socket_entry in socket_entries.values() {
        let default_uid = socket_entry.uid;
        let (pid, process, uid) = inode_pid_map
            .get(&socket_entry.inode)
            .cloned()
            .unwrap_or((0, UNKNOWN_LABEL.to_string(), default_uid));
        let username = uid_map
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| UNKNOWN_LABEL.to_string());

        connections.push(ResolvedConnection {
            local_addr: socket_entry.local_addr,
            remote_addr: socket_entry.remote_addr,
            protocol: socket_entry.protocol,
            state: socket_entry.state.clone(),
            inode: socket_entry.inode,
            pid,
            process,
            uid,
            username,
        });
    }

    connections
}

// Loads `/etc/passwd` into UID-to-username mapping for display.
fn load_uid_map() -> Result<HashMap<u32, String>, io::Error> {
    let passwd = fs::File::open("/etc/passwd")?;
    let reader = io::BufReader::new(passwd);
    let mut uid_map = HashMap::new();

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(line) => line,
            Err(_) => continue,
        };
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 3 {
            continue;
        }
        if let Ok(uid) = parts[2].parse::<u32>() {
            uid_map.insert(uid, parts[0].to_string());
        }
    }

    Ok(uid_map)
}
