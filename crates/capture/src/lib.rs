#![deny(warnings)]

//! Captures live packets from a Linux interface and converts raw frames into
//! flow-oriented records that the aggregator thread can consume.
//!
//! This crate is called by the GUI crate when capture starts or when a BPF
//! filter changes. It owns the libpcap handle, parses Ethernet/IP/TCP/UDP
//! headers, and emits `FlowRecord` messages over a bounded channel. The parser
//! intentionally keeps only transport endpoints and protocol metadata because
//! per-packet payload inspection is out of scope for this project.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use log::{debug, error};
use pcap::{Active, Capture};
use thiserror::Error;

/// libpcap capture buffer size in bytes.
/// 2 MB keeps short bursts from dropping packets under desktop traffic.
const PCAP_BUFFER_SIZE_BYTES: i32 = 2 * 1024 * 1024;

/// libpcap read timeout in milliseconds.
/// 100 ms prevents a busy loop while keeping UI updates responsive.
/// G-03: pcap blocks for up to this timeout, avoiding busy-wait polling.
const PCAP_READ_TIMEOUT_MS: i32 = 100;

/// Ethernet II header length in bytes.
const ETHERNET_HEADER_LEN: usize = 14;

/// VLAN-tagged Ethernet header length in bytes.
const VLAN_ETHERNET_HEADER_LEN: usize = 18;

/// Ethertype for IPv4 payloads.
const ETHERTYPE_IPV4: u16 = 0x0800;

/// Ethertype for IPv6 payloads.
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Ethertype for 802.1Q VLAN tag.
const ETHERTYPE_VLAN_8021Q: u16 = 0x8100;

/// Ethertype for 802.1ad QinQ VLAN tag.
const ETHERTYPE_VLAN_8021AD: u16 = 0x88a8;

/// IPv4 minimum header length in bytes.
const IPV4_MIN_HEADER_LEN: usize = 20;

/// IPv6 fixed header length in bytes.
const IPV6_HEADER_LEN: usize = 40;

/// TCP protocol number in IP headers.
const IP_PROTOCOL_TCP: u8 = 6;

/// UDP protocol number in IP headers.
const IP_PROTOCOL_UDP: u8 = 17;

/// Join timeout error message for the capture thread.
const CAPTURE_THREAD_JOIN_TIMEOUT_MSG: &str = "capture thread join timed out";

/// Panic error message for the capture thread.
const CAPTURE_THREAD_PANIC_MSG: &str = "capture thread panicked";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Tx,
    Rx,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub byte_count: u32,
    pub timestamp: Instant,
    pub direction: Direction,
}

#[derive(Debug, Clone)]
pub enum CaptureCommand {
    ApplyFilter(String),
    Stop,
}

#[derive(Debug)]
pub struct CaptureControl {
    cmd_tx: Sender<CaptureCommand>,
    join_handle: Option<JoinHandle<()>>,
}

impl CaptureControl {
    /// Applies a BPF expression on the running capture thread.
    pub fn apply_filter(&self, expr: String) -> Result<(), CaptureError> {
        self.cmd_tx
            .send(CaptureCommand::ApplyFilter(expr))
            .map_err(|e| CaptureError::ChannelSend(e.to_string()))
    }

    /// Requests a graceful stop of the running capture thread.
    pub fn stop(&self) -> Result<(), CaptureError> {
        self.cmd_tx
            .send(CaptureCommand::Stop)
            .map_err(|e| CaptureError::ChannelSend(e.to_string()))
    }

    /// Joins the capture thread and propagates panic state as an error.
    pub fn join(&mut self) -> Result<(), CaptureError> {
        if let Some(handle) = self.join_handle.take() {
            handle
                .join()
                .map_err(|_| CaptureError::ThreadJoin(CAPTURE_THREAD_PANIC_MSG.to_string()))?;
        }
        Ok(())
    }

    /// Joins the capture thread with a timeout so shutdown cannot block forever.
    pub fn join_timeout(&mut self, timeout: Duration) -> Result<(), CaptureError> {
        if let Some(handle) = self.join_handle.take() {
            let (result_sender, result_receiver) = mpsc::channel();
            thread::spawn(move || {
                let result = handle.join();
                let _ = result_sender.send(result);
            });

            match result_receiver.recv_timeout(timeout) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(CaptureError::ThreadJoin(CAPTURE_THREAD_PANIC_MSG.to_string())),
                Err(_) => Err(CaptureError::ThreadJoin(CAPTURE_THREAD_JOIN_TIMEOUT_MSG.to_string())),
            }
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("capture channel send failed: {0}")]
    ChannelSend(String),
    #[error("capture thread join failed: {0}")]
    ThreadJoin(String),
}

/// Spawns the capture thread for one interface and returns its control handle.
///
/// Opens libpcap in promiscuous mode, sets buffer and timeout options, then
/// streams parsed packets into the provided bounded channel.
pub fn spawn_capture_thread(
    interface: &str,
    local_ips: Vec<IpAddr>,
    flow_sender: SyncSender<FlowRecord>,
    running: Arc<AtomicBool>,
    status_tx: Sender<String>,
) -> Result<CaptureControl, CaptureError> {
    let inactive = Capture::from_device(interface)?;
    let mut capture = inactive
        .promisc(true)
        .buffer_size(PCAP_BUFFER_SIZE_BYTES)
        .timeout(PCAP_READ_TIMEOUT_MS)
        .open()?;

    let (command_sender, command_receiver) = mpsc::channel::<CaptureCommand>();
    let status_interface = interface.to_string();

    let join_handle = thread::spawn(move || {
        let _ = status_tx.send(format!("Capturing on {status_interface}..."));
        run_capture_loop(
            &mut capture,
            &local_ips,
            flow_sender,
            running,
            command_receiver,
            status_tx,
        );
    });

    Ok(CaptureControl {
        cmd_tx: command_sender,
        join_handle: Some(join_handle),
    })
}

// Runs the packet read loop and exits only on stop/disconnect conditions.
fn run_capture_loop(
    capture: &mut Capture<Active>,
    local_ips: &[IpAddr],
    flow_sender: SyncSender<FlowRecord>,
    running: Arc<AtomicBool>,
    command_receiver: Receiver<CaptureCommand>,
    status_tx: Sender<String>,
) {
    while running.load(Ordering::Relaxed) {
        if handle_pending_commands(capture, &command_receiver, &status_tx) {
            return;
        }

        match capture.next_packet() {
            Ok(packet) => {
                if let Some(record) = parse_packet(packet.data, packet.header.len, local_ips) {
                    if flow_sender.send(record).is_err() {
                        return;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                // G-10: fail closed on interface errors and notify GUI instead of spinning.
                error!("capture read error: {e}");
                running.store(false, Ordering::Relaxed);
                let _ = status_tx.send(
                    "Capture stopped: interface went down. Select an interface and click Start.".to_string(),
                );
                return;
            }
        }
    }
}

// Handles queued control commands and returns true when capture should stop.
fn handle_pending_commands(
    capture: &mut Capture<Active>,
    command_receiver: &Receiver<CaptureCommand>,
    status_tx: &Sender<String>,
) -> bool {
    loop {
        match command_receiver.try_recv() {
            Ok(CaptureCommand::ApplyFilter(filter_expression)) => {
                // Phase I Lesson WS-1: apply kernel-space BPF to reduce user-space load.
                match capture.filter(&filter_expression, true) {
                    Ok(()) => {
                        let _ = status_tx.send(format!("Filter applied: {filter_expression}"));
                    }
                    Err(error) => {
                        let _ = status_tx.send(format!("BPF error: {error}"));
                    }
                }
            }
            Ok(CaptureCommand::Stop) => return true,
            Err(mpsc::TryRecvError::Empty) => return false,
            Err(mpsc::TryRecvError::Disconnected) => return true,
        }
    }
}

// Parses one Ethernet frame and returns a flow record when the frame is IP.
fn parse_packet(
    packet_bytes: &[u8],
    packet_len: u32,
    local_ips: &[IpAddr],
) -> Option<FlowRecord> {
    if packet_bytes.len() < ETHERNET_HEADER_LEN {
        debug!("G-01: skipped short ethernet frame");
        return None;
    }

    let ether_type = u16::from_be_bytes([packet_bytes[12], packet_bytes[13]]);
    let mut l3_offset = ETHERNET_HEADER_LEN;
    let mut current_ether_type = ether_type;

    if current_ether_type == ETHERTYPE_VLAN_8021Q || current_ether_type == ETHERTYPE_VLAN_8021AD {
        if packet_bytes.len() < VLAN_ETHERNET_HEADER_LEN {
            debug!("G-01: skipped short vlan-tagged ethernet frame");
            return None;
        }
        current_ether_type = u16::from_be_bytes([packet_bytes[16], packet_bytes[17]]);
        l3_offset = VLAN_ETHERNET_HEADER_LEN;
    }

    let parsed = match current_ether_type {
        ETHERTYPE_IPV4 => parse_ipv4(packet_bytes, l3_offset)?,
        ETHERTYPE_IPV6 => parse_ipv6(packet_bytes, l3_offset)?,
        _ => {
            debug!("G-01: skipped non-IP ethernet frame");
            return None;
        }
    };

    let direction = classify_direction(local_ips, parsed.src_ip, parsed.dst_ip);

    Some(FlowRecord {
        key: FlowKey {
            src_ip: parsed.src_ip,
            dst_ip: parsed.dst_ip,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
            protocol: parsed.protocol,
        },
        byte_count: packet_len,
        timestamp: Instant::now(),
        direction,
    })
}

// Classifies traffic as TX or RX by comparing endpoints with local interface IPs.
fn classify_direction(local_ips: &[IpAddr], src_ip: IpAddr, dst_ip: IpAddr) -> Direction {
    // Phase I Lesson WS-3: classify each flow as TX/RX for directional bandwidth accounting.
    if local_ips.contains(&src_ip) {
        return Direction::Tx;
    }
    if local_ips.contains(&dst_ip) {
        return Direction::Rx;
    }
    Direction::Tx
}

struct ParsedL4 {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: Protocol,
}

// Parses an IPv4 packet and extracts source/destination IP and L4 ports.
fn parse_ipv4(packet_bytes: &[u8], layer3_offset: usize) -> Option<ParsedL4> {
    if packet_bytes.len() < layer3_offset + IPV4_MIN_HEADER_LEN {
        debug!("G-01: skipped short ipv4 header");
        return None;
    }

    let version_ihl = packet_bytes[layer3_offset];
    if version_ihl >> 4 != 4 {
        debug!("G-01: skipped non-ipv4 frame in ipv4 parser");
        return None;
    }

    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || packet_bytes.len() < layer3_offset + ihl {
        debug!("G-01: skipped invalid ipv4 ihl");
        return None;
    }

    let protocol_number = packet_bytes[layer3_offset + 9];
    let src_ip = Ipv4Addr::new(
        packet_bytes[layer3_offset + 12],
        packet_bytes[layer3_offset + 13],
        packet_bytes[layer3_offset + 14],
        packet_bytes[layer3_offset + 15],
    );
    let dst_ip = Ipv4Addr::new(
        packet_bytes[layer3_offset + 16],
        packet_bytes[layer3_offset + 17],
        packet_bytes[layer3_offset + 18],
        packet_bytes[layer3_offset + 19],
    );

    let layer4_offset = layer3_offset + ihl;
    if packet_bytes.len() < layer4_offset + 4 {
        debug!("G-01: skipped short ipv4 transport header");
        return None;
    }

    let src_port = u16::from_be_bytes([packet_bytes[layer4_offset], packet_bytes[layer4_offset + 1]]);
    let dst_port =
        u16::from_be_bytes([packet_bytes[layer4_offset + 2], packet_bytes[layer4_offset + 3]]);

    let protocol = protocol_from_num(protocol_number);
    if matches!(protocol, Protocol::Other(_)) {
        debug!("G-01: skipped non-TCP/UDP ipv4 packet");
        return None;
    }

    Some(ParsedL4 {
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol,
    })
}

// Parses an IPv6 packet and extracts source/destination IP and L4 ports.
fn parse_ipv6(packet_bytes: &[u8], layer3_offset: usize) -> Option<ParsedL4> {
    if packet_bytes.len() < layer3_offset + IPV6_HEADER_LEN {
        debug!("G-01: skipped short ipv6 header");
        return None;
    }

    let version = packet_bytes[layer3_offset] >> 4;
    if version != 6 {
        debug!("G-01: skipped non-ipv6 frame in ipv6 parser");
        return None;
    }

    let next_header = packet_bytes[layer3_offset + 6];
    let src_ip = read_ipv6_address(packet_bytes, layer3_offset + 8)?;
    let dst_ip = read_ipv6_address(packet_bytes, layer3_offset + 24)?;

    let layer4_offset = layer3_offset + IPV6_HEADER_LEN;
    if packet_bytes.len() < layer4_offset + 4 {
        debug!("G-01: skipped short ipv6 transport header");
        return None;
    }

    let src_port = u16::from_be_bytes([packet_bytes[layer4_offset], packet_bytes[layer4_offset + 1]]);
    let dst_port =
        u16::from_be_bytes([packet_bytes[layer4_offset + 2], packet_bytes[layer4_offset + 3]]);

    let protocol = protocol_from_num(next_header);
    if matches!(protocol, Protocol::Other(_)) {
        debug!("G-01: skipped non-TCP/UDP ipv6 packet");
        return None;
    }

    Some(ParsedL4 {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        src_port,
        dst_port,
        protocol,
    })
}

// Reads a single IPv6 address from a byte slice at the given start offset.
fn read_ipv6_address(packet_bytes: &[u8], offset: usize) -> Option<Ipv6Addr> {
    if packet_bytes.len() < offset + 16 {
        debug!("G-01: skipped short ipv6 address field");
        return None;
    }

    let mut addr_bytes = [0u8; 16];
    addr_bytes.copy_from_slice(&packet_bytes[offset..(offset + 16)]);
    Some(Ipv6Addr::from(addr_bytes))
}

// Maps the IP next-header value to the project protocol enum.
fn protocol_from_num(protocol_number: u8) -> Protocol {
    match protocol_number {
        IP_PROTOCOL_TCP => Protocol::Tcp,
        IP_PROTOCOL_UDP => Protocol::Udp,
        other => Protocol::Other(other),
    }
}
