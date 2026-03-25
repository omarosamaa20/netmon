//! Fallback socket enumeration by parsing /proc/net/ text files.
//!
//! This module exists only as a fallback for environments where the Netlink
//! SOCK_DIAG interface is unavailable (e.g., restricted containers). It is
//! not the preferred path. As documented in the Phase I survey report, the
//! /proc approach has two drawbacks compared to Netlink: it is O(n) in the
//! number of open sockets, and it produces a point-in-time text snapshot
//! rather than an atomic kernel-side dump. Prefer the Netlink path whenever
//! possible.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use capture::Protocol;

use crate::netlink::SocketEntry;

/// Number of parsed columns required to read inode and endpoint fields.
const PROC_NET_MIN_COLUMNS: usize = 10;

/// Hex string length for IPv4 addresses in `/proc/net/*`.
const PROC_IPV4_HEX_LEN: usize = 8;

/// Hex string length for IPv6 addresses in `/proc/net/*`.
const PROC_IPV6_HEX_LEN: usize = 32;

/// Placeholder uid when `/proc/net` row does not expose one reliably.
const UNKNOWN_UID: u32 = 0;

#[derive(Debug, thiserror::Error)]
pub(crate) enum FallbackError {
    #[error("could not open {path}: {source}")]
    FileOpen { path: String, source: std::io::Error },
    #[error("could not parse line in {file}: \"{line}\"")]
    ParseLine { file: String, line: String },
}

/// Reads socket rows from `/proc/net` files and returns inode-indexed entries.
pub(crate) fn read_proc_net() -> Result<HashMap<u64, SocketEntry>, FallbackError> {
    let mut sockets_by_inode = HashMap::<u64, SocketEntry>::new();

    read_proc_file("/proc/net/tcp", Protocol::Tcp, true, &mut sockets_by_inode)?;
    read_proc_file("/proc/net/tcp6", Protocol::Tcp, false, &mut sockets_by_inode)?;
    read_proc_file("/proc/net/udp", Protocol::Udp, true, &mut sockets_by_inode)?;
    read_proc_file("/proc/net/udp6", Protocol::Udp, false, &mut sockets_by_inode)?;

    Ok(sockets_by_inode)
}

// Reads and parses one `/proc/net/*` file into inode-indexed socket entries.
fn read_proc_file(
    file_path: &str,
    protocol: Protocol,
    is_ipv4: bool,
    sockets_by_inode: &mut HashMap<u64, SocketEntry>,
) -> Result<(), FallbackError> {
    // G-03: this read opens one /proc file per call and drops the handle immediately after read.
    let content = fs::read_to_string(file_path).map_err(|source| FallbackError::FileOpen {
        path: file_path.to_string(),
        source,
    })?;

    for (line_index, line) in content.lines().enumerate() {
        if line_index == 0 {
            continue;
        }

        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < PROC_NET_MIN_COLUMNS {
            return Err(FallbackError::ParseLine {
                file: file_path.to_string(),
                line: line.to_string(),
            });
        }

        // Column 1: local address in the form "IP_HEX:PORT_HEX".
        // The address hex uses little-endian words in `/proc/net` text output.
        let local_addr = parse_proc_socket_addr(columns[1], is_ipv4).ok_or_else(|| {
            FallbackError::ParseLine {
                file: file_path.to_string(),
                line: line.to_string(),
            }
        })?;

        // Column 2: remote address in the same encoded form as column 1.
        let remote_addr = parse_proc_socket_addr(columns[2], is_ipv4).ok_or_else(|| {
            FallbackError::ParseLine {
                file: file_path.to_string(),
                line: line.to_string(),
            }
        })?;

        // Column 3: TCP state code as hex (ignored for UDP rows).
        let state = parse_tcp_state(columns[3], protocol);

        // Column 9: socket inode as a decimal integer string.
        let inode = columns[9].parse::<u64>().map_err(|_| FallbackError::ParseLine {
            file: file_path.to_string(),
            line: line.to_string(),
        })?;

        sockets_by_inode.insert(
            inode,
            SocketEntry {
                inode,
                local_addr,
                remote_addr,
                state,
                uid: UNKNOWN_UID,
                protocol,
            },
        );
    }

    Ok(())
}

// Parses one `/proc/net/*` endpoint token into a SocketAddr.
fn parse_proc_socket_addr(endpoint_text: &str, is_ipv4: bool) -> Option<SocketAddr> {
    let mut split = endpoint_text.split(':');
    let ip_hex = split.next()?;
    let port_hex = split.next()?;

    // The port value is hexadecimal network-byte-order u16.
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if is_ipv4 {
        if ip_hex.len() != PROC_IPV4_HEX_LEN {
            return None;
        }

        // IPv4 is encoded as little-endian hex u32 in `/proc/net/tcp`.
        // Example: 0F02000A -> bytes [0A,00,02,0F] -> 10.0.2.15.
        let raw = u32::from_str_radix(ip_hex, 16).ok()?;
        let octets = raw.to_le_bytes();
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        return Some(SocketAddr::new(IpAddr::V4(ip), port));
    }

    if ip_hex.len() != PROC_IPV6_HEX_LEN {
        return None;
    }

    // IPv6 is encoded as four little-endian u32 words concatenated as hex.
    let mut bytes = [0u8; 16];
    for word_index in 0..4 {
        let start = word_index * 8;
        let word_hex = &ip_hex[start..start + 8];
        let raw_word = u32::from_str_radix(word_hex, 16).ok()?;
        let word_bytes = raw_word.to_le_bytes();
        bytes[word_index * 4] = word_bytes[0];
        bytes[word_index * 4 + 1] = word_bytes[1];
        bytes[word_index * 4 + 2] = word_bytes[2];
        bytes[word_index * 4 + 3] = word_bytes[3];
    }

    Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port))
}

// Converts kernel TCP state hex values from `/proc/net/tcp*` to text labels.
fn parse_tcp_state(state_hex: &str, protocol: Protocol) -> String {
    if protocol != Protocol::Tcp {
        return "UNCONN".to_string();
    }

    let state_value = match u8::from_str_radix(state_hex, 16) {
        Ok(value) => value,
        Err(_) => return "UNKNOWN".to_string(),
    };

    match state_value {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
    .to_string()
}
