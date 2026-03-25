//! Socket enumeration via the Linux Netlink SOCK_DIAG interface.
//!
//! This is the same kernel interface used by the `ss` command from iproute2.
//! It asks the kernel directly for a dump of all open sockets, returning
//! structured binary data in a single atomic operation. This avoids the
//! text-file parsing and O(n) overhead of reading /proc/net/tcp.
//!
//! The relevant kernel interface is AF_NETLINK with protocol NETLINK_SOCK_DIAG,
//! documented in netlink(7) and sock_diag(7) in the Linux man-pages.
//! The request message type is SOCK_DIAG_BY_FAMILY using the InetDiagReqV2
//! structure defined in <linux/inet_diag.h>.

use std::collections::HashMap;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use capture::Protocol;
use netlink_sys::{protocols, Socket, SocketAddr as NetlinkSocketAddr};

/// Bitmask selecting all socket states in inet_diag requests.
const REQUEST_SOCKET_STATES_ALL: u32 = u32::MAX;

/// Linux address family constant for IPv4.
const AF_INET_FAMILY: u8 = 2;

/// Linux address family constant for IPv6.
const AF_INET6_FAMILY: u8 = 10;

/// Linux IP protocol constant for TCP.
const IPPROTO_TCP_PROTOCOL: u8 = 6;

/// Linux IP protocol constant for UDP.
const IPPROTO_UDP_PROTOCOL: u8 = 17;

/// Netlink header type for SOCK_DIAG requests and responses.
const SOCK_DIAG_BY_FAMILY_TYPE: u16 = 20;

/// Netlink control message type indicating end of multipart dump.
const NLMSG_DONE_TYPE: u16 = 3;

/// Netlink control message type indicating kernel-side error response.
const NLMSG_ERROR_TYPE: u16 = 2;

/// Netlink request flag for request messages.
const NLM_F_REQUEST_FLAG: u16 = 0x0001;

/// Netlink request flag that expands to ROOT|MATCH dump behavior.
const NLM_F_DUMP_FLAG: u16 = 0x0300;

/// Netlink multipart dump flag.
const NLMSG_FLAG_DUMP_REQUEST: u16 = NLM_F_REQUEST_FLAG | NLM_F_DUMP_FLAG;

/// Sequence number used for all sock_diag requests from this process.
const NETLINK_REQUEST_SEQUENCE: u32 = 1;

/// Netlink receive buffer size in bytes.
const NETLINK_RECV_BUFFER_SIZE: usize = 1024 * 1024;

/// Kernel origin address for netlink requests.
const NETLINK_KERNEL_PORT_ID: u32 = 0;

/// Kernel group mask for unicast diagnostic queries.
const NETLINK_UNICAST_GROUPS: u32 = 0;

/// TCP state constants from <linux/tcp.h>.
const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_TIME_WAIT: u8 = 6;
const TCP_CLOSE: u8 = 7;
const TCP_CLOSE_WAIT: u8 = 8;
const TCP_LAST_ACK: u8 = 9;
const TCP_LISTEN: u8 = 10;
const TCP_CLOSING: u8 = 11;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NetlinkError {
    #[error("failed to open Netlink socket: {0}")]
    SocketOpen(std::io::Error),
    #[error("failed to send Netlink request: {0}")]
    SendFailed(std::io::Error),
    #[error("failed to receive Netlink response: {0}")]
    RecvFailed(std::io::Error),
    #[error("kernel returned a Netlink error message (errno {0})")]
    KernelError(i32),
    #[error("could not parse Netlink response message")]
    ParseError,
}

/// Holds the kernel-side socket metadata returned by a SOCK_DIAG query.
/// This is the Netlink equivalent of one row in /proc/net/tcp.
#[derive(Debug, Clone)]
pub(crate) struct SocketEntry {
    pub inode: u64,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: String,
    pub uid: u32,
    pub protocol: Protocol,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InetDiagSockIdRaw {
    idiag_sport: u16,
    idiag_dport: u16,
    idiag_src: [u32; 4],
    idiag_dst: [u32; 4],
    idiag_if: u32,
    idiag_cookie: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InetDiagReqV2Raw {
    sdiag_family: u8,
    sdiag_protocol: u8,
    idiag_ext: u8,
    pad: u8,
    idiag_states: u32,
    id: InetDiagSockIdRaw,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InetDiagMsgRaw {
    idiag_family: u8,
    idiag_state: u8,
    idiag_timer: u8,
    idiag_retrans: u8,
    id: InetDiagSockIdRaw,
    idiag_expires: u32,
    idiag_rqueue: u32,
    idiag_wqueue: u32,
    idiag_uid: u32,
    idiag_inode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NetlinkErrorMessageRaw {
    error: i32,
    msg: RawNlmsghdr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawNlmsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// Returns a map of socket inode to SocketEntry for all TCP and UDP sockets
/// currently open in the kernel, queried atomically via Netlink SOCK_DIAG.
pub(crate) fn query_sockets() -> Result<HashMap<u64, SocketEntry>, NetlinkError> {
    // Open a NETLINK_SOCK_DIAG socket. This is a special socket family the
    // Linux kernel provides for querying socket diagnostics without going
    // through the /proc filesystem. CAP_NET_ADMIN is not required; any
    // process can query its own sockets; root can query all sockets.
    let mut socket = Socket::new(protocols::NETLINK_SOCK_DIAG).map_err(NetlinkError::SocketOpen)?;
    socket.bind_auto().map_err(NetlinkError::SocketOpen)?;
    socket
        .connect(&NetlinkSocketAddr::new(
            NETLINK_KERNEL_PORT_ID,
            NETLINK_UNICAST_GROUPS,
        ))
        .map_err(NetlinkError::SocketOpen)?;

    let mut sockets_by_inode = HashMap::new();
    query_family_protocol(
        &mut socket,
        AF_INET_FAMILY,
        IPPROTO_TCP_PROTOCOL,
        Protocol::Tcp,
        &mut sockets_by_inode,
    )?;
    query_family_protocol(
        &mut socket,
        AF_INET_FAMILY,
        IPPROTO_UDP_PROTOCOL,
        Protocol::Udp,
        &mut sockets_by_inode,
    )?;
    query_family_protocol(
        &mut socket,
        AF_INET6_FAMILY,
        IPPROTO_TCP_PROTOCOL,
        Protocol::Tcp,
        &mut sockets_by_inode,
    )?;
    query_family_protocol(
        &mut socket,
        AF_INET6_FAMILY,
        IPPROTO_UDP_PROTOCOL,
        Protocol::Udp,
        &mut sockets_by_inode,
    )?;

    Ok(sockets_by_inode)
}

// Sends one inet_diag dump request and accumulates all socket rows from responses.
fn query_family_protocol(
    socket: &mut Socket,
    family: u8,
    protocol: u8,
    protocol_kind: Protocol,
    sockets_by_inode: &mut HashMap<u64, SocketEntry>,
) -> Result<(), NetlinkError> {
    let request_bytes = build_inet_diag_request(family, protocol)?;

    // Send the request. The kernel responds with a multipart Netlink message:
    // one SOCK_DIAG_BY_FAMILY message per matching socket, terminated by a
    // NLMSG_DONE message. We loop until we see NLMSG_DONE or an error.
    socket
        .send(&request_bytes, 0)
        .map_err(NetlinkError::SendFailed)?;

    let mut recv_buffer = vec![0u8; NETLINK_RECV_BUFFER_SIZE];
    loop {
        let received = socket
            .recv(&mut recv_buffer, 0)
            .map_err(NetlinkError::RecvFailed)?;
        if received == 0 {
            return Err(NetlinkError::ParseError);
        }

        let done = parse_response_messages(
            &recv_buffer[..received],
            protocol_kind,
            sockets_by_inode,
        )?;
        if done {
            break;
        }
    }

    Ok(())
}

// Builds one SOCK_DIAG_BY_FAMILY request payload for a family/protocol pair.
fn build_inet_diag_request(family: u8, protocol: u8) -> Result<Vec<u8>, NetlinkError> {
    // family: AF_INET or AF_INET6 selects IPv4 or IPv6 tables.
    // protocol: IPPROTO_TCP or IPPROTO_UDP selects transport protocol.
    // idiag_states: all bits set requests all kernel socket states.
    // id: zeroed InetDiagSockId means no endpoint filter, dump everything.
    let diag_request = InetDiagReqV2Raw {
        sdiag_family: family,
        sdiag_protocol: protocol,
        idiag_ext: 0,
        pad: 0,
        idiag_states: REQUEST_SOCKET_STATES_ALL,
        id: InetDiagSockIdRaw {
            idiag_sport: 0,
            idiag_dport: 0,
            idiag_src: [0; 4],
            idiag_dst: [0; 4],
            idiag_if: 0,
            idiag_cookie: [0; 2],
        },
    };

    let header = RawNlmsghdr {
        nlmsg_len: (size_of::<RawNlmsghdr>() + size_of::<InetDiagReqV2Raw>()) as u32,
        nlmsg_type: SOCK_DIAG_BY_FAMILY_TYPE,
        nlmsg_flags: NLMSG_FLAG_DUMP_REQUEST,
        nlmsg_seq: NETLINK_REQUEST_SEQUENCE,
        nlmsg_pid: 0,
    };

    let mut request = Vec::with_capacity(header.nlmsg_len as usize);
    append_struct_bytes(&mut request, &header);
    append_struct_bytes(&mut request, &diag_request);

    if request.is_empty() {
        return Err(NetlinkError::ParseError);
    }

    Ok(request)
}

// Parses one received netlink datagram and returns true when NLMSG_DONE appears.
fn parse_response_messages(
    response_bytes: &[u8],
    protocol_kind: Protocol,
    sockets_by_inode: &mut HashMap<u64, SocketEntry>,
) -> Result<bool, NetlinkError> {
    let mut offset = 0usize;
    let mut saw_done = false;

    while offset + size_of::<RawNlmsghdr>() <= response_bytes.len() {
        let header: RawNlmsghdr = read_struct(response_bytes, offset).ok_or(NetlinkError::ParseError)?;
        if header.nlmsg_len == 0 {
            return Err(NetlinkError::ParseError);
        }

        let message_len = header.nlmsg_len as usize;
        if offset + message_len > response_bytes.len() {
            return Err(NetlinkError::ParseError);
        }

        let payload_offset = offset + size_of::<RawNlmsghdr>();
        let payload_len = message_len.saturating_sub(size_of::<RawNlmsghdr>());
        let payload = &response_bytes[payload_offset..(payload_offset + payload_len)];

        if header.nlmsg_type == NLMSG_DONE_TYPE {
            saw_done = true;
            break;
        }

        if header.nlmsg_type == NLMSG_ERROR_TYPE {
            let kernel_error = parse_kernel_error(payload)?;
            return Err(NetlinkError::KernelError(kernel_error));
        }

        if header.nlmsg_type == SOCK_DIAG_BY_FAMILY_TYPE {
            let entry = parse_inet_diag_message(payload, protocol_kind)?;
            sockets_by_inode.insert(entry.inode, entry);
        }

        offset += nlmsg_align(message_len);
    }

    Ok(saw_done)
}

// Parses kernel NLMSG_ERROR payload and returns errno value.
fn parse_kernel_error(payload: &[u8]) -> Result<i32, NetlinkError> {
    let error_message: NetlinkErrorMessageRaw =
        read_struct(payload, 0).ok_or(NetlinkError::ParseError)?;
    if error_message.error == 0 {
        return Ok(0);
    }
    Ok(-error_message.error)
}

// Parses one inet_diag message payload into a resolver SocketEntry.
fn parse_inet_diag_message(payload: &[u8], protocol_kind: Protocol) -> Result<SocketEntry, NetlinkError> {
    let diag_message: InetDiagMsgRaw = read_struct(payload, 0).ok_or(NetlinkError::ParseError)?;
    let local_addr = socket_addr_from_diag(
        diag_message.idiag_family,
        diag_message.id.idiag_src,
        diag_message.id.idiag_sport,
    )
    .ok_or(NetlinkError::ParseError)?;
    let remote_addr = socket_addr_from_diag(
        diag_message.idiag_family,
        diag_message.id.idiag_dst,
        diag_message.id.idiag_dport,
    )
    .ok_or(NetlinkError::ParseError)?;

    Ok(SocketEntry {
        inode: u64::from(diag_message.idiag_inode),
        local_addr,
        remote_addr,
        state: tcp_state_to_str(diag_message.idiag_state).to_string(),
        uid: diag_message.idiag_uid,
        protocol: protocol_kind,
    })
}

// Builds a SocketAddr from inet_diag endpoint fields for IPv4 and IPv6.
fn socket_addr_from_diag(family: u8, addr_words: [u32; 4], raw_port: u16) -> Option<SocketAddr> {
    let port = u16::from_be(raw_port);

    if family == AF_INET_FAMILY {
        let ipv4 = Ipv4Addr::from(u32::from_be(addr_words[0]));
        return Some(SocketAddr::new(IpAddr::V4(ipv4), port));
    }

    if family == AF_INET6_FAMILY {
        let ipv6 = ipv6_from_be_words(addr_words);
        return Some(SocketAddr::new(IpAddr::V6(ipv6), port));
    }

    None
}

// Converts four big-endian u32 words into one IPv6 address.
fn ipv6_from_be_words(addr_words: [u32; 4]) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    for (index, word) in addr_words.iter().enumerate() {
        let network_word = u32::from_be(*word);
        let word_bytes = network_word.to_be_bytes();
        let start = index * 4;
        bytes[start..start + 4].copy_from_slice(&word_bytes);
    }
    Ipv6Addr::from(bytes)
}

// Converts a numeric TCP state value from the kernel's tcp_states enum
// into a human-readable string. Values come from <linux/tcp.h>.
fn tcp_state_to_str(state: u8) -> &'static str {
    match state {
        TCP_ESTABLISHED => "ESTABLISHED",
        TCP_SYN_SENT => "SYN_SENT",
        TCP_SYN_RECV => "SYN_RECV",
        TCP_FIN_WAIT1 => "FIN_WAIT1",
        TCP_FIN_WAIT2 => "FIN_WAIT2",
        TCP_TIME_WAIT => "TIME_WAIT",
        TCP_CLOSE => "CLOSE",
        TCP_CLOSE_WAIT => "CLOSE_WAIT",
        TCP_LAST_ACK => "LAST_ACK",
        TCP_LISTEN => "LISTEN",
        TCP_CLOSING => "CLOSING",
        _ => "UNKNOWN",
    }
}

// Aligns Netlink message lengths to 4-byte boundaries.
fn nlmsg_align(len: usize) -> usize {
    const NLMSG_ALIGNTO: usize = 4;
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

// Appends one plain old data struct to a byte buffer.
fn append_struct_bytes<T>(buffer: &mut Vec<u8>, value: &T) {
    let value_size = size_of::<T>();
    let value_ptr = (value as *const T).cast::<u8>();

    // SAFETY: `value_ptr` points to `value_size` initialized bytes owned by this
    // function call, and we only copy them into an output Vec without aliasing writes.
    let bytes = unsafe { std::slice::from_raw_parts(value_ptr, value_size) };
    buffer.extend_from_slice(bytes);
}

// Reads one C-compatible struct from a byte slice at the given offset.
fn read_struct<T: Copy>(bytes: &[u8], offset: usize) -> Option<T> {
    if offset + size_of::<T>() > bytes.len() {
        return None;
    }

    let ptr = bytes[offset..].as_ptr().cast::<T>();
    // SAFETY: bounds are checked above and `read_unaligned` handles possibly
    // unaligned netlink payload offsets returned by the kernel.
    Some(unsafe { ptr.read_unaligned() })
}
