# Resolver

As identified in our Phase I tool survey, `ss` scales better than `netstat` because it uses the Netlink SOCK_DIAG interface instead of parsing `/proc/net/tcp` text. The resolver now follows that same design: it queries socket metadata from the kernel through SOCK_DIAG first, and only falls back to `/proc/net` parsing when Netlink is unavailable.

## Primary Path: Netlink SOCK_DIAG

Netlink is a kernel-to-user-space IPC channel used for Linux networking control and diagnostics. In this project we use AF_NETLINK with protocol NETLINK_SOCK_DIAG to request socket dumps directly from the kernel as structured binary data.

The request type is SOCK_DIAG_BY_FAMILY with InetDiagReqV2. One request is sent per address-family and protocol pair: IPv4 TCP, IPv4 UDP, IPv6 TCP, and IPv6 UDP. Four requests are needed because family and protocol are explicit filter fields in each dump request.

Each request returns a multipart netlink response: one diagnostic message per socket, followed by NLMSG_DONE. The resolver loops over the response stream, parses each InetDiagMsg into inode, local/remote address, state, and uid, and stops only when NLMSG_DONE is seen.

## Fallback Path: /proc/net/ Parsing

If the Netlink query fails, resolver logs a warning and switches to the fallback parser for `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`. This preserves functionality in restricted environments such as hardened containers where NETLINK_SOCK_DIAG may be blocked.

The fallback is slower because it parses large text files in user space and is O(n) in open sockets. It is also non-atomic in practice because each file read captures a point-in-time text snapshot rather than a single kernel-side diagnostic dump.

## The Inode Join

Both paths produce socket inode values, but GUI rows require PID and process name. Resolver performs an inode join by scanning `/proc/<PID>/fd/` symlinks for targets like `socket:[12345]`, then matching that inode to the socket entry from Netlink or fallback parsing.

After inode to PID mapping, resolver reads `/proc/<PID>/comm` for process name and `/proc/<PID>/status` for effective UID. UID values are mapped to usernames using `/etc/passwd` loaded into memory.

## Why not Netlink for the PID scan too?

SOCK_DIAG gives rich socket metadata such as inode, endpoints, state, and uid, but it does not provide stable PID ownership in the response format we use here. PID resolution still requires `/proc/<PID>/fd/` inode matching. This reflects Linux design trade-offs: kernel networking ownership is primarily modeled by uid, and sockets can survive process boundaries through `fork` and descriptor inheritance, so per-process attribution is reconstructed from the live fd table.
