# Capture

The pcap crate is a Rust wrapper around libpcap, which is the standard packet capture API on Linux and Unix-like systems. It is used here instead of raw AF_PACKET sockets because it provides a smaller and clearer implementation path for this project, including BPF filtering and straightforward capture handle configuration.

The capture handle is opened on the selected interface in promiscuous mode, with a 2 MB capture buffer and a 100 ms read timeout. Promiscuous mode allows the interface to see traffic visible to the NIC, the buffer reduces burst drops, and the timeout prevents the capture loop from blocking indefinitely so control commands can be handled quickly.

Each raw frame is parsed as Ethernet first. If the EtherType is IPv4 or IPv6 (including VLAN-tagged frames), the parser reads source and destination IP addresses, then source and destination ports from the TCP or UDP header. These values become a FlowKey, and the packet length plus timestamp become a FlowRecord.

BPF filters are applied at runtime by sending an ApplyFilter command to the capture thread, which calls capture.filter(expr, true) on the active handle. If the expression is invalid, the pcap error is sent back to the status line so the user gets immediate feedback without restarting capture.

Direction is recorded as Tx or Rx relative to local interface addresses. If the packet source IP matches a local IP, it is treated as Tx. If the destination matches local IP, it is treated as Rx. This directional tag is later used by the aggregator to maintain separate transmit and receive counters.
