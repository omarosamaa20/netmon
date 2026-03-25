# Overview

Netmon is a Linux desktop tool that captures live network traffic and shows it as per-process bandwidth and connection data in real time. It combines packet capture, process/user attribution, and traffic control in one interface so you can both observe and act from the same screen.

Traditional tools often make you choose between packet-level visibility and process-level visibility. Wireshark is strong at packet inspection, and tools like iftop are strong at interface-level traffic, but neither gives this project's built-in workflow of mapping flows to PID/username and then immediately blocking that process through nftables.

The end-to-end path is simple: a packet arrives on a network interface, the capture crate parses endpoint metadata into a FlowRecord, the resolver links that flow to a process via Netlink or /proc socket inodes, the aggregator updates per-process counters, and the GUI renders the result as rows, charts, and connection details.

The implementation is written in Rust and uses libpcap through the pcap crate for capture, egui/eframe for the GUI, and nftables via the nft CLI for blocking. This keeps the project native to Linux which is the target system of choice.
