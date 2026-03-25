# netmon

Netmon is a Linux desktop tool that captures live network traffic and shows it as per-process bandwidth and connection data in real time. It combines packet capture, process/user attribution, and traffic control in one interface so you can both observe and act from the same screen.

Traditional tools often make you choose between packet-level visibility and process-level visibility. Wireshark is strong at packet inspection, and tools like iftop are strong at interface-level traffic, but neither gives this project's built-in workflow of mapping flows to PID/username and then immediately blocking that process through nftables.

The end-to-end path is simple: a packet arrives on a network interface, the capture crate parses endpoint metadata into a FlowRecord, the resolver links that flow to a process via Netlink or /proc socket inodes, the aggregator updates per-process counters, and the GUI renders the result as rows, charts, and connection details.

The implementation is written in Rust and uses libpcap through the pcap crate for capture, egui/eframe for the GUI, and nftables via the nft CLI for blocking. This keeps the project native to Linux which is the target system of choice.

## Prerequisites

- Ubuntu 22.04 or 24.04 (bare metal or VM)
- Rust stable toolchain (install via rustup.rs)
- libpcap development headers:
  sudo apt-get install -y libpcap-dev nftables
- Root or CAP_NET_RAW + CAP_NET_ADMIN privileges

## Build

git clone <repo>
cd netmon
cargo build --release

## Run

sudo ./target/release/netmon

## Notes

- Running inside VirtualBox: the application will show a warning banner.
  Capture is limited to traffic destined for or originating from the VM.
- The nftables table `inet filter` will be created on first run if it does
  not already exist. Existing rules in that table are left untouched.
- All blocked-process rules are removed when the application exits cleanly.
  On a crash, run `sudo nft flush table inet filter` to clear leftover rules.
