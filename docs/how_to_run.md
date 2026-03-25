# How To Run

## 1. System Requirements

Use Ubuntu 22.04 or 24.04 with a desktop session. Run as root or grant CAP_NET_RAW and CAP_NET_ADMIN to the netmon binary.

## 2. Install Dependencies

Install required system packages:

```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev nftables
```

## 3. Build

From the workspace root:

```bash
cd netmon
cargo build --release
```

Expected result is a successful build and a binary at target/release/netmon.

## 4. Run

Run the application with privileges:

```bash
sudo ./target/release/netmon
```

You should see a native egui window with toolbar, process table, chart, and connection table.

## 5. Basic Usage Walkthrough

1. Select a network interface from the toolbar.
2. Click Start and watch process rows begin updating.
3. Identify a high-traffic process in TX/s or RX/s.
4. Right-click its connection row and choose Block Process.
5. Verify rule insertion with:

```bash
sudo nft list ruleset
```

6. Use Unblock Process from the context menu to remove the rule.

## 6. Common Issues

Permission denied opening capture device: run as root or assign capabilities to the binary.

nft: command not found: install nftables with sudo apt-get install -y nftables.

No interfaces listed: verify network interfaces are up and libpcap is installed correctly.

Warning about VirtualBox capture limits: this means the VM may only see traffic to or from that VM unless adapter mode allows broader visibility.

## 7. Manual nftables Cleanup After Crash

If the program exits unexpectedly, clear leftover output rules:

```bash
sudo nft flush chain inet filter output
```
