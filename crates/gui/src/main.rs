#![deny(warnings)]

//! Renders the netmon desktop interface and coordinates capture, aggregation,
//! and controller actions from user input.
//!
//! This binary crate runs the `eframe` event loop, periodically reads immutable
//! snapshots from the aggregator thread, and shows process and connection data
//! in interactive tables and charts. User actions such as applying a BPF filter
//! or blocking a process call directly into the capture and controller crates.
//! The UI remains immediate-mode: each frame redraws from current shared state.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aggregator::{spawn_aggregator_thread, AggregatorControl, HistoryCsvRow, InterfaceStats, ProcessRow, ThreadKey};
use anyhow::Result;
use capture::{spawn_capture_thread, CaptureControl};
use eframe::egui::{self, Color32, RichText, ScrollArea};
use eframe::{App, Frame};
use egui_plot::{Line, Plot, PlotPoints};

/// Number of history points shown in traffic charts.
const CHART_HISTORY_SECONDS: usize = 300;

/// Number of samples used for short rolling rates.
const SHORT_RATE_WINDOW_SECONDS: usize = 2;

/// Default number of seconds shown by the live chart.
const DEFAULT_CHART_WINDOW_SECONDS: usize = 60;

/// UI repaint interval in milliseconds.
const UI_REPAINT_INTERVAL_MS: u64 = 16;

/// Join timeout for worker thread shutdown.
const THREAD_JOIN_TIMEOUT_SECS: u64 = 2;

/// Height of the process table scroll area.
const PROCESS_TABLE_HEIGHT: f32 = 320.0;

/// Height of the connection table scroll area.
const CONNECTION_TABLE_HEIGHT: f32 = 250.0;

/// Width at which the process/chart area switches from split to stacked.
const RESPONSIVE_STACK_WIDTH: f32 = 1200.0;

/// Height of the bandwidth chart area.
const CHART_HEIGHT: f32 = 300.0;

/// Per-second throughput threshold for orange warning rows.
const HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC: u64 = 1024 * 1024;

/// Per-second throughput threshold for red critical rows.
const VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC: u64 = 10 * 1024 * 1024;

/// Red tint used for blocked rows in the connection table.
const BLOCKED_ROW_COLOR: Color32 = Color32::from_rgb(255, 140, 140);

/// G-06: blocked processes must be visually distinct in the process table.
const BLOCKED_PROCESS_ROW_FILL: Color32 = Color32::from_rgb(70, 20, 20);

/// G-06: keep username text readable in a dedicated column.
const USER_COLUMN_MIN_WIDTH: f32 = 110.0;

/// Plot line color for TX bandwidth history.
const TX_LINE_COLOR: Color32 = Color32::from_rgb(80, 120, 240);

/// Plot line color for RX bandwidth history.
const RX_LINE_COLOR: Color32 = Color32::from_rgb(60, 180, 90);

/// Millisecond conversion helper for bits-per-second display.
const BITS_PER_BYTE: f64 = 8.0;

/// Binary scale used in byte/bit unit formatting.
const KIBI_BASE: f64 = 1024.0;

/// Process table PID column width.
const PROCESS_PID_WIDTH: f32 = 60.0;

/// Process table TID column width.
const PROCESS_TID_WIDTH: f32 = 60.0;

/// Process table process-name column width.
const PROCESS_NAME_WIDTH: f32 = 180.0;

/// Process table thread-name column width.
const PROCESS_THREAD_WIDTH: f32 = 180.0;

/// Process table bandwidth column width.
const PROCESS_BW_WIDTH: f32 = 88.0;

/// Process table total-byte column width.
const PROCESS_TOTAL_WIDTH: f32 = 96.0;

/// Connection table PID/TID width.
const CONNECTION_PID_WIDTH: f32 = 60.0;

/// Connection table thread-name width.
const CONNECTION_THREAD_WIDTH: f32 = 160.0;

/// Connection table process-name width.
const CONNECTION_PROCESS_WIDTH: f32 = 180.0;

/// Connection table address width.
const CONNECTION_ADDR_WIDTH: f32 = 160.0;

/// Connection table protocol/state width.
const CONNECTION_PROTO_WIDTH: f32 = 72.0;

/// Connection table traffic total width.
const CONNECTION_TOTAL_WIDTH: f32 = 96.0;

/// Path prefix used for session PCAP recordings.
const PCAP_SESSION_PREFIX: &str = "netmon_capture_";

/// Path prefix used for exported PCAP files.
const PCAP_EXPORT_PREFIX: &str = "netmon_export_";

#[derive(Clone)]
struct DeviceInfo {
    name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Pid,
    Tid,
    Process,
    Thread,
    User,
    ProtocolMix,
    TxRate,
    RxRate,
    TxTotal,
    RxTotal,
}

struct NetmonApp {
    devices: Vec<DeviceInfo>,
    selected_iface: usize,
    capture_control: Option<CaptureControl>,
    capture_running: Arc<AtomicBool>,
    app_running: Arc<AtomicBool>,

    tx_flow: SyncSender<capture::FlowRecord>,
    aggregator_control: Option<AggregatorControl>,

    rows_snapshot: Arc<RwLock<Vec<ProcessRow>>>,
    interface_snapshot: Arc<RwLock<InterfaceStats>>,
    status_snapshot: Arc<RwLock<String>>,
    blocked_pids: Arc<RwLock<HashSet<u32>>>,

    status_tx: Sender<String>,
    status_rx: Receiver<String>,

    selected_thread: Option<ThreadKey>,
    sort_column: SortColumn,
    sort_ascending: bool,

    is_capturing: bool,
    bpf_input: String,
    show_bits: bool,
    // G-10: tracks the last successfully applied BPF expression.
    active_filter: String,
    chart_window_seconds: usize,
    rate_limit_kbps_input: String,
    session_history_snapshot: Arc<RwLock<Vec<HistoryCsvRow>>>,
    capture_recording_path: Option<PathBuf>,
    pending_block: Option<(u32, String)>,
    virtualization_warning: bool,
}

impl NetmonApp {
    // Builds initial GUI state and starts the aggregator worker thread.
    fn new() -> Self {
        let devices = pcap::Device::list()
            .map(|list| {
                list.into_iter()
                    .map(|d| DeviceInfo { name: d.name })
                    .collect::<Vec<DeviceInfo>>()
            })
            .unwrap_or_default();

        let rows_snapshot = Arc::new(RwLock::new(Vec::new()));
        let interface_snapshot = Arc::new(RwLock::new(InterfaceStats::default()));
        let status_snapshot = Arc::new(RwLock::new("Ready".to_string()));
        let blocked_pids = Arc::new(RwLock::new(HashSet::new()));
        let session_history_snapshot = Arc::new(RwLock::new(Vec::new()));

        // Phase I Lesson WS-2: bounded channel provides backpressure between capture and UI pipeline.
        let (tx_flow, rx_flow) = mpsc::sync_channel::<capture::FlowRecord>(1024);
        let app_running = Arc::new(AtomicBool::new(true));

        let aggregator_control = Some(spawn_aggregator_thread(
            rx_flow,
            app_running.clone(),
            rows_snapshot.clone(),
            interface_snapshot.clone(),
            status_snapshot.clone(),
            blocked_pids.clone(),
            session_history_snapshot.clone(),
        ));

        let (status_tx, status_rx) = mpsc::channel::<String>();

        Self {
            devices,
            selected_iface: 0,
            capture_control: None,
            capture_running: Arc::new(AtomicBool::new(false)),
            app_running,
            tx_flow,
            aggregator_control,
            rows_snapshot,
            interface_snapshot,
            status_snapshot,
            blocked_pids,
            status_tx,
            status_rx,
            selected_thread: None,
            sort_column: SortColumn::Pid,
            sort_ascending: true,
            is_capturing: false,
            bpf_input: String::new(),
            show_bits: false,
            active_filter: String::new(),
            chart_window_seconds: DEFAULT_CHART_WINDOW_SECONDS,
            rate_limit_kbps_input: "1024".to_string(),
            session_history_snapshot,
            capture_recording_path: None,
            pending_block: None,
            virtualization_warning: detect_virtualbox(),
        }
    }

    // Starts packet capture on the currently selected interface.
    fn start_capture(&mut self) {
        if self.is_capturing || self.devices.is_empty() {
            return;
        }

        let iface = match self.devices.get(self.selected_iface) {
            Some(v) => v.name.clone(),
            None => return,
        };

        self.capture_running = Arc::new(AtomicBool::new(true));

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let recording_path = PathBuf::from(format!("{home}/{PCAP_SESSION_PREFIX}{ts}.pcap"));

        match spawn_capture_thread(
            &iface,
            Vec::new(),
            self.tx_flow.clone(),
            self.capture_running.clone(),
            self.status_tx.clone(),
            Some(recording_path.clone()),
        ) {
            Ok(control) => {
                self.capture_control = Some(control);
                self.capture_recording_path = Some(recording_path);
                self.is_capturing = true;
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Capturing on {iface}...");
                }
            }
            Err(e) => {
                self.capture_recording_path = None;
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Failed to start capture on {iface}: {e}");
                }
            }
        }
    }

    // Stops the active capture thread and updates status text.
    fn stop_capture(&mut self) {
        if !self.is_capturing {
            return;
        }

        self.capture_running.store(false, AtomicOrdering::Relaxed);

        if let Some(control) = self.capture_control.as_ref() {
            let _ = control.stop();
        }

        if let Some(mut control) = self.capture_control.take() {
            let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
        }

        self.is_capturing = false;
        if let Ok(mut status) = self.status_snapshot.write() {
            *status = "Capture stopped".to_string();
        }
    }

    // Restarts capture after an interface selection change.
    fn restart_capture_for_interface_change(&mut self) {
        let was_running = self.is_capturing;
        self.stop_capture();
        if was_running {
            self.start_capture();
        }
    }

    // Applies the current BPF expression through the capture control channel.
    fn apply_bpf_filter(&mut self) {
        if let Some(control) = self.capture_control.as_ref() {
            let expr = self.bpf_input.trim().to_string();
            if expr.is_empty() {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = "Enter a BPF expression before applying it".to_string();
                }
                return;
            }
            if let Err(e) = control.apply_filter(expr.clone()) {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("BPF error: {e}");
                }
            }
        } else if let Ok(mut status) = self.status_snapshot.write() {
            *status = "Cannot apply BPF: capture is not running".to_string();
        }
    }

    // Sorts process rows according to the selected column and direction.
    fn sorted_rows(&self, mut rows: Vec<ProcessRow>) -> Vec<ProcessRow> {
        rows.sort_by(|a, b| {
            let cmp = match self.sort_column {
                SortColumn::Pid => a.info.pid.cmp(&b.info.pid),
                SortColumn::Process => a.info.name.cmp(&b.info.name),
                SortColumn::User => a.info.username.cmp(&b.info.username),
                SortColumn::ProtocolMix => protocol_mix_summary(a).cmp(&protocol_mix_summary(b)),
                SortColumn::TxRate => two_second_avg(&a.tx_history).cmp(&two_second_avg(&b.tx_history)),
                SortColumn::RxRate => two_second_avg(&a.rx_history).cmp(&two_second_avg(&b.rx_history)),
                SortColumn::TxTotal => a.tx_bytes.cmp(&b.tx_bytes),
                SortColumn::RxTotal => a.rx_bytes.cmp(&b.rx_bytes),
                SortColumn::Tid => a.info.tid.cmp(&b.info.tid),
                SortColumn::Thread => a.info.thread_name.cmp(&b.info.thread_name),
            };

            if self.sort_ascending {
                cmp
            } else {
                match cmp {
                    Ordering::Less => Ordering::Greater,
                    Ordering::Equal => Ordering::Equal,
                    Ordering::Greater => Ordering::Less,
                }
            }
        });
        rows
    }

    // Updates sort state when the user clicks a process table header.
    fn set_sort(&mut self, col: SortColumn) {
        if self.sort_column == col {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = col;
            self.sort_ascending = true;
        }
    }

    // Clones the latest process snapshot from shared state.
    fn process_rows(&self) -> Vec<ProcessRow> {
        self.rows_snapshot
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    // Drains pending status messages sent from background threads.
    fn update_status_from_channel(&mut self) {
        while let Ok(msg) = self.status_rx.try_recv() {
            // G-10: keep last successful filter when invalid expressions fail.
            if let Some(applied_filter) = msg.strip_prefix("Filter applied: ") {
                self.active_filter = applied_filter.to_string();
            }

            // G-10: transition UI state to stopped when capture thread reports failure.
            if msg.starts_with("Capture stopped:") {
                self.is_capturing = false;
                self.capture_running.store(false, AtomicOrdering::Relaxed);
                if let Some(mut control) = self.capture_control.take() {
                    let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
                }
            }

            if let Ok(mut status) = self.status_snapshot.write() {
                *status = msg;
            }
        }
    }

    // Blocks one process through nftables and updates local blocked state.
    fn block_pid(&mut self, pid: u32, name: &str) {
        match controller::block_process(pid, name) {
            Ok(()) => {
                if let Ok(mut blocked) = self.blocked_pids.write() {
                    blocked.insert(pid);
                }
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Blocked {name} (PID {pid})");
                }
            }
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Block failed for PID {pid}: {e}");
                }
            }
        }
    }

    // Unblocks one process through nftables and updates local blocked state.
    fn unblock_pid(&mut self, pid: u32) {
        match controller::unblock_process(pid) {
            Ok(()) => {
                if let Ok(mut blocked) = self.blocked_pids.write() {
                    blocked.remove(&pid);
                }
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Unblocked PID {pid}");
                }
            }
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Unblock failed for PID {pid}: {e}");
                }
            }
        }
    }

    // Exports the current process snapshot to a timestamped CSV file.
    fn export_csv(&self) {
        let rows = self
            .session_history_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default();

        if rows.is_empty() {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "No session history captured yet".to_string();
            }
            return;
        }

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = format!("{home}/{PCAP_EXPORT_PREFIX}{ts}.csv");

        let mut file = match fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("CSV export failed: {e}");
                }
                return;
            }
        };

        let header =
            "timestamp,pid,tid,process,thread,user,uid,tx_bytes_total,rx_bytes_total,tx_2s_avg,rx_2s_avg,tx_10s_avg,rx_10s_avg\n";
        if file.write_all(header.as_bytes()).is_err() {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "CSV export failed while writing header".to_string();
            }
            return;
        }

        let mut rows = rows;
        rows.sort_by_key(|row| (row.timestamp, row.pid, row.tid));

        for row in rows {
            let line = format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                row.timestamp,
                row.pid,
                row.tid,
                sanitize_csv(&row.process),
                sanitize_csv(&row.thread),
                sanitize_csv(&row.user),
                row.uid,
                row.tx_bytes_total,
                row.rx_bytes_total,
                row.tx_2s_avg,
                row.rx_2s_avg,
                row.tx_10s_avg,
                row.rx_10s_avg
            );

            if file.write_all(line.as_bytes()).is_err() {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = "CSV export failed while writing rows".to_string();
                }
                return;
            }
        }

        if let Ok(mut status) = self.status_snapshot.write() {
            *status = format!("Exported CSV to {path}");
        }
    }

    // Exports the current capture session to a timestamped PCAP file.
    fn export_pcap(&self) {
        let Some(source_path) = self.capture_recording_path.as_ref() else {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "PCAP export unavailable: start capture first".to_string();
            }
            return;
        };

        if !source_path.exists() {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "PCAP export unavailable: no recording file yet".to_string();
            }
            return;
        }

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let destination_path = format!("{home}/{PCAP_EXPORT_PREFIX}{ts}.pcap");

        if let Err(error) = fs::copy(source_path, &destination_path) {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = format!("PCAP export failed: {error}");
            }
            return;
        }

        if let Ok(mut status) = self.status_snapshot.write() {
            *status = format!("Exported PCAP to {destination_path}");
        }
    }

    // Renders the top toolbar and interface bandwidth summary.
    fn render_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            self.render_virtualbox_warning(ui);
            self.render_toolbar_controls(ui);
            self.render_interface_summary(ui);
        });
    }

    // Renders the status bar with the latest background status message.
    fn render_status_panel(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            let text = self
                .status_snapshot
                .read()
                .map(|status_text| status_text.clone())
                .unwrap_or_else(|_| "Status unavailable".to_string());
            ui.label(text);
        });
    }

    // Renders process table, chart, and connection table in the main area.
    fn render_main_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let sorted_rows = self.sorted_rows(self.process_rows());
            self.render_process_and_chart_columns(ui, &sorted_rows);
            ui.separator();
            ui.heading("Connections");
            self.render_connection_table(ui, &sorted_rows);
        });
    }

    // Renders the VirtualBox warning banner when virtualized capture is detected.
    fn render_virtualbox_warning(&self, ui: &mut egui::Ui) {
        if self.virtualization_warning {
            ui.colored_label(
                Color32::YELLOW,
                "Warning: Running inside VirtualBox; promiscuous capture may be limited.",
            );
            ui.separator();
        }
    }

    // Renders interface selection, capture controls, and toolbar action buttons.
    fn render_toolbar_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Interface:");
            let interface_changed = self.render_interface_combo(ui);
            if interface_changed {
                self.restart_capture_for_interface_change();
            }

            self.render_capture_toggle_button(ui);

            ui.label("BPF Filter:");
            let response = ui.text_edit_singleline(&mut self.bpf_input);
            if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                self.apply_bpf_filter();
            }
            if ui.button("Apply BPF").clicked() {
                self.apply_bpf_filter();
            }

            ui.checkbox(&mut self.show_bits, "bits");
            ui.label("Chart window:");
            ui.add(egui::Slider::new(
                &mut self.chart_window_seconds,
                30..=CHART_HISTORY_SECONDS,
            )
            .step_by(10.0)
            .suffix("s"));

            if ui.button("Export CSV").clicked() {
                self.export_csv();
            }
            if ui.button("Export PCAP").clicked() {
                self.export_pcap();
            }
        });
    }

    // Renders the interface selection combo box and reports if selection changed.
    fn render_interface_combo(&mut self, ui: &mut egui::Ui) -> bool {
        let mut interface_changed = false;
        egui::ComboBox::from_id_source("iface_combo")
            .selected_text(
                self.devices
                    .get(self.selected_iface)
                    .map(|device| device.name.as_str())
                    .unwrap_or("No interfaces"),
            )
            .show_ui(ui, |ui| {
                for (index, device) in self.devices.iter().enumerate() {
                    if ui
                        .selectable_value(&mut self.selected_iface, index, &device.name)
                        .clicked()
                    {
                        interface_changed = true;
                    }
                }
            });
        interface_changed
    }

    // Renders the start/stop capture button based on current capture state.
    fn render_capture_toggle_button(&mut self, ui: &mut egui::Ui) {
        // G-07: explicit start/stop affordances for capture lifecycle control.
        if self.is_capturing {
            if ui.button("■ Stop").clicked() {
                self.stop_capture();
            }
            return;
        }

        if ui.button("▶ Start").clicked() {
            self.start_capture();
        }
    }

    // Renders aggregate interface TX/RX totals and current/peak bandwidth.
    fn render_interface_summary(&self, ui: &mut egui::Ui) {
        ui.separator();
        let interface_stats = self
            .interface_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default();

        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "TX Total: {}",
                format_bytes_or_bits(interface_stats.tx_bytes_total, self.show_bits)
            ));
            ui.label(format!(
                "RX Total: {}",
                format_bytes_or_bits(interface_stats.rx_bytes_total, self.show_bits)
            ));
            ui.label(format!(
                "Current BW: {}/s",
                format_bandwidth(interface_stats.current_bandwidth_bytes_per_sec)
            ));
            ui.label(format!(
                "Peak BW: {}/s",
                format_bandwidth(interface_stats.peak_bandwidth_bytes_per_sec)
            ));
            if !self.active_filter.is_empty() {
                // G-10: keep successful filter state visible after invalid attempts.
                ui.label(format!("Active Filter: {}", self.active_filter));
            }
        });
    }

    // Renders the process table and chart in either split or stacked form.
    fn render_process_and_chart_columns(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
        let available_width = ui.available_width();

        if available_width < RESPONSIVE_STACK_WIDTH {
            ui.vertical(|ui| {
                ui.heading("Processes");
                if let Some(column) = draw_process_table(ui, sorted_rows, self.show_bits, &mut self.selected_thread) {
                    self.set_sort(column);
                }

                ui.separator();
                ui.heading(format!("Chart (Last {}s)", self.chart_window_seconds));
                draw_chart(
                    ui,
                    sorted_rows,
                    self.selected_thread,
                    self.show_bits,
                    self.chart_window_seconds,
                );
            });
        } else {
            ui.columns(2, |columns| {
                columns[0].vertical(|ui| {
                    ui.heading("Processes");
                    if let Some(column) = draw_process_table(ui, sorted_rows, self.show_bits, &mut self.selected_thread) {
                        self.set_sort(column);
                    }
                });

                columns[1].vertical(|ui| {
                    ui.heading(format!("Chart (Last {}s)", self.chart_window_seconds));
                    draw_chart(
                        ui,
                        sorted_rows,
                        self.selected_thread,
                        self.show_bits,
                        self.chart_window_seconds,
                    );
                });
            });
        }

        self.render_selected_row_controls(ui, sorted_rows);
    }

    // Renders quick actions for the currently selected thread row.
    fn render_selected_row_controls(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
        let Some(selected_thread) = self.selected_thread else {
            return;
        };

        let Some(selected_row) = sorted_rows
            .iter()
            .find(|row| row.info.pid == selected_thread.pid && row.info.tid == selected_thread.tid) else {
            return;
        };

        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "Selected thread: {} / {} (PID {}, TID {}, user {})",
                selected_row.info.name,
                selected_row.info.thread_name,
                selected_row.info.pid,
                selected_row.info.tid,
                selected_row.info.username
            ));

            if ui.button("Block Process").clicked() {
                self.block_pid(selected_row.info.pid, &selected_row.info.name);
            }

            if ui.button("Block User").clicked() {
                self.block_user(&selected_row.info.username);
            }

            ui.label("Limit kbps:");
            ui.add(
                egui::TextEdit::singleline(&mut self.rate_limit_kbps_input).desired_width(72.0),
            );
            if ui.button("Limit Bandwidth").clicked() {
                self.limit_bandwidth(selected_row.info.pid, &selected_row.info.name);
            }
        });
    }

    // Renders the connection table and row-level context menu actions.
    fn render_connection_table(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
        let visible_connections = self.collect_visible_connections(sorted_rows);

        if let Some(selected_thread) = self.selected_thread {
            if let Some(selected_row) = sorted_rows
                .iter()
                .find(|row| row.info.pid == selected_thread.pid && row.info.tid == selected_thread.tid)
            {
                // G-06: selected-row header makes process-to-user ownership explicit.
                ui.label(format!(
                    "Process: {} (PID {}) | User: {}",
                    selected_row.info.name, selected_row.info.pid, selected_row.info.username
                ));
                ui.separator();
            }
        }

        ScrollArea::both().max_height(CONNECTION_TABLE_HEIGHT).show(ui, |ui| {
            egui::Grid::new("conn_grid").striped(true).show(ui, |ui| {
                draw_connection_table_header(ui);
                for (is_blocked, connection) in &visible_connections {
                    self.draw_connection_row(ui, *is_blocked, connection);
                }
            });
        });
    }

    // Collects connection rows for either the selected PID or all processes.
    fn collect_visible_connections(
        &self,
        sorted_rows: &[ProcessRow],
    ) -> Vec<(bool, aggregator::ConnectionEntry)> {
        let mut visible_connections = Vec::new();
        // TODO(future): async DNS resolution
        for row in sorted_rows {
            if self
                .selected_thread
                .is_none_or(|selected| selected.pid == row.info.pid && selected.tid == row.info.tid)
            {
                for connection in &row.connections {
                    visible_connections.push((row.is_blocked, connection.clone()));
                }
            }
        }
        visible_connections
    }

    // Draws one connection table row and attaches a context menu to PID cell.
    fn draw_connection_row(
        &mut self,
        ui: &mut egui::Ui,
        is_blocked: bool,
        connection: &aggregator::ConnectionEntry,
    ) {
        let row_color = if is_blocked {
            BLOCKED_ROW_COLOR
        } else {
            ui.visuals().text_color()
        };

        let pid_response = ui.add_sized(
            [CONNECTION_PID_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.pid.to_string()).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_PID_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.tid.to_string()).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_THREAD_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.thread_name.clone()).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_PROCESS_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.process.clone()).color(row_color)),
        );
        // G-02: show username directly on each connection row.
        ui.add_sized(
            [USER_COLUMN_MIN_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.username.clone()).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_ADDR_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.local_addr.to_string()).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_ADDR_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.remote_addr.to_string()).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_PROTO_WIDTH, 18.0],
            egui::Label::new(RichText::new(format_protocol(connection.protocol)).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_PROTO_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.state.clone()).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_TOTAL_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.tx_bytes.to_string()).color(row_color)),
        );
        ui.add_sized(
            [CONNECTION_TOTAL_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.rx_bytes.to_string()).color(row_color)),
        );
        ui.end_row();

        let pid = connection.pid;
        let process_name = connection.process.clone();
        pid_response.context_menu(|ui| {
            if ui.button("Block Process").clicked() {
                self.pending_block = Some((pid, process_name.clone()));
                ui.close_menu();
            }
            if ui.button("Block User").clicked() {
                self.block_user(&connection.username);
                ui.close_menu();
            }
            if ui.button("Limit Bandwidth").clicked() {
                self.limit_bandwidth(pid, &process_name);
                ui.close_menu();
            }
            if ui.button("Unblock Process").clicked() {
                self.unblock_pid(pid);
                ui.close_menu();
            }
        });
    }

    // Renders the confirmation dialog before inserting a block rule.
    fn render_block_confirmation_dialog(&mut self, ctx: &egui::Context) {
        if let Some((pid, process_name)) = self.pending_block.clone() {
            egui::Window::new("Confirm Block")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "Block all traffic for {process_name} (PID {pid})? This will insert an nftables rule. Confirm?"
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            self.block_pid(pid, &process_name);
                            self.pending_block = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_block = None;
                        }
                    });
                });
        }
    }
}

impl App for NetmonApp {
    // Renders one GUI frame from current shared snapshots and UI state.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        self.update_status_from_channel();

        // G-07: keyboard shortcut for quickly clearing process selection.
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.selected_thread = None;
        }

        self.render_top_panel(ctx);
        self.render_status_panel(ctx);
        self.render_main_panel(ctx);
        self.render_block_confirmation_dialog(ctx);
        // Phase I Lesson IF-4: deterministic repaint cadence keeps UI responsive under load.
        ctx.request_repaint_after(Duration::from_millis(UI_REPAINT_INTERVAL_MS));
    }
}

impl Drop for NetmonApp {
    // Stops worker threads and flushes netmon nft rules during application exit.
    fn drop(&mut self) {
        // G-03: coordinated shutdown sets stop flags, joins workers, then flushes nft rules.
        self.capture_running.store(false, AtomicOrdering::Relaxed);
        self.app_running.store(false, AtomicOrdering::Relaxed);

        if let Some(control) = self.capture_control.as_ref() {
            let _ = control.stop();
        }

        if let Some(mut control) = self.capture_control.take() {
            let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
        }

        if let Some(mut control) = self.aggregator_control.take() {
            let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
        }

        let _ = controller::unblock_all();
    }
}

// Draws the process table and returns the clicked sort column, if any.
fn draw_process_table(
    ui: &mut egui::Ui,
    rows: &[ProcessRow],
    show_bits: bool,
    selected_thread: &mut Option<ThreadKey>,
 ) -> Option<SortColumn> {
    let mut clicked_sort = None;
    let available_width = ui.available_width();
    let base_total_width = PROCESS_PID_WIDTH
        + PROCESS_NAME_WIDTH
        + USER_COLUMN_MIN_WIDTH
        + (PROCESS_BW_WIDTH * 3.0)
        + (PROCESS_TOTAL_WIDTH * 2.0)
        + PROCESS_TID_WIDTH
        + PROCESS_THREAD_WIDTH;
    let width_scale = (available_width / base_total_width).clamp(0.55, 1.6);
    let pid_width = PROCESS_PID_WIDTH * width_scale;
    let process_width = PROCESS_NAME_WIDTH * width_scale;
    let user_width = USER_COLUMN_MIN_WIDTH * width_scale;
    let bw_width = PROCESS_BW_WIDTH * width_scale;
    let total_width = PROCESS_TOTAL_WIDTH * width_scale;
    let tid_width = PROCESS_TID_WIDTH * width_scale;
    let thread_width = PROCESS_THREAD_WIDTH * width_scale;

    egui::Grid::new("process_header_grid")
        .striped(true)
        .show(ui, |ui| {
            if ui.add_sized([pid_width, 18.0], egui::Button::new("PID")).clicked() {
                clicked_sort = Some(SortColumn::Pid);
            }
            if ui
                .add_sized([process_width, 18.0], egui::Button::new("Process"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::Process);
            }
            if ui
                .add_sized([user_width, 18.0], egui::Button::new("User"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::User);
            }
            if ui.add_sized([bw_width, 18.0], egui::Button::new("Proto Mix")).clicked() {
                clicked_sort = Some(SortColumn::ProtocolMix);
            }
            if ui
                .add_sized([bw_width, 18.0], egui::Button::new("TX/s (2s)"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::TxRate);
            }
            if ui
                .add_sized([bw_width, 18.0], egui::Button::new("RX/s (2s)"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::RxRate);
            }
            if ui
                .add_sized([total_width, 18.0], egui::Button::new("TX Total"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::TxTotal);
            }
            if ui
                .add_sized([total_width, 18.0], egui::Button::new("RX Total"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::RxTotal);
            }
            if ui.add_sized([tid_width, 18.0], egui::Button::new("TID")).clicked() {
                clicked_sort = Some(SortColumn::Tid);
            }
            if ui
                .add_sized([thread_width, 18.0], egui::Button::new("Thread"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::Thread);
            }
            ui.end_row();
        });

    ScrollArea::both().max_height(PROCESS_TABLE_HEIGHT).show(ui, |ui| {
        for row in rows {
            let tx_rate = two_second_avg(&row.tx_history);
            let rx_rate = two_second_avg(&row.rx_history);
            // Phase I Lesson IF-3: highlight heavy senders to improve operator response speed.
            let hot_color = if tx_rate > VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC
                || rx_rate > VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC
            {
                Color32::RED
            } else if tx_rate > HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC
                || rx_rate > HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC
            {
                Color32::from_rgb(255, 140, 0)
            } else {
                ui.visuals().text_color()
            };

            let row_fill = if row.is_blocked {
                BLOCKED_PROCESS_ROW_FILL
            } else {
                Color32::TRANSPARENT
            };

            egui::Frame::none().fill(row_fill).show(ui, |ui| {
                ui.horizontal(|ui| {
                    let selected = *selected_thread == Some(ThreadKey { pid: row.info.pid, tid: row.info.tid });
                    let pid_response = ui.add_sized(
                        [pid_width, 18.0],
                        egui::Button::new(RichText::new(row.info.pid.to_string()).color(hot_color)).selected(selected),
                    );
                    if pid_response.clicked() {
                        if selected {
                            *selected_thread = None;
                        } else {
                            *selected_thread = Some(ThreadKey { pid: row.info.pid, tid: row.info.tid });
                        }
                    }
                    ui.add_sized(
                        [process_width, 18.0],
                        egui::Label::new(RichText::new(row.info.name.clone()).color(hot_color)),
                    );
                    let user_text = RichText::new(row.info.username.clone()).color(hot_color);
                    ui.add_sized([user_width, 18.0], egui::Label::new(user_text));
                    // Phase I Lesson WS-4: keep protocol split visible in the process table.
                    ui.add_sized(
                        [bw_width, 18.0],
                        egui::Label::new(RichText::new(protocol_mix_summary(row)).color(hot_color)),
                    );
                    // G-05: display throughput in human-readable per-second units.
                    ui.add_sized(
                        [bw_width, 18.0],
                        egui::Label::new(RichText::new(format_bandwidth(tx_rate)).color(hot_color)),
                    );
                    ui.add_sized(
                        [bw_width, 18.0],
                        egui::Label::new(RichText::new(format_bandwidth(rx_rate)).color(hot_color)),
                    );
                    ui.add_sized(
                        [total_width, 18.0],
                        egui::Label::new(RichText::new(format_bytes_or_bits(row.tx_bytes, show_bits)).color(hot_color)),
                    );
                    ui.add_sized(
                        [total_width, 18.0],
                        egui::Label::new(RichText::new(format_bytes_or_bits(row.rx_bytes, show_bits)).color(hot_color)),
                    );
                    ui.add_sized(
                        [tid_width, 18.0],
                        egui::Label::new(RichText::new(row.info.tid.to_string()).color(hot_color)),
                    );
                    ui.add_sized(
                        [thread_width, 18.0],
                        egui::Label::new(RichText::new(row.info.thread_name.clone()).color(hot_color)),
                    );
                });
            });
            ui.separator();
        }
    });

    clicked_sort
}

// Draws TX/RX chart lines for selected process or aggregate traffic.
fn draw_chart(
    ui: &mut egui::Ui,
    rows: &[ProcessRow],
    selected_thread: Option<ThreadKey>,
    _show_bits: bool,
    window_seconds: usize,
) {
    let window = window_seconds.clamp(1, CHART_HISTORY_SECONDS);

    let (tx_hist, rx_hist) = if let Some(selected_thread) = selected_thread {
        if let Some(row) = rows.iter().find(|r| {
            r.info.pid == selected_thread.pid && r.info.tid == selected_thread.tid
        }) {
            (row.tx_history, row.rx_history)
        } else {
            ([0; CHART_HISTORY_SECONDS], [0; CHART_HISTORY_SECONDS])
        }
    } else {
        let mut tx = [0u64; CHART_HISTORY_SECONDS];
        let mut rx = [0u64; CHART_HISTORY_SECONDS];
        for row in rows {
            for idx in 0..CHART_HISTORY_SECONDS {
                tx[idx] = tx[idx].saturating_add(row.tx_history[idx]);
                rx[idx] = rx[idx].saturating_add(row.rx_history[idx]);
            }
        }
        (tx, rx)
    };

    let tx_points = (0..window)
        .map(|i| [-(i as f64), bytes_to_kib_per_sec(tx_hist[i])])
        .collect::<PlotPoints>();
    let rx_points = (0..window)
        .map(|i| [-(i as f64), bytes_to_kib_per_sec(rx_hist[i])])
        .collect::<PlotPoints>();

    let tx_line = Line::new(tx_points).name("TX").color(TX_LINE_COLOR);
    let rx_line = Line::new(rx_points).name("RX").color(RX_LINE_COLOR);

    Plot::new("traffic_plot")
        .height(CHART_HEIGHT)
        // G-05: explicit axis labels for real-time demo clarity.
        .x_axis_label(format!("Last {window} seconds"))
        .y_axis_label("KB/s")
        .show(ui, |plot_ui| {
            plot_ui.line(tx_line);
            plot_ui.line(rx_line);
        });
}

// Draws the connection table header row.
fn draw_connection_table_header(ui: &mut egui::Ui) {
    ui.label(RichText::new("PID").strong());
    ui.label(RichText::new("TID").strong());
    ui.label(RichText::new("Thread").strong());
    ui.label(RichText::new("Process").strong());
    // G-02/G-06: user ownership must be visible in active socket rows.
    ui.label(RichText::new("User").strong());
    ui.label(RichText::new("Local").strong());
    ui.label(RichText::new("Remote").strong());
    ui.label(RichText::new("Proto").strong());
    ui.label(RichText::new("State").strong());
    ui.label(RichText::new("TX").strong());
    ui.label(RichText::new("RX").strong());
    ui.end_row();
}

impl NetmonApp {
    // Blocks every active PID currently associated with the given username.
    fn block_user(&mut self, username: &str) {
        let rows = self.process_rows();
        let mut blocked_pids = HashSet::new();
        let mut blocked_labels = Vec::new();
        let mut errors = Vec::new();

        for row in rows {
            if row.info.username != username || !blocked_pids.insert(row.info.pid) {
                continue;
            }

            match controller::block_process(row.info.pid, &row.info.name) {
                Ok(()) => {
                    blocked_labels.push(format!("{} (PID {})", row.info.name, row.info.pid));
                    if let Ok(mut blocked) = self.blocked_pids.write() {
                        blocked.insert(row.info.pid);
                    }
                }
                Err(error) => errors.push(format!("PID {}: {error}", row.info.pid)),
            }
        }

        if let Ok(mut status) = self.status_snapshot.write() {
            if !blocked_labels.is_empty() && errors.is_empty() {
                *status = format!("Blocked user {username}: {}", blocked_labels.join(", "));
            } else if !blocked_labels.is_empty() {
                *status = format!("Blocked user {username} with errors: {}", errors.join("; "));
            } else if errors.is_empty() {
                *status = format!("No active processes found for user {username}");
            } else {
                *status = format!("Failed to block user {username}: {}", errors.join("; "));
            }
        }
    }

    // Limits a selected PID using the controller's rate-limit hook.
    fn limit_bandwidth(&mut self, pid: u32, name: &str) {
        let rate_kbps = match self.rate_limit_kbps_input.trim().parse::<u32>() {
            Ok(value) if value > 0 => value,
            _ => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = "Enter a positive kbit/s value before limiting bandwidth".to_string();
                }
                return;
            }
        };

        match controller::rate_limit_process(pid, rate_kbps) {
            Ok(()) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Rate-limited {name} (PID {pid}) to {rate_kbps} kbit/s");
                }
            }
            Err(error) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Rate limit failed for PID {pid}: {error}");
                }
            }
        }
    }
}

// Computes a 2-second average from the newest two history samples.
fn two_second_avg(history: &[u64]) -> u64 {
    history[..SHORT_RATE_WINDOW_SECONDS]
        .iter()
        .copied()
        .sum::<u64>()
        / SHORT_RATE_WINDOW_SECONDS as u64
}

// Computes a 10-second average from the newest ten history samples.

// Converts bytes/s to KB/s for chart display.
fn bytes_to_kib_per_sec(bytes_per_sec: u64) -> f64 {
    (bytes_per_sec as f64) / KIBI_BASE
}

// G-05: helper for readable bandwidth rendering in tables and summary bars.
fn format_bandwidth(bytes_per_sec: u64) -> String {
    if bytes_per_sec < 1024 {
        return format!("{} B/s", bytes_per_sec);
    }
    if bytes_per_sec < 1024 * 1024 {
        return format!("{:.1} KB/s", (bytes_per_sec as f64) / KIBI_BASE);
    }
    format!("{:.1} MB/s", (bytes_per_sec as f64) / (KIBI_BASE * KIBI_BASE))
}

// Formats throughput as either byte or bit units based on UI toggle state.
fn format_bytes_or_bits(value: u64, bits: bool) -> String {
    if bits {
        format_scaled((value as f64) * BITS_PER_BYTE, ["b", "Kb", "Mb", "Gb", "Tb"])
    } else {
        format_scaled(value as f64, ["B", "KB", "MB", "GB", "TB"])
    }
}

// Formats one numeric value into a binary-scaled human-readable unit string.
fn format_scaled(mut value: f64, units: [&str; 5]) -> String {
    let mut idx = 0usize;
    while value >= KIBI_BASE && idx < units.len() - 1 {
        value /= KIBI_BASE;
        idx += 1;
    }
    format!("{value:.2} {}", units[idx])
}

// Maps the protocol enum to a short uppercase string for table rendering.
fn format_protocol(proto: capture::Protocol) -> &'static str {
    match proto {
        capture::Protocol::Tcp => "TCP",
        capture::Protocol::Udp => "UDP",
        capture::Protocol::Other(_) => "OTHER",
    }
}

// Summarizes protocol composition for one process row (TCP/UDP/OTHER counts).
fn protocol_mix_summary(row: &ProcessRow) -> String {
    let mut tcp = 0u32;
    let mut udp = 0u32;
    let mut other = 0u32;

    for conn in &row.connections {
        match conn.protocol {
            capture::Protocol::Tcp => tcp += 1,
            capture::Protocol::Udp => udp += 1,
            capture::Protocol::Other(_) => other += 1,
        }
    }

    format!("T:{tcp} U:{udp} O:{other}")
}

// Escapes problematic CSV characters in process and user names.
fn sanitize_csv(value: &str) -> String {
    value.replace('"', "'").replace(',', " ")
}

// Detects VirtualBox environment strings to show a capture limitation warning.
fn detect_virtualbox() -> bool {
    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .to_lowercase();
    let product = fs::read_to_string("/sys/class/dmi/id/product_name")
        .unwrap_or_default()
        .to_lowercase();

    host.contains("vbox") || product.contains("virtualbox")
}

// Checks Linux effective capabilities for CAP_NET_ADMIN and CAP_NET_RAW.
fn has_required_capabilities() -> bool {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(v) => v,
        Err(_) => return false,
    };

    let cap_eff_line = status.lines().find(|line| line.starts_with("CapEff:"));
    let cap_eff_hex = match cap_eff_line.and_then(|line| line.split_whitespace().nth(1)) {
        Some(v) => v,
        None => return false,
    };

    let cap_eff = match u64::from_str_radix(cap_eff_hex, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Linux capability bit index for CAP_NET_ADMIN.
    let cap_net_admin = 1u64 << 12;
    // Linux capability bit index for CAP_NET_RAW.
    let cap_net_raw = 1u64 << 13;

    (cap_eff & cap_net_admin) != 0 && (cap_eff & cap_net_raw) != 0
}

// Exits with code 1 unless the process is root or has required net capabilities.
fn ensure_privileges_or_exit() {
    // SAFETY: libc::geteuid has no preconditions and does not dereference pointers.
    let is_root = unsafe { libc::geteuid() == 0 };

    if is_root || has_required_capabilities() {
        return;
    }

    eprintln!(
        "Insufficient privileges. Run as root or grant CAP_NET_RAW and CAP_NET_ADMIN to this binary."
    );
    std::process::exit(1);
}

/// Starts the native egui application after privilege checks and nft setup.
fn main() -> Result<()> {
    ensure_privileges_or_exit();
    env_logger::init();

    let _ = controller::setup_nftables();

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Linux Network Monitor & Controller",
        options,
        Box::new(|_cc| Ok(Box::new(NetmonApp::new()))),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(())
}
