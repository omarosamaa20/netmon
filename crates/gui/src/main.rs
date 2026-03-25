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
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aggregator::{spawn_aggregator_thread, AggregatorControl, InterfaceStats, ProcessRow};
use anyhow::Result;
use capture::{spawn_capture_thread, CaptureControl};
use eframe::egui::{self, Color32, RichText, ScrollArea};
use eframe::{App, Frame};
use egui_plot::{Line, Plot, PlotPoints};

/// Number of history points shown in traffic charts.
const CHART_HISTORY_SECONDS: usize = 40;

/// UI repaint interval in milliseconds.
const UI_REPAINT_INTERVAL_MS: u64 = 16;

/// Join timeout for worker thread shutdown.
const THREAD_JOIN_TIMEOUT_SECS: u64 = 2;

/// Height of the process table scroll area.
const PROCESS_TABLE_HEIGHT: f32 = 320.0;

/// Height of the connection table scroll area.
const CONNECTION_TABLE_HEIGHT: f32 = 250.0;

/// Height of the bandwidth chart area.
const CHART_HEIGHT: f32 = 300.0;

/// Per-second throughput threshold for orange warning rows.
const HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC: u64 = 1024 * 1024;

/// Per-second throughput threshold for red critical rows.
const VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC: u64 = 10 * 1024 * 1024;

/// Red tint used for blocked rows in the connection table.
const BLOCKED_ROW_COLOR: Color32 = Color32::from_rgb(255, 140, 140);

/// Plot line color for TX bandwidth history.
const TX_LINE_COLOR: Color32 = Color32::from_rgb(80, 120, 240);

/// Plot line color for RX bandwidth history.
const RX_LINE_COLOR: Color32 = Color32::from_rgb(60, 180, 90);

/// Millisecond conversion helper for bits-per-second display.
const BITS_PER_BYTE: f64 = 8.0;

/// Decimal-thousand used in Kbps conversion.
const KILO_BASE_DECIMAL: f64 = 1000.0;

/// Binary scale used in byte/bit unit formatting.
const KIBI_BASE: f64 = 1024.0;

#[derive(Clone)]
struct DeviceInfo {
    name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Pid,
    Process,
    User,
    ProtocolMix,
    TxRate,
    RxRate,
    TxRate10s,
    RxRate10s,
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

    selected_pid: Option<u32>,
    sort_column: SortColumn,
    sort_ascending: bool,

    is_capturing: bool,
    bpf_input: String,
    show_bits: bool,
    dns_enabled: bool,
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
            selected_pid: None,
            sort_column: SortColumn::Pid,
            sort_ascending: true,
            is_capturing: false,
            bpf_input: String::new(),
            show_bits: false,
            dns_enabled: false,
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

        match spawn_capture_thread(
            &iface,
            Vec::new(),
            self.tx_flow.clone(),
            self.capture_running.clone(),
            self.status_tx.clone(),
        ) {
            Ok(control) => {
                self.capture_control = Some(control);
                self.is_capturing = true;
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Capturing on {iface}...");
                }
            }
            Err(e) => {
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
                SortColumn::TxRate => two_second_avg(a.tx_history).cmp(&two_second_avg(b.tx_history)),
                SortColumn::RxRate => two_second_avg(a.rx_history).cmp(&two_second_avg(b.rx_history)),
                SortColumn::TxRate10s => ten_second_avg(a.tx_history).cmp(&ten_second_avg(b.tx_history)),
                SortColumn::RxRate10s => ten_second_avg(a.rx_history).cmp(&ten_second_avg(b.rx_history)),
                SortColumn::TxTotal => a.tx_bytes.cmp(&b.tx_bytes),
                SortColumn::RxTotal => a.rx_bytes.cmp(&b.rx_bytes),
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
    fn update_status_from_channel(&self) {
        while let Ok(msg) = self.status_rx.try_recv() {
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
                    *status = format!("Blocked process {name} (PID {pid})");
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
        let rows = self.process_rows();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = format!("{home}/netmon_export_{ts}.csv");

        let mut file = match fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("CSV export failed: {e}");
                }
                return;
            }
        };

        // Phase I Lesson IF-1: export both short and medium rolling-rate windows.
        let header =
            "pid,process,user,uid,tx_bytes,rx_bytes,tx_2s_avg,rx_2s_avg,tx_10s_avg,rx_10s_avg\n";
        if file.write_all(header.as_bytes()).is_err() {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "CSV export failed while writing header".to_string();
            }
            return;
        }

        for row in rows {
            let line = format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                row.info.pid,
                sanitize_csv(&row.info.name),
                sanitize_csv(&row.info.username),
                row.info.uid,
                row.tx_bytes,
                row.rx_bytes,
                two_second_avg(row.tx_history),
                two_second_avg(row.rx_history),
                ten_second_avg(row.tx_history),
                ten_second_avg(row.rx_history)
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

    // Phase I Lesson TC-2: explicit placeholder for future packet-level export support.
    fn export_pcap_todo(&self) {
        if let Ok(mut status) = self.status_snapshot.write() {
            *status = "PCAP export is not implemented yet (TODO: capture sink + writer)".to_string();
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

            ui.checkbox(&mut self.show_bits, "bits");
            ui.checkbox(&mut self.dns_enabled, "DNS");

            if ui.button("Export CSV").clicked() {
                self.export_csv();
            }
            if ui.button("Export PCAP (TODO)").clicked() {
                self.export_pcap_todo();
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
        if self.is_capturing {
            if ui.button("Stop").clicked() {
                self.stop_capture();
            }
            return;
        }

        if ui.button("Start").clicked() {
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
                format_bytes_or_bits(interface_stats.current_bandwidth_bytes_per_sec, self.show_bits)
            ));
            ui.label(format!(
                "Peak BW: {}/s",
                format_bytes_or_bits(interface_stats.peak_bandwidth_bytes_per_sec, self.show_bits)
            ));
        });
    }

    // Renders the side-by-side process table and chart sections.
    fn render_process_and_chart_columns(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
        ui.columns(2, |columns| {
            columns[0].vertical(|ui| {
                ui.heading("Processes");
                if let Some(column) = draw_process_table(ui, sorted_rows, self.show_bits, &mut self.selected_pid)
                {
                    self.set_sort(column);
                }
            });

            columns[1].vertical(|ui| {
                ui.heading("Chart (Last 40s)");
                draw_chart(ui, sorted_rows, self.selected_pid, self.show_bits);
            });
        });
    }

    // Renders the connection table and row-level context menu actions.
    fn render_connection_table(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
        let visible_connections = self.collect_visible_connections(sorted_rows);

        ScrollArea::vertical().max_height(CONNECTION_TABLE_HEIGHT).show(ui, |ui| {
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
            if self.selected_pid.is_none() || self.selected_pid == Some(row.info.pid) {
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

        let pid_response = ui.selectable_label(false, RichText::new(connection.pid.to_string()).color(row_color));
        ui.label(RichText::new(connection.process.clone()).color(row_color));
        ui.label(RichText::new(connection.local_addr.to_string()).color(row_color));
        ui.label(RichText::new(connection.remote_addr.to_string()).color(row_color));
        ui.label(RichText::new(format_protocol(connection.protocol)).color(row_color));
        ui.label(RichText::new(connection.state.clone()).color(row_color));
        ui.label(RichText::new(connection.tx_bytes.to_string()).color(row_color));
        ui.label(RichText::new(connection.rx_bytes.to_string()).color(row_color));
        ui.end_row();

        let pid = connection.pid;
        let process_name = connection.process.clone();
        pid_response.context_menu(|ui| {
            if ui.button("Block Process").clicked() {
                self.pending_block = Some((pid, process_name.clone()));
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
    selected_pid: &mut Option<u32>,
 ) -> Option<SortColumn> {
    let mut clicked_sort = None;

    ui.horizontal(|ui| {
        if ui.button("PID").clicked() {
            clicked_sort = Some(SortColumn::Pid);
        }
        if ui.button("Process").clicked() {
            clicked_sort = Some(SortColumn::Process);
        }
        if ui.button("User").clicked() {
            clicked_sort = Some(SortColumn::User);
        }
        if ui.button("Proto Mix").clicked() {
            clicked_sort = Some(SortColumn::ProtocolMix);
        }
        if ui.button("TX/s (2s)").clicked() {
            clicked_sort = Some(SortColumn::TxRate);
        }
        if ui.button("RX/s (2s)").clicked() {
            clicked_sort = Some(SortColumn::RxRate);
        }
        if ui.button("TX/s (10s)").clicked() {
            clicked_sort = Some(SortColumn::TxRate10s);
        }
        if ui.button("RX/s (10s)").clicked() {
            clicked_sort = Some(SortColumn::RxRate10s);
        }
        if ui.button("TX Total").clicked() {
            clicked_sort = Some(SortColumn::TxTotal);
        }
        if ui.button("RX Total").clicked() {
            clicked_sort = Some(SortColumn::RxTotal);
        }
    });

    ScrollArea::vertical().max_height(PROCESS_TABLE_HEIGHT).show(ui, |ui| {
        for row in rows {
            let tx_rate = two_second_avg(row.tx_history);
            let rx_rate = two_second_avg(row.rx_history);
            let tx_rate_10s = ten_second_avg(row.tx_history);
            let rx_rate_10s = ten_second_avg(row.rx_history);
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

            ui.horizontal(|ui| {
                let selected = *selected_pid == Some(row.info.pid);
                if ui
                    .selectable_label(selected, RichText::new(row.info.pid.to_string()).color(hot_color))
                    .clicked()
                {
                    if selected {
                        *selected_pid = None;
                    } else {
                        *selected_pid = Some(row.info.pid);
                    }
                }
                ui.label(RichText::new(row.info.name.clone()).color(hot_color));
                ui.label(RichText::new(format!("{} ({})", row.info.username, row.info.uid)).color(hot_color));
                // Phase I Lesson WS-4: keep protocol split visible in the process table.
                ui.label(RichText::new(protocol_mix_summary(row)).color(hot_color));
                ui.label(RichText::new(format_bytes_or_bits(tx_rate, show_bits)).color(hot_color));
                ui.label(RichText::new(format_bytes_or_bits(rx_rate, show_bits)).color(hot_color));
                // Phase I Lesson IF-1: expose a smoother 10-second rate alongside 2-second rate.
                ui.label(RichText::new(format_bytes_or_bits(tx_rate_10s, show_bits)).color(hot_color));
                ui.label(RichText::new(format_bytes_or_bits(rx_rate_10s, show_bits)).color(hot_color));
                ui.label(RichText::new(format_bytes_or_bits(row.tx_bytes, show_bits)).color(hot_color));
                ui.label(RichText::new(format_bytes_or_bits(row.rx_bytes, show_bits)).color(hot_color));
            });
            ui.separator();
        }
    });

    clicked_sort
}

// Draws TX/RX chart lines for selected process or aggregate traffic.
fn draw_chart(ui: &mut egui::Ui, rows: &[ProcessRow], selected_pid: Option<u32>, _show_bits: bool) {
    // Phase I Lesson IF-2: fixed 40-second chart window gives immediate trend visibility.
    let (tx_hist, rx_hist) = if let Some(pid) = selected_pid {
        if let Some(row) = rows.iter().find(|r| r.info.pid == pid) {
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

    let tx_points = (0..CHART_HISTORY_SECONDS)
        .map(|i| [-(i as f64), bytes_to_kbps(tx_hist[i])])
        .collect::<PlotPoints>();
    let rx_points = (0..CHART_HISTORY_SECONDS)
        .map(|i| [-(i as f64), bytes_to_kbps(rx_hist[i])])
        .collect::<PlotPoints>();

    let tx_line = Line::new(tx_points).name("TX").color(TX_LINE_COLOR);
    let rx_line = Line::new(rx_points).name("RX").color(RX_LINE_COLOR);

    Plot::new("traffic_plot")
        .height(CHART_HEIGHT)
        .x_axis_label("Seconds")
        .y_axis_label("Kbps")
        .show(ui, |plot_ui| {
            plot_ui.line(tx_line);
            plot_ui.line(rx_line);
        });
}

// Draws the connection table header row.
fn draw_connection_table_header(ui: &mut egui::Ui) {
    ui.label(RichText::new("PID").strong());
    ui.label(RichText::new("Process").strong());
    ui.label(RichText::new("Local").strong());
    ui.label(RichText::new("Remote").strong());
    ui.label(RichText::new("Proto").strong());
    ui.label(RichText::new("State").strong());
    ui.label(RichText::new("TX").strong());
    ui.label(RichText::new("RX").strong());
    ui.end_row();
}

// Computes a 2-second average from the newest two history samples.
fn two_second_avg(history: [u64; CHART_HISTORY_SECONDS]) -> u64 {
    (history[0] + history[1]) / 2
}

// Computes a 10-second average from the newest ten history samples.
fn ten_second_avg(history: [u64; CHART_HISTORY_SECONDS]) -> u64 {
    history[0..10].iter().copied().sum::<u64>() / 10
}

// Converts bytes per second into kilobits per second for chart display.
fn bytes_to_kbps(bytes_per_sec: u64) -> f64 {
    (bytes_per_sec as f64) * BITS_PER_BYTE / KILO_BASE_DECIMAL
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
