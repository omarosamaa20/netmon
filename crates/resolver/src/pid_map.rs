use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// (pid, tid, process_name, thread_name, uid)
pub(crate) type InodePidEntry = (u32, u32, String, String, u32);

/// Scans /proc/<PID>/task/<TID>/fd/ for every thread to find which thread
/// owns each socket inode. Returns a map of inode -> (pid, tid, process_name, thread_name, uid).
///
/// Thread-level granularity: for each PID we iterate /proc/<PID>/task/ to get
/// all TIDs. Each TID may have its own open sockets. The thread name comes from
/// /proc/<PID>/task/<TID>/comm; the process name from /proc/<PID>/comm.
/// When TID == PID the entry is the main thread.
pub(crate) fn build_inode_pid_map() -> HashMap<u64, InodePidEntry> {
    let mut inode_to_pid = HashMap::new();

    let proc_entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return inode_to_pid,
    };

    for entry_result in proc_entries {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let process_name = match read_comm(pid, None) {
            Some(name) => name,
            None => continue,
        };
        let process_uid = match read_process_effective_uid(pid) {
            Some(uid) => uid,
            None => continue,
        };

        // Scan all threads under /proc/<pid>/task/
        let task_path = entry.path().join("task");
        let task_entries = match fs::read_dir(&task_path) {
            Ok(entries) => entries,
            Err(_) => {
                // No task directory - scan fd directly at the process level
                scan_fd_dir(
                    &entry.path().join("fd"),
                    pid,
                    pid,
                    &process_name,
                    &process_name,
                    process_uid,
                    &mut inode_to_pid,
                );
                continue;
            }
        };

        for task_entry_result in task_entries {
            let task_entry = match task_entry_result {
                Ok(e) => e,
                Err(_) => continue,
            };

            let tid = match task_entry.file_name().to_string_lossy().parse::<u32>() {
                Ok(tid) => tid,
                Err(_) => continue,
            };

            // Thread name: use /proc/<pid>/task/<tid>/comm, fall back to process name.
            let thread_name = read_comm(pid, Some(tid)).unwrap_or_else(|| process_name.clone());

            scan_fd_dir(
                &task_entry.path().join("fd"),
                pid,
                tid,
                &process_name,
                &thread_name,
                process_uid,
                &mut inode_to_pid,
            );
        }
    }

    inode_to_pid
}

// Scans one fd directory and inserts inode entries keyed by socket inode.
fn scan_fd_dir(
    fd_path: &Path,
    pid: u32,
    tid: u32,
    process_name: &str,
    thread_name: &str,
    uid: u32,
    inode_to_pid: &mut HashMap<u64, InodePidEntry>,
) {
    let fd_entries = match fs::read_dir(fd_path) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for fd_entry_result in fd_entries {
        let fd_entry = match fd_entry_result {
            Ok(fd_entry) => fd_entry,
            Err(_) => continue,
        };

        let symlink_target = match fs::read_link(fd_entry.path()) {
            Ok(target) => target,
            Err(_) => continue,
        };

        if let Some(socket_inode) = parse_socket_inode(&symlink_target) {
            inode_to_pid.insert(
                socket_inode,
                (pid, tid, process_name.to_string(), thread_name.to_string(), uid),
            );
        }
    }
}

// Reads /proc/<pid>/comm or /proc/<pid>/task/<tid>/comm for a name.
fn read_comm(pid: u32, tid: Option<u32>) -> Option<String> {
    let path = match tid {
        Some(tid) => format!("/proc/{pid}/task/{tid}/comm"),
        None => format!("/proc/{pid}/comm"),
    };
    fs::read_to_string(path).ok().map(|t| t.trim().to_string())
}

// Reads effective UID from `/proc/<pid>/status` (Uid: real effective saved fs).
fn read_process_effective_uid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(path).ok()?;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let columns: Vec<&str> = rest.split_whitespace().collect();
            if columns.len() >= 2 {
                return columns[1].parse::<u32>().ok();
            }
        }
    }

    None
}

// Parses "socket:[<inode>]" symlink targets into the raw inode number.
fn parse_socket_inode(target: &Path) -> Option<u64> {
    let target_text = target.to_string_lossy();
    let prefix = "socket:[";

    if !target_text.starts_with(prefix) || !target_text.ends_with(']') {
        return None;
    }

    let inode_text = &target_text[prefix.len()..target_text.len() - 1];
    inode_text.parse::<u64>().ok()
}