use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{EngineError, EngineResult};
use crate::resp::{write_array_header, write_bulk_string, write_integer};

#[derive(Clone, Debug)]
pub struct SlowLogEntry {
    pub id: u64,
    pub unix_timestamp: u64,
    pub duration_us: u64,
    pub client_id: u64,
    pub args: Vec<Box<[u8]>>,
}

struct RingEntries {
    buf: Vec<SlowLogEntry>,
    head: usize,
    len: usize,
    cap: usize,
}

impl RingEntries {
    fn with_capacity(cap: usize) -> Self {
        let actual = cap.max(16);
        let mut buf = Vec::with_capacity(actual);
        for _ in 0..actual {
            buf.push(SlowLogEntry {
                id: 0,
                unix_timestamp: 0,
                duration_us: 0,
                client_id: 0,
                args: Vec::new(),
            });
        }
        Self {
            buf,
            head: 0,
            len: 0,
            cap: actual,
        }
    }

    fn push(&mut self, entry: SlowLogEntry) {
        let pos = (self.head + self.len) % self.cap;
        if self.len < self.cap {
            self.buf[pos] = entry;
            self.len += 1;
        } else {
            self.buf[self.head] = entry;
            self.head = (self.head + 1) % self.cap;
        }
    }

    fn newest_first(&self, max_count: usize) -> Vec<SlowLogEntry> {
        let take = max_count.min(self.len);
        let mut out = Vec::with_capacity(take);
        for i in 0..take {
            let offset_from_newest = self.len - 1 - i;
            let idx = (self.head + offset_from_newest) % self.cap;
            out.push(self.buf[idx].clone());
        }
        out
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

/// Bounded ring-buffer `SlowLog` + operational metrics collector.
pub struct TelemetryHub {
    next_slowlog_id: AtomicU64,
    slowlog_threshold_us: AtomicU64,
    slowlog: Mutex<RingEntries>,
    pub tx_committed_total: AtomicU64,
    pub tx_aborted_total: AtomicU64,
    pub auth_failures_total: AtomicU64,
    pub scripts_executed_total: AtomicU64,
}

impl Default for TelemetryHub {
    fn default() -> Self {
        Self::new(128, 10_000)
    }
}

impl TelemetryHub {
    pub fn new(max_entries: usize, threshold_us: u64) -> Self {
        Self {
            next_slowlog_id: AtomicU64::new(1),
            slowlog_threshold_us: AtomicU64::new(threshold_us),
            slowlog: Mutex::new(RingEntries::with_capacity(max_entries)),
            tx_committed_total: AtomicU64::new(0),
            tx_aborted_total: AtomicU64::new(0),
            auth_failures_total: AtomicU64::new(0),
            scripts_executed_total: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn threshold_us(&self) -> u64 {
        self.slowlog_threshold_us.load(AtomicOrdering::Relaxed)
    }

    #[inline]
    pub fn set_threshold_us(&self, us: u64) {
        self.slowlog_threshold_us.store(us, AtomicOrdering::Relaxed);
    }

    pub fn record_command(&self, client_id: u64, duration_us: u64, args: &[&[u8]]) {
        let thresh = self.slowlog_threshold_us.load(AtomicOrdering::Relaxed);
        if duration_us < thresh {
            return;
        }
        let id = self.next_slowlog_id.fetch_add(1, AtomicOrdering::Relaxed);
        let unix_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let owned_args: Vec<Box<[u8]>> = args
            .iter()
            .take(8)
            .map(|s| s.iter().copied().take(128).collect::<Vec<u8>>().into_boxed_slice())
            .collect();

        if let Ok(mut guard) = self.slowlog.lock() {
            guard.push(SlowLogEntry {
                id,
                unix_timestamp,
                duration_us,
                client_id,
                args: owned_args,
            });
        }
    }

    pub fn slowlog_len(&self) -> EngineResult<usize> {
        let guard = self
            .slowlog
            .lock()
            .map_err(|_| EngineError::LockPoisoned("slowlog mutex"))?;
        Ok(guard.len)
    }

    pub fn slowlog_reset(&self) -> EngineResult<()> {
        let mut guard = self
            .slowlog
            .lock()
            .map_err(|_| EngineError::LockPoisoned("slowlog mutex"))?;
        guard.clear();
        Ok(())
    }

    pub fn slowlog_get_into(&self, count: usize, out: &mut Vec<u8>) -> EngineResult<()> {
        let entries = {
            let guard = self
                .slowlog
                .lock()
                .map_err(|_| EngineError::LockPoisoned("slowlog mutex"))?;
            guard.newest_first(count)
        };
        write_array_header(out, entries.len());
        for entry in entries {
            write_array_header(out, 4);
            write_integer(out, entry.id as i64);
            write_integer(out, entry.unix_timestamp as i64);
            write_integer(out, entry.duration_us as i64);
            write_array_header(out, entry.args.len());
            for a in entry.args {
                write_bulk_string(out, &a);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MetricsSnapshot {
    pub shards: usize,
    pub active_clients: usize,
    pub commands_total: u64,
    pub keys_total: usize,
    pub expired_lazy: u64,
    pub expired_active: u64,
    pub pubsub_patterns: usize,
    pub slowlog_len: usize,
    pub lsm_sstables: usize,
    pub tx_committed: u64,
    pub tx_aborted: u64,
    pub scripts_executed: u64,
    pub auth_failures: u64,
    pub raft_term: u64,
    pub raft_commit_index: u64,
    pub raft_role: &'static str,
}

pub fn render_prometheus_http_response(m: &MetricsSnapshot) -> Vec<u8> {
    let body = format!(
        "# HELP ferrum_commands_processed_total Total RESP3 commands processed\n\
         # TYPE ferrum_commands_processed_total counter\n\
         ferrum_commands_processed_total {}\n\
         # HELP ferrum_active_connections Current open TCP connections\n\
         # TYPE ferrum_active_connections gauge\n\
         ferrum_active_connections {}\n\
         # HELP ferrum_keys_total Total live keys across all shards\n\
         # TYPE ferrum_keys_total gauge\n\
         ferrum_keys_total {}\n\
         # HELP ferrum_expired_keys_total Keys evicted via TTL\n\
         # TYPE ferrum_expired_keys_total counter\n\
         ferrum_expired_keys_total{{mode=\"lazy\"}} {}\n\
         ferrum_expired_keys_total{{mode=\"active\"}} {}\n\
         # HELP ferrum_slowlog_entries Current entries in SlowLog ring buffer\n\
         # TYPE ferrum_slowlog_entries gauge\n\
         ferrum_slowlog_entries {}\n\
         # HELP ferrum_lsm_sstables_total Immutable disk SSTables in LSM engine\n\
         # TYPE ferrum_lsm_sstables_total gauge\n\
         ferrum_lsm_sstables_total {}\n\
         # HELP ferrum_transactions_total MULTI/EXEC outcomes\n\
         # TYPE ferrum_transactions_total counter\n\
         ferrum_transactions_total{{outcome=\"committed\"}} {}\n\
         ferrum_transactions_total{{outcome=\"aborted\"}} {}\n\
         # HELP ferrum_scripts_executed_total Bytecode VM scripts executed\n\
         # TYPE ferrum_scripts_executed_total counter\n\
         ferrum_scripts_executed_total {}\n\
         # HELP ferrum_auth_failures_total Failed RBAC authentication attempts\n\
         # TYPE ferrum_auth_failures_total counter\n\
         ferrum_auth_failures_total {}\n\
         # HELP ferrum_raft_term Current Raft consensus term\n\
         # TYPE ferrum_raft_term gauge\n\
         ferrum_raft_term {}\n\
         # HELP ferrum_raft_commit_index Highest committed Raft log index\n\
         # TYPE ferrum_raft_commit_index gauge\n\
         ferrum_raft_commit_index {}\n",
        m.commands_total,
        m.active_clients,
        m.keys_total,
        m.expired_lazy,
        m.expired_active,
        m.slowlog_len,
        m.lsm_sstables,
        m.tx_committed,
        m.tx_aborted,
        m.scripts_executed,
        m.auth_failures,
        m.raft_term,
        m.raft_commit_index,
    );

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut full = Vec::with_capacity(header.len() + body.len());
    full.extend_from_slice(header.as_bytes());
    full.extend_from_slice(body.as_bytes());
    full
}

pub fn render_info_all(m: &MetricsSnapshot) -> String {
    format!(
        "# Server\r\nengine:ferrum_kv\r\nversion:5.0.0-capstone\r\nshards:{}\r\n\
         # Clients\r\nactive_clients:{}\r\n\
         # Stats\r\ntotal_commands_processed:{}\r\nexpired_keys_lazy:{}\r\nexpired_keys_active:{}\r\npubsub_patterns:{}\r\nslowlog_entries:{}\r\ntx_committed:{}\r\ntx_aborted:{}\r\nscripts_executed:{}\r\nauth_failures:{}\r\n\
         # LSM\r\nlsm_sstables:{}\r\n\
         # Replication\r\nraft_role:{}\r\nraft_term:{}\r\nraft_commit_index:{}\r\n\
         # Keyspace\r\ndb0:keys={}\r\n",
        m.shards,
        m.active_clients,
        m.commands_total,
        m.expired_lazy,
        m.expired_active,
        m.pubsub_patterns,
        m.slowlog_len,
        m.tx_committed,
        m.tx_aborted,
        m.scripts_executed,
        m.auth_failures,
        m.lsm_sstables,
        m.raft_role,
        m.raft_term,
        m.raft_commit_index,
        m.keys_total,
    )
}
