use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::aof::{
    load_binary_snapshot, replay_aof, save_binary_snapshot, save_encrypted_snapshot, AofEngine,
    FsyncPolicy,
};
use crate::cluster::raft::{RaftLogEntry, RaftNode};
use crate::cluster::sharding::{key_hash_slot, ClusterTopology};
use crate::error::{EngineError, EngineResult};
use crate::pubsub::{ClientOutbox, ClientSubscriptions, PubSubBroker};
use crate::resp::{
    encode_command_slices, parse_f64_bytes, parse_i64_bytes, write_array_header, write_bulk_string,
    write_double, write_integer, write_map_header, write_null, write_simple_error,
    write_simple_string, FlatParseStatus, ParseStatus, RespFrame, RespParser, StreamReadBuffer,
};
use crate::security::AclManager;
use crate::storage::geospatial::GeoUnit;
use crate::storage::stream::StreamId;
use crate::storage::timeseries::TsAggregation;
use crate::storage::vector_hnsw::VectorMetric;
use crate::storage::{SetCondition, StorageEngine, TtlSweeper, DEFAULT_SHARD_COUNT};
use crate::telemetry::{
    render_info_all, render_prometheus_http_response, CachePadded, MetricsSnapshot, TelemetryHub,
};
use crate::tx::TransactionState;
use crate::vm::{sha256, ScriptCache};

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub node_id: String,
    pub worker_threads: usize,
    pub shard_count: usize,
    pub ttl_sweep_interval: Duration,
    pub aof_path: Option<PathBuf>,
    pub aof_fsync: FsyncPolicy,
    pub snapshot_path: PathBuf,
    pub lsm_dir: Option<PathBuf>,
    pub slowlog_threshold_us: u64,
    pub max_pooled_buffers: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8)
            .max(4);
        Self {
            bind_addr: "127.0.0.1:6379".to_string(),
            node_id: "ferrum-node-1".to_string(),
            worker_threads: cores,
            shard_count: DEFAULT_SHARD_COUNT,
            ttl_sweep_interval: Duration::from_millis(100),
            aof_path: Some(PathBuf::from("ferrum.aof")),
            aof_fsync: FsyncPolicy::EverySec,
            snapshot_path: PathBuf::from("ferrum.snap"),
            lsm_dir: None,
            slowlog_threshold_us: 10_000,
            max_pooled_buffers: 256,
        }
    }
}

/// Custom connection I/O buffer pool recycling heap allocations across TCP session lifecycles.
struct ConnectionBufferPool {
    buffers: Mutex<Vec<(StreamReadBuffer, Vec<u8>)>>,
    max_pooled: usize,
}

impl ConnectionBufferPool {
    fn new(max_pooled: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::with_capacity(max_pooled.min(64))),
            max_pooled,
        }
    }

    fn checkout(&self) -> (StreamReadBuffer, Vec<u8>) {
        if let Ok(mut guard) = self.buffers.lock() {
            if let Some(pair) = guard.pop() {
                return pair;
            }
        }
        (
            StreamReadBuffer::with_capacity(32 * 1024),
            Vec::with_capacity(32 * 1024),
        )
    }

    fn checkin(&self, mut read_buf: StreamReadBuffer, mut write_buf: Vec<u8>) {
        read_buf.reset(64 * 1024);
        write_buf.clear();
        if write_buf.capacity() > 64 * 1024 {
            write_buf.shrink_to_fit();
        }
        if let Ok(mut guard) = self.buffers.lock() {
            if guard.len() < self.max_pooled {
                guard.push((read_buf, write_buf));
            }
        }
    }
}

/// Power-of-two circular ring deque used inside each worker's work-stealing slot.
struct RingDeque<T> {
    slots: Box<[Option<T>]>,
    head: usize,
    len: usize,
}

impl<T> RingDeque<T> {
    fn with_capacity(cap: usize) -> Self {
        let actual = cap.max(16).next_power_of_two();
        let mut vec = Vec::with_capacity(actual);
        vec.resize_with(actual, || None);
        Self {
            slots: vec.into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push_back(&mut self, item: T) {
        if self.len == self.slots.len() {
            let new_cap = self.slots.len() * 2;
            let mut next = Vec::with_capacity(new_cap);
            next.resize_with(new_cap, || None);
            let old_mask = self.slots.len() - 1;
            for i in 0..self.len {
                next[i] = self.slots[(self.head + i) & old_mask].take();
            }
            self.slots = next.into_boxed_slice();
            self.head = 0;
        }
        let mask = self.slots.len() - 1;
        let tail = (self.head + self.len) & mask;
        self.slots[tail] = Some(item);
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let mask = self.slots.len() - 1;
        let item = self.slots[self.head].take();
        self.head = (self.head + 1) & mask;
        self.len -= 1;
        item
    }
}

struct ActiveConnection {
    id: u64,
    stream: TcpStream,
    read_buf: StreamReadBuffer,
    write_buf: Vec<u8>,
    write_offset: usize,
    scratch_args: Vec<(usize, usize)>,
    outbox: Arc<ClientOutbox>,
    subscriptions: ClientSubscriptions,
    authenticated_user: Option<String>,
    tx: TransactionState,
    asking: bool,
    closing: bool,
}

/// Shared state across the multi-threaded work-stealing reactor.
struct ReactorShared {
    storage: Arc<StorageEngine>,
    pubsub: Arc<PubSubBroker>,
    aof: Option<Arc<AofEngine>>,
    snapshot_path: PathBuf,
    acl: Arc<AclManager>,
    scripts: Arc<ScriptCache>,
    telemetry: Arc<TelemetryHub>,
    cluster: Arc<ClusterTopology>,
    raft: Arc<RaftNode>,
    pool: ConnectionBufferPool,
    deques: Vec<CachePadded<Mutex<RingDeque<Box<ActiveConnection>>>>>,
    wakeup: Arc<(Mutex<u64>, Condvar)>,
    shutdown: CachePadded<AtomicBool>,
    active_connections: CachePadded<AtomicUsize>,
    commands_processed: CachePadded<AtomicU64>,
}

impl ReactorShared {
    fn push_to_worker(&self, worker_idx: usize, conn: Box<ActiveConnection>) {
        let target = worker_idx % self.deques.len();
        if let Ok(mut guard) = self.deques[target].lock() {
            guard.push_back(conn);
        }
        let (lock, cvar) = &*self.wakeup;
        if let Ok(mut epoch) = lock.lock() {
            *epoch = epoch.wrapping_add(1);
            cvar.notify_one();
        }
    }

    fn steal_for_worker(&self, thief_idx: usize) -> Option<Box<ActiveConnection>> {
        let total = self.deques.len();
        for offset in 1..total {
            let victim_idx = (thief_idx + offset) % total;
            let mut stolen: Vec<Box<ActiveConnection>> = Vec::new();
            if let Ok(mut victim) = self.deques[victim_idx].try_lock() {
                if !victim.is_empty() {
                    let steal_count = (victim.len() / 2).max(1);
                    for _ in 0..steal_count {
                        if let Some(conn) = victim.pop_front() {
                            stolen.push(conn);
                        }
                    }
                }
            }
            if !stolen.is_empty() {
                let first = stolen.remove(0);
                if !stolen.is_empty() {
                    if let Ok(mut local) = self.deques[thief_idx].lock() {
                        for item in stolen {
                            local.push_back(item);
                        }
                    }
                }
                return Some(first);
            }
        }
        None
    }
}

pub struct FerrumServer {
    local_addr: SocketAddr,
    shared: Arc<ReactorShared>,
    ttl_sweeper: TtlSweeper,
    acceptor_thread: Option<JoinHandle<()>>,
    worker_threads: Vec<JoinHandle<()>>,
}

impl FerrumServer {
    pub fn start(config: ServerConfig) -> EngineResult<Self> {
        let storage = StorageEngine::new(config.shard_count)?;
        if let Some(ref lsm_dir) = config.lsm_dir {
            storage.attach_lsm(lsm_dir, 64 * 1024)?;
        }

        if config.snapshot_path.exists() {
            let _ = load_binary_snapshot(&config.snapshot_path, &storage)?;
        }

        let aof = match &config.aof_path {
            Some(path) => {
                if path.exists() {
                    let _ = replay_aof(path, &storage)?;
                }
                Some(AofEngine::open(path, config.aof_fsync)?)
            }
            None => None,
        };

        let listener = TcpListener::bind(&config.bind_addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;

        let wakeup = Arc::new((Mutex::new(0u64), Condvar::new()));
        let pubsub = PubSubBroker::new(Some(Arc::clone(&wakeup)));
        let ttl_sweeper = TtlSweeper::spawn(Arc::clone(&storage), config.ttl_sweep_interval)?;

        let acl = Arc::new(AclManager::new());
        let scripts = Arc::new(ScriptCache::default());
        let telemetry = Arc::new(TelemetryHub::new(256, config.slowlog_threshold_us));
        let cluster = Arc::new(ClusterTopology::new(
            config.node_id.clone(),
            local_addr.to_string(),
        ));
        let raft = RaftNode::new(
            config.node_id.clone(),
            Arc::clone(&storage),
            Arc::clone(&scripts),
        );

        let num_workers = config.worker_threads.max(1);
        let mut deques = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            deques.push(CachePadded::new(Mutex::new(RingDeque::with_capacity(64))));
        }

        let shared = Arc::new(ReactorShared {
            storage,
            pubsub,
            aof,
            snapshot_path: config.snapshot_path,
            acl,
            scripts,
            telemetry,
            cluster,
            raft,
            pool: ConnectionBufferPool::new(config.max_pooled_buffers),
            deques,
            wakeup,
            shutdown: CachePadded::new(AtomicBool::new(false)),
            active_connections: CachePadded::new(AtomicUsize::new(0)),
            commands_processed: CachePadded::new(AtomicU64::new(0)),
        });

        let mut worker_threads = Vec::with_capacity(num_workers);
        for worker_id in 0..num_workers {
            let shared_ref = Arc::clone(&shared);
            let handle = thread::Builder::new()
                .name(format!("ferrum-worker-{worker_id}"))
                .spawn(move || worker_loop(worker_id, shared_ref))?;
            worker_threads.push(handle);
        }

        let acceptor_shared = Arc::clone(&shared);
        let acceptor_thread = thread::Builder::new()
            .name("ferrum-acceptor".to_string())
            .spawn(move || acceptor_loop(listener, acceptor_shared))?;

        Ok(Self {
            local_addr,
            shared,
            ttl_sweeper,
            acceptor_thread: Some(acceptor_thread),
            worker_threads,
        })
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[inline]
    pub fn storage(&self) -> &Arc<StorageEngine> {
        &self.shared.storage
    }

    #[inline]
    pub fn raft_node(&self) -> &Arc<RaftNode> {
        &self.shared.raft
    }

    #[inline]
    pub fn cluster_topology(&self) -> &Arc<ClusterTopology> {
        &self.shared.cluster
    }

    #[inline]
    pub fn acl_manager(&self) -> &Arc<AclManager> {
        &self.shared.acl
    }

    #[inline]
    pub fn telemetry(&self) -> &Arc<TelemetryHub> {
        &self.shared.telemetry
    }

    pub fn shutdown(&mut self) {
        if self.shared.shutdown.swap(true, AtomicOrdering::AcqRel) {
            return;
        }
        let (lock, cvar) = &*self.shared.wakeup;
        if let Ok(mut epoch) = lock.lock() {
            *epoch = epoch.wrapping_add(1);
            cvar.notify_all();
        }
        if let Some(acceptor) = self.acceptor_thread.take() {
            let _ = acceptor.join();
        }
        for handle in self.worker_threads.drain(..) {
            let _ = handle.join();
        }
        self.ttl_sweeper.shutdown();
        if let Some(ref aof) = self.shared.aof {
            let _ = aof.flush_and_sync();
            aof.shutdown();
        }
    }
}

impl Drop for FerrumServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn acceptor_loop(listener: TcpListener, shared: Arc<ReactorShared>) {
    let mut next_client_id: u64 = 1;
    let mut rr_worker: usize = 0;

    while !shared.shutdown.load(AtomicOrdering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let _ = stream.set_nodelay(true);
                if stream.set_nonblocking(true).is_err() {
                    continue;
                }
                let initial_user = if shared.acl.requires_initial_auth().unwrap_or(false) {
                    None
                } else {
                    Some("default".to_string())
                };
                let (read_buf, write_buf) = shared.pool.checkout();
                let conn = Box::new(ActiveConnection {
                    id: next_client_id,
                    stream,
                    read_buf,
                    write_buf,
                    write_offset: 0,
                    scratch_args: Vec::with_capacity(16),
                    outbox: Arc::new(ClientOutbox::new()),
                    subscriptions: ClientSubscriptions::new(),
                    authenticated_user: initial_user,
                    tx: TransactionState::new(),
                    asking: false,
                    closing: false,
                });
                next_client_id = next_client_id.wrapping_add(1);
                shared.active_connections.fetch_add(1, AtomicOrdering::Relaxed);
                shared.push_to_worker(rr_worker, conn);
                rr_worker = rr_worker.wrapping_add(1);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_micros(400));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

fn worker_loop(worker_id: usize, shared: Arc<ReactorShared>) {
    let mut idle_streaks: u32 = 0;

    while !shared.shutdown.load(AtomicOrdering::Acquire) {
        let local_batch_len = shared.deques[worker_id]
            .lock()
            .map(|g| g.len())
            .unwrap_or(0);

        let mut made_progress = false;

        if local_batch_len > 0 {
            for _ in 0..local_batch_len {
                let maybe_conn = shared.deques[worker_id]
                    .lock()
                    .ok()
                    .and_then(|mut g| g.pop_front());
                let Some(mut conn) = maybe_conn else {
                    break;
                };

                let (keep_alive, did_io) = drive_connection(&mut conn, &shared);
                if did_io {
                    made_progress = true;
                }

                if keep_alive && !shared.shutdown.load(AtomicOrdering::Acquire) {
                    if let Ok(mut g) = shared.deques[worker_id].lock() {
                        g.push_back(conn);
                    }
                } else {
                    teardown_connection(conn, &shared);
                }
            }
        } else if let Some(mut stolen) = shared.steal_for_worker(worker_id) {
            let (keep_alive, did_io) = drive_connection(&mut stolen, &shared);
            if did_io {
                made_progress = true;
            }
            if keep_alive && !shared.shutdown.load(AtomicOrdering::Acquire) {
                if let Ok(mut g) = shared.deques[worker_id].lock() {
                    g.push_back(stolen);
                }
            } else {
                teardown_connection(stolen, &shared);
            }
        }

        if made_progress {
            idle_streaks = 0;
        } else {
            idle_streaks = idle_streaks.saturating_add(1);
            if idle_streaks <= 16 {
                std::hint::spin_loop();
            } else if idle_streaks <= 64 {
                thread::yield_now();
            } else {
                let (lock, cvar) = &*shared.wakeup;
                if let Ok(guard) = lock.lock() {
                    if !shared.shutdown.load(AtomicOrdering::Acquire) {
                        let _ = cvar.wait_timeout(guard, Duration::from_micros(250));
                    }
                }
            }
        }
    }

    if let Ok(mut guard) = shared.deques[worker_id].lock() {
        while let Some(conn) = guard.pop_front() {
            teardown_connection(conn, &shared);
        }
    }
}

fn teardown_connection(mut conn: Box<ActiveConnection>, shared: &ReactorShared) {
    let _ = shared
        .pubsub
        .disconnect_client(conn.id, &mut conn.subscriptions);
    let _ = conn.stream.shutdown(std::net::Shutdown::Both);
    shared.pool.checkin(conn.read_buf, conn.write_buf);
    shared.active_connections.fetch_sub(1, AtomicOrdering::Relaxed);
}

#[inline]
fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() >= 4 {
        for i in 0..=(buf.len() - 4) {
            if &buf[i..i + 4] == b"\r\n\r\n" {
                return Some(i + 4);
            }
        }
    }
    if buf.len() >= 2 {
        for i in 0..=(buf.len() - 2) {
            if &buf[i..i + 2] == b"\n\n" {
                return Some(i + 2);
            }
        }
    }
    None
}

fn build_metrics_snapshot(shared: &ReactorShared) -> MetricsSnapshot {
    let raft_status = shared.raft.status().ok();
    MetricsSnapshot {
        shards: shared.storage.shard_count(),
        active_clients: shared.active_connections.load(AtomicOrdering::Relaxed),
        commands_total: shared.commands_processed.load(AtomicOrdering::Relaxed),
        keys_total: shared.storage.dbsize().unwrap_or(0),
        expired_lazy: shared.storage.lazy_expired_total(),
        expired_active: shared.storage.active_expired_total(),
        pubsub_patterns: shared.pubsub.numpat().unwrap_or(0),
        slowlog_len: shared.telemetry.slowlog_len().unwrap_or(0),
        lsm_sstables: shared.storage.lsm_sstable_count(),
        tx_committed: shared
            .telemetry
            .tx_committed_total
            .load(AtomicOrdering::Relaxed),
        tx_aborted: shared
            .telemetry
            .tx_aborted_total
            .load(AtomicOrdering::Relaxed),
        scripts_executed: shared
            .telemetry
            .scripts_executed_total
            .load(AtomicOrdering::Relaxed),
        auth_failures: shared
            .telemetry
            .auth_failures_total
            .load(AtomicOrdering::Relaxed),
        raft_term: raft_status.as_ref().map(|s| s.current_term).unwrap_or(0),
        raft_commit_index: raft_status.as_ref().map(|s| s.commit_index).unwrap_or(0),
        raft_role: raft_status
            .as_ref()
            .map(|s| s.role.as_str())
            .unwrap_or("follower"),
    }
}

/// Drives a non-blocking TCP connection through dual-protocol HTTP `/metrics` detection, Pub/Sub outbox drain, RESP3 zero-copy parse/exec, and socket flush.
fn drive_connection(conn: &mut ActiveConnection, shared: &ReactorShared) -> (bool, bool) {
    const MAX_READ_PER_TURN: usize = 256 * 1024;
    let mut did_io = false;
    let mut peer_eof = false;

    if let Ok(drained) = conn.outbox.drain_into(&mut conn.write_buf) {
        if drained > 0 {
            did_io = true;
        }
    }

    if conn.write_offset < conn.write_buf.len() {
        match flush_nonblocking(&mut conn.stream, &mut conn.write_buf, &mut conn.write_offset) {
            Ok(wrote) => {
                if wrote > 0 {
                    did_io = true;
                }
            }
            Err(_) => return (false, true),
        }
    }

    let mut read_this_turn = 0usize;
    while !conn.closing && read_this_turn < MAX_READ_PER_TURN {
        let dst = conn.read_buf.writable_slice(16 * 1024);
        match conn.stream.read(dst) {
            Ok(0) => {
                peer_eof = true;
                did_io = true;
                break;
            }
            Ok(n) => {
                conn.read_buf.advance_write(n);
                read_this_turn += n;
                did_io = true;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return (false, true),
        }
    }

    if conn.read_buf.readable_len() > 0 && !conn.closing {
        let ActiveConnection {
            id,
            ref mut read_buf,
            ref mut write_buf,
            ref mut scratch_args,
            ref outbox,
            ref mut subscriptions,
            ref mut authenticated_user,
            ref mut tx,
            ref mut asking,
            ref mut closing,
            ..
        } = *conn;

        // Dual-Protocol Detector: serve Prometheus text format directly over HTTP/1.1 on `/metrics`.
        let readable = read_buf.readable_slice();
        if readable.starts_with(b"GET /metrics") {
            if let Some(hdr_end) = find_http_header_end(readable) {
                read_buf.consume(hdr_end);
                let snap = build_metrics_snapshot(shared);
                let http_resp = render_prometheus_http_response(&snap);
                write_buf.extend_from_slice(&http_resp);
                *closing = true;
                did_io = true;
            }
        } else {
            let mut parsed_count = 0u64;
            loop {
                let consumed = match RespParser::parse_flat_command(
                    read_buf.readable_slice(),
                    scratch_args,
                ) {
                    Ok(FlatParseStatus::Incomplete) => break,
                    Ok(FlatParseStatus::Complete { consumed }) => {
                        parsed_count += 1;
                        let frame_bytes = &read_buf.readable_slice()[..consumed];
                        let exec_res = if scratch_args.len() <= 16 {
                            let mut stack_args: [&[u8]; 16] = [&[]; 16];
                            for (dst, &(s, e)) in
                                stack_args.iter_mut().zip(scratch_args.iter())
                            {
                                *dst = &frame_bytes[s..e];
                            }
                            execute_session_args(
                                id,
                                &stack_args[..scratch_args.len()],
                                shared,
                                outbox,
                                subscriptions,
                                authenticated_user,
                                tx,
                                asking,
                                closing,
                                write_buf,
                            )
                        } else {
                            let heap_args: Vec<&[u8]> = scratch_args
                                .iter()
                                .map(|&(s, e)| &frame_bytes[s..e])
                                .collect();
                            execute_session_args(
                                id,
                                &heap_args,
                                shared,
                                outbox,
                                subscriptions,
                                authenticated_user,
                                tx,
                                asking,
                                closing,
                                write_buf,
                            )
                        };
                        if let Err(err) = exec_res {
                            tx.mark_abort();
                            let msg = err.to_resp_error_message();
                            write_simple_error(write_buf, msg.as_bytes());
                        }
                        consumed
                    }
                    Ok(FlatParseStatus::Fallback) => match RespParser::parse(read_buf.readable_slice()) {
                        Ok(ParseStatus::Incomplete) => break,
                        Ok(ParseStatus::Complete { frame, consumed }) => {
                            parsed_count += 1;
                            if let Err(err) = execute_session_frame(
                                id,
                                &frame,
                                shared,
                                outbox,
                                subscriptions,
                                authenticated_user,
                                tx,
                                asking,
                                closing,
                                write_buf,
                            ) {
                                tx.mark_abort();
                                let msg = err.to_resp_error_message();
                                write_simple_error(write_buf, msg.as_bytes());
                            }
                            consumed
                        }
                        Err(proto_err) => {
                            let msg = proto_err.to_resp_error_message();
                            write_simple_error(write_buf, msg.as_bytes());
                            *closing = true;
                            break;
                        }
                    },
                    Err(proto_err) => {
                        let msg = proto_err.to_resp_error_message();
                        write_simple_error(write_buf, msg.as_bytes());
                        *closing = true;
                        break;
                    }
                };
                read_buf.consume(consumed);
                if *closing {
                    break;
                }
            }

            if parsed_count > 0 {
                shared
                    .commands_processed
                    .fetch_add(parsed_count, AtomicOrdering::Relaxed);
                did_io = true;
            }
        }
    }

    if conn.write_offset < conn.write_buf.len() {
        match flush_nonblocking(&mut conn.stream, &mut conn.write_buf, &mut conn.write_offset) {
            Ok(wrote) => {
                if wrote > 0 {
                    did_io = true;
                }
            }
            Err(_) => return (false, true),
        }
    }

    let write_drained = conn.write_offset >= conn.write_buf.len();
    if (peer_eof || conn.closing) && write_drained {
        return (false, did_io);
    }

    (true, did_io)
}

fn flush_nonblocking(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    offset: &mut usize,
) -> io::Result<usize> {
    let mut total_written = 0usize;
    while *offset < buf.len() {
        match stream.write(&buf[*offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket write returned 0",
                ))
            }
            Ok(n) => {
                *offset += n;
                total_written += n;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    if *offset >= buf.len() {
        buf.clear();
        *offset = 0;
    } else if *offset > 32 * 1024 && *offset * 2 >= buf.len() {
        let rem = buf.len() - *offset;
        buf.copy_within(*offset.., 0);
        buf.truncate(rem);
        *offset = 0;
    }
    Ok(total_written)
}

#[allow(clippy::too_many_arguments)]
fn execute_session_args(
    client_id: u64,
    args: &[&[u8]],
    shared: &ReactorShared,
    outbox: &Arc<ClientOutbox>,
    subscriptions: &mut ClientSubscriptions,
    authenticated_user: &mut Option<String>,
    tx: &mut TransactionState,
    asking: &mut bool,
    closing: &mut bool,
    out: &mut Vec<u8>,
) -> EngineResult<()> {
    if args.is_empty() {
        return Err(EngineError::InvalidArgument("empty command array".to_string()));
    }

    let started = Instant::now();
    let res = dispatch_session_command(
        client_id,
        args,
        shared,
        outbox,
        subscriptions,
        authenticated_user,
        tx,
        asking,
        closing,
        out,
    );
    let elapsed_us = started.elapsed().as_micros() as u64;
    shared.telemetry.record_command(client_id, elapsed_us, args);
    res
}

#[allow(clippy::too_many_arguments)]
fn execute_session_frame(
    client_id: u64,
    frame: &RespFrame<'_>,
    shared: &ReactorShared,
    outbox: &Arc<ClientOutbox>,
    subscriptions: &mut ClientSubscriptions,
    authenticated_user: &mut Option<String>,
    tx: &mut TransactionState,
    asking: &mut bool,
    closing: &mut bool,
    out: &mut Vec<u8>,
) -> EngineResult<()> {
    let RespFrame::Array(items) = frame else {
        return Err(EngineError::Protocol(
            "client command must be a RESP Array".to_string(),
        ));
    };
    if items.is_empty() {
        return Err(EngineError::InvalidArgument("empty command array".to_string()));
    }

    let mut args: Vec<&[u8]> = Vec::with_capacity(items.len());
    for item in items {
        let slice = item.as_bytes().ok_or_else(|| {
            EngineError::Protocol("command arguments must be BulkString or SimpleString".to_string())
        })?;
        args.push(slice);
    }

    execute_session_args(
        client_id,
        &args,
        shared,
        outbox,
        subscriptions,
        authenticated_user,
        tx,
        asking,
        closing,
        out,
    )
}

fn extract_primary_key<'a>(args: &[&'a [u8]]) -> Option<&'a [u8]> {
    if args.len() < 2 {
        return None;
    }
    let cmd = args[0];
    if cmd.eq_ignore_ascii_case(b"PING")
        || cmd.eq_ignore_ascii_case(b"ECHO")
        || cmd.eq_ignore_ascii_case(b"QUIT")
        || cmd.eq_ignore_ascii_case(b"RESET")
        || cmd.eq_ignore_ascii_case(b"HELLO")
        || cmd.eq_ignore_ascii_case(b"COMMAND")
        || cmd.eq_ignore_ascii_case(b"INFO")
        || cmd.eq_ignore_ascii_case(b"DBSIZE")
        || cmd.eq_ignore_ascii_case(b"FLUSHDB")
        || cmd.eq_ignore_ascii_case(b"KEYS")
        || cmd.eq_ignore_ascii_case(b"SAVE")
        || cmd.eq_ignore_ascii_case(b"SAVE.ENCRYPTED")
        || cmd.eq_ignore_ascii_case(b"BGREWRITEAOF")
        || cmd.eq_ignore_ascii_case(b"AUTH")
        || cmd.eq_ignore_ascii_case(b"ACL")
        || cmd.eq_ignore_ascii_case(b"SLOWLOG")
        || cmd.eq_ignore_ascii_case(b"CONFIG")
        || cmd.eq_ignore_ascii_case(b"SCRIPT")
        || cmd.eq_ignore_ascii_case(b"MULTI")
        || cmd.eq_ignore_ascii_case(b"EXEC")
        || cmd.eq_ignore_ascii_case(b"DISCARD")
        || cmd.eq_ignore_ascii_case(b"UNWATCH")
        || cmd.eq_ignore_ascii_case(b"ASKING")
        || cmd.eq_ignore_ascii_case(b"CLUSTER")
        || cmd.eq_ignore_ascii_case(b"RAFT")
        || cmd.eq_ignore_ascii_case(b"SUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"UNSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"PSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"PUNSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"PUBLISH")
        || cmd.eq_ignore_ascii_case(b"PUBSUB")
        || starts_with_ignore_ascii_case(cmd, b"RAFT.")
        || starts_with_ignore_ascii_case(cmd, b"LSM.")
    {
        return None;
    }
    if cmd.eq_ignore_ascii_case(b"EVAL") || cmd.eq_ignore_ascii_case(b"EVALSHA") {
        if args.len() >= 4 {
            if let Ok(nk) = parse_i64_bytes(args[2]) {
                if nk > 0 {
                    return Some(args[3]);
                }
            }
        }
        return None;
    }
    if cmd.eq_ignore_ascii_case(b"XGROUP") {
        return args.get(2).copied();
    }
    if cmd.eq_ignore_ascii_case(b"XREAD") || cmd.eq_ignore_ascii_case(b"XREADGROUP") {
        if let Some(pos) = args.iter().position(|s| s.eq_ignore_ascii_case(b"STREAMS")) {
            return args.get(pos + 1).copied();
        }
        return None;
    }
    Some(args[1])
}

#[inline]
fn starts_with_ignore_ascii_case(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && haystack[..prefix.len()].eq_ignore_ascii_case(prefix)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_session_command(
    client_id: u64,
    args: &[&[u8]],
    shared: &ReactorShared,
    outbox: &Arc<ClientOutbox>,
    subscriptions: &mut ClientSubscriptions,
    authenticated_user: &mut Option<String>,
    tx: &mut TransactionState,
    asking: &mut bool,
    closing: &mut bool,
    out: &mut Vec<u8>,
) -> EngineResult<()> {
    let cmd = args[0];

    // 1. Handle AUTH & ASKING upfront
    if cmd.eq_ignore_ascii_case(b"AUTH") {
        let res = match args.len() {
            2 => shared.acl.authenticate(b"default", args[1]),
            3 => shared.acl.authenticate(args[1], args[2]),
            _ => {
                return Err(EngineError::InvalidArgument(
                    "wrong number of arguments for 'auth' command".to_string(),
                ))
            }
        };
        match res {
            Ok(uname) => {
                *authenticated_user = Some(uname);
                write_simple_string(out, b"OK");
                return Ok(());
            }
            Err(err) => {
                shared
                    .telemetry
                    .auth_failures_total
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return Err(err);
            }
        }
    }

    if cmd.eq_ignore_ascii_case(b"ASKING") {
        require_exact_args("asking", args, 1)?;
        *asking = true;
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"ACL")
        && args.len() == 2
        && args[1].eq_ignore_ascii_case(b"WHOAMI")
    {
        let Some(ref who) = *authenticated_user else {
            return Err(EngineError::InvalidArgument(
                "NOAUTH Authentication required.".to_string(),
            ));
        };
        write_bulk_string(out, who.as_bytes());
        return Ok(());
    }

    let was_asking = std::mem::replace(asking, false);

    // 2. Enforce RBAC ACL permissions & key-prefix globs
    let primary_key = extract_primary_key(args);
    if let Err(err) = shared
        .acl
        .authorize_command(authenticated_user.as_deref(), cmd, primary_key)
    {
        if authenticated_user.is_none() {
            shared
                .telemetry
                .auth_failures_total
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        return Err(err);
    }

    // 3. Enforce Redis subscriber-mode restrictions
    if subscriptions.total_count() > 0
        && !cmd.eq_ignore_ascii_case(b"SUBSCRIBE")
        && !cmd.eq_ignore_ascii_case(b"UNSUBSCRIBE")
        && !cmd.eq_ignore_ascii_case(b"PSUBSCRIBE")
        && !cmd.eq_ignore_ascii_case(b"PUNSUBSCRIBE")
        && !cmd.eq_ignore_ascii_case(b"PING")
        && !cmd.eq_ignore_ascii_case(b"QUIT")
        && !cmd.eq_ignore_ascii_case(b"RESET")
    {
        return Err(EngineError::InvalidArgument(
            "Can't execute command in subscribed mode".to_string(),
        ));
    }

    // 4. Enforce 16,384-slot Cluster routing (`-MOVED` / `-ASK`)
    if let Some(key) = primary_key {
        if let Some(redir) = shared
            .cluster
            .check_slot_redirect(key, was_asking, &shared.storage)?
        {
            write_simple_error(out, &redir.to_resp_error_bytes());
            return Ok(());
        }
    }

    // 5. Optimistic Concurrency Transaction Lifecycle (`WATCH`, `UNWATCH`, `MULTI`, `DISCARD`, `EXEC`)
    if cmd.eq_ignore_ascii_case(b"WATCH") {
        require_min_args("watch", args, 2)?;
        let _fence = shared.storage.tx_shared_guard()?;
        tx.watch_keys(&args[1..], &shared.storage)?;
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"UNWATCH") {
        require_exact_args("unwatch", args, 1)?;
        tx.unwatch();
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"MULTI") {
        require_exact_args("multi", args, 1)?;
        tx.begin_multi()?;
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"DISCARD") {
        require_exact_args("discard", args, 1)?;
        tx.discard()?;
        shared
            .telemetry
            .tx_aborted_total
            .fetch_add(1, AtomicOrdering::Relaxed);
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"EXEC") {
        require_exact_args("exec", args, 1)?;
        let (stamps, queued_cmds) = tx.take_for_exec()?;
        let _excl_fence = shared.storage.tx_exclusive_guard()?;
        if !shared.storage.verify_watched_stamps_sorted(&stamps)? {
            shared
                .telemetry
                .tx_aborted_total
                .fetch_add(1, AtomicOrdering::Relaxed);
            write_null(out);
            return Ok(());
        }

        write_array_header(out, queued_cmds.len());
        for q_cmd in &queued_cmds {
            let q_slices: Vec<&[u8]> = q_cmd.iter().map(|v| v.as_slice()).collect();
            if let Err(err) = execute_core_command(
                client_id,
                &q_slices,
                shared,
                authenticated_user,
                outbox,
                subscriptions,
                closing,
                true,
                out,
            ) {
                let msg = err.to_resp_error_message();
                write_simple_error(out, msg.as_bytes());
            }
        }
        shared
            .telemetry
            .tx_committed_total
            .fetch_add(1, AtomicOrdering::Relaxed);
        return Ok(());
    }

    if tx.in_multi() {
        if cmd.eq_ignore_ascii_case(b"SUBSCRIBE")
            || cmd.eq_ignore_ascii_case(b"PSUBSCRIBE")
            || cmd.eq_ignore_ascii_case(b"UNSUBSCRIBE")
            || cmd.eq_ignore_ascii_case(b"PUNSUBSCRIBE")
        {
            return Err(EngineError::InvalidArgument(
                "Pub/Sub commands are not allowed inside MULTI".to_string(),
            ));
        }
        tx.enqueue(args);
        write_simple_string(out, b"QUEUED");
        return Ok(());
    }

    execute_core_command(
        client_id,
        args,
        shared,
        authenticated_user,
        outbox,
        subscriptions,
        closing,
        false,
        out,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_core_command(
    client_id: u64,
    args: &[&[u8]],
    shared: &ReactorShared,
    authenticated_user: &mut Option<String>,
    outbox: &Arc<ClientOutbox>,
    subscriptions: &mut ClientSubscriptions,
    closing: &mut bool,
    inside_exclusive_tx: bool,
    out: &mut Vec<u8>,
) -> EngineResult<()> {
    let cmd = args[0];

    // Commands that perform outbound RPCs or background persistence run outside `tx_shared_guard`.
    if cmd.eq_ignore_ascii_case(b"PING") {
        if args.len() == 1 {
            write_simple_string(out, b"PONG");
        } else if args.len() == 2 {
            write_bulk_string(out, args[1]);
        } else {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'ping' command".to_string(),
            ));
        }
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"ECHO") {
        require_exact_args("echo", args, 2)?;
        write_bulk_string(out, args[1]);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"QUIT") {
        *closing = true;
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"RESET") {
        shared.pubsub.disconnect_client(client_id, subscriptions)?;
        if shared.acl.requires_initial_auth().unwrap_or(false) {
            *authenticated_user = None;
        }
        write_simple_string(out, b"RESET");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"HELLO") {
        write_map_header(out, 4);
        write_bulk_string(out, b"server");
        write_bulk_string(out, b"ferrum_kv");
        write_bulk_string(out, b"version");
        write_bulk_string(out, b"5.0.0");
        write_bulk_string(out, b"proto");
        write_integer(out, 3);
        write_bulk_string(out, b"id");
        write_integer(out, client_id as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"COMMAND") {
        write_array_header(out, 0);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"INFO") {
        let snap = build_metrics_snapshot(shared);
        let text = render_info_all(&snap);
        write_bulk_string(out, text.as_bytes());
        return Ok(());
    }

    // ==================== TELEMETRY, SLOWLOG & CONFIG ====================

    if cmd.eq_ignore_ascii_case(b"SLOWLOG") {
        require_min_args("slowlog", args, 2)?;
        let sub = args[1];
        if sub.eq_ignore_ascii_case(b"LEN") {
            write_integer(out, shared.telemetry.slowlog_len()? as i64);
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"RESET") {
            shared.telemetry.slowlog_reset()?;
            write_simple_string(out, b"OK");
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"GET") {
            let count = if args.len() >= 3 {
                parse_i64_bytes(args[2])?.max(0) as usize
            } else {
                32
            };
            shared.telemetry.slowlog_get_into(count, out)?;
            return Ok(());
        } else {
            return Err(EngineError::InvalidArgument(
                "unknown SLOWLOG subcommand, expected GET|LEN|RESET".to_string(),
            ));
        }
    }

    if cmd.eq_ignore_ascii_case(b"CONFIG") {
        require_min_args("config", args, 3)?;
        if args[1].eq_ignore_ascii_case(b"SET") {
            require_exact_args("config set", args, 4)?;
            if args[2].eq_ignore_ascii_case(b"slowlog-log-slower-than") {
                let us = parse_i64_bytes(args[3])?.max(0) as u64;
                shared.telemetry.set_threshold_us(us);
                write_simple_string(out, b"OK");
                return Ok(());
            }
            return Err(EngineError::InvalidArgument("unsupported CONFIG parameter".to_string()));
        } else if args[1].eq_ignore_ascii_case(b"GET") {
            if args[2].eq_ignore_ascii_case(b"slowlog-log-slower-than") {
                write_array_header(out, 2);
                write_bulk_string(out, b"slowlog-log-slower-than");
                let v = shared.telemetry.threshold_us().to_string();
                write_bulk_string(out, v.as_bytes());
                return Ok(());
            }
            write_array_header(out, 0);
            return Ok(());
        }
    }

    // ==================== RBAC ACL COMMANDS ====================

    if cmd.eq_ignore_ascii_case(b"ACL") {
        require_min_args("acl", args, 2)?;
        if args[1].eq_ignore_ascii_case(b"WHOAMI") {
            let who = authenticated_user.as_deref().unwrap_or("default");
            write_bulk_string(out, who.as_bytes());
            return Ok(());
        } else if args[1].eq_ignore_ascii_case(b"SETUSER") {
            require_min_args("acl setuser", args, 3)?;
            shared.acl.set_user(args[2], &args[3..])?;
            write_simple_string(out, b"OK");
            return Ok(());
        } else if args[1].eq_ignore_ascii_case(b"LIST") {
            let users = shared.acl.list_users()?;
            write_array_header(out, users.len());
            for u in users {
                write_bulk_string(out, u.as_bytes());
            }
            return Ok(());
        } else {
            return Err(EngineError::InvalidArgument(
                "unknown ACL subcommand, expected WHOAMI|SETUSER|LIST".to_string(),
            ));
        }
    }

    // ==================== CLUSTER & RAFT CONSENSUS RPCs ====================

    if cmd.eq_ignore_ascii_case(b"CLUSTER") {
        require_min_args("cluster", args, 2)?;
        let sub = args[1];
        if sub.eq_ignore_ascii_case(b"KEYSLOT") {
            require_exact_args("cluster keyslot", args, 3)?;
            write_integer(out, key_hash_slot(args[2]) as i64);
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"MYID") {
            let id = shared.cluster.local_node_id()?;
            write_bulk_string(out, id.as_bytes());
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"SLOTS") {
            shared.cluster.write_cluster_slots(out)?;
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"ADDSLOTSRANGE") {
            require_min_args("cluster addslotsrange", args, 4)?;
            let start = parse_i64_bytes(args[2])? as u16;
            let end = parse_i64_bytes(args[3])? as u16;
            let owner = if args.len() >= 5 {
                std::str::from_utf8(args[4])?
            } else {
                "SELF"
            };
            shared.cluster.assign_slot_range(start, end, owner)?;
            write_simple_string(out, b"OK");
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"SETSLOT") {
            require_min_args("cluster setslot", args, 4)?;
            let slot = parse_i64_bytes(args[2])? as u16;
            let action = args[3];
            if action.eq_ignore_ascii_case(b"MIGRATING") {
                require_exact_args("cluster setslot migrating", args, 5)?;
                shared
                    .cluster
                    .set_slot_migrating(slot, std::str::from_utf8(args[4])?)?;
            } else if action.eq_ignore_ascii_case(b"IMPORTING") {
                require_exact_args("cluster setslot importing", args, 5)?;
                shared
                    .cluster
                    .set_slot_importing(slot, std::str::from_utf8(args[4])?)?;
            } else if action.eq_ignore_ascii_case(b"NODE") {
                require_exact_args("cluster setslot node", args, 5)?;
                shared
                    .cluster
                    .assign_slot_range(slot, slot, std::str::from_utf8(args[4])?)?;
            } else if action.eq_ignore_ascii_case(b"STABLE") {
                shared.cluster.set_slot_stable(slot)?;
            } else {
                return Err(EngineError::InvalidArgument(
                    "unknown CLUSTER SETSLOT mode".to_string(),
                ));
            }
            write_simple_string(out, b"OK");
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"MIGRATE") {
            if inside_exclusive_tx {
                return Err(EngineError::InvalidArgument(
                    "CLUSTER MIGRATE is not allowed inside MULTI/EXEC".to_string(),
                ));
            }
            require_exact_args("cluster migrate", args, 4)?;
            let target = std::str::from_utf8(args[2])?;
            let moved = shared.cluster.migrate_key(target, args[3], &shared.storage)?;
            write_simple_string(out, if moved { b"OK" } else { b"NOKEY" });
            return Ok(());
        } else {
            return Err(EngineError::InvalidArgument(
                "unknown CLUSTER subcommand".to_string(),
            ));
        }
    }

    if cmd.eq_ignore_ascii_case(b"RAFT") {
        require_min_args("raft", args, 2)?;
        let sub = args[1];
        if sub.eq_ignore_ascii_case(b"PROPOSE")
            || sub.eq_ignore_ascii_case(b"REQUESTVOTE")
            || sub.eq_ignore_ascii_case(b"VOTE")
            || sub.eq_ignore_ascii_case(b"APPENDENTRIES")
            || sub.eq_ignore_ascii_case(b"APPEND")
            || sub.eq_ignore_ascii_case(b"ELECT")
        {
            if inside_exclusive_tx {
                return Err(EngineError::InvalidArgument(
                    "synchronous RAFT command is not allowed inside MULTI/EXEC".to_string(),
                ));
            }
        }
        if sub.eq_ignore_ascii_case(b"PROPOSE") {
            require_min_args("raft propose", args, 3)?;
            shared.raft.propose_command(&args[2..], out)?;
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"REQUESTVOTE") || sub.eq_ignore_ascii_case(b"VOTE") {
            require_exact_args("raft requestvote", args, 6)?;
            let term = parse_i64_bytes(args[2])?.max(0) as u64;
            let candidate_id = std::str::from_utf8(args[3])?;
            let last_idx = parse_i64_bytes(args[4])?.max(0) as u64;
            let last_term = parse_i64_bytes(args[5])?.max(0) as u64;
            let (cur_term, granted) =
                shared
                    .raft
                    .handle_request_vote(term, candidate_id, last_idx, last_term)?;
            write_array_header(out, 2);
            write_integer(out, cur_term as i64);
            write_integer(out, i64::from(granted));
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"APPENDENTRIES") || sub.eq_ignore_ascii_case(b"APPEND") {
            require_min_args("raft appendentries", args, 7)?;
            if (args.len() - 7) % 3 != 0 {
                return Err(EngineError::InvalidArgument(
                    "malformed RAFT APPENDENTRIES entry triples".to_string(),
                ));
            }
            let term = parse_i64_bytes(args[2])?.max(0) as u64;
            let leader_id = std::str::from_utf8(args[3])?;
            let prev_idx = parse_i64_bytes(args[4])?.max(0) as u64;
            let prev_term = parse_i64_bytes(args[5])?.max(0) as u64;
            let leader_commit = parse_i64_bytes(args[6])?.max(0) as u64;

            let mut entries = Vec::with_capacity((args.len() - 7) / 3);
            let mut i = 7usize;
            while i + 2 < args.len() {
                let e_idx = parse_i64_bytes(args[i])?.max(1) as u64;
                let e_term = parse_i64_bytes(args[i + 1])?.max(0) as u64;
                let e_wire = args[i + 2];
                entries.push(RaftLogEntry::decode_command_wire(e_idx, e_term, e_wire)?);
                i += 3;
            }
            let (cur_term, ok, my_last) = shared.raft.handle_append_entries(
                term,
                leader_id,
                prev_idx,
                prev_term,
                entries,
                leader_commit,
            )?;
            write_array_header(out, 3);
            write_integer(out, cur_term as i64);
            write_integer(out, i64::from(ok));
            write_integer(out, my_last as i64);
            return Ok(());
        } else if sub.eq_ignore_ascii_case(b"ELECT") {
            let won = shared.raft.start_election()?;
            write_integer(out, i64::from(won));
            return Ok(());
        } else {
            return Err(EngineError::InvalidArgument(
                "unknown RAFT subcommand".to_string(),
            ));
        }
    }

    if cmd.eq_ignore_ascii_case(b"RAFT.VOTE") || cmd.eq_ignore_ascii_case(b"RAFT.REQUESTVOTE") {
        if inside_exclusive_tx {
            return Err(EngineError::InvalidArgument(
                "RAFT.VOTE is not allowed inside MULTI/EXEC".to_string(),
            ));
        }
        require_exact_args("raft.vote", args, 5)?;
        let term = parse_i64_bytes(args[1])?.max(0) as u64;
        let candidate_id = std::str::from_utf8(args[2])?;
        let last_idx = parse_i64_bytes(args[3])?.max(0) as u64;
        let last_term = parse_i64_bytes(args[4])?.max(0) as u64;
        let (cur_term, granted) =
            shared
                .raft
                .handle_request_vote(term, candidate_id, last_idx, last_term)?;
        write_array_header(out, 2);
        write_integer(out, cur_term as i64);
        write_integer(out, i64::from(granted));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"RAFT.APPEND") || cmd.eq_ignore_ascii_case(b"RAFT.APPENDENTRIES") {
        if inside_exclusive_tx {
            return Err(EngineError::InvalidArgument(
                "RAFT.APPEND is not allowed inside MULTI/EXEC".to_string(),
            ));
        }
        require_min_args("raft.append", args, 6)?;
        if (args.len() - 6) % 3 != 0 {
            return Err(EngineError::InvalidArgument(
                "malformed RAFT.APPEND entry triples".to_string(),
            ));
        }
        let term = parse_i64_bytes(args[1])?.max(0) as u64;
        let leader_id = std::str::from_utf8(args[2])?;
        let prev_idx = parse_i64_bytes(args[3])?.max(0) as u64;
        let prev_term = parse_i64_bytes(args[4])?.max(0) as u64;
        let leader_commit = parse_i64_bytes(args[5])?.max(0) as u64;

        let mut entries = Vec::with_capacity((args.len() - 6) / 3);
        let mut i = 6usize;
        while i + 2 < args.len() {
            let e_idx = parse_i64_bytes(args[i])?.max(1) as u64;
            let e_term = parse_i64_bytes(args[i + 1])?.max(0) as u64;
            let e_wire = args[i + 2];
            entries.push(RaftLogEntry::decode_command_wire(e_idx, e_term, e_wire)?);
            i += 3;
        }
        let (cur_term, ok, my_last) = shared.raft.handle_append_entries(
            term,
            leader_id,
            prev_idx,
            prev_term,
            entries,
            leader_commit,
        )?;
        write_array_header(out, 3);
        write_integer(out, cur_term as i64);
        write_integer(out, i64::from(ok));
        write_integer(out, my_last as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"RAFT.STATUS") {
        let st = shared.raft.status()?;
        write_map_header(out, 7);
        write_bulk_string(out, b"node_id");
        write_bulk_string(out, st.node_id.as_bytes());
        write_bulk_string(out, b"role");
        write_bulk_string(out, st.role.as_str().as_bytes());
        write_bulk_string(out, b"term");
        write_integer(out, st.current_term as i64);
        write_bulk_string(out, b"commit_index");
        write_integer(out, st.commit_index as i64);
        write_bulk_string(out, b"last_applied");
        write_integer(out, st.last_applied as i64);
        write_bulk_string(out, b"log_len");
        write_integer(out, st.log_len as i64);
        write_bulk_string(out, b"leader_id");
        match st.leader_id {
            Some(l) => write_bulk_string(out, l.as_bytes()),
            None => write_null(out),
        }
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"RAFT.ELECT") {
        if inside_exclusive_tx {
            return Err(EngineError::InvalidArgument(
                "RAFT.ELECT is not allowed inside MULTI/EXEC".to_string(),
            ));
        }
        let won = shared.raft.start_election()?;
        write_integer(out, i64::from(won));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"RAFT.PROPOSE") {
        if inside_exclusive_tx {
            return Err(EngineError::InvalidArgument(
                "RAFT.PROPOSE is not allowed inside MULTI/EXEC".to_string(),
            ));
        }
        require_min_args("raft.propose", args, 2)?;
        shared.raft.propose_command(&args[1..], out)?;
        return Ok(());
    }

    // ==================== PERSISTENCE & SNAPSHOTS ====================

    if cmd.eq_ignore_ascii_case(b"SAVE") {
        require_exact_args("save", args, 1)?;
        save_binary_snapshot(&shared.snapshot_path, &shared.storage)?;
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"SAVE.ENCRYPTED") {
        require_exact_args("save.encrypted", args, 2)?;
        let key32 = sha256(args[1]);
        let mut enc_path = shared.snapshot_path.as_os_str().to_os_string();
        enc_path.push(".enc");
        save_encrypted_snapshot(PathBuf::from(enc_path), &shared.storage, &key32)?;
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"BGREWRITEAOF") {
        require_exact_args("bgrewriteaof", args, 1)?;
        let Some(ref aof_arc) = shared.aof else {
            return Err(EngineError::InvalidArgument(
                "AOF persistence is disabled on this server instance".to_string(),
            ));
        };
        let aof_clone = Arc::clone(aof_arc);
        let storage_clone = Arc::clone(&shared.storage);
        thread::Builder::new()
            .name("ferrum-aof-compactor".to_string())
            .spawn(move || {
                let _ = aof_clone.compact_from_storage(&storage_clone);
            })?;
        write_simple_string(out, b"Background append only file rewriting started");
        return Ok(());
    }

    // ==================== HYBRID LSM-TREE ENGINE ====================

    if cmd.eq_ignore_ascii_case(b"LSM.PUT") {
        require_exact_args("lsm.put", args, 3)?;
        shared.storage.lsm_engine()?.put(args[1], args[2])?;
        write_simple_string(out, b"OK");
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"LSM.DEL") {
        require_exact_args("lsm.del", args, 2)?;
        shared.storage.lsm_engine()?.delete(args[1])?;
        write_simple_string(out, b"OK");
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"LSM.GET") {
        require_exact_args("lsm.get", args, 2)?;
        shared.storage.lsm_engine()?.get_into(args[1], out)?;
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"LSM.SCAN") {
        require_min_args("lsm.scan", args, 3)?;
        let limit = if args.len() >= 5 && args[3].eq_ignore_ascii_case(b"LIMIT") {
            parse_i64_bytes(args[4])?.max(1) as usize
        } else if args.len() == 4 {
            parse_i64_bytes(args[3])?.max(1) as usize
        } else {
            100
        };
        let rows = shared.storage.lsm_engine()?.scan(args[1], args[2], limit)?;
        write_array_header(out, rows.len() * 2);
        for (k, v) in rows {
            write_bulk_string(out, &k);
            write_bulk_string(out, &v);
        }
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"LSM.FLUSH") {
        require_exact_args("lsm.flush", args, 1)?;
        let flushed = shared.storage.lsm_engine()?.flush()?;
        write_integer(out, i64::from(flushed));
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"LSM.COMPACT") {
        require_exact_args("lsm.compact", args, 1)?;
        let remaining_sst = shared.storage.lsm_engine()?.compact_all()?;
        write_integer(out, remaining_sst as i64);
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"LSM.STATS") {
        require_exact_args("lsm.stats", args, 1)?;
        let (mem_keys, sst_cnt, sst_entries) = shared.storage.lsm_engine()?.stats()?;
        write_map_header(out, 3);
        write_bulk_string(out, b"memtable_keys");
        write_integer(out, mem_keys as i64);
        write_bulk_string(out, b"sstables");
        write_integer(out, sst_cnt as i64);
        write_bulk_string(out, b"sstable_entries");
        write_integer(out, sst_entries as i64);
        return Ok(());
    }

    // ==================== SHARDED IN-MEMORY STORAGE & BYTECODE VM ====================
    // Acquire shared TX fence when running outside `EXEC` so `EXEC` multi-shard verification is atomic.
    let _shared_tx_guard = if inside_exclusive_tx {
        None
    } else {
        Some(shared.storage.tx_shared_guard()?)
    };

    // --- Scripting VM ---
    if cmd.eq_ignore_ascii_case(b"SCRIPT") {
        require_min_args("script", args, 2)?;
        if args[1].eq_ignore_ascii_case(b"LOAD") {
            require_exact_args("script load", args, 3)?;
            let (sha, _) = shared.scripts.load_script(args[2])?;
            write_bulk_string(out, sha.as_bytes());
            return Ok(());
        } else if args[1].eq_ignore_ascii_case(b"EXISTS") {
            require_min_args("script exists", args, 3)?;
            let flags = shared.scripts.exists(&args[2..])?;
            write_array_header(out, flags.len());
            for f in flags {
                write_integer(out, i64::from(f));
            }
            return Ok(());
        } else if args[1].eq_ignore_ascii_case(b"FLUSH") {
            shared.scripts.flush()?;
            write_simple_string(out, b"OK");
            return Ok(());
        } else {
            return Err(EngineError::InvalidArgument(
                "unknown SCRIPT subcommand".to_string(),
            ));
        }
    }

    if cmd.eq_ignore_ascii_case(b"EVAL") || cmd.eq_ignore_ascii_case(b"EVALSHA") {
        require_min_args("eval", args, 3)?;
        let num_keys = parse_i64_bytes(args[2])?;
        if num_keys < 0 || 3 + (num_keys as usize) > args.len() {
            return Err(EngineError::InvalidArgument(
                "Number of keys can't be negative or greater than arguments".to_string(),
            ));
        }
        let nk = num_keys as usize;
        let keys = &args[3..3 + nk];
        let argv = &args[3 + nk..];
        let val = if cmd.eq_ignore_ascii_case(b"EVAL") {
            shared
                .scripts
                .eval_source(args[1], keys, argv, &shared.storage)?
        } else {
            shared
                .scripts
                .eval_sha(args[1], keys, argv, &shared.storage)?
        };
        shared
            .telemetry
            .scripts_executed_total
            .fetch_add(1, AtomicOrdering::Relaxed);
        val.write_resp(out);
        return Ok(());
    }

    // --- String & Generic Keyspace ---
    if cmd.eq_ignore_ascii_case(b"GET") {
        require_exact_args("get", args, 2)?;
        shared.storage.get_into(args[1], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"CAS") {
        require_exact_args("cas", args, 4)?;
        let cur = shared.storage.get_bytes(args[1])?;
        let matched = match &cur {
            Some(c) => c.as_ref() == args[2],
            None => args[2].is_empty() || args[2] == b"__NIL__",
        };
        if matched {
            shared
                .storage
                .set(args[1], args[3], None, SetCondition::Always)?;
            if let Some(ref aof) = shared.aof {
                aof.log_command(&[b"SET", args[1], args[3]])?;
            }
            write_integer(out, 1);
        } else {
            write_integer(out, 0);
        }
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"SET") {
        require_min_args("set", args, 3)?;
        let key = args[1];
        let val = args[2];
        let mut ttl: Option<Duration> = None;
        let mut cond = SetCondition::Always;
        let mut idx = 3usize;
        while idx < args.len() {
            let opt = args[idx];
            if opt.eq_ignore_ascii_case(b"NX") {
                cond = SetCondition::IfAbsent;
                idx += 1;
            } else if opt.eq_ignore_ascii_case(b"XX") {
                cond = SetCondition::IfPresent;
                idx += 1;
            } else if opt.eq_ignore_ascii_case(b"EX") {
                if idx + 1 >= args.len() {
                    return Err(EngineError::InvalidArgument("syntax error".to_string()));
                }
                let secs = parse_i64_bytes(args[idx + 1])?;
                if secs <= 0 {
                    return Err(EngineError::InvalidArgument(
                        "invalid expire time in 'set' command".to_string(),
                    ));
                }
                ttl = Some(Duration::from_secs(secs as u64));
                idx += 2;
            } else if opt.eq_ignore_ascii_case(b"PX") {
                if idx + 1 >= args.len() {
                    return Err(EngineError::InvalidArgument("syntax error".to_string()));
                }
                let ms = parse_i64_bytes(args[idx + 1])?;
                if ms <= 0 {
                    return Err(EngineError::InvalidArgument(
                        "invalid expire time in 'set' command".to_string(),
                    ));
                }
                ttl = Some(Duration::from_millis(ms as u64));
                idx += 2;
            } else {
                return Err(EngineError::InvalidArgument("syntax error".to_string()));
            }
        }

        let applied = shared.storage.set(key, val, ttl, cond)?;
        if applied {
            if let Some(ref aof) = shared.aof {
                if let Some(d) = ttl {
                    let unix_ms = shared.storage.now_unix_ms() + d.as_millis() as u64;
                    let ms_str = unix_ms.to_string();
                    let mut batch = Vec::with_capacity(96 + key.len() + val.len());
                    encode_command_slices(&mut batch, &[b"SET", key, val]);
                    encode_command_slices(&mut batch, &[b"PEXPIREAT", key, ms_str.as_bytes()]);
                    aof.log_raw_bytes(batch)?;
                } else {
                    aof.log_command(&[b"SET", key, val])?;
                }
            }
            write_simple_string(out, b"OK");
        } else {
            write_null(out);
        }
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"DEL") {
        require_min_args("del", args, 2)?;
        let count = shared.storage.del(&args[1..])?;
        if count > 0 {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, count as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"EXISTS") {
        require_min_args("exists", args, 2)?;
        write_integer(out, shared.storage.exists(&args[1..])? as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"TYPE") {
        require_exact_args("type", args, 2)?;
        let t = shared.storage.key_type(args[1])?;
        write_simple_string(out, t.as_bytes());
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"INCR") {
        require_exact_args("incr", args, 2)?;
        let v = shared.storage.incr_by(args[1], 1)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, v);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"DECR") {
        require_exact_args("decr", args, 2)?;
        let v = shared.storage.incr_by(args[1], -1)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, v);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"INCRBY") {
        require_exact_args("incrby", args, 3)?;
        let delta = parse_i64_bytes(args[2])?;
        let v = shared.storage.incr_by(args[1], delta)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, v);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"APPEND") {
        require_exact_args("append", args, 3)?;
        let len = shared.storage.append(args[1], args[2])?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, len as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"STRLEN") {
        require_exact_args("strlen", args, 2)?;
        write_integer(out, shared.storage.strlen(args[1])? as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"EXPIRE") {
        require_exact_args("expire", args, 3)?;
        let secs = parse_i64_bytes(args[2])?;
        let ms = secs.saturating_mul(1000);
        let ok = shared.storage.pexpire(args[1], ms)?;
        if ok {
            if let Some(ref aof) = shared.aof {
                let target = shared
                    .storage
                    .now_unix_ms()
                    .saturating_add(ms.max(0) as u64);
                let target_s = target.to_string();
                aof.log_command(&[b"PEXPIREAT", args[1], target_s.as_bytes()])?;
            }
        }
        write_integer(out, i64::from(ok));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PEXPIRE") {
        require_exact_args("pexpire", args, 3)?;
        let ms = parse_i64_bytes(args[2])?;
        let ok = shared.storage.pexpire(args[1], ms)?;
        if ok {
            if let Some(ref aof) = shared.aof {
                let target = shared
                    .storage
                    .now_unix_ms()
                    .saturating_add(ms.max(0) as u64);
                let target_s = target.to_string();
                aof.log_command(&[b"PEXPIREAT", args[1], target_s.as_bytes()])?;
            }
        }
        write_integer(out, i64::from(ok));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PEXPIREAT") {
        require_exact_args("pexpireat", args, 3)?;
        let target = parse_i64_bytes(args[2])?;
        let ok = if target <= 0 {
            shared.storage.del(&[args[1]])? > 0
        } else {
            shared.storage.pexpire_at_unix_ms(args[1], target as u64)?
        };
        if ok {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, i64::from(ok));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"TTL") {
        require_exact_args("ttl", args, 2)?;
        let pttl = shared.storage.pttl(args[1])?;
        let ttl = if pttl < 0 { pttl } else { (pttl + 500) / 1000 };
        write_integer(out, ttl);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PTTL") {
        require_exact_args("pttl", args, 2)?;
        write_integer(out, shared.storage.pttl(args[1])?);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PERSIST") {
        require_exact_args("persist", args, 2)?;
        let ok = shared.storage.persist(args[1])?;
        if ok {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, i64::from(ok));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"DBSIZE") {
        require_exact_args("dbsize", args, 1)?;
        write_integer(out, shared.storage.dbsize()? as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"FLUSHDB") {
        shared.storage.flushdb()?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(&[b"FLUSHDB"])?;
        }
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"KEYS") {
        require_exact_args("keys", args, 2)?;
        shared.storage.keys_into(args[1], out)?;
        return Ok(());
    }

    // ==================== LISTS (RING BUFFER) ====================

    if cmd.eq_ignore_ascii_case(b"LPUSH") {
        require_min_args("lpush", args, 3)?;
        let len = shared.storage.list_push(args[1], &args[2..], true)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, len as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"RPUSH") {
        require_min_args("rpush", args, 3)?;
        let len = shared.storage.list_push(args[1], &args[2..], false)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, len as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"LPOP") {
        require_exact_args("lpop", args, 2)?;
        match shared.storage.list_pop(args[1], true)? {
            Some(val) => {
                if let Some(ref aof) = shared.aof {
                    aof.log_command(args)?;
                }
                write_bulk_string(out, &val);
            }
            None => write_null(out),
        }
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"RPOP") {
        require_exact_args("rpop", args, 2)?;
        match shared.storage.list_pop(args[1], false)? {
            Some(val) => {
                if let Some(ref aof) = shared.aof {
                    aof.log_command(args)?;
                }
                write_bulk_string(out, &val);
            }
            None => write_null(out),
        }
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"LLEN") {
        require_exact_args("llen", args, 2)?;
        write_integer(out, shared.storage.llen(args[1])? as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"LINDEX") {
        require_exact_args("lindex", args, 3)?;
        shared
            .storage
            .lindex_into(args[1], parse_i64_bytes(args[2])?, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"LRANGE") {
        require_exact_args("lrange", args, 4)?;
        shared.storage.lrange_into(
            args[1],
            parse_i64_bytes(args[2])?,
            parse_i64_bytes(args[3])?,
            out,
        )?;
        return Ok(());
    }

    // ==================== HASHES (ROBIN HOOD TABLE) ====================

    if cmd.eq_ignore_ascii_case(b"HSET") {
        if args.len() < 4 || args.len() % 2 != 0 {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'hset' command".to_string(),
            ));
        }
        let mut pairs = Vec::with_capacity((args.len() - 2) / 2);
        let mut i = 2usize;
        while i + 1 < args.len() {
            pairs.push((args[i], args[i + 1]));
            i += 2;
        }
        let added = shared.storage.hset(args[1], &pairs)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, added as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"HGET") {
        require_exact_args("hget", args, 3)?;
        shared.storage.hget_into(args[1], args[2], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"HDEL") {
        require_min_args("hdel", args, 3)?;
        let removed = shared.storage.hdel(args[1], &args[2..])?;
        if removed > 0 {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, removed as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"HLEN") {
        require_exact_args("hlen", args, 2)?;
        write_integer(out, shared.storage.hlen(args[1])? as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"HGETALL") {
        require_exact_args("hgetall", args, 2)?;
        shared.storage.hgetall_into(args[1], out)?;
        return Ok(());
    }

    // ==================== SORTED SETS & 52-BIT MORTON GEOHASH ====================

    if cmd.eq_ignore_ascii_case(b"ZADD") {
        if args.len() < 4 || args.len() % 2 != 0 {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'zadd' command".to_string(),
            ));
        }
        let mut entries = Vec::with_capacity((args.len() - 2) / 2);
        let mut i = 2usize;
        while i + 1 < args.len() {
            entries.push((parse_f64_bytes(args[i])?, args[i + 1]));
            i += 2;
        }
        let added = shared.storage.zadd(args[1], &entries)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, added as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"ZREM") {
        require_min_args("zrem", args, 3)?;
        let removed = shared.storage.zrem(args[1], &args[2..])?;
        if removed > 0 {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, removed as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"ZSCORE") {
        require_exact_args("zscore", args, 3)?;
        shared.storage.zscore_into(args[1], args[2], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"ZCARD") {
        require_exact_args("zcard", args, 2)?;
        write_integer(out, shared.storage.zcard(args[1])? as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"ZRANK") {
        require_exact_args("zrank", args, 3)?;
        match shared.storage.zrank(args[1], args[2])? {
            Some(rank) => write_integer(out, rank as i64),
            None => write_null(out),
        }
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"ZRANGE") {
        if args.len() != 4 && args.len() != 5 {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'zrange' command".to_string(),
            ));
        }
        let start = parse_i64_bytes(args[2])?;
        let stop = parse_i64_bytes(args[3])?;
        let with_scores = if args.len() == 5 {
            if args[4].eq_ignore_ascii_case(b"WITHSCORES") {
                true
            } else {
                return Err(EngineError::InvalidArgument("syntax error".to_string()));
            }
        } else {
            false
        };
        shared
            .storage
            .zrange_into(args[1], start, stop, with_scores, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"ZRANGEBYSCORE") {
        if args.len() != 4 && args.len() != 5 {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'zrangebyscore' command".to_string(),
            ));
        }
        let min_s = parse_f64_bytes(args[2])?;
        let max_s = parse_f64_bytes(args[3])?;
        let with_scores = if args.len() == 5 {
            if args[4].eq_ignore_ascii_case(b"WITHSCORES") {
                true
            } else {
                return Err(EngineError::InvalidArgument("syntax error".to_string()));
            }
        } else {
            false
        };
        shared
            .storage
            .zrange_by_score_into(args[1], min_s, max_s, with_scores, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"GEOADD") {
        if args.len() < 5 || (args.len() - 2) % 3 != 0 {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'geoadd' command".to_string(),
            ));
        }
        let mut items = Vec::with_capacity((args.len() - 2) / 3);
        let mut i = 2usize;
        while i + 2 < args.len() {
            items.push((
                parse_f64_bytes(args[i])?,
                parse_f64_bytes(args[i + 1])?,
                args[i + 2],
            ));
            i += 3;
        }
        let added = shared.storage.geoadd(args[1], &items)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, added as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"GEOPOS") {
        require_min_args("geopos", args, 3)?;
        shared.storage.geopos_into(args[1], &args[2..], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"GEODIST") {
        if args.len() != 4 && args.len() != 5 {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'geodist' command".to_string(),
            ));
        }
        let unit = if args.len() == 5 {
            GeoUnit::from_bytes(args[4])?
        } else {
            GeoUnit::Meters
        };
        shared
            .storage
            .geodist_into(args[1], args[2], args[3], unit, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"GEORADIUS") {
        require_min_args("georadius", args, 6)?;
        let lon = parse_f64_bytes(args[2])?;
        let lat = parse_f64_bytes(args[3])?;
        let radius = parse_f64_bytes(args[4])?;
        let unit = GeoUnit::from_bytes(args[5])?;
        let mut with_dist = false;
        let mut with_coord = false;
        let mut ascending = true;
        let mut count: Option<usize> = None;

        let mut i = 6usize;
        while i < args.len() {
            let opt = args[i];
            if opt.eq_ignore_ascii_case(b"WITHDIST") {
                with_dist = true;
                i += 1;
            } else if opt.eq_ignore_ascii_case(b"WITHCOORD") {
                with_coord = true;
                i += 1;
            } else if opt.eq_ignore_ascii_case(b"ASC") {
                ascending = true;
                i += 1;
            } else if opt.eq_ignore_ascii_case(b"DESC") {
                ascending = false;
                i += 1;
            } else if opt.eq_ignore_ascii_case(b"COUNT") {
                if i + 1 >= args.len() {
                    return Err(EngineError::InvalidArgument("syntax error".to_string()));
                }
                count = Some(parse_i64_bytes(args[i + 1])?.max(1) as usize);
                i += 2;
            } else {
                return Err(EngineError::InvalidArgument("syntax error".to_string()));
            }
        }
        shared.storage.georadius_into(
            args[1], lon, lat, radius, unit, with_dist, with_coord, ascending, count, out,
        )?;
        return Ok(());
    }

    // ==================== REDIS STREAMS & CONSUMER GROUPS ====================

    if cmd.eq_ignore_ascii_case(b"XADD") {
        if args.len() < 5 || (args.len() - 3) % 2 != 0 {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'xadd' command".to_string(),
            ));
        }
        let mut pairs = Vec::with_capacity((args.len() - 3) / 2);
        let mut i = 3usize;
        while i + 1 < args.len() {
            pairs.push((args[i], args[i + 1]));
            i += 2;
        }
        let assigned_id = shared.storage.xadd(args[1], args[2], &pairs)?;
        let id_bytes = assigned_id.format_bytes();
        if let Some(ref aof) = shared.aof {
            let mut aof_cmd: Vec<&[u8]> = Vec::with_capacity(args.len());
            aof_cmd.push(b"XADD");
            aof_cmd.push(args[1]);
            aof_cmd.push(&id_bytes);
            aof_cmd.extend_from_slice(&args[3..]);
            aof.log_command(&aof_cmd)?;
        }
        write_bulk_string(out, &id_bytes);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"XLEN") {
        require_exact_args("xlen", args, 2)?;
        write_integer(out, shared.storage.xlen(args[1])? as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"XRANGE") {
        require_min_args("xrange", args, 4)?;
        let start = StreamId::parse_range_bound(args[2], false)?;
        let end = StreamId::parse_range_bound(args[3], true)?;
        let count = if args.len() == 6 && args[4].eq_ignore_ascii_case(b"COUNT") {
            Some(parse_i64_bytes(args[5])?.max(1) as usize)
        } else if args.len() == 4 {
            None
        } else {
            return Err(EngineError::InvalidArgument("syntax error".to_string()));
        };
        shared.storage.xrange_into(args[1], start, end, count, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"XREAD") {
        require_min_args("xread", args, 4)?;
        let mut idx = 1usize;
        let mut count = None;
        if args[idx].eq_ignore_ascii_case(b"COUNT") {
            require_min_args("xread", args, 6)?;
            count = Some(parse_i64_bytes(args[idx + 1])?.max(1) as usize);
            idx += 2;
        }
        if !args[idx].eq_ignore_ascii_case(b"STREAMS") {
            return Err(EngineError::InvalidArgument("syntax error".to_string()));
        }
        idx += 1;
        let rem = &args[idx..];
        if rem.is_empty() || rem.len() % 2 != 0 {
            return Err(EngineError::InvalidArgument(
                "Unbalanced XREAD list of streams".to_string(),
            ));
        }
        let half = rem.len() / 2;
        let mut streams = Vec::with_capacity(half);
        for i in 0..half {
            let sid = if rem[half + i] == b"0" {
                StreamId::ZERO
            } else {
                StreamId::parse_explicit(rem[half + i])?
            };
            streams.push((rem[i], sid));
        }
        shared.storage.xread_into(&streams, count, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"XGROUP") {
        require_min_args("xgroup", args, 5)?;
        if !args[1].eq_ignore_ascii_case(b"CREATE") {
            return Err(EngineError::InvalidArgument(
                "unknown XGROUP subcommand, expected CREATE".to_string(),
            ));
        }
        let mkstream = if args.len() == 6 {
            if args[5].eq_ignore_ascii_case(b"MKSTREAM") {
                true
            } else {
                return Err(EngineError::InvalidArgument("syntax error".to_string()));
            }
        } else {
            false
        };
        shared
            .storage
            .xgroup_create(args[2], args[3], args[4], mkstream)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"XREADGROUP") {
        require_min_args("xreadgroup", args, 7)?;
        if !args[1].eq_ignore_ascii_case(b"GROUP") {
            return Err(EngineError::InvalidArgument("syntax error".to_string()));
        }
        let group = args[2];
        let consumer = args[3];
        let mut idx = 4usize;
        let mut count = None;
        if args[idx].eq_ignore_ascii_case(b"COUNT") {
            require_min_args("xreadgroup", args, 9)?;
            count = Some(parse_i64_bytes(args[idx + 1])?.max(1) as usize);
            idx += 2;
        }
        if !args[idx].eq_ignore_ascii_case(b"STREAMS") {
            return Err(EngineError::InvalidArgument("syntax error".to_string()));
        }
        idx += 1;
        let rem = &args[idx..];
        if rem.is_empty() || rem.len() % 2 != 0 {
            return Err(EngineError::InvalidArgument(
                "Unbalanced XREADGROUP list of streams".to_string(),
            ));
        }
        let half = rem.len() / 2;
        let mut streams = Vec::with_capacity(half);
        for i in 0..half {
            streams.push((rem[i], rem[half + i]));
        }
        shared
            .storage
            .xreadgroup_into(group, consumer, &streams, count, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"XACK") {
        require_min_args("xack", args, 4)?;
        let mut ids = Vec::with_capacity(args.len() - 3);
        for &raw in &args[3..] {
            ids.push(StreamId::parse_explicit(raw)?);
        }
        let acked = shared.storage.xack(args[1], args[2], &ids)?;
        if acked > 0 {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, acked as i64);
        return Ok(());
    }

    // ==================== PROBABILISTIC (HLL, BLOOM, CMS) ====================

    if cmd.eq_ignore_ascii_case(b"PFADD") {
        require_min_args("pfadd", args, 2)?;
        let altered = shared.storage.pfadd(args[1], &args[2..])?;
        if altered {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, i64::from(altered));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PFCOUNT") {
        require_min_args("pfcount", args, 2)?;
        let card = shared.storage.pfcount(&args[1..])?;
        write_integer(out, card as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PFMERGE") {
        require_min_args("pfmerge", args, 3)?;
        shared.storage.pfmerge(args[1], &args[2..])?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_simple_string(out, b"OK");
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"BF.ADD") {
        require_exact_args("bf.add", args, 3)?;
        let added = shared.storage.bf_add(args[1], args[2])?;
        if added {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, i64::from(added));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"BF.EXISTS") {
        require_exact_args("bf.exists", args, 3)?;
        let exists = shared.storage.bf_exists(args[1], args[2])?;
        write_integer(out, i64::from(exists));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"CMS.INCRBY") {
        if args.len() < 4 || args.len() % 2 != 0 {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'cms.incrby' command".to_string(),
            ));
        }
        let mut inc = Vec::with_capacity((args.len() - 2) / 2);
        let mut i = 2usize;
        while i + 1 < args.len() {
            let delta = parse_i64_bytes(args[i + 1])?;
            if delta < 0 {
                return Err(EngineError::InvalidArgument(
                    "CMS.INCRBY increment must be non-negative".to_string(),
                ));
            }
            inc.push((args[i], delta as u64));
            i += 2;
        }
        let vals = shared.storage.cms_incrby(args[1], &inc)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_array_header(out, vals.len());
        for v in vals {
            write_integer(out, v as i64);
        }
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"CMS.QUERY") {
        require_min_args("cms.query", args, 3)?;
        let vals = shared.storage.cms_query(args[1], &args[2..])?;
        write_array_header(out, vals.len());
        for v in vals {
            write_integer(out, v as i64);
        }
        return Ok(());
    }

    // ==================== HNSW VECTOR SIMILARITY ENGINE ====================

    if cmd.eq_ignore_ascii_case(b"VADD") {
        require_min_args("vadd", args, 4)?;
        let mut metric = None;
        let mut sq8 = None;
        let mut end = args.len();
        while end > 3 {
            let tail = args[end - 1];
            if tail.eq_ignore_ascii_case(b"SQ8") {
                sq8 = Some(true);
                end -= 1;
            } else if tail.eq_ignore_ascii_case(b"F32") {
                sq8 = Some(false);
                end -= 1;
            } else if end >= 5 && args[end - 2].eq_ignore_ascii_case(b"METRIC") {
                metric = Some(VectorMetric::from_bytes(tail)?);
                end -= 2;
            } else {
                break;
            }
        }
        if end <= 3 {
            return Err(EngineError::InvalidArgument(
                "VADD requires at least one float dimension".to_string(),
            ));
        }
        let mut vec = Vec::with_capacity(end - 3);
        for &tok in &args[3..end] {
            vec.push(parse_f64_bytes(tok)? as f32);
        }
        let added = shared.storage.vadd(args[1], args[2], &vec, metric, sq8)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(args)?;
        }
        write_integer(out, i64::from(added));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"VSEARCH") {
        require_min_args("vsearch", args, 4)?;
        let k = parse_i64_bytes(args[2])?.max(1) as usize;
        let mut ef = None;
        let mut end = args.len();
        if end >= 6 && args[end - 2].eq_ignore_ascii_case(b"EF") {
            ef = Some(parse_i64_bytes(args[end - 1])?.max(1) as usize);
            end -= 2;
        }
        let mut query = Vec::with_capacity(end - 3);
        for &tok in &args[3..end] {
            query.push(parse_f64_bytes(tok)? as f32);
        }
        shared.storage.vsearch_into(args[1], &query, k, ef, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"VCARD") {
        require_exact_args("vcard", args, 2)?;
        write_integer(out, shared.storage.vcard(args[1])? as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"VREM") {
        require_exact_args("vrem", args, 3)?;
        let removed = shared.storage.vrem(args[1], args[2])?;
        if removed {
            if let Some(ref aof) = shared.aof {
                aof.log_command(args)?;
            }
        }
        write_integer(out, i64::from(removed));
        return Ok(());
    }

    // ==================== BM25 FULL-TEXT INDEX ====================

    if cmd.eq_ignore_ascii_case(b"FT.ADD") {
        require_min_args("ft.add", args, 4)?;
        let text_owned: String = if args.len() == 4 {
            std::str::from_utf8(args[3])?.to_string()
        } else {
            let mut parts = Vec::with_capacity(args.len() - 3);
            for &a in &args[3..] {
                parts.push(std::str::from_utf8(a)?);
            }
            parts.join(" ")
        };
        let added = shared.storage.ft_add(args[1], args[2], &text_owned)?;
        if let Some(ref aof) = shared.aof {
            aof.log_command(&[b"FT.ADD", args[1], args[2], text_owned.as_bytes()])?;
        }
        write_integer(out, i64::from(added));
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"FT.SEARCH") {
        require_min_args("ft.search", args, 3)?;
        let query = std::str::from_utf8(args[2])?;
        let limit = if args.len() == 5 && args[3].eq_ignore_ascii_case(b"LIMIT") {
            parse_i64_bytes(args[4])?.max(1) as usize
        } else if args.len() == 3 {
            10
        } else {
            return Err(EngineError::InvalidArgument("syntax error".to_string()));
        };
        shared.storage.ft_search_into(args[1], query, limit, out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"FT.SUGG") {
        require_min_args("ft.sugg", args, 3)?;
        let prefix = std::str::from_utf8(args[2])?;
        let limit = if args.len() == 5 && args[3].eq_ignore_ascii_case(b"LIMIT") {
            parse_i64_bytes(args[4])?.max(1) as usize
        } else {
            10
        };
        shared.storage.ft_sugg_into(args[1], prefix, limit, out)?;
        return Ok(());
    }

    // ==================== GORILLA XOR TIME-SERIES ====================

    if cmd.eq_ignore_ascii_case(b"TS.ADD") {
        require_exact_args("ts.add", args, 4)?;
        let ts = if args[2] == b"*" {
            shared.storage.now_unix_ms() as i64
        } else {
            parse_i64_bytes(args[2])?
        };
        let val = parse_f64_bytes(args[3])?;
        let stored_ts = shared.storage.ts_add(args[1], ts, val)?;
        if let Some(ref aof) = shared.aof {
            let ts_s = stored_ts.to_string();
            aof.log_command(&[b"TS.ADD", args[1], ts_s.as_bytes(), args[3]])?;
        }
        write_integer(out, stored_ts);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"TS.GET") {
        require_exact_args("ts.get", args, 2)?;
        shared.storage.ts_get_into(args[1], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"TS.RANGE") {
        require_min_args("ts.range", args, 4)?;
        let from_ts = if args[2] == b"-" {
            i64::MIN
        } else {
            parse_i64_bytes(args[2])?
        };
        let to_ts = if args[3] == b"+" {
            i64::MAX
        } else {
            parse_i64_bytes(args[3])?
        };
        let agg = if args.len() == 7 && args[4].eq_ignore_ascii_case(b"AGG") {
            let kind = TsAggregation::from_bytes(args[5])?;
            let bucket = parse_i64_bytes(args[6])?;
            Some((kind, bucket))
        } else if args.len() == 4 {
            None
        } else {
            return Err(EngineError::InvalidArgument("syntax error".to_string()));
        };
        let _ = write_double;
        shared
            .storage
            .ts_range_into(args[1], from_ts, to_ts, agg, out)?;
        return Ok(());
    }

    // ==================== PUB/SUB ====================

    if cmd.eq_ignore_ascii_case(b"SUBSCRIBE") {
        require_min_args("subscribe", args, 2)?;
        shared
            .pubsub
            .subscribe(client_id, outbox, subscriptions, &args[1..], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"UNSUBSCRIBE") {
        shared
            .pubsub
            .unsubscribe(client_id, subscriptions, &args[1..], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PSUBSCRIBE") {
        require_min_args("psubscribe", args, 2)?;
        shared
            .pubsub
            .psubscribe(client_id, outbox, subscriptions, &args[1..], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PUNSUBSCRIBE") {
        shared
            .pubsub
            .punsubscribe(client_id, subscriptions, &args[1..], out)?;
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PUBLISH") {
        require_exact_args("publish", args, 3)?;
        let receivers = shared.pubsub.publish(args[1], args[2])?;
        write_integer(out, receivers as i64);
        return Ok(());
    }

    if cmd.eq_ignore_ascii_case(b"PUBSUB") {
        require_min_args("pubsub", args, 2)?;
        if args[1].eq_ignore_ascii_case(b"NUMPAT") {
            write_integer(out, shared.pubsub.numpat()? as i64);
            return Ok(());
        }
        return Err(EngineError::InvalidArgument(
            "unknown PUBSUB subcommand".to_string(),
        ));
    }

    let name = String::from_utf8_lossy(cmd);
    Err(EngineError::InvalidArgument(format!(
        "unknown command '{}'",
        name
    )))
}

#[inline]
fn require_exact_args(name: &str, args: &[&[u8]], expected: usize) -> EngineResult<()> {
    if args.len() != expected {
        Err(EngineError::InvalidArgument(format!(
            "wrong number of arguments for '{}' command",
            name
        )))
    } else {
        Ok(())
    }
}

#[inline]
fn require_min_args(name: &str, args: &[&[u8]], min_len: usize) -> EngineResult<()> {
    if args.len() < min_len {
        Err(EngineError::InvalidArgument(format!(
            "wrong number of arguments for '{}' command",
            name
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_padded_alignment_and_record_version_watch_tombstone() {
        assert_eq!(std::mem::align_of::<CachePadded<AtomicU64>>(), 64);

        let engine = StorageEngine::new(4).unwrap();
        engine
            .set(b"k_watch", b"v1", None, SetCondition::Always)
            .unwrap();
        let stamp_before = engine.watch_stamp(b"k_watch").unwrap();
        assert_eq!(stamp_before.version, 1);

        // Overwrite in-place increments Record.version without needing key_versions entry.
        engine
            .set(b"k_watch", b"v2", None, SetCondition::Always)
            .unwrap();
        let stamp_after_set = engine.watch_stamp(b"k_watch").unwrap();
        assert_eq!(stamp_after_set.version, 2);

        // Deleting a watched key preserves bumped version in tombstone map so WATCH detects DEL.
        let deleted = engine.del(&[b"k_watch".as_slice()]).unwrap();
        assert_eq!(deleted, 1);
        let stamp_after_del = engine.watch_stamp(b"k_watch").unwrap();
        assert!(stamp_after_del.version > stamp_after_set.version);
    }

    #[test]
    fn test_multi_exec_rejects_synchronous_network_commands() {
        let mut cfg = ServerConfig::default();
        cfg.bind_addr = "127.0.0.1:0".to_string();
        cfg.aof_path = None;
        cfg.snapshot_path = std::env::temp_dir().join("ferrum_tx_rpc_test.snap");
        let mut server = FerrumServer::start(cfg).unwrap();
        let addr = server.local_addr();

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut payload = Vec::new();
        encode_command_slices(&mut payload, &[b"MULTI"]);
        encode_command_slices(
            &mut payload,
            &[b"CLUSTER", b"MIGRATE", &addr.to_string().into_bytes(), b"k1"],
        );
        encode_command_slices(&mut payload, &[b"RAFT", b"PROPOSE", b"SET", b"k1", b"v1"]);
        encode_command_slices(
            &mut payload,
            &[b"RAFT", b"REQUESTVOTE", b"1", b"node2", b"0", b"0"],
        );
        encode_command_slices(
            &mut payload,
            &[b"RAFT", b"APPENDENTRIES", b"1", b"node2", b"0", b"0", b"0"],
        );
        encode_command_slices(&mut payload, &[b"EXEC"]);
        client.write_all(&payload).unwrap();

        let mut rbuf = StreamReadBuffer::with_capacity(4096);
        let mut frames = Vec::new();
        while frames.len() < 6 {
            let dst = rbuf.writable_slice(1024);
            let n = client.read(dst).unwrap();
            assert!(n > 0);
            rbuf.advance_write(n);
            while let ParseStatus::Complete { frame, consumed } =
                RespParser::parse(rbuf.readable_slice()).unwrap()
            {
                let is_exec = frames.len() == 5;
                if is_exec {
                    if let RespFrame::Array(items) = frame {
                        assert_eq!(items.len(), 4);
                        for item in items {
                            assert!(matches!(item, RespFrame::SimpleError(_)));
                        }
                    } else {
                        panic!("expected EXEC array reply");
                    }
                }
                frames.push(consumed);
                rbuf.consume(consumed);
            }
        }

        server.shutdown();
    }
}
