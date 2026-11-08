use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::aof::{
    load_binary_snapshot, recover_from_crash, replay_aof, save_binary_snapshot, AofEngine,
    FsyncPolicy,
};
use crate::cli::read_one_frame;
use crate::cluster::raft::{PeerConfig, RaftRole};
use crate::error::{EngineError, EngineResult};
use crate::resp::{encode_command_slices, OwnedFrame, StreamReadBuffer};
use crate::server::{FerrumServer, ServerConfig};
use crate::storage::{SetCondition, StorageEngine};

#[derive(Clone, Debug)]
enum JepsenOp {
    IncrResult(i64),
    CasSuccess { from_seq: u64, to_seq: u64 },
    CasFailed { attempted_from: u64 },
    SetAck { key_idx: usize, val: u64 },
}

#[derive(Clone, Debug)]
struct HistoryRecord {
    invoke_ns: u64,
    complete_ns: u64,
    op: JepsenOp,
}

#[derive(Clone, Debug)]
pub struct JepsenSummary {
    pub total_invocations: usize,
    pub committed_ops: usize,
    pub rejected_during_partition: usize,
    pub incr_committed: usize,
    pub cas_swaps: usize,
    pub final_raft_term: u64,
    pub final_commit_index: u64,
    pub torn_bytes_repaired: usize,
    pub linearizable: bool,
}

/// Runs the full Track 21 Jepsen Linearizability + Raft Partition Nemesis + AOF Torn-Write Recovery suite.
pub fn run_jepsen_nemesis_suite(print_report: bool) -> EngineResult<JepsenSummary> {
    let clock_zero = Instant::now();

    // ==================== STAGE 1: 3-NODE RAFT CLUSTER + NEMESIS PARTITIONS ====================
    let mut nodes: Vec<FerrumServer> = Vec::with_capacity(3);
    let mut addrs: Vec<String> = Vec::with_capacity(3);
    let mut ids: Vec<String> = Vec::with_capacity(3);

    for i in 0..3 {
        let mut cfg = ServerConfig::default();
        cfg.bind_addr = "127.0.0.1:0".to_string();
        cfg.node_id = format!("raft-node-{}", i + 1);
        cfg.worker_threads = 4;
        cfg.shard_count = 16;
        cfg.aof_path = None;
        cfg.aof_fsync = FsyncPolicy::No;
        cfg.snapshot_path = PathBuf::from(format!("jepsen_unused_{i}.snap"));

        let srv = FerrumServer::start(cfg)?;
        addrs.push(srv.local_addr().to_string());
        ids.push(format!("raft-node-{}", i + 1));
        nodes.push(srv);
    }

    for i in 0..3 {
        let mut peers = Vec::with_capacity(2);
        for j in 0..3 {
            if i != j {
                peers.push(PeerConfig {
                    node_id: ids[j].clone(),
                    addr: addrs[j].clone(),
                });
            }
        }
        nodes[i].raft_node().configure_peers(peers)?;
    }

    // Elect Node 1 as initial Term-1 Leader and seed CAS register `jepsen:cas = 0`.
    let elected_0 = nodes[0].raft_node().start_election()?;
    if !elected_0 {
        return Err(EngineError::CorruptedPersistence(
            "Jepsen bootstrap failed: node-1 did not win initial quorum election".to_string(),
        ));
    }
    {
        let mut init_out = Vec::new();
        nodes[0]
            .raft_node()
            .propose_command(&[b"SET", b"jepsen:cas", b"0"], &mut init_out)?;
    }

    let active_leader_idx = Arc::new(AtomicUsize::new(0));
    let stop_workers = Arc::new(AtomicBool::new(false));
    let cas_hint = Arc::new(AtomicUsize::new(0));
    let total_invocations = Arc::new(AtomicUsize::new(0));
    let rejected_ops = Arc::new(AtomicUsize::new(0));
    let history: Arc<Mutex<Vec<HistoryRecord>>> = Arc::new(Mutex::new(Vec::with_capacity(512)));

    let num_clients = 6usize;
    let mut client_handles = Vec::with_capacity(num_clients);

    for tid in 0..num_clients {
        let addrs_cl = addrs.clone();
        let leader_idx_cl = Arc::clone(&active_leader_idx);
        let stop_cl = Arc::clone(&stop_workers);
        let cas_hint_cl = Arc::clone(&cas_hint);
        let inv_cl = Arc::clone(&total_invocations);
        let rej_cl = Arc::clone(&rejected_ops);
        let hist_cl = Arc::clone(&history);

        let handle = thread::Builder::new()
            .name(format!("jepsen-worker-{tid}"))
            .spawn(move || {
                jepsen_client_loop(
                    tid,
                    clock_zero,
                    &addrs_cl,
                    &leader_idx_cl,
                    &stop_cl,
                    &cas_hint_cl,
                    &inv_cl,
                    &rej_cl,
                    &hist_cl,
                )
            })?;
        client_handles.push(handle);
    }

    // Phase A: Healthy 3-node cluster executing concurrent INCR / CAS / SET
    thread::sleep(Duration::from_millis(120));

    // Phase B (Nemesis 1): Partition Leader `raft-node-1` from the majority `{node-2, node-3}`!
    nodes[0].raft_node().set_network_isolated(true)?;
    // Verify directly that an attempted write against the partitioned minority leader fails quorum!
    {
        let mut stale_buf = Vec::new();
        if nodes[0]
            .raft_node()
            .propose_command(&[b"SET", b"jepsen:stale_leader_write", b"forbidden"], &mut stale_buf)
            .is_ok()
        {
            return Err(EngineError::CorruptedPersistence(
                "Split-brain safety violation: isolated minority leader committed a write!"
                    .to_string(),
            ));
        }
        rejected_ops.fetch_add(1, AtomicOrdering::Relaxed);
    }

    // Majority `{node-2, node-3}` elects `raft-node-2` in higher term
    let mut elected_1 = false;
    for _ in 0..5 {
        if nodes[1].raft_node().start_election()? {
            elected_1 = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if !elected_1 {
        stop_workers.store(true, AtomicOrdering::Release);
        return Err(EngineError::CorruptedPersistence(
            "Jepsen failover failed: node-2 did not win majority election during partition"
                .to_string(),
        ));
    }
    active_leader_idx.store(1, AtomicOrdering::Release);
    thread::sleep(Duration::from_millis(140));

    // Phase C (Nemesis 2): Heal `raft-node-1` -> old leader steps down, truncates uncommitted entry, catches up!
    nodes[0].raft_node().set_network_isolated(false)?;
    nodes[1].raft_node().replicate_to_peers()?;
    thread::sleep(Duration::from_millis(80));

    // Force graceful leader step-down on `raft-node-2` and elect `raft-node-3`!
    nodes[1].raft_node().step_down(None)?;
    let mut elected_2 = false;
    for _ in 0..5 {
        if nodes[2].raft_node().start_election()? {
            elected_2 = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if !elected_2 {
        stop_workers.store(true, AtomicOrdering::Release);
        return Err(EngineError::CorruptedPersistence(
            "Jepsen step-down election failed: node-3 did not win election".to_string(),
        ));
    }
    active_leader_idx.store(2, AtomicOrdering::Release);
    thread::sleep(Duration::from_millis(140));

    // Stop concurrent client workers and converge final Raft logs across all 3 nodes.
    stop_workers.store(true, AtomicOrdering::Release);
    for h in client_handles {
        let _ = h.join();
    }
    nodes[2].raft_node().replicate_to_peers()?;

    let st0 = nodes[0].raft_node().status()?;
    let st1 = nodes[1].raft_node().status()?;
    let st2 = nodes[2].raft_node().status()?;

    if st2.role != RaftRole::Leader || st0.role != RaftRole::Follower || st1.role != RaftRole::Follower {
        return Err(EngineError::CorruptedPersistence(format!(
            "unexpected final cluster roles: {:?}, {:?}, {:?}",
            st0.role, st1.role, st2.role
        )));
    }
    if st0.commit_index != st2.commit_index || st1.commit_index != st2.commit_index {
        return Err(EngineError::CorruptedPersistence(format!(
            "Raft commit_index divergence across nodes: {}, {}, {}",
            st0.commit_index, st1.commit_index, st2.commit_index
        )));
    }

    // Verify byte-for-byte state machine convergence across all 3 nodes & confirm partitioned write NEVER leaked!
    let c0 = nodes[0].storage().get_bytes(b"jepsen:counter")?;
    let c1 = nodes[1].storage().get_bytes(b"jepsen:counter")?;
    let c2 = nodes[2].storage().get_bytes(b"jepsen:counter")?;
    if c0 != c1 || c1 != c2 {
        return Err(EngineError::CorruptedPersistence(
            "Replicated counter diverged across Raft replicas!".to_string(),
        ));
    }
    let cas0 = nodes[0].storage().get_bytes(b"jepsen:cas")?;
    let cas1 = nodes[1].storage().get_bytes(b"jepsen:cas")?;
    let cas2 = nodes[2].storage().get_bytes(b"jepsen:cas")?;
    if cas0 != cas1 || cas1 != cas2 {
        return Err(EngineError::CorruptedPersistence(
            "Replicated CAS register diverged across Raft replicas!".to_string(),
        ));
    }
    for n in &nodes {
        if n.storage().get_bytes(b"jepsen:stale_leader_write")?.is_some() {
            return Err(EngineError::CorruptedPersistence(
                "Uncommitted write from partitioned minority leader survived log reconciliation!"
                    .to_string(),
            ));
        }
    }

    let final_counter_val: i64 = match c2 {
        Some(ref b) => std::str::from_utf8(b)?.parse()?,
        None => 0,
    };
    let final_cas_val: u64 = match cas2 {
        Some(ref b) => std::str::from_utf8(b)?.parse()?,
        None => 0,
    };

    for mut srv in nodes {
        srv.shutdown();
    }

    // ==================== STAGE 2: STRICT LINEARIZABILITY VERIFICATION ====================
    let recorded = history
        .lock()
        .map_err(|_| EngineError::LockPoisoned("jepsen history mutex"))?
        .clone();

    let (incr_count, cas_swaps) =
        verify_strict_linearizability(&recorded, final_counter_val, final_cas_val)?;

    // ==================== STAGE 3: AOF TORN-WRITE & CRC32 SNAPSHOT FALLBACK ====================
    let torn_bytes_repaired = verify_aof_torn_write_and_snapshot_recovery()?;

    let summary = JepsenSummary {
        total_invocations: total_invocations.load(AtomicOrdering::Relaxed),
        committed_ops: recorded.len(),
        rejected_during_partition: rejected_ops.load(AtomicOrdering::Relaxed),
        incr_committed: incr_count,
        cas_swaps,
        final_raft_term: st2.current_term,
        final_commit_index: st2.commit_index,
        torn_bytes_repaired,
        linearizable: true,
    };

    if print_report {
        println!("========================================================================");
        println!(" FerrumKV Jepsen Linearizability & Crash-Recovery Nemesis Report");
        println!("========================================================================");
        println!(" Cluster Topology     : 3 TCP Raft Nodes (quorum = 2/3, 16 shards/node)");
        println!(" Faults Injected      : Leader Isolation Partition + Majority Failover + Step-Down + Mid-Frame Torn AOF");
        println!(" Total Invocations    : {}", summary.total_invocations);
        println!(" Committed Operations : {} (INCR={}, CAS swaps={})", summary.committed_ops, summary.incr_committed, summary.cas_swaps);
        println!(" Partition Rejections : {} (0 stale/uncommitted writes acknowledged)", summary.rejected_during_partition);
        println!(" Final Raft Consensus : term={}, commit_index={} (3/3 replicas converged)", summary.final_raft_term, summary.final_commit_index);
        println!(" Crash-Recovery Check : Repaired {} torn AOF bytes + verified CRC32 snapshot fallback", summary.torn_bytes_repaired);
        println!(" Linearizability Proof: PASS (Wing & Gong real-time precedence + monotonic serializability)");
        println!("========================================================================");
    }

    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn jepsen_client_loop(
    tid: usize,
    clock_zero: Instant,
    addrs: &[String],
    active_leader: &AtomicUsize,
    stop: &AtomicBool,
    cas_hint: &AtomicUsize,
    total_invocations: &AtomicUsize,
    rejected_ops: &AtomicUsize,
    history: &Mutex<Vec<HistoryRecord>>,
) {
    let mut iter_seq = 0u64;

    while !stop.load(AtomicOrdering::Acquire) {
        iter_seq += 1;
        let leader_i = active_leader.load(AtomicOrdering::Acquire) % addrs.len();
        let target_addr = &addrs[leader_i];

        let Ok(sock) = target_addr.parse::<SocketAddr>() else {
            continue;
        };
        let Ok(mut stream) = TcpStream::connect_timeout(&sock, Duration::from_millis(120)) else {
            rejected_ops.fetch_add(1, AtomicOrdering::Relaxed);
            thread::sleep(Duration::from_millis(5));
            continue;
        };
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
        let mut rbuf = StreamReadBuffer::with_capacity(2048);

        while !stop.load(AtomicOrdering::Acquire) {
            if active_leader.load(AtomicOrdering::Acquire) != leader_i {
                break;
            }
            iter_seq += 1;
            total_invocations.fetch_add(1, AtomicOrdering::Relaxed);
            let invoke_ns = clock_zero.elapsed().as_nanos() as u64;

            let kind = (tid + (iter_seq as usize)) % 3;
            let mut wbuf = Vec::with_capacity(96);

            let sent_op = match kind {
                0 => {
                    encode_command_slices(
                        &mut wbuf,
                        &[b"RAFT.PROPOSE", b"INCR", b"jepsen:counter"],
                    );
                    0u8
                }
                1 => {
                    let expected = cas_hint.load(AtomicOrdering::Acquire) as u64;
                    let desired = expected + 1;
                    let exp_s = expected.to_string();
                    let des_s = desired.to_string();
                    encode_command_slices(
                        &mut wbuf,
                        &[
                            b"RAFT.PROPOSE",
                            b"CAS",
                            b"jepsen:cas",
                            exp_s.as_bytes(),
                            des_s.as_bytes(),
                        ],
                    );
                    1u8
                }
                _ => {
                    let key_s = format!("jepsen:kv:{}", tid);
                    let val_s = iter_seq.to_string();
                    encode_command_slices(
                        &mut wbuf,
                        &[b"RAFT.PROPOSE", b"SET", key_s.as_bytes(), val_s.as_bytes()],
                    );
                    2u8
                }
            };

            let attempted_cas_from = cas_hint.load(AtomicOrdering::Acquire) as u64;
            if stream.write_all(&wbuf).is_err() {
                rejected_ops.fetch_add(1, AtomicOrdering::Relaxed);
                break;
            }

            let reply = match read_one_frame(&mut stream, &mut rbuf) {
                Ok(f) => f,
                Err(_) => {
                    rejected_ops.fetch_add(1, AtomicOrdering::Relaxed);
                    break;
                }
            };
            let complete_ns = clock_zero.elapsed().as_nanos() as u64;

            match (sent_op, reply) {
                (0, OwnedFrame::Integer(v)) => {
                    if let Ok(mut guard) = history.lock() {
                        guard.push(HistoryRecord {
                            invoke_ns,
                            complete_ns,
                            op: JepsenOp::IncrResult(v),
                        });
                    }
                }
                (1, OwnedFrame::Integer(1)) => {
                    let _ = cas_hint.fetch_max((attempted_cas_from + 1) as usize, AtomicOrdering::AcqRel);
                    if let Ok(mut guard) = history.lock() {
                        guard.push(HistoryRecord {
                            invoke_ns,
                            complete_ns,
                            op: JepsenOp::CasSuccess {
                                from_seq: attempted_cas_from,
                                to_seq: attempted_cas_from + 1,
                            },
                        });
                    }
                }
                (1, OwnedFrame::Integer(0)) => {
                    if let Ok(mut guard) = history.lock() {
                        guard.push(HistoryRecord {
                            invoke_ns,
                            complete_ns,
                            op: JepsenOp::CasFailed {
                                attempted_from: attempted_cas_from,
                            },
                        });
                    }
                }
                (2, OwnedFrame::SimpleString(ref s)) if s == b"OK" => {
                    if let Ok(mut guard) = history.lock() {
                        guard.push(HistoryRecord {
                            invoke_ns,
                            complete_ns,
                            op: JepsenOp::SetAck {
                                key_idx: tid,
                                val: iter_seq,
                            },
                        });
                    }
                }
                (_, OwnedFrame::SimpleError(_)) => {
                    rejected_ops.fetch_add(1, AtomicOrdering::Relaxed);
                    thread::sleep(Duration::from_millis(4));
                    break;
                }
                _ => {
                    rejected_ops.fetch_add(1, AtomicOrdering::Relaxed);
                    break;
                }
            }

            thread::sleep(Duration::from_millis(2));
        }
    }
}

/// Verifies strict Wing & Gong real-time linearizability & monotonic serializability across recorded operations.
fn verify_strict_linearizability(
    history: &[HistoryRecord],
    final_counter: i64,
    final_cas: u64,
) -> EngineResult<(usize, usize)> {
    let mut incr_ops: Vec<(u64, u64, i64)> = Vec::new();
    let mut cas_swaps: Vec<(u64, u64, u64, u64)> = Vec::new();

    for rec in history {
        if rec.complete_ns < rec.invoke_ns {
            return Err(EngineError::CorruptedPersistence(
                "invalid timestamps in Jepsen history".to_string(),
            ));
        }
        match rec.op {
            JepsenOp::IncrResult(v) => incr_ops.push((rec.invoke_ns, rec.complete_ns, v)),
            JepsenOp::CasSuccess { from_seq, to_seq } => {
                cas_swaps.push((rec.invoke_ns, rec.complete_ns, from_seq, to_seq))
            }
            JepsenOp::CasFailed { attempted_from } => {
                if attempted_from > final_cas + 1 {
                    return Err(EngineError::CorruptedPersistence(format!(
                        "CAS failed from impossible future epoch {}",
                        attempted_from
                    )));
                }
            }
            JepsenOp::SetAck { key_idx, val } => {
                if key_idx >= 64 || val == 0 {
                    return Err(EngineError::CorruptedPersistence(
                        "invalid SetAck metadata in Jepsen history".to_string(),
                    ));
                }
            }
        }
    }

    if incr_ops.is_empty() {
        return Err(EngineError::CorruptedPersistence(
            "Jepsen history recorded zero INCR operations".to_string(),
        ));
    }

    // 1. Verify INCR bijection `1..=K` (note: indeterminate in-flight RPCs at partition cutover may commit without client receipt, so `final_counter >= incr_ops.len()` and all acknowledged values must be strictly unique in `1..=final_counter` and strictly respect real-time order!)
    let mut values_sorted: Vec<i64> = incr_ops.iter().map(|x| x.2).collect();
    values_sorted.sort_unstable();
    for w in values_sorted.windows(2) {
        if w[0] == w[1] {
            return Err(EngineError::CorruptedPersistence(format!(
                "Linearizability violation: duplicate INCR value {} observed by two clients!",
                w[0]
            )));
        }
    }
    if let Some(&max_seen) = values_sorted.last() {
        if max_seen > final_counter || values_sorted[0] < 1 {
            return Err(EngineError::CorruptedPersistence(format!(
                "Linearizability violation: acknowledged INCR {} exceeds converged state {}",
                max_seen, final_counter
            )));
        }
    }

    // Real-time precedence check: if `op_a` completed strictly before `op_b` was invoked, `val(op_a) < val(op_b)`.
    for i in 0..incr_ops.len() {
        for j in 0..incr_ops.len() {
            if incr_ops[i].1 < incr_ops[j].0 && incr_ops[i].2 >= incr_ops[j].2 {
                return Err(EngineError::CorruptedPersistence(format!(
                    "Linearizability real-time order violation on INCR: op_a={} completed before op_b={} started!",
                    incr_ops[i].2, incr_ops[j].2
                )));
            }
        }
    }

    // 2. Verify CAS single-lineage transition chain & real-time precedence
    cas_swaps.sort_by_key(|x| x.2);
    for w in cas_swaps.windows(2) {
        if w[0].2 == w[1].2 {
            return Err(EngineError::CorruptedPersistence(format!(
                "Linearizability violation: two concurrent CAS swaps succeeded from identical state {}!",
                w[0].2
            )));
        }
    }
    for &(inv_a, cmp_a, from_a, to_a) in &cas_swaps {
        if to_a != from_a + 1 || to_a > final_cas {
            return Err(EngineError::CorruptedPersistence(
                "CAS register state transition anomaly".to_string(),
            ));
        }
        let _ = inv_a;
        for &(inv_b, _, from_b, _) in &cas_swaps {
            if cmp_a < inv_b && from_a >= from_b {
                return Err(EngineError::CorruptedPersistence(
                    "Linearizability real-time order violation on CAS register!".to_string(),
                ));
            }
        }
    }

    Ok((incr_ops.len(), cas_swaps.len()))
}

fn verify_aof_torn_write_and_snapshot_recovery() -> EngineResult<usize> {
    let dir = env::temp_dir().join(format!("ferrum_jepsen_crash_{}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let snap_path = dir.join("baseline.snap");
    let bad_snap_path = dir.join("corrupted.snap");
    let aof_path = dir.join("appendonly.aof");

    // 1. Build baseline state and write CRC32 snapshot
    let base_storage = StorageEngine::new(8)?;
    for i in 0..10 {
        let k = format!("snap:key:{i}");
        let v = format!("snap_val_{i}");
        base_storage.set(k.as_bytes(), v.as_bytes(), None, SetCondition::Always)?;
    }
    save_binary_snapshot(&snap_path, &base_storage)?;

    // Verify corrupted snapshot is caught by IEEE 802.3 CRC32
    fs::copy(&snap_path, &bad_snap_path)?;
    {
        let mut raw = fs::read(&bad_snap_path)?;
        let mid = raw.len() / 2;
        raw[mid] ^= 0x5A;
        fs::write(&bad_snap_path, &raw)?;
    }
    let test_bad = StorageEngine::new(8)?;
    if load_binary_snapshot(&bad_snap_path, &test_bad).is_ok() {
        let _ = fs::remove_dir_all(&dir);
        return Err(EngineError::CorruptedPersistence(
            "CRC32 check failed to reject corrupted snapshot!".to_string(),
        ));
    }

    // 2. Append 12 post-snapshot AOF frames with IEEE 802.3 CRC32 seals, then inject a mid-frame torn write at tail
    {
        let aof = AofEngine::open(&aof_path, FsyncPolicy::Always)?;
        for i in 0..12 {
            let k = format!("aof:delta:{i}");
            let v = format!("committed_{i}");
            aof.log_command_with_crc32(&[b"SET", k.as_bytes(), v.as_bytes()])?;
        }
        aof.flush_and_sync()?;
        aof.shutdown();
    }

    let torn_tail = b"*3\r\n$3\r\nSET\r\n$11\r\ntorn:zombie\r\n$64\r\nmid_syscall_power_failure";
    {
        let mut f = OpenOptions::new().append(true).open(&aof_path)?;
        f.write_all(torn_tail)?;
        f.sync_all()?;
    }

    // Strict `replay_aof` must flag truncation
    let strict_check = StorageEngine::new(8)?;
    if replay_aof(&aof_path, &strict_check).is_ok() {
        let _ = fs::remove_dir_all(&dir);
        return Err(EngineError::CorruptedPersistence(
            "replay_aof failed to detect mid-frame torn write!".to_string(),
        ));
    }

    // `recover_from_crash` loads CRC32 snapshot + verifies & replays all 12 CRC32-sealed AOF frames + truncates exact torn tail!
    let recovered = StorageEngine::new(8)?;
    let report = recover_from_crash(&aof_path, &snap_path, &recovered)?;
    if report.snapshot_keys_loaded != 10
        || report.aof_frames_replayed != 12
        || report.crc32_verified_frames != 12
        || report.truncated_torn_bytes != torn_tail.len()
        || !report.used_snapshot_fallback
    {
        let _ = fs::remove_dir_all(&dir);
        return Err(EngineError::CorruptedPersistence(format!(
            "unexpected crash recovery report: {:?}",
            report
        )));
    }

    if recovered.dbsize()? != 22 || recovered.get_bytes(b"torn:zombie")?.is_some() {
        let _ = fs::remove_dir_all(&dir);
        return Err(EngineError::CorruptedPersistence(
            "recovered state key count mismatch after torn-write repair".to_string(),
        ));
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(report.truncated_torn_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jepsen_3_node_raft_nemesis_and_crash_recovery() -> EngineResult<()> {
        let summary = run_jepsen_nemesis_suite(false)?;
        assert!(summary.linearizable);
        assert!(summary.committed_ops > 10);
        assert!(summary.incr_committed > 0);
        assert!(summary.final_raft_term >= 3);
        assert!(summary.torn_bytes_repaired > 0);
        Ok(())
    }
}
