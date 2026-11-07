use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::cli::read_one_frame;
use crate::error::{EngineError, EngineResult};
use crate::resp::{
    encode_command_slices, parse_f64_bytes, parse_i64_bytes, write_bulk_string, write_integer,
    write_null, write_simple_error, write_simple_string, OwnedFrame, ParseStatus, RespFrame,
    RespParser, StreamReadBuffer,
};
use crate::storage::{SetCondition, StorageEngine};
use crate::vm::ScriptCache;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

impl RaftRole {
    pub fn as_str(self) -> &'static str {
        match self {
            RaftRole::Follower => "follower",
            RaftRole::Candidate => "candidate",
            RaftRole::Leader => "leader",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RaftLogEntry {
    pub index: u64,
    pub term: u64,
    pub command: Vec<Vec<u8>>,
}

impl RaftLogEntry {
    pub fn encode_command_wire(&self) -> Vec<u8> {
        let slices: Vec<&[u8]> = self.command.iter().map(|v| v.as_slice()).collect();
        let mut wire = Vec::with_capacity(64);
        encode_command_slices(&mut wire, &slices);
        wire
    }

    pub fn decode_command_wire(index: u64, term: u64, wire: &[u8]) -> EngineResult<Self> {
        let status = RespParser::parse(wire)?;
        let ParseStatus::Complete { frame, .. } = status else {
            return Err(EngineError::Protocol(
                "incomplete Raft command wire payload".to_string(),
            ));
        };
        let RespFrame::Array(items) = frame else {
            return Err(EngineError::Protocol(
                "Raft command wire payload must be RESP Array".to_string(),
            ));
        };
        let mut command = Vec::with_capacity(items.len());
        for item in items {
            let b = item.as_bytes().ok_or_else(|| {
                EngineError::Protocol("Raft command element must be byte slice".to_string())
            })?;
            command.push(b.to_vec());
        }
        Ok(Self {
            index,
            term,
            command,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub node_id: String,
    pub addr: String,
}

#[derive(Clone, Debug)]
pub struct RaftStatusSnapshot {
    pub node_id: String,
    pub role: RaftRole,
    pub current_term: u64,
    pub voted_for: Option<String>,
    pub leader_id: Option<String>,
    pub commit_index: u64,
    pub last_applied: u64,
    pub log_len: usize,
    pub isolated: bool,
}

struct RaftState {
    role: RaftRole,
    current_term: u64,
    voted_for: Option<String>,
    leader_id: Option<String>,
    log: Vec<RaftLogEntry>, // 1-indexed logically (`log[0]` has `index == 1`)
    commit_index: u64,
    last_applied: u64,
    peers: Vec<PeerConfig>,
    next_index: Vec<u64>,
    match_index: Vec<u64>,
    isolated_self: bool,
    blocked_peers: Vec<String>,
    applied_outputs: Vec<(u64, Vec<u8>)>,
    last_contact: Instant,
}

impl RaftState {
    fn last_log_index(&self) -> u64 {
        self.log.len() as u64
    }

    fn last_log_term(&self) -> u64 {
        self.log.last().map(|e| e.term).unwrap_or(0)
    }

    fn term_at(&self, index: u64) -> Option<u64> {
        if index == 0 {
            Some(0)
        } else {
            self.log.get((index - 1) as usize).map(|e| e.term)
        }
    }

    fn is_peer_blocked(&self, peer_id: &str) -> bool {
        self.isolated_self || self.blocked_peers.iter().any(|p| p == peer_id)
    }
}

/// Ongaro & Ousterhout Raft Consensus State Machine & RESP3 Log Replicator.
pub struct RaftNode {
    node_id: String,
    storage: Arc<StorageEngine>,
    scripts: Arc<ScriptCache>,
    propose_lock: Mutex<()>,
    state: Mutex<RaftState>,
}

impl RaftNode {
    pub fn new(
        node_id: impl Into<String>,
        storage: Arc<StorageEngine>,
        scripts: Arc<ScriptCache>,
    ) -> Arc<Self> {
        Arc::new(Self {
            node_id: node_id.into(),
            storage,
            scripts,
            propose_lock: Mutex::new(()),
            state: Mutex::new(RaftState {
                role: RaftRole::Follower,
                current_term: 0,
                voted_for: None,
                leader_id: None,
                log: Vec::new(),
                commit_index: 0,
                last_applied: 0,
                peers: Vec::new(),
                next_index: Vec::new(),
                match_index: Vec::new(),
                isolated_self: false,
                blocked_peers: Vec::new(),
                applied_outputs: Vec::new(),
                last_contact: Instant::now(),
            }),
        })
    }

    #[inline]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn configure_peers(&self, peers: Vec<PeerConfig>) -> EngineResult<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
        let next_idx = guard.last_log_index() + 1;
        guard.next_index = vec![next_idx; peers.len()];
        guard.match_index = vec![0; peers.len()];
        guard.peers = peers;
        Ok(())
    }

    pub fn set_network_isolated(&self, isolated: bool) -> EngineResult<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
        guard.isolated_self = isolated;
        Ok(())
    }

    pub fn set_peer_blocked(&self, peer_id: &str, blocked: bool) -> EngineResult<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
        if blocked {
            if !guard.blocked_peers.iter().any(|p| p == peer_id) {
                guard.blocked_peers.push(peer_id.to_string());
            }
        } else {
            guard.blocked_peers.retain(|p| p != peer_id);
        }
        Ok(())
    }

    pub fn step_down(&self, min_term: Option<u64>) -> EngineResult<()> {
        let _propose_guard = self
            .propose_lock
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft propose mutex"))?;
        let _ = self.replicate_to_peers();
        let mut guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
        if let Some(t) = min_term {
            if t > guard.current_term {
                guard.current_term = t;
                guard.voted_for = None;
            }
        }
        guard.role = RaftRole::Follower;
        guard.leader_id = None;
        Ok(())
    }

    pub fn status(&self) -> EngineResult<RaftStatusSnapshot> {
        let guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
        Ok(RaftStatusSnapshot {
            node_id: self.node_id.clone(),
            role: guard.role,
            current_term: guard.current_term,
            voted_for: guard.voted_for.clone(),
            leader_id: guard.leader_id.clone(),
            commit_index: guard.commit_index,
            last_applied: guard.last_applied,
            log_len: guard.log.len(),
            isolated: guard.isolated_self,
        })
    }

    /// Handles `RAFT.VOTE <term> <candidate_id> <last_log_idx> <last_log_term>`.
    pub fn handle_request_vote(
        &self,
        term: u64,
        candidate_id: &str,
        last_log_idx: u64,
        last_log_term: u64,
    ) -> EngineResult<(u64, bool)> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;

        if guard.isolated_self || guard.is_peer_blocked(candidate_id) {
            return Err(EngineError::InvalidArgument(
                "NETSPLIT node partitioned".to_string(),
            ));
        }

        if term > guard.current_term {
            guard.current_term = term;
            guard.role = RaftRole::Follower;
            guard.voted_for = None;
            guard.leader_id = None;
        }

        if term < guard.current_term {
            return Ok((guard.current_term, false));
        }

        let my_last_term = guard.last_log_term();
        let my_last_idx = guard.last_log_index();
        // Raft §5.4.1 Election Safety: candidate's log must be at least as up-to-date as voter's.
        let up_to_date = last_log_term > my_last_term
            || (last_log_term == my_last_term && last_log_idx >= my_last_idx);

        let vote_available = match &guard.voted_for {
            None => true,
            Some(prev) => prev == candidate_id,
        };

        if vote_available && up_to_date {
            guard.voted_for = Some(candidate_id.to_string());
            guard.last_contact = Instant::now();
            Ok((guard.current_term, true))
        } else {
            Ok((guard.current_term, false))
        }
    }

    /// Handles `RAFT.APPEND <term> <leader_id> <prev_log_idx> <prev_log_term> <leader_commit> [entry_term entry_wire ...]`.
    pub fn handle_append_entries(
        &self,
        term: u64,
        leader_id: &str,
        prev_log_idx: u64,
        prev_log_term: u64,
        entries: Vec<RaftLogEntry>,
        leader_commit: u64,
    ) -> EngineResult<(u64, bool, u64)> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;

        if guard.isolated_self || guard.is_peer_blocked(leader_id) {
            return Err(EngineError::InvalidArgument(
                "NETSPLIT node partitioned".to_string(),
            ));
        }

        if term < guard.current_term {
            return Ok((guard.current_term, false, guard.last_log_index()));
        }

        if term > guard.current_term || guard.role != RaftRole::Follower {
            if term > guard.current_term {
                guard.voted_for = None;
            }
            guard.current_term = term;
            guard.role = RaftRole::Follower;
        }
        guard.leader_id = Some(leader_id.to_string());
        guard.last_contact = Instant::now();

        // Consistency check on (prev_log_idx, prev_log_term)
        match guard.term_at(prev_log_idx) {
            Some(local_prev_term) if local_prev_term == prev_log_term => {}
            _ => {
                return Ok((guard.current_term, false, guard.last_log_index()));
            }
        }

        // Reconcile incoming entries, truncating uncommitted conflicts
        for entry in entries {
            let expected_vec_pos = (entry.index - 1) as usize;
            if expected_vec_pos < guard.log.len() {
                if guard.log[expected_vec_pos].term != entry.term {
                    guard.log.truncate(expected_vec_pos);
                    guard.log.push(entry);
                }
            } else if expected_vec_pos == guard.log.len() {
                guard.log.push(entry);
            }
        }

        if leader_commit > guard.commit_index {
            guard.commit_index = leader_commit.min(guard.last_log_index());
        }

        self.apply_committed_locked(&mut guard)?;
        Ok((guard.current_term, true, guard.last_log_index()))
    }

    /// Starts a synchronous Raft election round across configured TCP peers.
    pub fn start_election(&self) -> EngineResult<bool> {
        let (election_term, last_idx, last_term, peers_snapshot, isolated) = {
            let mut guard = self
                .state
                .lock()
                .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
            if guard.isolated_self {
                return Ok(false);
            }
            guard.current_term += 1;
            guard.role = RaftRole::Candidate;
            guard.voted_for = Some(self.node_id.clone());
            guard.leader_id = None;
            guard.last_contact = Instant::now();

            let peers: Vec<(PeerConfig, bool)> = guard
                .peers
                .iter()
                .map(|p| (p.clone(), guard.is_peer_blocked(&p.node_id)))
                .collect();
            (
                guard.current_term,
                guard.last_log_index(),
                guard.last_log_term(),
                peers,
                guard.isolated_self,
            )
        };

        if isolated {
            return Ok(false);
        }

        let total_cluster_nodes = peers_snapshot.len() + 1;
        let majority = (total_cluster_nodes / 2) + 1;
        let mut granted_votes = 1usize;
        let mut highest_seen_term = election_term;

        for (peer, blocked) in &peers_snapshot {
            if *blocked {
                continue;
            }
            if let Ok((peer_term, vote_granted)) =
                rpc_request_vote(&peer.addr, election_term, &self.node_id, last_idx, last_term)
            {
                if peer_term > highest_seen_term {
                    highest_seen_term = peer_term;
                }
                if peer_term == election_term && vote_granted {
                    granted_votes += 1;
                }
            }
        }

        let won = {
            let mut guard = self
                .state
                .lock()
                .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;

            if highest_seen_term > guard.current_term {
                guard.current_term = highest_seen_term;
                guard.role = RaftRole::Follower;
                guard.voted_for = None;
                guard.leader_id = None;
                return Ok(false);
            }

            if guard.role == RaftRole::Candidate
                && guard.current_term == election_term
                && granted_votes >= majority
                && !guard.isolated_self
            {
                guard.role = RaftRole::Leader;
                guard.leader_id = Some(self.node_id.clone());
                let next_idx = guard.last_log_index() + 1;
                guard.next_index = vec![next_idx; guard.peers.len()];
                guard.match_index = vec![0; guard.peers.len()];
                true
            } else {
                false
            }
        };

        if won {
            let _ = self.replicate_to_peers();
        }
        Ok(won)
    }

    /// Replicates leader log entries to all reachable peers and advances `commit_index` on majority quorum.
    pub fn replicate_to_peers(&self) -> EngineResult<u64> {
        // Perform up to 4 fast catch-up rounds when follower `next_index` backs off.
        for _ in 0..4 {
            let (term, leader_commit, peer_jobs) = {
                let guard = self
                    .state
                    .lock()
                    .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
                if guard.role != RaftRole::Leader || guard.isolated_self {
                    return Ok(guard.commit_index);
                }

                let mut jobs = Vec::with_capacity(guard.peers.len());
                for (i, peer) in guard.peers.iter().enumerate() {
                    if guard.is_peer_blocked(&peer.node_id) {
                        continue;
                    }
                    let next_idx = guard.next_index[i].max(1);
                    let prev_idx = next_idx - 1;
                    let prev_term = guard.term_at(prev_idx).unwrap_or(0);
                    let entries: Vec<RaftLogEntry> = if (next_idx as usize) <= guard.log.len() {
                        guard.log[(next_idx - 1) as usize..].to_vec()
                    } else {
                        Vec::new()
                    };
                    jobs.push((i, peer.addr.clone(), prev_idx, prev_term, entries));
                }
                (guard.current_term, guard.commit_index, jobs)
            };

            if peer_jobs.is_empty() {
                let mut guard = self
                    .state
                    .lock()
                    .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
                if guard.role == RaftRole::Leader && guard.peers.is_empty() && !guard.isolated_self {
                    guard.commit_index = guard.last_log_index();
                    self.apply_committed_locked(&mut guard)?;
                }
                return Ok(guard.commit_index);
            }

            let mut results = Vec::with_capacity(peer_jobs.len());
            for (peer_i, addr, prev_idx, prev_term, entries) in peer_jobs {
                if let Ok(resp) = rpc_append_entries(
                    &addr,
                    term,
                    &self.node_id,
                    prev_idx,
                    prev_term,
                    leader_commit,
                    &entries,
                ) {
                    results.push((peer_i, prev_idx, entries.len(), resp));
                }
            }

            let mut any_backoff = false;
            {
                let mut guard = self
                    .state
                    .lock()
                    .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
                if guard.role != RaftRole::Leader || guard.current_term != term {
                    return Ok(guard.commit_index);
                }

                for (peer_i, prev_idx, sent_len, (peer_term, ok, peer_last_idx)) in results {
                    if peer_term > guard.current_term {
                        guard.current_term = peer_term;
                        guard.role = RaftRole::Follower;
                        guard.voted_for = None;
                        guard.leader_id = None;
                        return Ok(guard.commit_index);
                    }
                    if ok {
                        let matched = prev_idx + (sent_len as u64);
                        if matched > guard.match_index[peer_i] {
                            guard.match_index[peer_i] = matched;
                        }
                        guard.next_index[peer_i] = guard.match_index[peer_i] + 1;
                    } else {
                        let hint = peer_last_idx + 1;
                        let decremented = guard.next_index[peer_i].saturating_sub(1).max(1);
                        guard.next_index[peer_i] = decremented.min(hint.max(1));
                        any_backoff = true;
                    }
                }

                // Advance `commit_index` to highest N replicated on a strict majority with `log[N].term == current_term`.
                let total_nodes = guard.peers.len() + 1;
                let majority = (total_nodes / 2) + 1;
                let last_idx = guard.last_log_index();

                for candidate_n in ((guard.commit_index + 1)..=last_idx).rev() {
                    if guard.term_at(candidate_n) != Some(guard.current_term) {
                        continue;
                    }
                    let mut replicas = 1usize; // self
                    for &m in &guard.match_index {
                        if m >= candidate_n {
                            replicas += 1;
                        }
                    }
                    if replicas >= majority {
                        guard.commit_index = candidate_n;
                        break;
                    }
                }

                self.apply_committed_locked(&mut guard)?;
                if !any_backoff {
                    return Ok(guard.commit_index);
                }
            }
        }

        let guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
        Ok(guard.commit_index)
    }

    /// Appends a state-machine command on the Leader, replicates to majority quorum, and writes the committed reply into `out`.
    pub fn propose_command(&self, args: &[&[u8]], out: &mut Vec<u8>) -> EngineResult<u64> {
        let _propose_guard = self
            .propose_lock
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft propose mutex"))?;
        let entry_idx = {
            let mut guard = self
                .state
                .lock()
                .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
            if guard.role != RaftRole::Leader {
                let leader_hint = guard.leader_id.as_deref().unwrap_or("unknown");
                return Err(EngineError::InvalidArgument(format!(
                    "NOTLEADER current role is {}, leader={}",
                    guard.role.as_str(),
                    leader_hint
                )));
            }
            if guard.isolated_self {
                return Err(EngineError::InvalidArgument(
                    "QUORUM leader is network-isolated".to_string(),
                ));
            }

            let idx = guard.last_log_index() + 1;
            let term = guard.current_term;
            let cmd_owned: Vec<Vec<u8>> = args.iter().map(|s| s.to_vec()).collect();
            guard.log.push(RaftLogEntry {
                index: idx,
                term,
                command: cmd_owned,
            });
            idx
        };

        let committed = self.replicate_to_peers()?;
        if committed < entry_idx {
            return Err(EngineError::InvalidArgument(format!(
                "QUORUM failed to reach majority commit for index {}",
                entry_idx
            )));
        }

        let guard = self
            .state
            .lock()
            .map_err(|_| EngineError::LockPoisoned("raft state mutex"))?;
        if let Some((_, ref reply_bytes)) =
            guard.applied_outputs.iter().rev().find(|(i, _)| *i == entry_idx)
        {
            out.extend_from_slice(reply_bytes);
        } else {
            write_simple_string(out, b"OK");
        }
        Ok(entry_idx)
    }

    fn apply_committed_locked(&self, state: &mut RaftState) -> EngineResult<()> {
        while state.last_applied < state.commit_index {
            let next_idx = state.last_applied + 1;
            let entry = state
                .log
                .get((next_idx - 1) as usize)
                .cloned()
                .ok_or_else(|| {
                    EngineError::CorruptedPersistence(format!(
                        "missing committed Raft entry {}",
                        next_idx
                    ))
                })?;

            let mut reply_buf = Vec::with_capacity(64);
            if let Err(err) = apply_replicated_command(&entry.command, &self.storage, &self.scripts, &mut reply_buf)
            {
                reply_buf.clear();
                let msg = err.to_resp_error_message();
                write_simple_error(&mut reply_buf, msg.as_bytes());
            }

            if state.applied_outputs.len() >= 2048 {
                state.applied_outputs.drain(..512);
            }
            state.applied_outputs.push((next_idx, reply_buf));
            state.last_applied = next_idx;
        }
        Ok(())
    }
}

fn apply_replicated_command(
    command: &[Vec<u8>],
    storage: &StorageEngine,
    scripts: &ScriptCache,
    out: &mut Vec<u8>,
) -> EngineResult<()> {
    if command.is_empty() {
        write_simple_string(out, b"OK");
        return Ok(());
    }
    let slices: Vec<&[u8]> = command.iter().map(|v| v.as_slice()).collect();
    let cmd = slices[0];

    if cmd.eq_ignore_ascii_case(b"SET") && slices.len() >= 3 {
        let mut cond = SetCondition::Always;
        if slices.len() >= 4 {
            if slices[3].eq_ignore_ascii_case(b"NX") {
                cond = SetCondition::IfAbsent;
            } else if slices[3].eq_ignore_ascii_case(b"XX") {
                cond = SetCondition::IfPresent;
            }
        }
        if storage.set(slices[1], slices[2], None, cond)? {
            write_simple_string(out, b"OK");
        } else {
            write_null(out);
        }
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"GET") && slices.len() == 2 {
        storage.get_into(slices[1], out)?;
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"DEL") && slices.len() >= 2 {
        let n = storage.del(&slices[1..])?;
        write_integer(out, n as i64);
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"INCR") && slices.len() == 2 {
        let v = storage.incr_by(slices[1], 1)?;
        write_integer(out, v);
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"DECR") && slices.len() == 2 {
        let v = storage.incr_by(slices[1], -1)?;
        write_integer(out, v);
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"INCRBY") && slices.len() == 3 {
        let delta = parse_i64_bytes(slices[2])?;
        let v = storage.incr_by(slices[1], delta)?;
        write_integer(out, v);
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"CAS") && slices.len() == 4 {
        // Built-in atomic Compare-And-Swap (`CAS key expected desired`) returning 1 on swap, 0 on mismatch.
        let current = storage.get_bytes(slices[1])?;
        let matches = match &current {
            Some(cur) => cur.as_ref() == slices[2],
            None => slices[2].is_empty() || slices[2] == b"__NIL__",
        };
        if matches {
            storage.set(slices[1], slices[3], None, SetCondition::Always)?;
            write_integer(out, 1);
        } else {
            write_integer(out, 0);
        }
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"HSET") && slices.len() >= 4 && slices.len() % 2 == 0 {
        let mut pairs = Vec::with_capacity((slices.len() - 2) / 2);
        let mut i = 2;
        while i + 1 < slices.len() {
            pairs.push((slices[i], slices[i + 1]));
            i += 2;
        }
        let added = storage.hset(slices[1], &pairs)?;
        write_integer(out, added as i64);
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"ZADD") && slices.len() >= 4 && slices.len() % 2 == 0 {
        let mut entries = Vec::with_capacity((slices.len() - 2) / 2);
        let mut i = 2;
        while i + 1 < slices.len() {
            entries.push((parse_f64_bytes(slices[i])?, slices[i + 1]));
            i += 2;
        }
        let added = storage.zadd(slices[1], &entries)?;
        write_integer(out, added as i64);
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"EVAL") && slices.len() >= 3 {
        let num_keys = parse_i64_bytes(slices[2])?;
        if num_keys < 0 || 3 + (num_keys as usize) > slices.len() {
            return Err(EngineError::InvalidArgument(
                "invalid EVAL numkeys in Raft log".to_string(),
            ));
        }
        let nk = num_keys as usize;
        let keys = &slices[3..3 + nk];
        let argv = &slices[3 + nk..];
        let val = scripts.eval_source(slices[1], keys, argv, storage)?;
        val.write_resp(out);
        return Ok(());
    }

    write_bulk_string(out, b"APPLIED");
    Ok(())
}

fn rpc_request_vote(
    addr: &str,
    term: u64,
    candidate_id: &str,
    last_log_idx: u64,
    last_log_term: u64,
) -> EngineResult<(u64, bool)> {
    let sock: SocketAddr = addr.parse()?;
    let mut stream = TcpStream::connect_timeout(&sock, Duration::from_millis(150))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    stream.set_write_timeout(Some(Duration::from_millis(200)))?;

    let t_s = term.to_string();
    let li_s = last_log_idx.to_string();
    let lt_s = last_log_term.to_string();

    let mut wbuf = Vec::with_capacity(128);
    encode_command_slices(
        &mut wbuf,
        &[
            b"RAFT.VOTE",
            t_s.as_bytes(),
            candidate_id.as_bytes(),
            li_s.as_bytes(),
            lt_s.as_bytes(),
        ],
    );
    stream.write_all(&wbuf)?;

    let mut rbuf = StreamReadBuffer::with_capacity(1024);
    let reply = read_one_frame(&mut stream, &mut rbuf)?;
    match reply {
        OwnedFrame::Array(items) if items.len() == 2 => {
            let p_term = match items[0] {
                OwnedFrame::Integer(v) if v >= 0 => v as u64,
                _ => return Err(EngineError::Protocol("invalid RAFT.VOTE term".to_string())),
            };
            let granted = matches!(items[1], OwnedFrame::Integer(1) | OwnedFrame::Boolean(true));
            Ok((p_term, granted))
        }
        OwnedFrame::SimpleError(e) => Err(EngineError::InvalidArgument(
            String::from_utf8_lossy(&e).into_owned(),
        )),
        _ => Err(EngineError::Protocol("malformed RAFT.VOTE response".to_string())),
    }
}

fn rpc_append_entries(
    addr: &str,
    term: u64,
    leader_id: &str,
    prev_log_idx: u64,
    prev_log_term: u64,
    leader_commit: u64,
    entries: &[RaftLogEntry],
) -> EngineResult<(u64, bool, u64)> {
    let sock: SocketAddr = addr.parse()?;
    let mut stream = TcpStream::connect_timeout(&sock, Duration::from_millis(150))?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;

    let t_s = term.to_string();
    let pi_s = prev_log_idx.to_string();
    let pt_s = prev_log_term.to_string();
    let lc_s = leader_commit.to_string();

    let mut entry_blobs: Vec<(String, String, Vec<u8>)> = Vec::with_capacity(entries.len());
    for e in entries {
        entry_blobs.push((e.index.to_string(), e.term.to_string(), e.encode_command_wire()));
    }

    let mut cmd_parts: Vec<&[u8]> = Vec::with_capacity(6 + entry_blobs.len() * 3);
    cmd_parts.push(b"RAFT.APPEND");
    cmd_parts.push(t_s.as_bytes());
    cmd_parts.push(leader_id.as_bytes());
    cmd_parts.push(pi_s.as_bytes());
    cmd_parts.push(pt_s.as_bytes());
    cmd_parts.push(lc_s.as_bytes());
    for (idx_s, et_s, wire) in &entry_blobs {
        cmd_parts.push(idx_s.as_bytes());
        cmd_parts.push(et_s.as_bytes());
        cmd_parts.push(wire.as_slice());
    }

    let mut wbuf = Vec::with_capacity(256);
    encode_command_slices(&mut wbuf, &cmd_parts);
    stream.write_all(&wbuf)?;

    let mut rbuf = StreamReadBuffer::with_capacity(1024);
    let reply = read_one_frame(&mut stream, &mut rbuf)?;
    match reply {
        OwnedFrame::Array(items) if items.len() == 3 => {
            let p_term = match items[0] {
                OwnedFrame::Integer(v) if v >= 0 => v as u64,
                _ => return Err(EngineError::Protocol("invalid RAFT.APPEND term".to_string())),
            };
            let ok = matches!(items[1], OwnedFrame::Integer(1) | OwnedFrame::Boolean(true));
            let last_idx = match items[2] {
                OwnedFrame::Integer(v) if v >= 0 => v as u64,
                _ => 0,
            };
            Ok((p_term, ok, last_idx))
        }
        OwnedFrame::SimpleError(e) => Err(EngineError::InvalidArgument(
            String::from_utf8_lossy(&e).into_owned(),
        )),
        _ => Err(EngineError::Protocol("malformed RAFT.APPEND response".to_string())),
    }
}
