use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{EngineError, EngineResult};
use crate::resp::{
    encode_command_slices, parse_f64_bytes, parse_i64_bytes, ParseStatus, RespFrame, RespParser,
    StreamReadBuffer,
};
use crate::security::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use crate::storage::fts::FullTextIndex;
use crate::storage::probabilistic::{
    BloomFilter, CountMinSketch, HyperLogLog, CMS_DEPTH, CMS_WIDTH, HLL_PACKED_BYTES,
};
use crate::storage::stream::{PendingEntry, StreamId, StreamLog};
use crate::storage::timeseries::GorillaTimeSeries;
use crate::storage::vector_hnsw::{HnswIndex, VectorMetric};
use crate::storage::{DataValue, ExportedEntry, SetCondition, StorageEngine};
use crate::vm::sha256;

const SNAPSHOT_MAGIC: &[u8; 5] = b"FRKV\x02";
const SNAPSHOT_MAGIC_V1: &[u8; 5] = b"FRKV\x01";
const ENCRYPTED_MAGIC: &[u8; 5] = b"FRKE\x01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsyncPolicy {
    Always,
    EverySec,
    No,
}

impl FsyncPolicy {
    pub fn from_str_name(s: &str) -> EngineResult<Self> {
        if s.eq_ignore_ascii_case("always") {
            Ok(FsyncPolicy::Always)
        } else if s.eq_ignore_ascii_case("everysec") {
            Ok(FsyncPolicy::EverySec)
        } else if s.eq_ignore_ascii_case("no") {
            Ok(FsyncPolicy::No)
        } else {
            Err(EngineError::InvalidArgument(format!(
                "unknown fsync policy '{}', expected always|everysec|no",
                s
            )))
        }
    }
}

enum AofEvent {
    Append(Vec<u8>),
    FlushSync(SyncSender<EngineResult<()>>),
    Rotate {
        temp_path: PathBuf,
        trailing_delta: Vec<u8>,
        ack: SyncSender<EngineResult<()>>,
    },
    Shutdown(SyncSender<()>),
}

/// Asynchronous MPSC Write-Ahead Log (AOF) + Atomic Compaction & Binary Snapshot Engine.
pub struct AofEngine {
    path: PathBuf,
    policy: FsyncPolicy,
    tx: Sender<AofEvent>,
    rewrite_in_progress: AtomicBool,
    rewrite_delta: Mutex<Option<Vec<u8>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AofEngine {
    pub fn open(path: impl AsRef<Path>, policy: FsyncPolicy) -> EngineResult<Arc<Self>> {
        let path_buf = path.as_ref().to_path_buf();
        if let Some(parent) = path_buf.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path_buf)?;

        let (tx, rx) = mpsc::channel::<AofEvent>();
        let worker_path = path_buf.clone();

        let handle = thread::Builder::new()
            .name("ferrum-aof-writer".to_string())
            .spawn(move || aof_writer_loop(worker_path, file, policy, rx))?;

        Ok(Arc::new(Self {
            path: path_buf,
            policy,
            tx,
            rewrite_in_progress: AtomicBool::new(false),
            rewrite_delta: Mutex::new(None),
            worker: Mutex::new(Some(handle)),
        }))
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn policy(&self) -> FsyncPolicy {
        self.policy
    }

    /// Enqueues a raw RESP mutation frame to the async AOF writer (and live compaction delta buffer if active).
    pub fn log_command(&self, parts: &[&[u8]]) -> EngineResult<()> {
        let mut encoded = Vec::with_capacity(64);
        encode_command_slices(&mut encoded, parts);
        self.log_raw_bytes(encoded)
    }

    /// Enqueues a RESP mutation frame paired with an IEEE 802.3 CRC32 verification frame (`AOF.CRC32`).
    pub fn log_command_with_crc32(&self, parts: &[&[u8]]) -> EngineResult<u32> {
        let mut encoded = Vec::with_capacity(96);
        let crc = encode_command_with_crc32(&mut encoded, parts);
        self.log_raw_bytes(encoded)?;
        Ok(crc)
    }

    pub fn log_raw_bytes(&self, encoded: Vec<u8>) -> EngineResult<()> {
        if self.rewrite_in_progress.load(AtomicOrdering::Acquire) {
            let mut delta_guard = self
                .rewrite_delta
                .lock()
                .map_err(|_| EngineError::LockPoisoned("aof rewrite delta mutex"))?;
            if let Some(ref mut delta_buf) = *delta_guard {
                delta_buf.extend_from_slice(&encoded);
            }
        }
        self.tx
            .send(AofEvent::Append(encoded))
            .map_err(|_| EngineError::ChannelClosed("AOF writer channel"))
    }

    pub fn flush_and_sync(&self) -> EngineResult<()> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.tx
            .send(AofEvent::FlushSync(ack_tx))
            .map_err(|_| EngineError::ChannelClosed("AOF writer channel"))?;
        ack_rx
            .recv()
            .map_err(|_| EngineError::ChannelClosed("AOF sync ack"))?
    }

    /// Non-blocking AOF log compaction (`BGREWRITEAOF`) with live delta capture and atomic file rotation.
    pub fn compact_from_storage(&self, storage: &StorageEngine) -> EngineResult<()> {
        if self
            .rewrite_in_progress
            .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
            .is_err()
        {
            return Err(EngineError::InvalidArgument(
                "Background AOF rewrite already in progress".to_string(),
            ));
        }

        let result = self.compact_inner(storage);
        self.rewrite_in_progress
            .store(false, AtomicOrdering::Release);
        result
    }

    fn compact_inner(&self, storage: &StorageEngine) -> EngineResult<()> {
        {
            let mut delta_guard = self
                .rewrite_delta
                .lock()
                .map_err(|_| EngineError::LockPoisoned("aof rewrite delta mutex"))?;
            *delta_guard = Some(Vec::with_capacity(4096));
        }

        let mut temp_name = self.path.as_os_str().to_os_string();
        temp_name.push(".rewrite.tmp");
        let temp_path = PathBuf::from(temp_name);

        let write_res = (|| -> EngineResult<()> {
            let tmp_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&temp_path)?;
            let mut writer = BufWriter::with_capacity(64 * 1024, tmp_file);
            let mut scratch = Vec::with_capacity(1024);

            for shard_idx in 0..storage.shard_count() {
                let entries = storage.export_shard_snapshot(shard_idx)?;
                for entry in entries {
                    scratch.clear();
                    encode_exported_entry_aof(&entry, &mut scratch)?;
                    writer.write_all(&scratch)?;
                }
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
            Ok(())
        })();

        if let Err(err) = write_res {
            if let Ok(mut guard) = self.rewrite_delta.lock() {
                *guard = None;
            }
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }

        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        {
            let mut delta_guard = self
                .rewrite_delta
                .lock()
                .map_err(|_| EngineError::LockPoisoned("aof rewrite delta mutex"))?;
            let trailing_delta = delta_guard.take().unwrap_or_default();
            self.tx
                .send(AofEvent::Rotate {
                    temp_path: temp_path.clone(),
                    trailing_delta,
                    ack: ack_tx,
                })
                .map_err(|_| EngineError::ChannelClosed("AOF writer channel"))?;
        }

        ack_rx
            .recv()
            .map_err(|_| EngineError::ChannelClosed("AOF rotate ack"))?
    }

    pub fn shutdown(&self) {
        let mut guard = match self.worker.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(handle) = guard.take() {
            let (ack_tx, ack_rx) = mpsc::sync_channel(1);
            if self.tx.send(AofEvent::Shutdown(ack_tx)).is_ok() {
                let _ = ack_rx.recv_timeout(Duration::from_secs(5));
            }
            let _ = handle.join();
        }
    }
}

impl Drop for AofEngine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn aof_writer_loop(
    live_path: PathBuf,
    initial_file: File,
    policy: FsyncPolicy,
    rx: Receiver<AofEvent>,
) {
    let mut writer: Option<BufWriter<File>> =
        Some(BufWriter::with_capacity(64 * 1024, initial_file));
    let mut dirty_since_sync = false;
    let mut last_sync = Instant::now();

    loop {
        let event = match policy {
            FsyncPolicy::EverySec => match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(ev) => ev,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if dirty_since_sync && last_sync.elapsed() >= Duration::from_secs(1) {
                        if let Some(ref mut w) = writer {
                            if w.flush().is_ok() && w.get_ref().sync_data().is_ok() {
                                dirty_since_sync = false;
                                last_sync = Instant::now();
                            }
                        }
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            },
            _ => match rx.recv() {
                Ok(ev) => ev,
                Err(_) => break,
            },
        };

        match event {
            AofEvent::Append(bytes) => {
                if let Some(ref mut w) = writer {
                    let _ = w.write_all(&bytes);
                    match policy {
                        FsyncPolicy::Always => {
                            let _ = w.flush();
                            let _ = w.get_ref().sync_data();
                            dirty_since_sync = false;
                            last_sync = Instant::now();
                        }
                        FsyncPolicy::EverySec => {
                            let _ = w.flush();
                            dirty_since_sync = true;
                            if last_sync.elapsed() >= Duration::from_secs(1) {
                                let _ = w.get_ref().sync_data();
                                dirty_since_sync = false;
                                last_sync = Instant::now();
                            }
                        }
                        FsyncPolicy::No => {
                            let _ = w.flush();
                        }
                    }
                }
            }
            AofEvent::FlushSync(ack) => {
                let res = if let Some(ref mut w) = writer {
                    w.flush()
                        .and_then(|_| w.get_ref().sync_data())
                        .map_err(EngineError::Io)
                } else {
                    Ok(())
                };
                dirty_since_sync = false;
                last_sync = Instant::now();
                let _ = ack.send(res);
            }
            AofEvent::Rotate {
                temp_path,
                trailing_delta,
                ack,
            } => {
                if let Some(mut w) = writer.take() {
                    let _ = w.flush();
                    drop(w);
                }

                let rotate_res = (|| -> EngineResult<()> {
                    if !trailing_delta.is_empty() {
                        let mut tmp_append =
                            OpenOptions::new().append(true).open(&temp_path)?;
                        tmp_append.write_all(&trailing_delta)?;
                        tmp_append.sync_all()?;
                    }
                    fs::rename(&temp_path, &live_path)?;
                    let reopened = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .read(true)
                        .open(&live_path)?;
                    writer = Some(BufWriter::with_capacity(64 * 1024, reopened));
                    dirty_since_sync = false;
                    last_sync = Instant::now();
                    Ok(())
                })();

                if writer.is_none() {
                    if let Ok(fallback) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .read(true)
                        .open(&live_path)
                    {
                        writer = Some(BufWriter::with_capacity(64 * 1024, fallback));
                    }
                }
                let _ = ack.send(rotate_res);
            }
            AofEvent::Shutdown(ack) => {
                if let Some(mut w) = writer.take() {
                    let _ = w.flush();
                    let _ = w.get_ref().sync_all();
                }
                let _ = ack.send(());
                break;
            }
        }
    }
}

fn encode_exported_entry_aof(entry: &ExportedEntry, out: &mut Vec<u8>) -> EngineResult<()> {
    match &entry.value {
        DataValue::String(val) => {
            encode_command_slices(out, &[b"SET", &entry.key, val]);
        }
        DataValue::List(list) => {
            let all: Vec<&[u8]> = list.iter().collect();
            for chunk in all.chunks(128) {
                let mut cmd = Vec::with_capacity(chunk.len() + 2);
                cmd.push(b"RPUSH".as_slice());
                cmd.push(&entry.key);
                cmd.extend_from_slice(chunk);
                encode_command_slices(out, &cmd);
            }
        }
        DataValue::Hash(map) => {
            let pairs: Vec<(&[u8], &[u8])> = map.iter().map(|(k, v)| (k, v.as_ref())).collect();
            for chunk in pairs.chunks(64) {
                let mut cmd = Vec::with_capacity(chunk.len() * 2 + 2);
                cmd.push(b"HSET".as_slice());
                cmd.push(&entry.key);
                for &(f, v) in chunk {
                    cmd.push(f);
                    cmd.push(v);
                }
                encode_command_slices(out, &cmd);
            }
        }
        DataValue::SortedSet(zset) => {
            let items: Vec<(&[u8], String)> = zset
                .iter()
                .map(|(m, s)| {
                    let s_txt = if s == f64::INFINITY {
                        "inf".to_string()
                    } else if s == f64::NEG_INFINITY {
                        "-inf".to_string()
                    } else {
                        s.to_string()
                    };
                    (m, s_txt)
                })
                .collect();
            for chunk in items.chunks(64) {
                let mut cmd: Vec<&[u8]> = Vec::with_capacity(chunk.len() * 2 + 2);
                cmd.push(b"ZADD");
                cmd.push(&entry.key);
                for (m, s_txt) in chunk {
                    cmd.push(s_txt.as_bytes());
                    cmd.push(m);
                }
                encode_command_slices(out, &cmd);
            }
        }
        DataValue::Stream(stream) => {
            for se in stream.entries() {
                let id_b = se.id.format_bytes();
                let mut cmd: Vec<&[u8]> = Vec::with_capacity(3 + se.fields.len() * 2);
                cmd.push(b"XADD");
                cmd.push(&entry.key);
                cmd.push(&id_b);
                for (f, v) in &se.fields {
                    cmd.push(f);
                    cmd.push(v);
                }
                encode_command_slices(out, &cmd);
            }
            for (_, grp) in stream.groups().iter() {
                let last_b = grp.last_delivered_id.format_bytes();
                let pel_tokens: Vec<(Vec<u8>, &[u8], String, String)> = grp
                    .pel
                    .iter()
                    .map(|p| {
                        (
                            p.id.format_bytes(),
                            p.consumer.as_ref(),
                            p.delivery_time_ms.to_string(),
                            p.delivery_count.to_string(),
                        )
                    })
                    .collect();
                let mut cmd: Vec<&[u8]> = Vec::with_capacity(4 + pel_tokens.len() * 4);
                cmd.push(b"XGROUP.RESTORE");
                cmd.push(&entry.key);
                cmd.push(&grp.name);
                cmd.push(&last_b);
                for (id_b, cons, ts_s, cnt_s) in &pel_tokens {
                    cmd.push(id_b);
                    cmd.push(cons);
                    cmd.push(ts_s.as_bytes());
                    cmd.push(cnt_s.as_bytes());
                }
                encode_command_slices(out, &cmd);
            }
        }
        DataValue::HyperLogLog(hll) => {
            encode_command_slices(out, &[b"PFSETRAW", &entry.key, hll.as_packed_bytes()]);
        }
        DataValue::BloomFilter(bf) => {
            let probes_s = bf.num_probes().to_string();
            let mut raw = Vec::with_capacity(bf.words().len() * 8);
            for &w in bf.words() {
                raw.extend_from_slice(&w.to_le_bytes());
            }
            encode_command_slices(out, &[b"BF.SETRAW", &entry.key, probes_s.as_bytes(), &raw]);
        }
        DataValue::CountMinSketch(cms) => {
            let mut raw = Vec::with_capacity(CMS_DEPTH * CMS_WIDTH * 8);
            for row in cms.matrix() {
                for &cell in row {
                    raw.extend_from_slice(&cell.to_le_bytes());
                }
            }
            encode_command_slices(out, &[b"CMS.SETRAW", &entry.key, &raw]);
        }
        DataValue::VectorIndex(hnsw) => {
            let metric_tag: &[u8] = match hnsw.metric() {
                VectorMetric::Cosine => b"COSINE",
                VectorMetric::L2 => b"L2",
                VectorMetric::InnerProduct => b"IP",
            };
            let sq8_tag: &[u8] = if hnsw.uses_sq8() { b"SQ8" } else { b"F32" };
            for (ext_id, vec) in hnsw.active_entries() {
                let floats: Vec<String> = vec.iter().map(|v| v.to_string()).collect();
                let mut cmd: Vec<&[u8]> = Vec::with_capacity(6 + floats.len());
                cmd.push(b"VADD");
                cmd.push(&entry.key);
                cmd.push(ext_id);
                for f in &floats {
                    cmd.push(f.as_bytes());
                }
                cmd.push(b"METRIC");
                cmd.push(metric_tag);
                cmd.push(sq8_tag);
                encode_command_slices(out, &cmd);
            }
        }
        DataValue::FullTextIndex(fts) => {
            for (doc_id, text) in fts.active_documents() {
                encode_command_slices(out, &[b"FT.ADD", &entry.key, doc_id, text.as_bytes()]);
            }
        }
        DataValue::TimeSeries(ts) => {
            let samples = ts.decode_all()?;
            for (t, v) in samples {
                let t_s = t.to_string();
                let v_s = v.to_string();
                encode_command_slices(
                    out,
                    &[b"TS.ADD", &entry.key, t_s.as_bytes(), v_s.as_bytes()],
                );
            }
        }
    }

    if let Some(unix_ms) = entry.expire_unix_ms {
        let ms_txt = unix_ms.to_string();
        encode_command_slices(out, &[b"PEXPIREAT", &entry.key, ms_txt.as_bytes()]);
    }
    Ok(())
}

fn has_subsequent_resp_command_marker(rem: &[u8]) -> bool {
    if rem.len() < 5 {
        return false;
    }
    let tail = &rem[1..];
    tail.windows(4)
        .any(|w| w == b"\r\n*1" || w == b"\r\n*2" || w == b"\r\n*3" || w == b"\r\n*4")
}

/// Replays in-memory AOF bytes into `StorageEngine` (`[WAL-01]` compliant: skips trailing NUL padding at EOF
/// and rejects mid-file `ParseStatus::Incomplete` frames followed by `\r\n*2` or `\r\n*3` command markers).
pub fn recover_into(raw: &[u8], storage: &StorageEngine) -> EngineResult<usize> {
    let mut offset = 0usize;
    let mut applied = 0usize;

    while offset < raw.len() {
        if raw[offset..].iter().all(|&b| b == 0) {
            break;
        }
        match RespParser::parse(&raw[offset..])? {
            ParseStatus::Complete { frame, consumed } => {
                apply_replayed_frame(&frame, storage)?;
                offset += consumed;
                applied += 1;
            }
            ParseStatus::Incomplete => {
                if has_subsequent_resp_command_marker(&raw[offset..]) {
                    return Err(EngineError::CorruptedPersistence(
                        "mid-file incomplete AOF frame before subsequent command marker".to_string(),
                    ));
                }
                return Err(EngineError::CorruptedPersistence(
                    "truncated trailing frame in AOF log".to_string(),
                ));
            }
        }
    }

    Ok(applied)
}

/// Replays an existing AOF file into `StorageEngine` on server boot.
pub fn replay_aof(path: impl AsRef<Path>, storage: &StorageEngine) -> EngineResult<usize> {
    let path_ref = path.as_ref();
    if !path_ref.exists() {
        return Ok(0);
    }
    let mut file = File::open(path_ref)?;
    let mut stream_buf = StreamReadBuffer::with_capacity(64 * 1024);
    let mut replayed = 0usize;

    loop {
        let n = {
            let dst = stream_buf.writable_slice(16 * 1024);
            file.read(dst)?
        };
        if n > 0 {
            stream_buf.advance_write(n);
        }

        loop {
            let rem = stream_buf.readable_slice();
            if rem.is_empty() {
                break;
            }
            if n == 0 && rem.iter().all(|&b| b == 0) {
                stream_buf.consume(rem.len());
                break;
            }
            let status = RespParser::parse(rem)?;
            let (frame, consumed) = match status {
                ParseStatus::Incomplete => {
                    if n == 0 && has_subsequent_resp_command_marker(rem) {
                        return Err(EngineError::CorruptedPersistence(
                            "mid-file incomplete AOF frame before subsequent command marker"
                                .to_string(),
                        ));
                    }
                    break;
                }
                ParseStatus::Complete { frame, consumed } => (frame, consumed),
            };
            apply_replayed_frame(&frame, storage)?;
            stream_buf.consume(consumed);
            replayed += 1;
        }

        if n == 0 {
            if stream_buf.readable_len() > 0 {
                return Err(EngineError::CorruptedPersistence(
                    "truncated trailing frame in AOF log".to_string(),
                ));
            }
            break;
        }
    }

    Ok(replayed)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashRecoveryReport {
    pub snapshot_keys_loaded: usize,
    pub aof_frames_replayed: usize,
    pub crc32_verified_frames: usize,
    pub truncated_torn_bytes: usize,
    pub used_snapshot_fallback: bool,
}

/// Encodes a RESP command followed by an inline `*2\r\n$9\r\nAOF.CRC32\r\n$8\r\n<hex>\r\n` IEEE 802.3 CRC32 frame.
pub fn encode_command_with_crc32(out: &mut Vec<u8>, parts: &[&[u8]]) -> u32 {
    let start = out.len();
    encode_command_slices(out, parts);
    let crc = !crc32_update(0xFFFF_FFFF, &out[start..]);
    let hex_str = format!("{crc:08x}");
    encode_command_slices(out, &[b"AOF.CRC32", hex_str.as_bytes()]);
    crc
}

fn parse_aof_crc32_frame(frame: &RespFrame<'_>) -> EngineResult<Option<u32>> {
    let RespFrame::Array(items) = frame else {
        return Ok(None);
    };
    if items.len() == 2 {
        if let (Some(cmd), Some(hex_bytes)) = (items[0].as_bytes(), items[1].as_bytes()) {
            if cmd.eq_ignore_ascii_case(b"AOF.CRC32") {
                let hex_str = std::str::from_utf8(hex_bytes).map_err(|_| {
                    EngineError::CorruptedPersistence("invalid UTF-8 in AOF.CRC32 frame".to_string())
                })?;
                let crc = u32::from_str_radix(hex_str, 16).map_err(|_| {
                    EngineError::CorruptedPersistence("invalid hex in AOF.CRC32 frame".to_string())
                })?;
                return Ok(Some(crc));
            }
        }
    }
    Ok(None)
}

/// Crash-recovery pipeline handling mid-frame AOF torn writes, per-frame IEEE 802.3 CRC32 verification,
/// and CRC32 snapshot fallback.
pub fn recover_from_crash(
    aof_path: &Path,
    snapshot_path: &Path,
    storage: &StorageEngine,
) -> EngineResult<CrashRecoveryReport> {
    let mut snapshot_keys = 0usize;
    let mut used_fallback = false;

    if snapshot_path.exists() {
        match load_binary_snapshot(snapshot_path, storage) {
            Ok(cnt) => snapshot_keys = cnt,
            Err(_) => {
                storage.flushdb()?;
            }
        }
    }

    if !aof_path.exists() {
        return Ok(CrashRecoveryReport {
            snapshot_keys_loaded: snapshot_keys,
            aof_frames_replayed: 0,
            crc32_verified_frames: 0,
            truncated_torn_bytes: 0,
            used_snapshot_fallback: false,
        });
    }

    let raw = fs::read(aof_path)?;
    let mut offset = 0usize;
    let mut replayed = 0usize;
    let mut crc32_verified = 0usize;

    while offset < raw.len() {
        if raw[offset..].iter().all(|&b| b == 0) {
            offset = raw.len();
            break;
        }
        match RespParser::parse(&raw[offset..]) {
            Ok(ParseStatus::Complete { frame, consumed }) => {
                let frame_slice = &raw[offset..offset + consumed];
                let computed_frame_crc = !crc32_update(0xFFFF_FFFF, frame_slice);

                // Look ahead for an optional paired `AOF.CRC32` verification frame before mutating storage
                let mut total_step = consumed;
                let mut has_verified_crc = false;
                let next_offset = offset + consumed;
                if next_offset < raw.len() {
                    if let Ok(ParseStatus::Complete {
                        frame: next_frame,
                        consumed: next_consumed,
                    }) = RespParser::parse(&raw[next_offset..])
                    {
                        match parse_aof_crc32_frame(&next_frame) {
                            Ok(Some(expected_crc)) => {
                                if expected_crc != computed_frame_crc {
                                    used_fallback = snapshot_keys > 0;
                                    break;
                                }
                                has_verified_crc = true;
                                total_step += next_consumed;
                            }
                            Ok(None) => {}
                            Err(_) => {
                                used_fallback = snapshot_keys > 0;
                                break;
                            }
                        }
                    }
                }

                if apply_replayed_frame(&frame, storage).is_err() {
                    used_fallback = snapshot_keys > 0;
                    break;
                }
                offset += total_step;
                replayed += 1;
                if has_verified_crc {
                    crc32_verified += 1;
                }
            }
            Ok(ParseStatus::Incomplete) => {
                if has_subsequent_resp_command_marker(&raw[offset..]) {
                    return Err(EngineError::CorruptedPersistence(
                        "mid-file incomplete AOF frame before subsequent command marker"
                            .to_string(),
                    ));
                }
                used_fallback = snapshot_keys > 0;
                break;
            }
            Err(_) => {
                used_fallback = snapshot_keys > 0;
                break;
            }
        }
    }

    let torn_bytes = raw.len().saturating_sub(offset);
    if torn_bytes > 0 {
        let f = OpenOptions::new().write(true).open(aof_path)?;
        f.set_len(offset as u64)?;
        f.sync_all()?;
    }

    Ok(CrashRecoveryReport {
        snapshot_keys_loaded: snapshot_keys,
        aof_frames_replayed: replayed,
        crc32_verified_frames: crc32_verified,
        truncated_torn_bytes: torn_bytes,
        used_snapshot_fallback: used_fallback,
    })
}

pub fn apply_replayed_frame(frame: &RespFrame<'_>, storage: &StorageEngine) -> EngineResult<()> {
    let RespFrame::Array(items) = frame else {
        return Err(EngineError::CorruptedPersistence(
            "expected RESP array command in AOF".to_string(),
        ));
    };
    if items.is_empty() {
        return Ok(());
    }
    let mut args = Vec::with_capacity(items.len());
    for item in items {
        let b = item.as_bytes().ok_or_else(|| {
            EngineError::CorruptedPersistence("non-bytes token in AOF array".to_string())
        })?;
        args.push(b);
    }

    let cmd = args[0];
    if cmd.eq_ignore_ascii_case(b"AOF.CRC32") {
        return Ok(());
    }
    if cmd.eq_ignore_ascii_case(b"SET") && args.len() >= 3 {
        storage.set(args[1], args[2], None, SetCondition::Always)?;
    } else if cmd.eq_ignore_ascii_case(b"DEL") && args.len() >= 2 {
        storage.del(&args[1..])?;
    } else if cmd.eq_ignore_ascii_case(b"INCR") && args.len() == 2 {
        storage.incr_by(args[1], 1)?;
    } else if cmd.eq_ignore_ascii_case(b"DECR") && args.len() == 2 {
        storage.incr_by(args[1], -1)?;
    } else if cmd.eq_ignore_ascii_case(b"INCRBY") && args.len() == 3 {
        let delta = parse_i64_bytes(args[2])?;
        storage.incr_by(args[1], delta)?;
    } else if cmd.eq_ignore_ascii_case(b"APPEND") && args.len() == 3 {
        storage.append(args[1], args[2])?;
    } else if cmd.eq_ignore_ascii_case(b"PEXPIREAT") && args.len() == 3 {
        let target = parse_i64_bytes(args[2])?;
        if target <= 0 {
            storage.del(&[args[1]])?;
        } else {
            storage.pexpire_at_unix_ms(args[1], target as u64)?;
        }
    } else if cmd.eq_ignore_ascii_case(b"PERSIST") && args.len() == 2 {
        storage.persist(args[1])?;
    } else if cmd.eq_ignore_ascii_case(b"FLUSHDB") {
        storage.flushdb()?;
    } else if cmd.eq_ignore_ascii_case(b"LPUSH") && args.len() >= 3 {
        storage.list_push(args[1], &args[2..], true)?;
    } else if cmd.eq_ignore_ascii_case(b"RPUSH") && args.len() >= 3 {
        storage.list_push(args[1], &args[2..], false)?;
    } else if cmd.eq_ignore_ascii_case(b"LPOP") && args.len() == 2 {
        storage.list_pop(args[1], true)?;
    } else if cmd.eq_ignore_ascii_case(b"RPOP") && args.len() == 2 {
        storage.list_pop(args[1], false)?;
    } else if cmd.eq_ignore_ascii_case(b"HSET") && args.len() >= 4 && args.len() % 2 == 0 {
        let mut pairs = Vec::with_capacity((args.len() - 2) / 2);
        let mut idx = 2;
        while idx + 1 < args.len() {
            pairs.push((args[idx], args[idx + 1]));
            idx += 2;
        }
        storage.hset(args[1], &pairs)?;
    } else if cmd.eq_ignore_ascii_case(b"HDEL") && args.len() >= 3 {
        storage.hdel(args[1], &args[2..])?;
    } else if cmd.eq_ignore_ascii_case(b"ZADD") && args.len() >= 4 && args.len() % 2 == 0 {
        let mut entries = Vec::with_capacity((args.len() - 2) / 2);
        let mut idx = 2;
        while idx + 1 < args.len() {
            let score = parse_f64_bytes(args[idx])?;
            entries.push((score, args[idx + 1]));
            idx += 2;
        }
        storage.zadd(args[1], &entries)?;
    } else if cmd.eq_ignore_ascii_case(b"ZREM") && args.len() >= 3 {
        storage.zrem(args[1], &args[2..])?;
    } else if cmd.eq_ignore_ascii_case(b"GEOADD") && args.len() >= 5 && (args.len() - 2) % 3 == 0 {
        let mut items = Vec::with_capacity((args.len() - 2) / 3);
        let mut i = 2;
        while i + 2 < args.len() {
            let lon = parse_f64_bytes(args[i])?;
            let lat = parse_f64_bytes(args[i + 1])?;
            items.push((lon, lat, args[i + 2]));
            i += 3;
        }
        storage.geoadd(args[1], &items)?;
    } else if cmd.eq_ignore_ascii_case(b"XADD") && args.len() >= 5 && (args.len() - 3) % 2 == 0 {
        let mut pairs = Vec::with_capacity((args.len() - 3) / 2);
        let mut i = 3;
        while i + 1 < args.len() {
            pairs.push((args[i], args[i + 1]));
            i += 2;
        }
        storage.xadd(args[1], args[2], &pairs)?;
    } else if cmd.eq_ignore_ascii_case(b"XGROUP") && args.len() >= 5 {
        if args[1].eq_ignore_ascii_case(b"CREATE") {
            let mk = args
                .get(5)
                .map(|s| s.eq_ignore_ascii_case(b"MKSTREAM"))
                .unwrap_or(false);
            storage.xgroup_create(args[2], args[3], args[4], mk)?;
        }
    } else if cmd.eq_ignore_ascii_case(b"XACK") && args.len() >= 4 {
        let mut ids = Vec::with_capacity(args.len() - 3);
        for &raw_id in &args[3..] {
            ids.push(StreamId::parse_explicit(raw_id)?);
        }
        storage.xack(args[1], args[2], &ids)?;
    } else if cmd.eq_ignore_ascii_case(b"XGROUP.RESTORE") && args.len() >= 4 {
        let key = args[1];
        let grp_name = args[2];
        let last_id = StreamId::parse_explicit(args[3])?;
        let mut pending = Vec::new();
        let mut i = 4usize;
        while i + 3 < args.len() {
            let pid = StreamId::parse_explicit(args[i])?;
            let consumer = args[i + 1].to_vec().into_boxed_slice();
            let d_ms = parse_i64_bytes(args[i + 2])?.max(0) as u64;
            let d_cnt = parse_i64_bytes(args[i + 3])?.max(1) as u64;
            pending.push(PendingEntry {
                id: pid,
                consumer,
                delivery_time_ms: d_ms,
                delivery_count: d_cnt,
            });
            i += 4;
        }
        let shard_idx = storage.shard_index(key);
        let existing = storage
            .export_shard_snapshot(shard_idx)?
            .into_iter()
            .find(|e| e.key.as_ref() == key);
        let (mut slog, exp) = match existing {
            Some(ExportedEntry {
                value: DataValue::Stream(s),
                expire_unix_ms,
                ..
            }) => (s, expire_unix_ms),
            _ => (StreamLog::new(), None),
        };
        slog.restore_group_state(grp_name, last_id, pending);
        storage.put_raw_value(key, DataValue::Stream(slog), exp)?;
    } else if cmd.eq_ignore_ascii_case(b"PFADD") && args.len() >= 3 {
        storage.pfadd(args[1], &args[2..])?;
    } else if cmd.eq_ignore_ascii_case(b"PFMERGE") && args.len() >= 3 {
        storage.pfmerge(args[1], &args[2..])?;
    } else if cmd.eq_ignore_ascii_case(b"PFSETRAW") && args.len() == 3 {
        let hll = HyperLogLog::from_packed_bytes(args[2]).ok_or_else(|| {
            EngineError::CorruptedPersistence("invalid HyperLogLog packed length".to_string())
        })?;
        storage.put_raw_value(args[1], DataValue::HyperLogLog(hll), None)?;
    } else if cmd.eq_ignore_ascii_case(b"BF.ADD") && args.len() == 3 {
        storage.bf_add(args[1], args[2])?;
    } else if cmd.eq_ignore_ascii_case(b"BF.SETRAW") && args.len() == 4 {
        let probes = parse_i64_bytes(args[2])?.max(2) as u32;
        let raw = args[3];
        if raw.len() % 8 != 0 {
            return Err(EngineError::CorruptedPersistence(
                "invalid BF.SETRAW word alignment".to_string(),
            ));
        }
        let mut words = Vec::with_capacity(raw.len() / 8);
        for chunk in raw.chunks_exact(8) {
            words.push(u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]));
        }
        let bf = BloomFilter::from_raw_parts(probes, words);
        storage.put_raw_value(args[1], DataValue::BloomFilter(bf), None)?;
    } else if cmd.eq_ignore_ascii_case(b"CMS.INCRBY") && args.len() >= 4 && args.len() % 2 == 0 {
        let mut inc = Vec::with_capacity((args.len() - 2) / 2);
        let mut i = 2;
        while i + 1 < args.len() {
            let d = parse_i64_bytes(args[i + 1])?.max(0) as u64;
            inc.push((args[i], d));
            i += 2;
        }
        storage.cms_incrby(args[1], &inc)?;
    } else if cmd.eq_ignore_ascii_case(b"CMS.SETRAW") && args.len() == 3 {
        let raw = args[2];
        if raw.len() != CMS_DEPTH * CMS_WIDTH * 8 {
            return Err(EngineError::CorruptedPersistence(
                "invalid CMS.SETRAW byte size".to_string(),
            ));
        }
        let mut mat = Box::new([[0u64; CMS_WIDTH]; CMS_DEPTH]);
        let mut pos = 0usize;
        for row in 0..CMS_DEPTH {
            for col in 0..CMS_WIDTH {
                mat[row][col] = u64::from_le_bytes([
                    raw[pos],
                    raw[pos + 1],
                    raw[pos + 2],
                    raw[pos + 3],
                    raw[pos + 4],
                    raw[pos + 5],
                    raw[pos + 6],
                    raw[pos + 7],
                ]);
                pos += 8;
            }
        }
        storage.put_raw_value(
            args[1],
            DataValue::CountMinSketch(Box::new(CountMinSketch::from_matrix(mat))),
            None,
        )?;
    } else if cmd.eq_ignore_ascii_case(b"VADD") && args.len() >= 4 {
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
        let mut vec = Vec::with_capacity(end - 3);
        for &tok in &args[3..end] {
            vec.push(parse_f64_bytes(tok)? as f32);
        }
        storage.vadd(args[1], args[2], &vec, metric, sq8)?;
    } else if cmd.eq_ignore_ascii_case(b"VREM") && args.len() == 3 {
        storage.vrem(args[1], args[2])?;
    } else if cmd.eq_ignore_ascii_case(b"FT.ADD") && args.len() == 4 {
        let txt = std::str::from_utf8(args[3])?;
        storage.ft_add(args[1], args[2], txt)?;
    } else if cmd.eq_ignore_ascii_case(b"TS.ADD") && args.len() == 4 {
        let ts = parse_i64_bytes(args[2])?;
        let val = parse_f64_bytes(args[3])?;
        storage.ts_add(args[1], ts, val)?;
    }
    Ok(())
}

// ==================== BINARY POINT-IN-TIME SNAPSHOT + CRC32 + AEAD ====================

fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
}

pub fn serialize_snapshot_bytes(storage: &StorageEngine) -> EngineResult<(Vec<u8>, usize)> {
    let mut payload = Vec::with_capacity(4096);
    let mut crc: u32 = 0xFFFF_FFFF;

    let mut write_checked = |buf: &[u8]| {
        crc = crc32_update(crc, buf);
        payload.extend_from_slice(buf);
    };

    write_checked(SNAPSHOT_MAGIC);

    let mut all_entries = Vec::new();
    for shard_idx in 0..storage.shard_count() {
        all_entries.extend(storage.export_shard_snapshot(shard_idx)?);
    }

    let count = all_entries.len();
    write_checked(&(count as u64).to_le_bytes());

    for entry in &all_entries {
        let exp_raw: u64 = entry.expire_unix_ms.unwrap_or(0);
        write_checked(&exp_raw.to_le_bytes());
        write_checked(&(entry.key.len() as u32).to_le_bytes());
        write_checked(&entry.key);

        match &entry.value {
            DataValue::String(val) => {
                write_checked(&[1u8]);
                write_checked(&(val.len() as u32).to_le_bytes());
                write_checked(val);
            }
            DataValue::List(list) => {
                write_checked(&[2u8]);
                write_checked(&(list.len() as u32).to_le_bytes());
                for item in list.iter() {
                    write_checked(&(item.len() as u32).to_le_bytes());
                    write_checked(item);
                }
            }
            DataValue::Hash(map) => {
                write_checked(&[3u8]);
                write_checked(&(map.len() as u32).to_le_bytes());
                for (f, v) in map.iter() {
                    write_checked(&(f.len() as u32).to_le_bytes());
                    write_checked(f);
                    write_checked(&(v.len() as u32).to_le_bytes());
                    write_checked(v);
                }
            }
            DataValue::SortedSet(zset) => {
                write_checked(&[4u8]);
                write_checked(&(zset.len() as u32).to_le_bytes());
                for (mem, score) in zset.iter() {
                    write_checked(&score.to_bits().to_le_bytes());
                    write_checked(&(mem.len() as u32).to_le_bytes());
                    write_checked(mem);
                }
            }
            DataValue::Stream(stream) => {
                write_checked(&[5u8]);
                write_checked(&(stream.entries().len() as u32).to_le_bytes());
                for se in stream.entries() {
                    write_checked(&se.id.ms.to_le_bytes());
                    write_checked(&se.id.seq.to_le_bytes());
                    write_checked(&(se.fields.len() as u32).to_le_bytes());
                    for (f, v) in &se.fields {
                        write_checked(&(f.len() as u32).to_le_bytes());
                        write_checked(f);
                        write_checked(&(v.len() as u32).to_le_bytes());
                        write_checked(v);
                    }
                }
                write_checked(&(stream.groups().len() as u32).to_le_bytes());
                for (_, grp) in stream.groups().iter() {
                    write_checked(&(grp.name.len() as u32).to_le_bytes());
                    write_checked(&grp.name);
                    write_checked(&grp.last_delivered_id.ms.to_le_bytes());
                    write_checked(&grp.last_delivered_id.seq.to_le_bytes());
                    write_checked(&(grp.pel.len() as u32).to_le_bytes());
                    for p in &grp.pel {
                        write_checked(&p.id.ms.to_le_bytes());
                        write_checked(&p.id.seq.to_le_bytes());
                        write_checked(&(p.consumer.len() as u32).to_le_bytes());
                        write_checked(&p.consumer);
                        write_checked(&p.delivery_time_ms.to_le_bytes());
                        write_checked(&p.delivery_count.to_le_bytes());
                    }
                }
            }
            DataValue::HyperLogLog(hll) => {
                write_checked(&[6u8]);
                write_checked(hll.as_packed_bytes());
            }
            DataValue::BloomFilter(bf) => {
                write_checked(&[7u8]);
                write_checked(&bf.num_probes().to_le_bytes());
                write_checked(&(bf.words().len() as u32).to_le_bytes());
                for &w in bf.words() {
                    write_checked(&w.to_le_bytes());
                }
            }
            DataValue::CountMinSketch(cms) => {
                write_checked(&[8u8]);
                for row in cms.matrix() {
                    for &cell in row {
                        write_checked(&cell.to_le_bytes());
                    }
                }
            }
            DataValue::VectorIndex(hnsw) => {
                write_checked(&[9u8]);
                write_checked(&[hnsw.metric().code(), u8::from(hnsw.uses_sq8())]);
                write_checked(&(hnsw.dimension() as u32).to_le_bytes());
                let active: Vec<(&[u8], &[f32])> = hnsw.active_entries().collect();
                write_checked(&(active.len() as u32).to_le_bytes());
                for (ext_id, vec) in active {
                    write_checked(&(ext_id.len() as u32).to_le_bytes());
                    write_checked(ext_id);
                    for &f in vec {
                        write_checked(&f.to_bits().to_le_bytes());
                    }
                }
            }
            DataValue::FullTextIndex(fts) => {
                write_checked(&[10u8]);
                let docs: Vec<(&[u8], &str)> = fts.active_documents().collect();
                write_checked(&(docs.len() as u32).to_le_bytes());
                for (doc_id, txt) in docs {
                    write_checked(&(doc_id.len() as u32).to_le_bytes());
                    write_checked(doc_id);
                    let tb = txt.as_bytes();
                    write_checked(&(tb.len() as u32).to_le_bytes());
                    write_checked(tb);
                }
            }
            DataValue::TimeSeries(ts) => {
                write_checked(&[11u8]);
                let pts = ts.decode_all()?;
                write_checked(&(pts.len() as u32).to_le_bytes());
                for (t, v) in pts {
                    write_checked(&t.to_le_bytes());
                    write_checked(&v.to_bits().to_le_bytes());
                }
            }
        }
    }

    let final_crc = !crc;
    payload.extend_from_slice(&final_crc.to_le_bytes());
    Ok((payload, count))
}

pub fn deserialize_snapshot_bytes(raw: &[u8], storage: &StorageEngine) -> EngineResult<usize> {
    if raw.len() < SNAPSHOT_MAGIC.len() + 8 + 4 {
        return Err(EngineError::CorruptedPersistence(
            "snapshot shorter than minimum header+checksum".to_string(),
        ));
    }

    let payload_end = raw.len() - 4;
    let expected_crc = u32::from_le_bytes([
        raw[payload_end],
        raw[payload_end + 1],
        raw[payload_end + 2],
        raw[payload_end + 3],
    ]);
    let computed_crc = !crc32_update(0xFFFF_FFFF, &raw[..payload_end]);
    if expected_crc != computed_crc {
        return Err(EngineError::CorruptedPersistence(
            "snapshot CRC32 checksum mismatch".to_string(),
        ));
    }

    if &raw[..5] != SNAPSHOT_MAGIC && &raw[..5] != SNAPSHOT_MAGIC_V1 {
        return Err(EngineError::CorruptedPersistence(
            "invalid snapshot magic header".to_string(),
        ));
    }

    let mut pos = 5usize;
    const MAX_SNAPSHOT_FRAME_BYTES: usize = 64 * 1024 * 1024;
    let read_u32 = |buf: &[u8], cur: &mut usize| -> EngineResult<u32> {
        if *cur + 4 > buf.len() {
            return Err(EngineError::CorruptedPersistence("unexpected EOF".to_string()));
        }
        let v = u32::from_le_bytes([buf[*cur], buf[*cur + 1], buf[*cur + 2], buf[*cur + 3]]);
        *cur += 4;
        Ok(v)
    };
    let read_u64 = |buf: &[u8], cur: &mut usize| -> EngineResult<u64> {
        if *cur + 8 > buf.len() {
            return Err(EngineError::CorruptedPersistence("unexpected EOF".to_string()));
        }
        let v = u64::from_le_bytes([
            buf[*cur],
            buf[*cur + 1],
            buf[*cur + 2],
            buf[*cur + 3],
            buf[*cur + 4],
            buf[*cur + 5],
            buf[*cur + 6],
            buf[*cur + 7],
        ]);
        *cur += 8;
        Ok(v)
    };
    fn read_slice<'a>(buf: &'a [u8], cur: &mut usize, len: usize) -> EngineResult<&'a [u8]> {
        if len > MAX_SNAPSHOT_FRAME_BYTES || len > buf.len().saturating_sub(*cur) {
            return Err(EngineError::CorruptedPersistence("unexpected EOF".to_string()));
        }
        let s = &buf[*cur..*cur + len];
        *cur += len;
        Ok(s)
    }
    fn read_bytes(buf: &[u8], cur: &mut usize) -> EngineResult<Vec<u8>> {
        if *cur + 4 > buf.len() {
            return Err(EngineError::CorruptedPersistence("unexpected EOF".to_string()));
        }
        let len = u32::from_le_bytes([buf[*cur], buf[*cur + 1], buf[*cur + 2], buf[*cur + 3]]) as usize;
        *cur += 4;
        let rem = buf.len().saturating_sub(*cur);
        if len > MAX_SNAPSHOT_FRAME_BYTES || len > rem {
            return Err(EngineError::CorruptedPersistence(
                "snapshot length prefix exceeds remaining buffer".to_string(),
            ));
        }
        let mut out = vec![0u8; len];
        out.copy_from_slice(&buf[*cur..*cur + len]);
        *cur += len;
        Ok(out)
    }
    fn check_item_count(count: usize, min_bytes_per_item: usize, rem: usize) -> EngineResult<()> {
        if count.saturating_mul(min_bytes_per_item.max(1)) > rem {
            return Err(EngineError::CorruptedPersistence(
                "snapshot collection count exceeds remaining buffer".to_string(),
            ));
        }
        Ok(())
    }

    let data = &raw[..payload_end];
    let total = read_u64(data, &mut pos)? as usize;
    check_item_count(total, 13, data.len().saturating_sub(pos))?;
    let mut loaded = 0usize;

    for _ in 0..total {
        let exp_ms = read_u64(data, &mut pos)?;
        let exp_opt = if exp_ms > 0 { Some(exp_ms) } else { None };
        let key_vec = read_bytes(data, &mut pos)?;
        let key = key_vec.as_slice();
        let tag = read_slice(data, &mut pos, 1)?[0];

        match tag {
            1 => {
                let vlen = read_u32(data, &mut pos)? as usize;
                let val = read_slice(data, &mut pos, vlen)?;
                storage.set(key, val, None, SetCondition::Always)?;
                if exp_ms > 0 {
                    storage.pexpire_at_unix_ms(key, exp_ms)?;
                }
            }
            2 => {
                let count = read_u32(data, &mut pos)? as usize;
                check_item_count(count, 4, data.len().saturating_sub(pos))?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let ilen = read_u32(data, &mut pos)? as usize;
                    items.push(read_slice(data, &mut pos, ilen)?);
                }
                if !items.is_empty() {
                    storage.list_push(key, &items, false)?;
                }
                if exp_ms > 0 {
                    storage.pexpire_at_unix_ms(key, exp_ms)?;
                }
            }
            3 => {
                let count = read_u32(data, &mut pos)? as usize;
                check_item_count(count, 8, data.len().saturating_sub(pos))?;
                let mut pairs = Vec::with_capacity(count);
                for _ in 0..count {
                    let flen = read_u32(data, &mut pos)? as usize;
                    let f = read_slice(data, &mut pos, flen)?;
                    let vlen = read_u32(data, &mut pos)? as usize;
                    let v = read_slice(data, &mut pos, vlen)?;
                    pairs.push((f, v));
                }
                if !pairs.is_empty() {
                    storage.hset(key, &pairs)?;
                }
                if exp_ms > 0 {
                    storage.pexpire_at_unix_ms(key, exp_ms)?;
                }
            }
            4 => {
                let count = read_u32(data, &mut pos)? as usize;
                check_item_count(count, 12, data.len().saturating_sub(pos))?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let bits = read_u64(data, &mut pos)?;
                    let score = f64::from_bits(bits);
                    let mlen = read_u32(data, &mut pos)? as usize;
                    let mem = read_slice(data, &mut pos, mlen)?;
                    entries.push((score, mem));
                }
                if !entries.is_empty() {
                    storage.zadd(key, &entries)?;
                }
                if exp_ms > 0 {
                    storage.pexpire_at_unix_ms(key, exp_ms)?;
                }
            }
            5 => {
                let mut slog = StreamLog::new();
                let e_cnt = read_u32(data, &mut pos)? as usize;
                check_item_count(e_cnt, 20, data.len().saturating_sub(pos))?;
                for _ in 0..e_cnt {
                    let ms = read_u64(data, &mut pos)?;
                    let seq = read_u64(data, &mut pos)?;
                    let f_cnt = read_u32(data, &mut pos)? as usize;
                    check_item_count(f_cnt, 8, data.len().saturating_sub(pos))?;
                    let mut pairs = Vec::with_capacity(f_cnt);
                    for _ in 0..f_cnt {
                        let fl = read_u32(data, &mut pos)? as usize;
                        let f = read_slice(data, &mut pos, fl)?;
                        let vl = read_u32(data, &mut pos)? as usize;
                        let v = read_slice(data, &mut pos, vl)?;
                        pairs.push((f, v));
                    }
                    let id_b = StreamId { ms, seq }.format_bytes();
                    slog.xadd(&id_b, &pairs)?;
                }
                let g_cnt = read_u32(data, &mut pos)? as usize;
                check_item_count(g_cnt, 24, data.len().saturating_sub(pos))?;
                for _ in 0..g_cnt {
                    let nl = read_u32(data, &mut pos)? as usize;
                    let gname = read_slice(data, &mut pos, nl)?;
                    let l_ms = read_u64(data, &mut pos)?;
                    let l_seq = read_u64(data, &mut pos)?;
                    let p_cnt = read_u32(data, &mut pos)? as usize;
                    check_item_count(p_cnt, 36, data.len().saturating_sub(pos))?;
                    let mut pel = Vec::with_capacity(p_cnt);
                    for _ in 0..p_cnt {
                        let p_ms = read_u64(data, &mut pos)?;
                        let p_seq = read_u64(data, &mut pos)?;
                        let cl = read_u32(data, &mut pos)? as usize;
                        let cons = read_slice(data, &mut pos, cl)?.to_vec().into_boxed_slice();
                        let dt = read_u64(data, &mut pos)?;
                        let dc = read_u64(data, &mut pos)?;
                        pel.push(PendingEntry {
                            id: StreamId {
                                ms: p_ms,
                                seq: p_seq,
                            },
                            consumer: cons,
                            delivery_time_ms: dt,
                            delivery_count: dc,
                        });
                    }
                    slog.restore_group_state(
                        gname,
                        StreamId {
                            ms: l_ms,
                            seq: l_seq,
                        },
                        pel,
                    );
                }
                storage.put_raw_value(key, DataValue::Stream(slog), exp_opt)?;
            }
            6 => {
                let raw_hll = read_slice(data, &mut pos, HLL_PACKED_BYTES)?;
                let hll = HyperLogLog::from_packed_bytes(raw_hll).ok_or_else(|| {
                    EngineError::CorruptedPersistence("corrupted HLL snapshot".to_string())
                })?;
                storage.put_raw_value(key, DataValue::HyperLogLog(hll), exp_opt)?;
            }
            7 => {
                let probes = read_u32(data, &mut pos)?;
                let w_cnt = read_u32(data, &mut pos)? as usize;
                check_item_count(w_cnt, 8, data.len().saturating_sub(pos))?;
                let mut words = Vec::with_capacity(w_cnt);
                for _ in 0..w_cnt {
                    words.push(read_u64(data, &mut pos)?);
                }
                let bf = BloomFilter::from_raw_parts(probes, words);
                storage.put_raw_value(key, DataValue::BloomFilter(bf), exp_opt)?;
            }
            8 => {
                let mut mat = Box::new([[0u64; CMS_WIDTH]; CMS_DEPTH]);
                for row in 0..CMS_DEPTH {
                    for col in 0..CMS_WIDTH {
                        mat[row][col] = read_u64(data, &mut pos)?;
                    }
                }
                storage.put_raw_value(
                    key,
                    DataValue::CountMinSketch(Box::new(CountMinSketch::from_matrix(mat))),
                    exp_opt,
                )?;
            }
            9 => {
                let hdr = read_slice(data, &mut pos, 2)?;
                let metric = VectorMetric::from_code(hdr[0])?;
                let uses_sq8 = hdr[1] != 0;
                let dim = read_u32(data, &mut pos)? as usize;
                let v_cnt = read_u32(data, &mut pos)? as usize;
                if dim > 65_536 {
                    return Err(EngineError::CorruptedPersistence(
                        "snapshot vector dimension exceeds bound".to_string(),
                    ));
                }
                check_item_count(v_cnt, 4usize.saturating_add(dim.saturating_mul(4)), data.len().saturating_sub(pos))?;
                let mut hnsw = HnswIndex::new(metric, uses_sq8);
                let mut vec_buf = vec![0.0f32; dim];
                for _ in 0..v_cnt {
                    let id_len = read_u32(data, &mut pos)? as usize;
                    let ext_id = read_slice(data, &mut pos, id_len)?;
                    for slot in vec_buf.iter_mut() {
                        *slot = f32::from_bits(read_u32(data, &mut pos)?);
                    }
                    hnsw.upsert(ext_id, &vec_buf, Some(metric), Some(uses_sq8))?;
                }
                storage.put_raw_value(key, DataValue::VectorIndex(hnsw), exp_opt)?;
            }
            10 => {
                let d_cnt = read_u32(data, &mut pos)? as usize;
                check_item_count(d_cnt, 8, data.len().saturating_sub(pos))?;
                let mut fts = FullTextIndex::new();
                for _ in 0..d_cnt {
                    let id_len = read_u32(data, &mut pos)? as usize;
                    let doc_id = read_slice(data, &mut pos, id_len)?;
                    let t_len = read_u32(data, &mut pos)? as usize;
                    let txt = std::str::from_utf8(read_slice(data, &mut pos, t_len)?)?;
                    fts.add_document(doc_id, txt);
                }
                storage.put_raw_value(key, DataValue::FullTextIndex(fts), exp_opt)?;
            }
            11 => {
                let s_cnt = read_u32(data, &mut pos)? as usize;
                check_item_count(s_cnt, 16, data.len().saturating_sub(pos))?;
                let mut ts = GorillaTimeSeries::new();
                for _ in 0..s_cnt {
                    let t = read_u64(data, &mut pos)? as i64;
                    let v = f64::from_bits(read_u64(data, &mut pos)?);
                    ts.append(t, v)?;
                }
                storage.put_raw_value(key, DataValue::TimeSeries(ts), exp_opt)?;
            }
            other => {
                return Err(EngineError::CorruptedPersistence(format!(
                    "unknown snapshot value tag {}",
                    other
                )))
            }
        }

        loaded += 1;
    }

    Ok(loaded)
}

/// Writes an atomic binary snapshot (`SAVE`) protected by an IEEE 802.3 CRC32 checksum.
pub fn save_binary_snapshot(path: impl AsRef<Path>, storage: &StorageEngine) -> EngineResult<usize> {
    let dest = path.as_ref();
    let (bytes, count) = serialize_snapshot_bytes(storage)?;
    write_atomic_file(dest, &bytes)?;
    Ok(count)
}

pub fn load_binary_snapshot(path: impl AsRef<Path>, storage: &StorageEngine) -> EngineResult<usize> {
    let p = path.as_ref();
    if !p.exists() {
        return Ok(0);
    }
    let mut reader = BufReader::new(File::open(p)?);
    let mut raw = Vec::new();
    reader.read_to_end(&mut raw)?;
    deserialize_snapshot_bytes(&raw, storage)
}

/// Writes an RFC 8439 ChaCha20-Poly1305 encrypted snapshot envelope (`FRKE\x01 || 12B nonce || ciphertext || 16B tag`).
pub fn save_encrypted_snapshot(
    path: impl AsRef<Path>,
    storage: &StorageEngine,
    key: &[u8; 32],
) -> EngineResult<usize> {
    let (plain_bytes, count) = serialize_snapshot_bytes(storage)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    let digest = sha256(&nanos.to_le_bytes());
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);

    let sealed = chacha20_poly1305_encrypt(key, &nonce, ENCRYPTED_MAGIC, &plain_bytes);
    let mut envelope = Vec::with_capacity(ENCRYPTED_MAGIC.len() + 12 + sealed.len());
    envelope.extend_from_slice(ENCRYPTED_MAGIC);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&sealed);

    write_atomic_file(path.as_ref(), &envelope)?;
    Ok(count)
}

/// Verifies Poly1305 MAC + inner CRC32 and loads an encrypted ChaCha20-Poly1305 snapshot envelope.
pub fn load_encrypted_snapshot(
    path: impl AsRef<Path>,
    storage: &StorageEngine,
    key: &[u8; 32],
) -> EngineResult<usize> {
    let p = path.as_ref();
    if !p.exists() {
        return Ok(0);
    }
    let envelope = fs::read(p)?;
    if envelope.len() < ENCRYPTED_MAGIC.len() + 12 + 16 {
        return Err(EngineError::CorruptedPersistence(
            "encrypted snapshot envelope truncated".to_string(),
        ));
    }
    if &envelope[..5] != ENCRYPTED_MAGIC {
        return Err(EngineError::CorruptedPersistence(
            "invalid encrypted snapshot magic header".to_string(),
        ));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&envelope[5..17]);
    let plaintext = chacha20_poly1305_decrypt(key, &nonce, ENCRYPTED_MAGIC, &envelope[17..])?;
    deserialize_snapshot_bytes(&plaintext, storage)
}

fn write_atomic_file(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp_os = dest.as_os_str().to_os_string();
    tmp_os.push(".snap.tmp");
    let tmp_path = PathBuf::from(tmp_os);

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)?;
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    writer.write_all(bytes)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);

    fs::rename(&tmp_path, dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wal01_trailing_nul_padding_and_mid_file_incomplete_frame() -> EngineResult<()> {
        let storage = StorageEngine::new(4)?;
        let mut raw = Vec::new();
        encode_command_slices(&mut raw, &[b"SET", b"k1", b"v1"]);
        raw.extend_from_slice(&[0u8; 64]); // Trailing NUL padding at EOF
        let applied = recover_into(&raw, &storage)?;
        assert_eq!(applied, 1);
        assert_eq!(storage.get_bytes(b"k1")?.as_deref(), Some(&b"v1"[..]));

        // Mid-file incomplete frame (claims $9999 bytes) followed by another command `\r\n*3\r\n...`
        let mut mid_corrupt = Vec::new();
        encode_command_slices(&mut mid_corrupt, &[b"SET", b"k1", b"v1"]);
        mid_corrupt.extend_from_slice(b"*3\r\n$3\r\nSET\r\n$2\r\nk2\r\n$9999\r\nshort\r\n*3\r\n$3\r\nSET\r\n$2\r\nk3\r\n$2\r\nv3\r\n");

        let storage2 = StorageEngine::new(4)?;
        let res = recover_into(&mid_corrupt, &storage2);
        assert!(
            matches!(res, Err(EngineError::CorruptedPersistence(_))),
            "expected CorruptedPersistence on mid-file incomplete AOF frame, got {res:?}"
        );
        Ok(())
    }

    #[test]
    fn test_wal02_snapshot_oversized_length_prefix_rejects_oom() -> EngineResult<()> {
        let mut payload = Vec::new();
        payload.extend_from_slice(SNAPSHOT_MAGIC);
        payload.extend_from_slice(&1u64.to_le_bytes()); // 1 entry
        payload.extend_from_slice(&0u64.to_le_bytes()); // expire_ms = 0
        payload.extend_from_slice(&(0xFFFF_FFFFu32).to_le_bytes()); // corrupted 4 GiB key_len!
        let crc = !crc32_update(0xFFFF_FFFF, &payload);
        payload.extend_from_slice(&crc.to_le_bytes());

        let storage = StorageEngine::new(4)?;
        let res = deserialize_snapshot_bytes(&payload, &storage);
        assert!(
            matches!(res, Err(EngineError::CorruptedPersistence(_))),
            "expected CorruptedPersistence on 4 GiB key_len prefix, got {res:?}"
        );
        Ok(())
    }
}
