pub mod fts;
pub mod geospatial;
pub mod hashtable;
pub mod list;
pub mod lsm;
pub mod probabilistic;
pub mod skiplist;
pub mod stream;
pub mod timeseries;
pub mod vector_hnsw;

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockWriteGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{EngineError, EngineResult};
use crate::pubsub::glob_match;
use crate::resp::{
    parse_i64_bytes, write_array_header, write_bulk_string, write_double, write_integer,
    write_map_header, write_null,
};
use crate::storage::fts::FullTextIndex;
use crate::storage::geospatial::{
    geohash_decode_52bit, geohash_encode_52bit, georadius_query, haversine_meters, GeoUnit,
};
use crate::storage::hashtable::{fnv1a_64, siphash24, RawHashTable};
use crate::storage::list::RingList;
use crate::storage::lsm::LsmEngine;
use crate::storage::probabilistic::{BloomFilter, CountMinSketch, HyperLogLog};
use crate::storage::skiplist::SortedSet;
use crate::storage::stream::{StreamEntry, StreamId, StreamLog};
use crate::storage::timeseries::{GorillaTimeSeries, TsAggregation};
use crate::storage::vector_hnsw::{HnswIndex, VectorMetric};
use crate::telemetry::CachePadded;

pub const DEFAULT_SHARD_COUNT: usize = 64;

#[derive(Clone, Debug)]
pub enum DataValue {
    String(Box<[u8]>),
    List(RingList),
    Hash(RawHashTable<Box<[u8]>>),
    SortedSet(SortedSet),
    Stream(StreamLog),
    HyperLogLog(HyperLogLog),
    BloomFilter(BloomFilter),
    CountMinSketch(Box<CountMinSketch>),
    VectorIndex(HnswIndex),
    FullTextIndex(FullTextIndex),
    TimeSeries(GorillaTimeSeries),
}

impl DataValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            DataValue::String(_) => "string",
            DataValue::List(_) => "list",
            DataValue::Hash(_) => "hash",
            DataValue::SortedSet(_) => "zset",
            DataValue::Stream(_) => "stream",
            DataValue::HyperLogLog(_) => "hyperloglog",
            DataValue::BloomFilter(_) => "MBbloom--",
            DataValue::CountMinSketch(_) => "CMSketch",
            DataValue::VectorIndex(_) => "vector",
            DataValue::FullTextIndex(_) => "fts",
            DataValue::TimeSeries(_) => "timeseries",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Record {
    pub value: DataValue,
    pub expires_at: Option<Instant>,
    pub version: u64,
}

impl Record {
    #[inline]
    pub fn is_expired(&self, now: Instant) -> bool {
        match self.expires_at {
            Some(deadline) => now >= deadline,
            None => false,
        }
    }
}

#[derive(Debug)]
pub struct Shard {
    table: RawHashTable<Record>,
    /// Tracks tombstone versions ONLY for keys currently under `WATCH` when deleted (`DEL`/expire).
    key_versions: RawHashTable<u64>,
    next_version: u64,
    flush_epoch: u64,
    expiring_keys: usize,
    sweep_cursor: usize,
}

impl Shard {
    fn new(shard_idx: usize) -> Self {
        let seed0 =
            0x517c_c1b7_2722_0a95u64.wrapping_add((shard_idx as u64).wrapping_mul(0x9e37_79b9));
        let seed1 = 0x85eb_ca6b_c2b2_ae35u64 ^ (shard_idx as u64).rotate_left(19);
        Self {
            table: RawHashTable::with_capacity_and_seeds(512, seed0, seed1),
            key_versions: RawHashTable::with_capacity_and_seeds(16, seed0 ^ 0xA5A5, seed1 ^ 0x5A5A),
            next_version: 1,
            flush_epoch: 0,
            expiring_keys: 0,
            sweep_cursor: 0,
        }
    }

    #[inline]
    pub fn key_version(&self, key: &[u8]) -> u64 {
        if let Some(rec) = self.table.get(key) {
            rec.version
        } else {
            self.key_versions.get(key).copied().unwrap_or(0)
        }
    }

    #[inline]
    pub fn flush_epoch(&self) -> u64 {
        self.flush_epoch
    }

    #[inline]
    fn alloc_version(&mut self) -> u64 {
        let v = self.next_version;
        self.next_version = self.next_version.wrapping_add(1);
        v
    }

    #[inline]
    fn register_watch(&mut self, key: &[u8]) -> u64 {
        let ver = self.key_version(key);
        if let Some(slot) = self.key_versions.get_mut(key) {
            *slot = ver;
        } else {
            self.key_versions
                .insert(key.to_vec().into_boxed_slice(), ver);
        }
        ver
    }

    #[inline]
    fn bump_version(&mut self, key: &[u8]) {
        let v = self.alloc_version();
        if let Some(rec) = self.table.get_mut(key) {
            rec.version = v;
        } else if let Some(slot) = self.key_versions.get_mut(key) {
            *slot = v;
        }
    }

    #[inline]
    fn remove_key(&mut self, key: &[u8]) -> Option<Record> {
        let removed = self.table.remove(key).map(|(_, rec)| rec);
        if let Some(ref rec) = removed {
            if rec.expires_at.is_some() {
                self.expiring_keys = self.expiring_keys.saturating_sub(1);
            }
            let v = self.alloc_version();
            if let Some(slot) = self.key_versions.get_mut(key) {
                *slot = v;
            }
        }
        removed
    }

    #[inline]
    fn upsert_record(&mut self, key: Box<[u8]>, mut rec: Record) {
        let new_has_ttl = rec.expires_at.is_some();
        rec.version = self.alloc_version();
        if let Some(prev) = self.table.insert(key, rec) {
            if prev.expires_at.is_some() && !new_has_ttl {
                self.expiring_keys = self.expiring_keys.saturating_sub(1);
            } else if prev.expires_at.is_none() && new_has_ttl {
                self.expiring_keys += 1;
            }
        } else if new_has_ttl {
            self.expiring_keys += 1;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetCondition {
    Always,
    IfAbsent,
    IfPresent,
}

#[derive(Clone, Debug)]
pub struct ExportedEntry {
    pub key: Box<[u8]>,
    pub value: DataValue,
    pub expire_unix_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct WatchedKeyStamp {
    pub key: Box<[u8]>,
    pub shard_idx: usize,
    pub flush_epoch: u64,
    pub version: u64,
}

pub struct StorageEngine {
    shards: Vec<CachePadded<RwLock<Shard>>>,
    shard_mask: usize,
    tx_exec_fence: CachePadded<RwLock<()>>,
    lsm: Mutex<Option<Arc<LsmEngine>>>,
    boot_instant: Instant,
    boot_unix_ms: u64,
    lazy_expired_count: CachePadded<AtomicU64>,
    active_expired_count: CachePadded<AtomicU64>,
}

impl StorageEngine {
    pub fn new(requested_shards: usize) -> EngineResult<Arc<Self>> {
        let shard_count = requested_shards.max(2).next_power_of_two();
        let mut shards = Vec::with_capacity(shard_count);
        for idx in 0..shard_count {
            shards.push(CachePadded::new(RwLock::new(Shard::new(idx))));
        }
        let boot_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        Ok(Arc::new(Self {
            shards,
            shard_mask: shard_count - 1,
            tx_exec_fence: CachePadded::new(RwLock::new(())),
            lsm: Mutex::new(None),
            boot_instant: Instant::now(),
            boot_unix_ms,
            lazy_expired_count: CachePadded::new(AtomicU64::new(0)),
            active_expired_count: CachePadded::new(AtomicU64::new(0)),
        }))
    }

    pub fn attach_lsm(&self, dir: impl AsRef<Path>, flush_bytes: usize) -> EngineResult<()> {
        let engine = Arc::new(LsmEngine::open(dir, flush_bytes)?);
        let mut guard = self
            .lsm
            .lock()
            .map_err(|_| EngineError::LockPoisoned("storage lsm holder"))?;
        *guard = Some(engine);
        Ok(())
    }

    pub fn lsm_engine(&self) -> EngineResult<Arc<LsmEngine>> {
        let mut guard = self
            .lsm
            .lock()
            .map_err(|_| EngineError::LockPoisoned("storage lsm holder"))?;
        if let Some(ref arc) = *guard {
            return Ok(Arc::clone(arc));
        }
        let default_dir = std::env::temp_dir().join(format!("ferrum_lsm_{}", std::process::id()));
        let created = Arc::new(LsmEngine::open(default_dir, 64 * 1024)?);
        *guard = Some(Arc::clone(&created));
        Ok(created)
    }

    pub fn lsm_sstable_count(&self) -> usize {
        if let Ok(guard) = self.lsm.lock() {
            if let Some(ref lsm) = *guard {
                if let Ok((_, sst, _)) = lsm.stats() {
                    return sst;
                }
            }
        }
        0
    }

    #[inline]
    pub fn tx_shared_guard(&self) -> EngineResult<std::sync::RwLockReadGuard<'_, ()>> {
        self.tx_exec_fence
            .read()
            .map_err(|_| EngineError::LockPoisoned("tx_exec_fence read"))
    }

    #[inline]
    pub fn tx_exclusive_guard(&self) -> EngineResult<RwLockWriteGuard<'_, ()>> {
        self.tx_exec_fence
            .write()
            .map_err(|_| EngineError::LockPoisoned("tx_exec_fence write"))
    }

    /// Captures a key's current `(shard_idx, flush_epoch, key_version)` stamp for `WATCH`.
    pub fn watch_stamp(&self, key: &[u8]) -> EngineResult<WatchedKeyStamp> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;
        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }
        let version = guard.register_watch(key);
        Ok(WatchedKeyStamp {
            key: key.to_vec().into_boxed_slice(),
            shard_idx: idx,
            flush_epoch: guard.flush_epoch(),
            version,
        })
    }

    /// Deadlock-free multi-shard lock acquisition (sorted by ascending `shard_idx`) verifying all `WATCH` epochs.
    pub fn verify_watched_stamps_sorted(&self, stamps: &[WatchedKeyStamp]) -> EngineResult<bool> {
        if stamps.is_empty() {
            return Ok(true);
        }
        let mut shard_ids: Vec<usize> = stamps.iter().map(|s| s.shard_idx).collect();
        shard_ids.sort_unstable();
        shard_ids.dedup();

        // Acquire write locks in strictly ascending shard index order to prevent AB-BA deadlocks.
        let mut guards: Vec<(usize, RwLockWriteGuard<'_, Shard>)> =
            Vec::with_capacity(shard_ids.len());
        for sid in shard_ids {
            guards.push((sid, self.write_shard(sid)?));
        }

        let now = Instant::now();
        for stamp in stamps {
            let Ok(pos) = guards.binary_search_by_key(&stamp.shard_idx, |(sid, _)| *sid) else {
                return Ok(false);
            };
            let shard = &mut guards[pos].1;
            if let Some(rec) = shard.table.get(&stamp.key) {
                if rec.is_expired(now) {
                    shard.remove_key(&stamp.key);
                    self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }
            if shard.flush_epoch() != stamp.flush_epoch
                || shard.key_version(&stamp.key) != stamp.version
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[inline]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    #[inline]
    pub fn lazy_expired_total(&self) -> u64 {
        self.lazy_expired_count.load(AtomicOrdering::Relaxed)
    }

    #[inline]
    pub fn active_expired_total(&self) -> u64 {
        self.active_expired_count.load(AtomicOrdering::Relaxed)
    }

    #[inline]
    pub fn now_unix_ms(&self) -> u64 {
        self.boot_unix_ms
            .saturating_add(self.boot_instant.elapsed().as_millis() as u64)
    }

    #[inline]
    pub fn instant_to_unix_ms(&self, instant: Instant) -> u64 {
        if instant <= self.boot_instant {
            let diff = self.boot_instant.duration_since(instant).as_millis() as u64;
            self.boot_unix_ms.saturating_sub(diff)
        } else {
            let diff = instant.duration_since(self.boot_instant).as_millis() as u64;
            self.boot_unix_ms.saturating_add(diff)
        }
    }

    #[inline]
    pub fn unix_ms_to_instant(&self, target_unix_ms: u64) -> Option<Instant> {
        let current_ms = self.now_unix_ms();
        if target_unix_ms <= current_ms {
            None
        } else {
            Some(Instant::now() + Duration::from_millis(target_unix_ms - current_ms))
        }
    }

    #[inline]
    pub fn shard_index(&self, key: &[u8]) -> usize {
        let h = fnv1a_64(key) ^ siphash24(0x243f_6a88_85a3_08d3, 0x1319_8a2e_0370_7344, key);
        ((h >> 32) as usize ^ (h as usize)) & self.shard_mask
    }

    #[inline]
    fn read_shard(&self, idx: usize) -> EngineResult<std::sync::RwLockReadGuard<'_, Shard>> {
        self.shards[idx]
            .read()
            .map_err(|_| EngineError::LockPoisoned("storage shard read lock"))
    }

    #[inline]
    fn write_shard(&self, idx: usize) -> EngineResult<RwLockWriteGuard<'_, Shard>> {
        self.shards[idx]
            .write()
            .map_err(|_| EngineError::LockPoisoned("storage shard write lock"))
    }

    fn evict_if_expired(&self, shard_idx: usize, key: &[u8], now: Instant) -> EngineResult<()> {
        let mut guard = self.write_shard(shard_idx)?;
        let expired = guard
            .table
            .get(key)
            .map(|rec| rec.is_expired(now))
            .unwrap_or(false);
        if expired {
            guard.remove_key(key);
            self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
        }
        Ok(())
    }

    // ==================== STRING COMMANDS ====================

    pub fn get_bytes(&self, key: &[u8]) -> EngineResult<Option<Box<[u8]>>> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(None),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::String(bytes) => return Ok(Some(bytes.clone())),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "string",
                            actual: other.type_name(),
                        });
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(None)
    }

    pub fn get_into(&self, key: &[u8], out: &mut Vec<u8>) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let mut expired_at = None;
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_null(out);
                    return Ok(());
                }
                Some(rec) => {
                    let is_exp = if rec.expires_at.is_some() {
                        let now = Instant::now();
                        if rec.is_expired(now) {
                            expired_at = Some(now);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !is_exp {
                        match &rec.value {
                            DataValue::String(bytes) => {
                                write_bulk_string(out, bytes);
                                return Ok(());
                            }
                            other => {
                                return Err(EngineError::WrongType {
                                    expected: "string",
                                    actual: other.type_name(),
                                });
                            }
                        }
                    }
                }
            }
        }
        if let Some(now) = expired_at {
            self.evict_if_expired(idx, key, now)?;
        }
        write_null(out);
        Ok(())
    }

    pub fn set(
        &self,
        key: &[u8],
        val: &[u8],
        ttl: Option<Duration>,
        cond: SetCondition,
    ) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let mut guard = self.write_shard(idx)?;
        let now = if ttl.is_some() || guard.expiring_keys > 0 {
            Some(Instant::now())
        } else {
            None
        };
        let expires_at = match (ttl, now) {
            (Some(d), Some(n)) => Some(n + d),
            _ => None,
        };

        let next_ver = guard.next_version;
        if let Some(rec) = guard.table.get_mut(key) {
            let is_exp = match (rec.expires_at, now) {
                (Some(dl), Some(n)) => n >= dl,
                _ => false,
            };
            if is_exp {
                if matches!(cond, SetCondition::IfPresent) {
                    guard.remove_key(key);
                    self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                    return Ok(false);
                }
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            } else if matches!(cond, SetCondition::IfAbsent) {
                return Ok(false);
            }

            let prev_has_ttl = rec.expires_at.is_some();
            let new_has_ttl = expires_at.is_some();
            match &mut rec.value {
                DataValue::String(existing) if existing.len() == val.len() => {
                    existing.copy_from_slice(val);
                }
                slot => {
                    *slot = DataValue::String(val.to_vec().into_boxed_slice());
                }
            }
            rec.expires_at = expires_at;
            rec.version = next_ver;
            guard.next_version = next_ver.wrapping_add(1);
            if prev_has_ttl && !new_has_ttl {
                guard.expiring_keys = guard.expiring_keys.saturating_sub(1);
            } else if !prev_has_ttl && new_has_ttl {
                guard.expiring_keys += 1;
            }
            return Ok(true);
        }
        if matches!(cond, SetCondition::IfPresent) {
            return Ok(false);
        }
        let record = Record {
            value: DataValue::String(val.to_vec().into_boxed_slice()),
            expires_at,
            version: 0,
        };
        guard.upsert_record(key.to_vec().into_boxed_slice(), record);
        Ok(true)
    }

    pub fn put_raw_value(
        &self,
        key: &[u8],
        value: DataValue,
        expire_unix_ms: Option<u64>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let expires_at = match expire_unix_ms {
            None | Some(0) => None,
            Some(ms) => match self.unix_ms_to_instant(ms) {
                Some(dl) => Some(dl),
                None => return Ok(()),
            },
        };
        let mut guard = self.write_shard(idx)?;
        guard.upsert_record(
            key.to_vec().into_boxed_slice(),
            Record {
                value,
                expires_at,
                version: 0,
            },
        );
        Ok(())
    }

    pub fn incr_by(&self, key: &[u8], delta: i64) -> EngineResult<i64> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        match guard.table.get_mut(key) {
            None => {
                let mut formatted = Vec::with_capacity(20);
                crate::resp::write_i64_decimal(&mut formatted, delta);
                guard.upsert_record(
                    key.to_vec().into_boxed_slice(),
                    Record {
                        value: DataValue::String(formatted.into_boxed_slice()),
                        expires_at: None,
                        version: 0,
                    },
                );
                Ok(delta)
            }
            Some(rec) => match &mut rec.value {
                DataValue::String(bytes) => {
                    let current = parse_i64_bytes(bytes)?;
                    let next = current.checked_add(delta).ok_or_else(|| {
                        EngineError::InvalidArgument(
                            "increment or decrement would overflow".to_string(),
                        )
                    })?;
                    let mut formatted = Vec::with_capacity(20);
                    crate::resp::write_i64_decimal(&mut formatted, next);
                    *bytes = formatted.into_boxed_slice();
                    guard.bump_version(key);
                    Ok(next)
                }
                other => Err(EngineError::WrongType {
                    expected: "string",
                    actual: other.type_name(),
                }),
            },
        }
    }

    pub fn append(&self, key: &[u8], suffix: &[u8]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        match guard.table.get_mut(key) {
            None => {
                let len = suffix.len();
                guard.upsert_record(
                    key.to_vec().into_boxed_slice(),
                    Record {
                        value: DataValue::String(suffix.to_vec().into_boxed_slice()),
                        expires_at: None,
                        version: 0,
                    },
                );
                Ok(len)
            }
            Some(rec) => match &mut rec.value {
                DataValue::String(bytes) => {
                    let mut combined = Vec::with_capacity(bytes.len() + suffix.len());
                    combined.extend_from_slice(bytes);
                    combined.extend_from_slice(suffix);
                    let total = combined.len();
                    *bytes = combined.into_boxed_slice();
                    guard.bump_version(key);
                    Ok(total)
                }
                other => Err(EngineError::WrongType {
                    expected: "string",
                    actual: other.type_name(),
                }),
            },
        }
    }

    pub fn strlen(&self, key: &[u8]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(0),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::String(b) => return Ok(b.len()),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "string",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(0)
    }

    // ==================== GENERIC KEY & TTL COMMANDS ====================

    pub fn del(&self, keys: &[&[u8]]) -> EngineResult<usize> {
        let now = Instant::now();
        let mut deleted = 0usize;
        for &key in keys {
            let idx = self.shard_index(key);
            let mut guard = self.write_shard(idx)?;
            if let Some(rec) = guard.remove_key(key) {
                if !rec.is_expired(now) {
                    deleted += 1;
                } else {
                    self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }
        }
        Ok(deleted)
    }

    pub fn exists(&self, keys: &[&[u8]]) -> EngineResult<usize> {
        let now = Instant::now();
        let mut count = 0usize;
        for &key in keys {
            let idx = self.shard_index(key);
            let expired = {
                let guard = self.read_shard(idx)?;
                match guard.table.get(key) {
                    None => false,
                    Some(rec) if !rec.is_expired(now) => {
                        count += 1;
                        false
                    }
                    Some(_) => true,
                }
            };
            if expired {
                self.evict_if_expired(idx, key, now)?;
            }
        }
        Ok(count)
    }

    pub fn key_type(&self, key: &[u8]) -> EngineResult<&'static str> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok("none"),
                Some(rec) if !rec.is_expired(now) => return Ok(rec.value.type_name()),
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok("none")
    }

    pub fn pexpire(&self, key: &[u8], ttl_ms: i64) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        let Some(rec) = guard.table.get_mut(key) else {
            return Ok(false);
        };
        if rec.is_expired(now) {
            guard.remove_key(key);
            self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            return Ok(false);
        }
        if ttl_ms <= 0 {
            guard.remove_key(key);
            return Ok(true);
        }
        let had_ttl = rec.expires_at.is_some();
        rec.expires_at = Some(now + Duration::from_millis(ttl_ms as u64));
        if !had_ttl {
            guard.expiring_keys += 1;
        }
        guard.bump_version(key);
        Ok(true)
    }

    pub fn pexpire_at_unix_ms(&self, key: &[u8], target_unix_ms: u64) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        let Some(rec) = guard.table.get_mut(key) else {
            return Ok(false);
        };
        if rec.is_expired(now) {
            guard.remove_key(key);
            self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            return Ok(false);
        }
        match self.unix_ms_to_instant(target_unix_ms) {
            None => {
                guard.remove_key(key);
                Ok(true)
            }
            Some(deadline) => {
                let had_ttl = rec.expires_at.is_some();
                rec.expires_at = Some(deadline);
                if !had_ttl {
                    guard.expiring_keys += 1;
                }
                guard.bump_version(key);
                Ok(true)
            }
        }
    }

    pub fn pttl(&self, key: &[u8]) -> EngineResult<i64> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(-2),
                Some(rec) if !rec.is_expired(now) => {
                    return Ok(match rec.expires_at {
                        None => -1,
                        Some(deadline) => {
                            deadline.saturating_duration_since(now).as_millis() as i64
                        }
                    });
                }
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(-2)
    }

    pub fn persist(&self, key: &[u8]) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;
        let Some(rec) = guard.table.get_mut(key) else {
            return Ok(false);
        };
        if rec.is_expired(now) {
            guard.remove_key(key);
            self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            return Ok(false);
        }
        if rec.expires_at.take().is_some() {
            guard.expiring_keys = guard.expiring_keys.saturating_sub(1);
            guard.bump_version(key);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn dbsize(&self) -> EngineResult<usize> {
        let now = Instant::now();
        let mut total = 0usize;
        for idx in 0..self.shards.len() {
            let guard = self.read_shard(idx)?;
            for (_, rec) in guard.table.iter() {
                if !rec.is_expired(now) {
                    total += 1;
                }
            }
        }
        Ok(total)
    }

    pub fn flushdb(&self) -> EngineResult<()> {
        for idx in 0..self.shards.len() {
            let mut guard = self.write_shard(idx)?;
            guard.table.clear();
            guard.key_versions.clear();
            guard.flush_epoch = guard.flush_epoch.wrapping_add(1);
            guard.expiring_keys = 0;
            guard.sweep_cursor = 0;
        }
        Ok(())
    }

    pub fn keys_into(&self, pattern: &[u8], out: &mut Vec<u8>) -> EngineResult<()> {
        let now = Instant::now();
        let mut matched: Vec<Box<[u8]>> = Vec::new();
        for idx in 0..self.shards.len() {
            let guard = self.read_shard(idx)?;
            for (k, rec) in guard.table.iter() {
                if !rec.is_expired(now) && glob_match(pattern, k) {
                    matched.push(k.to_vec().into_boxed_slice());
                }
            }
        }
        write_array_header(out, matched.len());
        for k in matched {
            write_bulk_string(out, &k);
        }
        Ok(())
    }

    // ==================== LIST COMMANDS ====================

    pub fn list_push(&self, key: &[u8], values: &[&[u8]], front: bool) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        if let Some(rec) = guard.table.get_mut(key) {
            let len = match &mut rec.value {
                DataValue::List(list) => {
                    for &v in values {
                        let boxed = v.to_vec().into_boxed_slice();
                        if front {
                            list.push_front(boxed);
                        } else {
                            list.push_back(boxed);
                        }
                    }
                    list.len()
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "list",
                        actual: other.type_name(),
                    })
                }
            };
            guard.bump_version(key);
            Ok(len)
        } else {
            let mut list = RingList::with_capacity(values.len());
            for &v in values {
                let boxed = v.to_vec().into_boxed_slice();
                if front {
                    list.push_front(boxed);
                } else {
                    list.push_back(boxed);
                }
            }
            let len = list.len();
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::List(list),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(len)
        }
    }

    pub fn list_pop(&self, key: &[u8], front: bool) -> EngineResult<Option<Box<[u8]>>> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                return Ok(None);
            }
        }

        let mut remove_empty = false;
        let popped = match guard.table.get_mut(key) {
            None => None,
            Some(rec) => match &mut rec.value {
                DataValue::List(list) => {
                    let item = if front { list.pop_front() } else { list.pop_back() };
                    remove_empty = list.is_empty();
                    item
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "list",
                        actual: other.type_name(),
                    })
                }
            },
        };
        if remove_empty {
            guard.remove_key(key);
        } else if popped.is_some() {
            guard.bump_version(key);
        }
        Ok(popped)
    }

    pub fn llen(&self, key: &[u8]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(0),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::List(list) => return Ok(list.len()),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "list",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(0)
    }

    pub fn lindex_into(&self, key: &[u8], index: i64, out: &mut Vec<u8>) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_null(out);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::List(list) => {
                        match list.get(index) {
                            Some(val) => write_bulk_string(out, val),
                            None => write_null(out),
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "list",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_null(out);
        Ok(())
    }

    pub fn lrange_into(
        &self,
        key: &[u8],
        start: i64,
        stop: i64,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::List(list) => {
                        let items = list.range(start, stop);
                        write_array_header(out, items.len());
                        for item in items {
                            write_bulk_string(out, item);
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "list",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    // ==================== HASH COMMANDS ====================

    pub fn hset(&self, key: &[u8], pairs: &[(&[u8], &[u8])]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        let mut newly_added = 0usize;
        if let Some(rec) = guard.table.get_mut(key) {
            match &mut rec.value {
                DataValue::Hash(map) => {
                    for &(field, val) in pairs {
                        if map
                            .insert(
                                field.to_vec().into_boxed_slice(),
                                val.to_vec().into_boxed_slice(),
                            )
                            .is_none()
                        {
                            newly_added += 1;
                        }
                    }
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "hash",
                        actual: other.type_name(),
                    })
                }
            }
            guard.bump_version(key);
            Ok(newly_added)
        } else {
            let mut map = RawHashTable::with_capacity_and_seeds(
                pairs.len().max(8),
                0xa076_1d64_78bd_642f,
                0xe703_7ed1_a0b4_28db,
            );
            for &(field, val) in pairs {
                if map
                    .insert(
                        field.to_vec().into_boxed_slice(),
                        val.to_vec().into_boxed_slice(),
                    )
                    .is_none()
                {
                    newly_added += 1;
                }
            }
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::Hash(map),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(newly_added)
        }
    }

    pub fn hget_into(&self, key: &[u8], field: &[u8], out: &mut Vec<u8>) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_null(out);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::Hash(map) => {
                        match map.get(field) {
                            Some(val) => write_bulk_string(out, val),
                            None => write_null(out),
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "hash",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_null(out);
        Ok(())
    }

    pub fn hdel(&self, key: &[u8], fields: &[&[u8]]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                return Ok(0);
            }
        }

        let mut removed = 0usize;
        let mut empty_after = false;
        if let Some(rec) = guard.table.get_mut(key) {
            match &mut rec.value {
                DataValue::Hash(map) => {
                    for &f in fields {
                        if map.remove(f).is_some() {
                            removed += 1;
                        }
                    }
                    empty_after = map.is_empty();
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "hash",
                        actual: other.type_name(),
                    })
                }
            }
        }
        if empty_after {
            guard.remove_key(key);
        } else if removed > 0 {
            guard.bump_version(key);
        }
        Ok(removed)
    }

    pub fn hlen(&self, key: &[u8]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(0),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::Hash(map) => return Ok(map.len()),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "hash",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(0)
    }

    pub fn hgetall_into(&self, key: &[u8], out: &mut Vec<u8>) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_map_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::Hash(map) => {
                        write_map_header(out, map.len());
                        for (field, val) in map.iter() {
                            write_bulk_string(out, field);
                            write_bulk_string(out, val);
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "hash",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_map_header(out, 0);
        Ok(())
    }

    // ==================== SORTED SET & GEOSPATIAL COMMANDS ====================

    pub fn zadd(&self, key: &[u8], entries: &[(f64, &[u8])]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        let mut added = 0usize;
        if let Some(rec) = guard.table.get_mut(key) {
            match &mut rec.value {
                DataValue::SortedSet(zset) => {
                    for &(score, member) in entries {
                        if zset.zadd(score, member.to_vec().into_boxed_slice()) {
                            added += 1;
                        }
                    }
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "zset",
                        actual: other.type_name(),
                    })
                }
            }
            guard.bump_version(key);
            Ok(added)
        } else {
            let mut zset = SortedSet::new();
            for &(score, member) in entries {
                if zset.zadd(score, member.to_vec().into_boxed_slice()) {
                    added += 1;
                }
            }
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::SortedSet(zset),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(added)
        }
    }

    pub fn zrem(&self, key: &[u8], members: &[&[u8]]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                return Ok(0);
            }
        }

        let mut removed = 0usize;
        let mut empty_after = false;
        if let Some(rec) = guard.table.get_mut(key) {
            match &mut rec.value {
                DataValue::SortedSet(zset) => {
                    for &m in members {
                        if zset.zrem(m) {
                            removed += 1;
                        }
                    }
                    empty_after = zset.is_empty();
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "zset",
                        actual: other.type_name(),
                    })
                }
            }
        }
        if empty_after {
            guard.remove_key(key);
        } else if removed > 0 {
            guard.bump_version(key);
        }
        Ok(removed)
    }

    pub fn zscore_into(&self, key: &[u8], member: &[u8], out: &mut Vec<u8>) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_null(out);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::SortedSet(zset) => {
                        match zset.zscore(member) {
                            Some(score) => write_double(out, score),
                            None => write_null(out),
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "zset",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_null(out);
        Ok(())
    }

    pub fn zcard(&self, key: &[u8]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(0),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::SortedSet(zset) => return Ok(zset.len()),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "zset",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(0)
    }

    pub fn zrank(&self, key: &[u8], member: &[u8]) -> EngineResult<Option<usize>> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(None),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::SortedSet(zset) => return Ok(zset.zrank(member)),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "zset",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(None)
    }

    pub fn zrange_into(
        &self,
        key: &[u8],
        start: i64,
        stop: i64,
        with_scores: bool,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::SortedSet(zset) => {
                        let items = zset.zrange(start, stop);
                        if with_scores {
                            write_array_header(out, items.len() * 2);
                            for (mem, score) in items {
                                write_bulk_string(out, mem);
                                write_double(out, score);
                            }
                        } else {
                            write_array_header(out, items.len());
                            for (mem, _) in items {
                                write_bulk_string(out, mem);
                            }
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "zset",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    pub fn zrange_by_score_into(
        &self,
        key: &[u8],
        min_score: f64,
        max_score: f64,
        with_scores: bool,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::SortedSet(zset) => {
                        let items = zset.zrange_by_score(min_score, max_score);
                        if with_scores {
                            write_array_header(out, items.len() * 2);
                            for (mem, score) in items {
                                write_bulk_string(out, mem);
                                write_double(out, score);
                            }
                        } else {
                            write_array_header(out, items.len());
                            for (mem, _) in items {
                                write_bulk_string(out, mem);
                            }
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "zset",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    pub fn geoadd(&self, key: &[u8], items: &[(f64, f64, &[u8])]) -> EngineResult<usize> {
        let mut zentries = Vec::with_capacity(items.len());
        for &(lon, lat, member) in items {
            let hash52 = geohash_encode_52bit(lon, lat)?;
            zentries.push((hash52 as f64, member));
        }
        self.zadd(key, &zentries)
    }

    pub fn geopos_into(&self, key: &[u8], members: &[&[u8]], out: &mut Vec<u8>) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, members.len());
                    for _ in members {
                        write_null(out);
                    }
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::SortedSet(zset) => {
                        write_array_header(out, members.len());
                        for &m in members {
                            match zset.zscore(m) {
                                Some(score) => {
                                    let (lon, lat) = geohash_decode_52bit(score as u64);
                                    write_array_header(out, 2);
                                    write_double(out, lon);
                                    write_double(out, lat);
                                }
                                None => write_null(out),
                            }
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "zset",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, members.len());
        for _ in members {
            write_null(out);
        }
        Ok(())
    }

    pub fn geodist_into(
        &self,
        key: &[u8],
        m1: &[u8],
        m2: &[u8],
        unit: GeoUnit,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_null(out);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::SortedSet(zset) => {
                        match (zset.zscore(m1), zset.zscore(m2)) {
                            (Some(s1), Some(s2)) => {
                                let (lon1, lat1) = geohash_decode_52bit(s1 as u64);
                                let (lon2, lat2) = geohash_decode_52bit(s2 as u64);
                                let dist_m = haversine_meters(lon1, lat1, lon2, lat2);
                                write_double(out, unit.from_meters(dist_m));
                            }
                            _ => write_null(out),
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "zset",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_null(out);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn georadius_into(
        &self,
        key: &[u8],
        lon: f64,
        lat: f64,
        radius: f64,
        unit: GeoUnit,
        with_dist: bool,
        with_coord: bool,
        ascending: bool,
        count: Option<usize>,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::SortedSet(zset) => {
                        let hits =
                            georadius_query(zset, lon, lat, radius, unit, ascending, count)?;
                        write_array_header(out, hits.len());
                        for m in hits {
                            if !with_dist && !with_coord {
                                write_bulk_string(out, &m.member);
                            } else {
                                let cols =
                                    1 + usize::from(with_dist) + usize::from(with_coord);
                                write_array_header(out, cols);
                                write_bulk_string(out, &m.member);
                                if with_dist {
                                    write_double(out, m.dist_unit);
                                }
                                if with_coord {
                                    write_array_header(out, 2);
                                    write_double(out, m.lon);
                                    write_double(out, m.lat);
                                }
                            }
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "zset",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    // ==================== REDIS STREAMS & CONSUMER GROUPS ====================

    pub fn xadd(
        &self,
        key: &[u8],
        id_spec: &[u8],
        pairs: &[(&[u8], &[u8])],
    ) -> EngineResult<StreamId> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        if let Some(rec) = guard.table.get_mut(key) {
            let id = match &mut rec.value {
                DataValue::Stream(stream) => stream.xadd(id_spec, pairs)?,
                other => {
                    return Err(EngineError::WrongType {
                        expected: "stream",
                        actual: other.type_name(),
                    })
                }
            };
            guard.bump_version(key);
            Ok(id)
        } else {
            let mut stream = StreamLog::new();
            let id = stream.xadd(id_spec, pairs)?;
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::Stream(stream),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(id)
        }
    }

    pub fn xlen(&self, key: &[u8]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(0),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::Stream(s) => return Ok(s.len()),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "stream",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(0)
    }

    pub fn xrange_into(
        &self,
        key: &[u8],
        start: StreamId,
        end: StreamId,
        count: Option<usize>,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::Stream(s) => {
                        let entries = s.xrange(start, end, count);
                        write_stream_entries_slice(&entries, out);
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "stream",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    pub fn xread_into(
        &self,
        streams: &[(&[u8], StreamId)],
        count: Option<usize>,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let now = Instant::now();
        let mut results: Vec<(&[u8], Vec<StreamEntry>)> = Vec::new();

        for &(key, after_id) in streams {
            let idx = self.shard_index(key);
            let expired = {
                let guard = self.read_shard(idx)?;
                match guard.table.get(key) {
                    None => false,
                    Some(rec) if !rec.is_expired(now) => {
                        match &rec.value {
                            DataValue::Stream(s) => {
                                let entries: Vec<StreamEntry> =
                                    s.xread_after(after_id, count).into_iter().cloned().collect();
                                if !entries.is_empty() {
                                    results.push((key, entries));
                                }
                            }
                            other => {
                                return Err(EngineError::WrongType {
                                    expected: "stream",
                                    actual: other.type_name(),
                                })
                            }
                        }
                        false
                    }
                    Some(_) => true,
                }
            };
            if expired {
                self.evict_if_expired(idx, key, now)?;
            }
        }

        if results.is_empty() {
            write_null(out);
            return Ok(());
        }
        write_array_header(out, results.len());
        for (key, entries) in results {
            write_array_header(out, 2);
            write_bulk_string(out, key);
            let refs: Vec<&StreamEntry> = entries.iter().collect();
            write_stream_entries_slice(&refs, out);
        }
        Ok(())
    }

    pub fn xgroup_create(
        &self,
        key: &[u8],
        group_name: &[u8],
        start_spec: &[u8],
        mkstream: bool,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        if let Some(rec) = guard.table.get_mut(key) {
            match &mut rec.value {
                DataValue::Stream(s) => s.create_group(group_name, start_spec)?,
                other => {
                    return Err(EngineError::WrongType {
                        expected: "stream",
                        actual: other.type_name(),
                    })
                }
            }
            guard.bump_version(key);
            Ok(())
        } else if mkstream {
            let mut s = StreamLog::new();
            s.create_group(group_name, start_spec)?;
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::Stream(s),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(())
        } else {
            Err(EngineError::InvalidArgument(
                "The XGROUP subcommand requires the key to exist (or specify MKSTREAM)".to_string(),
            ))
        }
    }

    pub fn xreadgroup_into(
        &self,
        group: &[u8],
        consumer: &[u8],
        streams: &[(&[u8], &[u8])],
        count: Option<usize>,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let now = Instant::now();
        let mut results: Vec<(&[u8], Vec<StreamEntry>)> = Vec::new();

        for &(key, id_spec) in streams {
            let idx = self.shard_index(key);
            let mut guard = self.write_shard(idx)?;
            if let Some(rec) = guard.table.get(key) {
                if rec.is_expired(now) {
                    guard.remove_key(key);
                    self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                }
            }
            let Some(rec) = guard.table.get_mut(key) else {
                return Err(EngineError::InvalidArgument(
                    "NOGROUP No such key or consumer group".to_string(),
                ));
            };
            let entries = match &mut rec.value {
                DataValue::Stream(s) => s.xreadgroup(group, consumer, id_spec, count)?,
                other => {
                    return Err(EngineError::WrongType {
                        expected: "stream",
                        actual: other.type_name(),
                    })
                }
            };
            if !entries.is_empty() {
                guard.bump_version(key);
                results.push((key, entries));
            }
        }

        if results.is_empty() {
            write_null(out);
            return Ok(());
        }
        write_array_header(out, results.len());
        for (key, entries) in results {
            write_array_header(out, 2);
            write_bulk_string(out, key);
            let refs: Vec<&StreamEntry> = entries.iter().collect();
            write_stream_entries_slice(&refs, out);
        }
        Ok(())
    }

    pub fn xack(&self, key: &[u8], group: &[u8], ids: &[StreamId]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                return Ok(0);
            }
        }

        let Some(rec) = guard.table.get_mut(key) else {
            return Ok(0);
        };
        let acked = match &mut rec.value {
            DataValue::Stream(s) => s.xack(group, ids)?,
            other => {
                return Err(EngineError::WrongType {
                    expected: "stream",
                    actual: other.type_name(),
                })
            }
        };
        if acked > 0 {
            guard.bump_version(key);
        }
        Ok(acked)
    }

    // ==================== PROBABILISTIC (HLL / BLOOM / CMS) ====================

    pub fn pfadd(&self, key: &[u8], elements: &[&[u8]]) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        if let Some(rec) = guard.table.get_mut(key) {
            let mut altered = false;
            match &mut rec.value {
                DataValue::HyperLogLog(hll) => {
                    for &el in elements {
                        if hll.add(el) {
                            altered = true;
                        }
                    }
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "hyperloglog",
                        actual: other.type_name(),
                    })
                }
            }
            if altered {
                guard.bump_version(key);
            }
            Ok(altered)
        } else {
            let mut hll = HyperLogLog::new();
            for &el in elements {
                hll.add(el);
            }
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::HyperLogLog(hll),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(true)
        }
    }

    pub fn pfcount(&self, keys: &[&[u8]]) -> EngineResult<u64> {
        if keys.len() == 1 {
            let key = keys[0];
            let idx = self.shard_index(key);
            let now = Instant::now();
            {
                let guard = self.read_shard(idx)?;
                match guard.table.get(key) {
                    None => return Ok(0),
                    Some(rec) if !rec.is_expired(now) => match &rec.value {
                        DataValue::HyperLogLog(hll) => return Ok(hll.count()),
                        other => {
                            return Err(EngineError::WrongType {
                                expected: "hyperloglog",
                                actual: other.type_name(),
                            })
                        }
                    },
                    Some(_) => {}
                }
            }
            self.evict_if_expired(idx, key, now)?;
            return Ok(0);
        }

        let mut merged = HyperLogLog::new();
        let now = Instant::now();
        for &key in keys {
            let idx = self.shard_index(key);
            let expired = {
                let guard = self.read_shard(idx)?;
                match guard.table.get(key) {
                    None => false,
                    Some(rec) if !rec.is_expired(now) => {
                        match &rec.value {
                            DataValue::HyperLogLog(hll) => {
                                merged.merge_from(hll);
                            }
                            other => {
                                return Err(EngineError::WrongType {
                                    expected: "hyperloglog",
                                    actual: other.type_name(),
                                })
                            }
                        }
                        false
                    }
                    Some(_) => true,
                }
            };
            if expired {
                self.evict_if_expired(idx, key, now)?;
            }
        }
        Ok(merged.count())
    }

    pub fn pfmerge(&self, dest_key: &[u8], source_keys: &[&[u8]]) -> EngineResult<()> {
        let mut acc = HyperLogLog::new();
        let now = Instant::now();

        for &key in std::iter::once(&dest_key).chain(source_keys.iter()) {
            let idx = self.shard_index(key);
            let expired = {
                let guard = self.read_shard(idx)?;
                match guard.table.get(key) {
                    None => false,
                    Some(rec) if !rec.is_expired(now) => {
                        match &rec.value {
                            DataValue::HyperLogLog(hll) => {
                                acc.merge_from(hll);
                            }
                            other => {
                                return Err(EngineError::WrongType {
                                    expected: "hyperloglog",
                                    actual: other.type_name(),
                                })
                            }
                        }
                        false
                    }
                    Some(_) => true,
                }
            };
            if expired {
                self.evict_if_expired(idx, key, now)?;
            }
        }

        let dest_idx = self.shard_index(dest_key);
        let mut guard = self.write_shard(dest_idx)?;
        let prev_exp = guard
            .table
            .get(dest_key)
            .and_then(|r| if r.is_expired(now) { None } else { r.expires_at });
        guard.upsert_record(
            dest_key.to_vec().into_boxed_slice(),
            Record {
                value: DataValue::HyperLogLog(acc),
                expires_at: prev_exp,
                version: 0,
            },
        );
        Ok(())
    }

    pub fn bf_add(&self, key: &[u8], item: &[u8]) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        if let Some(rec) = guard.table.get_mut(key) {
            let changed = match &mut rec.value {
                DataValue::BloomFilter(bf) => bf.add(item),
                other => {
                    return Err(EngineError::WrongType {
                        expected: "MBbloom--",
                        actual: other.type_name(),
                    })
                }
            };
            if changed {
                guard.bump_version(key);
            }
            Ok(changed)
        } else {
            let mut bf = BloomFilter::default();
            bf.add(item);
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::BloomFilter(bf),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(true)
        }
    }

    pub fn bf_exists(&self, key: &[u8], item: &[u8]) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(false),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::BloomFilter(bf) => return Ok(bf.exists(item)),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "MBbloom--",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(false)
    }

    pub fn cms_incrby(&self, key: &[u8], increments: &[(&[u8], u64)]) -> EngineResult<Vec<u64>> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        let mut out = Vec::with_capacity(increments.len());
        if let Some(rec) = guard.table.get_mut(key) {
            match &mut rec.value {
                DataValue::CountMinSketch(cms) => {
                    for &(item, delta) in increments {
                        out.push(cms.incr_by(item, delta));
                    }
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "CMSketch",
                        actual: other.type_name(),
                    })
                }
            }
            guard.bump_version(key);
            Ok(out)
        } else {
            let mut cms = Box::new(CountMinSketch::new());
            for &(item, delta) in increments {
                out.push(cms.incr_by(item, delta));
            }
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::CountMinSketch(cms),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(out)
        }
    }

    pub fn cms_query(&self, key: &[u8], items: &[&[u8]]) -> EngineResult<Vec<u64>> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(vec![0u64; items.len()]),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::CountMinSketch(cms) => {
                        return Ok(items.iter().map(|&it| cms.query(it)).collect())
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "CMSketch",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(vec![0u64; items.len()])
    }

    // ==================== HNSW VECTOR INDEX ====================

    pub fn vadd(
        &self,
        key: &[u8],
        id: &[u8],
        vec: &[f32],
        metric: Option<VectorMetric>,
        sq8: Option<bool>,
    ) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        if let Some(rec) = guard.table.get_mut(key) {
            let added = match &mut rec.value {
                DataValue::VectorIndex(hnsw) => hnsw.upsert(id, vec, metric, sq8)?,
                other => {
                    return Err(EngineError::WrongType {
                        expected: "vector",
                        actual: other.type_name(),
                    })
                }
            };
            guard.bump_version(key);
            Ok(added)
        } else {
            let mut hnsw =
                HnswIndex::new(metric.unwrap_or(VectorMetric::Cosine), sq8.unwrap_or(true));
            let added = hnsw.upsert(id, vec, metric, sq8)?;
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::VectorIndex(hnsw),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(added)
        }
    }

    pub fn vsearch_into(
        &self,
        key: &[u8],
        query: &[f32],
        k: usize,
        ef: Option<usize>,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::VectorIndex(hnsw) => {
                        let hits = hnsw.search(query, k, ef)?;
                        write_array_header(out, hits.len() * 2);
                        for (id, score) in hits {
                            write_bulk_string(out, &id);
                            write_double(out, score);
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "vector",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    pub fn vcard(&self, key: &[u8]) -> EngineResult<usize> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => return Ok(0),
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::VectorIndex(hnsw) => return Ok(hnsw.len()),
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "vector",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        Ok(0)
    }

    pub fn vrem(&self, key: &[u8], id: &[u8]) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
                return Ok(false);
            }
        }

        let mut empty_after = false;
        let removed = match guard.table.get_mut(key) {
            None => false,
            Some(rec) => match &mut rec.value {
                DataValue::VectorIndex(hnsw) => {
                    let ok = hnsw.remove(id);
                    empty_after = hnsw.is_empty();
                    ok
                }
                other => {
                    return Err(EngineError::WrongType {
                        expected: "vector",
                        actual: other.type_name(),
                    })
                }
            },
        };
        if empty_after {
            guard.remove_key(key);
        } else if removed {
            guard.bump_version(key);
        }
        Ok(removed)
    }

    // ==================== BM25 FULL-TEXT SEARCH ====================

    pub fn ft_add(&self, key: &[u8], doc_id: &[u8], text: &str) -> EngineResult<bool> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        if let Some(rec) = guard.table.get_mut(key) {
            let added = match &mut rec.value {
                DataValue::FullTextIndex(fts) => fts.add_document(doc_id, text),
                other => {
                    return Err(EngineError::WrongType {
                        expected: "fts",
                        actual: other.type_name(),
                    })
                }
            };
            guard.bump_version(key);
            Ok(added)
        } else {
            let mut fts = FullTextIndex::new();
            let added = fts.add_document(doc_id, text);
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::FullTextIndex(fts),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(added)
        }
    }

    pub fn ft_search_into(
        &self,
        key: &[u8],
        query: &str,
        limit: usize,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::FullTextIndex(fts) => {
                        let hits = fts.search(query, limit);
                        write_array_header(out, hits.len() * 2);
                        for (doc_id, score) in hits {
                            write_bulk_string(out, &doc_id);
                            write_double(out, score);
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "fts",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    pub fn ft_sugg_into(
        &self,
        key: &[u8],
        prefix: &str,
        limit: usize,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::FullTextIndex(fts) => {
                        let suggestions = fts.suggest(prefix, limit);
                        write_array_header(out, suggestions.len());
                        for w in suggestions {
                            write_bulk_string(out, w.as_bytes());
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "fts",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    // ==================== GORILLA TIME-SERIES ====================

    pub fn ts_add(&self, key: &[u8], ts: i64, val: f64) -> EngineResult<i64> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        let mut guard = self.write_shard(idx)?;

        if let Some(rec) = guard.table.get(key) {
            if rec.is_expired(now) {
                guard.remove_key(key);
                self.lazy_expired_count.fetch_add(1, AtomicOrdering::Relaxed);
            }
        }

        if let Some(rec) = guard.table.get_mut(key) {
            match &mut rec.value {
                DataValue::TimeSeries(series) => series.append(ts, val)?,
                other => {
                    return Err(EngineError::WrongType {
                        expected: "timeseries",
                        actual: other.type_name(),
                    })
                }
            }
            guard.bump_version(key);
            Ok(ts)
        } else {
            let mut series = GorillaTimeSeries::new();
            series.append(ts, val)?;
            guard.upsert_record(
                key.to_vec().into_boxed_slice(),
                Record {
                    value: DataValue::TimeSeries(series),
                    expires_at: None,
                    version: 0,
                },
            );
            Ok(ts)
        }
    }

    pub fn ts_get_into(&self, key: &[u8], out: &mut Vec<u8>) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_null(out);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::TimeSeries(series) => {
                        match series.latest() {
                            Some((ts, val)) => {
                                write_array_header(out, 2);
                                write_integer(out, ts);
                                write_double(out, val);
                            }
                            None => write_null(out),
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "timeseries",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_null(out);
        Ok(())
    }

    pub fn ts_range_into(
        &self,
        key: &[u8],
        from_ts: i64,
        to_ts: i64,
        agg: Option<(TsAggregation, i64)>,
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let idx = self.shard_index(key);
        let now = Instant::now();
        {
            let guard = self.read_shard(idx)?;
            match guard.table.get(key) {
                None => {
                    write_array_header(out, 0);
                    return Ok(());
                }
                Some(rec) if !rec.is_expired(now) => match &rec.value {
                    DataValue::TimeSeries(series) => {
                        let pts = series.range_query(from_ts, to_ts, agg)?;
                        write_array_header(out, pts.len());
                        for (t, v) in pts {
                            write_array_header(out, 2);
                            write_integer(out, t);
                            write_double(out, v);
                        }
                        return Ok(());
                    }
                    other => {
                        return Err(EngineError::WrongType {
                            expected: "timeseries",
                            actual: other.type_name(),
                        })
                    }
                },
                Some(_) => {}
            }
        }
        self.evict_if_expired(idx, key, now)?;
        write_array_header(out, 0);
        Ok(())
    }

    // ==================== ACTIVE PROBABILISTIC TTL SWEEPER & SNAPSHOT ====================

    pub fn active_ttl_sweep_cycle(&self, time_budget: Duration) -> EngineResult<usize> {
        const SAMPLE_SLOTS: usize = 32;
        const REPEAT_THRESHOLD: usize = 5;

        let cycle_start = Instant::now();
        let mut total_evicted = 0usize;

        for shard_idx in 0..self.shards.len() {
            if cycle_start.elapsed() >= time_budget {
                break;
            }

            loop {
                let has_expiring = {
                    let guard = self.read_shard(shard_idx)?;
                    guard.expiring_keys > 0
                };
                if !has_expiring {
                    break;
                }

                let now = Instant::now();
                let mut guard = self.write_shard(shard_idx)?;
                if guard.expiring_keys == 0 {
                    break;
                }

                let mut cursor = guard.sweep_cursor;
                let expired_keys = guard
                    .table
                    .sample_keys(&mut cursor, SAMPLE_SLOTS, |_, rec| rec.is_expired(now));
                guard.sweep_cursor = cursor;

                let batch_count = expired_keys.len();
                for k in expired_keys {
                    guard.remove_key(&k);
                }

                if batch_count > 0 {
                    total_evicted += batch_count;
                    self.active_expired_count
                        .fetch_add(batch_count as u64, AtomicOrdering::Relaxed);
                }

                if batch_count < REPEAT_THRESHOLD || cycle_start.elapsed() >= time_budget {
                    break;
                }
            }
        }

        Ok(total_evicted)
    }

    pub fn export_shard_snapshot(&self, shard_idx: usize) -> EngineResult<Vec<ExportedEntry>> {
        let now = Instant::now();
        let guard = self.read_shard(shard_idx)?;
        let mut entries = Vec::with_capacity(guard.table.len());
        for (k, rec) in guard.table.iter() {
            if !rec.is_expired(now) {
                entries.push(ExportedEntry {
                    key: k.to_vec().into_boxed_slice(),
                    value: rec.value.clone(),
                    expire_unix_ms: rec.expires_at.map(|dl| self.instant_to_unix_ms(dl)),
                });
            }
        }
        Ok(entries)
    }
}

fn write_stream_entries_slice(entries: &[&StreamEntry], out: &mut Vec<u8>) {
    write_array_header(out, entries.len());
    for entry in entries {
        write_array_header(out, 2);
        let id_bytes = entry.id.format_bytes();
        write_bulk_string(out, &id_bytes);
        write_array_header(out, entry.fields.len() * 2);
        for (f, v) in &entry.fields {
            write_bulk_string(out, f);
            write_bulk_string(out, v);
        }
    }
}

pub struct TtlSweeper {
    stop_flag: Arc<AtomicBool>,
    wakeup: Arc<(Mutex<bool>, Condvar)>,
    join_handle: Option<JoinHandle<()>>,
}

impl TtlSweeper {
    pub fn spawn(engine: Arc<StorageEngine>, interval: Duration) -> EngineResult<Self> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let wakeup = Arc::new((Mutex::new(false), Condvar::new()));

        let stop_clone = Arc::clone(&stop_flag);
        let wakeup_clone = Arc::clone(&wakeup);

        let handle = thread::Builder::new()
            .name("ferrum-ttl-sweeper".to_string())
            .spawn(move || {
                let budget = (interval / 4).max(Duration::from_millis(5));
                while !stop_clone.load(AtomicOrdering::Acquire) {
                    let _ = engine.active_ttl_sweep_cycle(budget);

                    let (lock, cvar) = &*wakeup_clone;
                    if let Ok(guard) = lock.lock() {
                        if !*guard && !stop_clone.load(AtomicOrdering::Acquire) {
                            let _ = cvar.wait_timeout(guard, interval);
                        }
                    } else {
                        break;
                    }
                }
            })?;

        Ok(Self {
            stop_flag,
            wakeup,
            join_handle: Some(handle),
        })
    }

    pub fn shutdown(&mut self) {
        self.stop_flag.store(true, AtomicOrdering::Release);
        let (lock, cvar) = &*self.wakeup;
        if let Ok(mut guard) = lock.lock() {
            *guard = true;
            cvar.notify_all();
        }
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for TtlSweeper {
    fn drop(&mut self) {
        self.shutdown();
    }
}
