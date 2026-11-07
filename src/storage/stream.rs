use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{EngineError, EngineResult};
use crate::resp::parse_i64_bytes;
use crate::storage::hashtable::RawHashTable;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct StreamId {
    pub ms: u64,
    pub seq: u64,
}

impl StreamId {
    pub const ZERO: StreamId = StreamId { ms: 0, seq: 0 };
    pub const MAX: StreamId = StreamId {
        ms: u64::MAX,
        seq: u64::MAX,
    };

    pub fn format_bytes(&self) -> Vec<u8> {
        format!("{}-{}", self.ms, self.seq).into_bytes()
    }

    pub fn parse_range_bound(raw: &[u8], is_end: bool) -> EngineResult<Self> {
        if raw == b"-" {
            return Ok(Self::ZERO);
        }
        if raw == b"+" {
            return Ok(Self::MAX);
        }
        Self::parse_explicit_or_partial(raw, if is_end { u64::MAX } else { 0 })
    }

    pub fn parse_explicit(raw: &[u8]) -> EngineResult<Self> {
        Self::parse_explicit_or_partial(raw, 0)
    }

    fn parse_explicit_or_partial(raw: &[u8], default_seq: u64) -> EngineResult<Self> {
        if let Some(dash_pos) = raw.iter().position(|&b| b == b'-') {
            let ms_i = parse_i64_bytes(&raw[..dash_pos])?;
            let seq_i = parse_i64_bytes(&raw[dash_pos + 1..])?;
            if ms_i < 0 || seq_i < 0 {
                return Err(EngineError::InvalidArgument(
                    "Invalid stream ID specified as stream command argument".to_string(),
                ));
            }
            Ok(StreamId {
                ms: ms_i as u64,
                seq: seq_i as u64,
            })
        } else {
            let ms_i = parse_i64_bytes(raw)?;
            if ms_i < 0 {
                return Err(EngineError::InvalidArgument(
                    "Invalid stream ID specified as stream command argument".to_string(),
                ));
            }
            Ok(StreamId {
                ms: ms_i as u64,
                seq: default_seq,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub struct StreamEntry {
    pub id: StreamId,
    pub fields: Vec<(Box<[u8]>, Box<[u8]>)>,
}

#[derive(Clone, Debug)]
pub struct PendingEntry {
    pub id: StreamId,
    pub consumer: Box<[u8]>,
    pub delivery_time_ms: u64,
    pub delivery_count: u64,
}

#[derive(Clone, Debug)]
pub struct ConsumerGroup {
    pub name: Box<[u8]>,
    pub last_delivered_id: StreamId,
    pub pel: Vec<PendingEntry>,
    pub consumers: RawHashTable<usize>,
}

impl ConsumerGroup {
    pub fn new(name: Box<[u8]>, start_id: StreamId) -> Self {
        Self {
            name,
            last_delivered_id: start_id,
            pel: Vec::new(),
            consumers: RawHashTable::new(),
        }
    }

    pub fn record_pending(&mut self, id: StreamId, consumer: &[u8], now_ms: u64) {
        if let Some(existing) = self.pel.iter_mut().find(|p| p.id == id) {
            if existing.consumer.as_ref() != consumer {
                if let Some(old_cnt) = self.consumers.get_mut(&existing.consumer) {
                    *old_cnt = old_cnt.saturating_sub(1);
                }
                existing.consumer = consumer.to_vec().into_boxed_slice();
                if let Some(cnt) = self.consumers.get_mut(consumer) {
                    *cnt += 1;
                } else {
                    self.consumers
                        .insert(consumer.to_vec().into_boxed_slice(), 1);
                }
            }
            existing.delivery_time_ms = now_ms;
            existing.delivery_count += 1;
            return;
        }

        self.pel.push(PendingEntry {
            id,
            consumer: consumer.to_vec().into_boxed_slice(),
            delivery_time_ms: now_ms,
            delivery_count: 1,
        });
        if let Some(cnt) = self.consumers.get_mut(consumer) {
            *cnt += 1;
        } else {
            self.consumers
                .insert(consumer.to_vec().into_boxed_slice(), 1);
        }
    }

    pub fn ack(&mut self, ids: &[StreamId]) -> usize {
        let mut acked = 0usize;
        for target in ids {
            if let Some(pos) = self.pel.iter().position(|p| p.id == *target) {
                let removed = self.pel.remove(pos);
                if let Some(cnt) = self.consumers.get_mut(&removed.consumer) {
                    *cnt = cnt.saturating_sub(1);
                }
                acked += 1;
            }
        }
        acked
    }
}

#[derive(Clone, Debug, Default)]
pub struct StreamLog {
    entries: Vec<StreamEntry>,
    last_id: StreamId,
    groups: RawHashTable<ConsumerGroup>,
}

impl StreamLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_id: StreamId::ZERO,
            groups: RawHashTable::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    pub fn last_id(&self) -> StreamId {
        self.last_id
    }

    #[inline]
    pub fn entries(&self) -> &[StreamEntry] {
        &self.entries
    }

    #[inline]
    pub fn groups(&self) -> &RawHashTable<ConsumerGroup> {
        &self.groups
    }

    fn current_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1)
    }

    pub fn resolve_next_id(&self, id_spec: &[u8]) -> EngineResult<StreamId> {
        let resolved = if id_spec == b"*" {
            let now_ms = Self::current_unix_ms();
            if now_ms > self.last_id.ms {
                StreamId { ms: now_ms, seq: 0 }
            } else {
                StreamId {
                    ms: self.last_id.ms,
                    seq: self.last_id.seq.saturating_add(1),
                }
            }
        } else if let Some(star_pos) = id_spec.iter().position(|&b| b == b'*') {
            if star_pos == 0 || id_spec[star_pos - 1] != b'-' || star_pos + 1 != id_spec.len() {
                return Err(EngineError::InvalidArgument(
                    "Invalid stream ID specified as stream command argument".to_string(),
                ));
            }
            let ms_i = parse_i64_bytes(&id_spec[..star_pos - 1])?;
            if ms_i < 0 {
                return Err(EngineError::InvalidArgument(
                    "Invalid stream ID specified as stream command argument".to_string(),
                ));
            }
            let ms = ms_i as u64;
            if ms < self.last_id.ms {
                return Err(EngineError::InvalidArgument(
                    "The ID specified in XADD is equal or smaller than the target stream top item"
                        .to_string(),
                ));
            } else if ms == self.last_id.ms {
                StreamId {
                    ms,
                    seq: self.last_id.seq.saturating_add(1),
                }
            } else {
                StreamId {
                    ms,
                    seq: u64::from(ms == 0),
                }
            }
        } else {
            StreamId::parse_explicit(id_spec)?
        };

        if resolved == StreamId::ZERO {
            return Err(EngineError::InvalidArgument(
                "The ID specified in XADD must be greater than 0-0".to_string(),
            ));
        }
        if !self.entries.is_empty() && resolved <= self.last_id {
            return Err(EngineError::InvalidArgument(
                "The ID specified in XADD is equal or smaller than the target stream top item"
                    .to_string(),
            ));
        }
        Ok(resolved)
    }

    pub fn xadd(&mut self, id_spec: &[u8], pairs: &[(&[u8], &[u8])]) -> EngineResult<StreamId> {
        if pairs.is_empty() {
            return Err(EngineError::InvalidArgument(
                "wrong number of arguments for 'xadd' command".to_string(),
            ));
        }
        let id = self.resolve_next_id(id_spec)?;
        let fields = pairs
            .iter()
            .map(|&(k, v)| (k.to_vec().into_boxed_slice(), v.to_vec().into_boxed_slice()))
            .collect();
        self.entries.push(StreamEntry { id, fields });
        self.last_id = id;
        Ok(id)
    }

    fn lower_bound_idx(&self, target: StreamId, strictly_greater: bool) -> usize {
        self.entries.partition_point(|e| {
            if strictly_greater {
                e.id <= target
            } else {
                e.id < target
            }
        })
    }

    pub fn xrange(&self, start: StreamId, end: StreamId, count: Option<usize>) -> Vec<&StreamEntry> {
        if start > end || self.entries.is_empty() {
            return Vec::new();
        }
        let start_idx = self.lower_bound_idx(start, false);
        let max_items = count.unwrap_or(usize::MAX);
        let mut out = Vec::new();
        for entry in &self.entries[start_idx..] {
            if entry.id > end || out.len() >= max_items {
                break;
            }
            out.push(entry);
        }
        out
    }

    pub fn xread_after(&self, after_id: StreamId, count: Option<usize>) -> Vec<&StreamEntry> {
        let start_idx = self.lower_bound_idx(after_id, true);
        let max_items = count.unwrap_or(usize::MAX);
        self.entries[start_idx..]
            .iter()
            .take(max_items)
            .collect()
    }

    pub fn create_group(&mut self, group_name: &[u8], start_spec: &[u8]) -> EngineResult<()> {
        if self.groups.contains_key(group_name) {
            return Err(EngineError::InvalidArgument(
                "BUSYGROUP Consumer Group name already exists".to_string(),
            ));
        }
        let start_id = if start_spec == b"$" {
            self.last_id
        } else if start_spec == b"0" {
            StreamId::ZERO
        } else {
            StreamId::parse_explicit(start_spec)?
        };
        let group = ConsumerGroup::new(group_name.to_vec().into_boxed_slice(), start_id);
        self.groups
            .insert(group_name.to_vec().into_boxed_slice(), group);
        Ok(())
    }

    pub fn restore_group_state(
        &mut self,
        group_name: &[u8],
        last_delivered_id: StreamId,
        pending: Vec<PendingEntry>,
    ) {
        let mut grp = ConsumerGroup::new(group_name.to_vec().into_boxed_slice(), last_delivered_id);
        for p in pending {
            if let Some(cnt) = grp.consumers.get_mut(&p.consumer) {
                *cnt += 1;
            } else {
                grp.consumers.insert(p.consumer.clone(), 1);
            }
            grp.pel.push(p);
        }
        self.groups
            .insert(group_name.to_vec().into_boxed_slice(), grp);
    }

    pub fn xreadgroup(
        &mut self,
        group_name: &[u8],
        consumer_name: &[u8],
        id_spec: &[u8],
        count: Option<usize>,
    ) -> EngineResult<Vec<StreamEntry>> {
        let max_items = count.unwrap_or(usize::MAX);
        let now_ms = Self::current_unix_ms();

        if id_spec == b">" {
            let last_deliv = self
                .groups
                .get(group_name)
                .ok_or_else(|| {
                    EngineError::InvalidArgument(
                        "NOGROUP No such consumer group for key".to_string(),
                    )
                })?
                .last_delivered_id;

            let start_idx = self.entries.partition_point(|e| e.id <= last_deliv);
            let delivered: Vec<StreamEntry> = self.entries[start_idx..]
                .iter()
                .take(max_items)
                .cloned()
                .collect();

            if let Some(group) = self.groups.get_mut(group_name) {
                if !group.consumers.contains_key(consumer_name) {
                    group
                        .consumers
                        .insert(consumer_name.to_vec().into_boxed_slice(), 0);
                }
                for entry in &delivered {
                    if entry.id > group.last_delivered_id {
                        group.last_delivered_id = entry.id;
                    }
                    group.record_pending(entry.id, consumer_name, now_ms);
                }
            }
            Ok(delivered)
        } else {
            let after_id = if id_spec == b"0" {
                StreamId::ZERO
            } else {
                StreamId::parse_explicit(id_spec)?
            };
            let pending_ids: Vec<StreamId> = {
                let group = self.groups.get(group_name).ok_or_else(|| {
                    EngineError::InvalidArgument(
                        "NOGROUP No such consumer group for key".to_string(),
                    )
                })?;
                group
                    .pel
                    .iter()
                    .filter(|p| p.consumer.as_ref() == consumer_name && p.id > after_id)
                    .map(|p| p.id)
                    .take(max_items)
                    .collect()
            };

            let mut out = Vec::with_capacity(pending_ids.len());
            for pid in pending_ids {
                if let Ok(idx) = self.entries.binary_search_by(|e| e.id.cmp(&pid)) {
                    if idx < self.entries.len() && self.entries[idx].id.cmp(&pid) == Ordering::Equal
                    {
                        out.push(self.entries[idx].clone());
                    }
                }
            }
            Ok(out)
        }
    }

    pub fn xack(&mut self, group_name: &[u8], ids: &[StreamId]) -> EngineResult<usize> {
        let group = self.groups.get_mut(group_name).ok_or_else(|| {
            EngineError::InvalidArgument("NOGROUP No such consumer group for key".to_string())
        })?;
        Ok(group.ack(ids))
    }

    pub fn pel_len(&self, group_name: &[u8]) -> Option<usize> {
        self.groups.get(group_name).map(|g| g.pel.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_consumer_group_pel_and_xack() -> EngineResult<()> {
        let mut stream = StreamLog::new();
        let id1 = stream.xadd(b"1000-0", &[(b"sensor", b"t1")])?;
        let id2 = stream.xadd(b"1000-*", &[(b"sensor", b"t2")])?;
        let id3 = stream.xadd(b"*", &[(b"sensor", b"t3")])?;
        assert_eq!(id1, StreamId { ms: 1000, seq: 0 });
        assert_eq!(id2, StreamId { ms: 1000, seq: 1 });
        assert!(id3 > id2);
        assert_eq!(stream.len(), 3);

        stream.create_group(b"workers", b"0-0")?;
        let batch1 = stream.xreadgroup(b"workers", b"c1", b">", Some(2))?;
        assert_eq!(batch1.len(), 2);
        assert_eq!(stream.pel_len(b"workers"), Some(2));

        // Re-reading pending entries for consumer c1 via "0-0"
        let history = stream.xreadgroup(b"workers", b"c1", b"0-0", None)?;
        assert_eq!(history.len(), 2);

        // Consumer c2 picks up the 3rd entry
        let batch2 = stream.xreadgroup(b"workers", b"c2", b">", Some(10))?;
        assert_eq!(batch2.len(), 1);
        assert_eq!(stream.pel_len(b"workers"), Some(3));

        // Acknowledge id1 and id3
        let acked = stream.xack(b"workers", &[id1, id3])?;
        assert_eq!(acked, 2);
        assert_eq!(stream.pel_len(b"workers"), Some(1));
        Ok(())
    }
}
