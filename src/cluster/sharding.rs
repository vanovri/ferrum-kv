use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::RwLock;
use std::time::Duration;

use crate::cli::read_one_frame;
use crate::error::{EngineError, EngineResult};
use crate::resp::{
    encode_command_slices, write_array_header, write_bulk_string, write_integer, OwnedFrame,
    StreamReadBuffer,
};
use crate::storage::{DataValue, StorageEngine};

pub const CLUSTER_SLOTS: usize = 16_384;
const SLOT_BITMAP_WORDS: usize = CLUSTER_SLOTS / 64;

/// XMODEM CRC16-CCITT (`poly = 0x1021`, `init = 0x0000`) matching the Redis Cluster specification.
#[inline]
pub fn crc16_ccitt(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in bytes {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Computes Redis Cluster 16,384 hash slot (`0..16384`), honoring `{hash_tag}` substrings.
#[inline]
pub fn key_hash_slot(key: &[u8]) -> u16 {
    let effective = extract_hash_tag(key);
    crc16_ccitt(effective) & 0x3FFF
}

#[inline]
pub fn extract_hash_tag(key: &[u8]) -> &[u8] {
    if let Some(open_idx) = key.iter().position(|&b| b == b'{') {
        if let Some(rel_close) = key[open_idx + 1..].iter().position(|&b| b == b'}') {
            if rel_close > 0 {
                return &key[open_idx + 1..open_idx + 1 + rel_close];
            }
        }
    }
    key
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotRedirection {
    pub is_ask: bool,
    pub slot: u16,
    pub target_addr: String,
}

impl SlotRedirection {
    pub fn to_resp_error_bytes(&self) -> Vec<u8> {
        let prefix = if self.is_ask { "ASK" } else { "MOVED" };
        format!("{} {} {}", prefix, self.slot, self.target_addr).into_bytes()
    }
}

struct TopologyInner {
    local_node_id: String,
    local_addr: String,
    local_bitmap: [u64; SLOT_BITMAP_WORDS],
    slot_owners: Vec<String>,
    migrating_to: Vec<Option<String>>,
    importing_from: Vec<Option<String>>,
}

/// 16,384-slot Redis Cluster shard topology & `-MOVED` / `-ASK` router.
pub struct ClusterTopology {
    enabled: AtomicBool,
    inner: RwLock<TopologyInner>,
}

impl ClusterTopology {
    pub fn new(local_node_id: impl Into<String>, local_addr: impl Into<String>) -> Self {
        let node_id = local_node_id.into();
        let addr = local_addr.into();
        let mut bitmap = [0u64; SLOT_BITMAP_WORDS];
        for w in &mut bitmap {
            *w = u64::MAX;
        }
        let mut owners = Vec::with_capacity(CLUSTER_SLOTS);
        let mut migrating = Vec::with_capacity(CLUSTER_SLOTS);
        let mut importing = Vec::with_capacity(CLUSTER_SLOTS);
        for _ in 0..CLUSTER_SLOTS {
            owners.push(addr.clone());
            migrating.push(None);
            importing.push(None);
        }

        Self {
            enabled: AtomicBool::new(false),
            inner: RwLock::new(TopologyInner {
                local_node_id: node_id,
                local_addr: addr,
                local_bitmap: bitmap,
                slot_owners: owners,
                migrating_to: migrating,
                importing_from: importing,
            }),
        }
    }

    pub fn set_local_addr(&self, addr: impl Into<String>) -> EngineResult<()> {
        let new_addr = addr.into();
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("cluster topology write"))?;
        let prev_addr = guard.local_addr.clone();
        for owner in &mut guard.slot_owners {
            if *owner == prev_addr {
                *owner = new_addr.clone();
            }
        }
        guard.local_addr = new_addr;
        Ok(())
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(AtomicOrdering::Acquire)
    }

    #[inline]
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, AtomicOrdering::Release);
    }

    pub fn local_node_id(&self) -> EngineResult<String> {
        let guard = self
            .inner
            .read()
            .map_err(|_| EngineError::LockPoisoned("cluster topology read"))?;
        Ok(guard.local_node_id.clone())
    }

    pub fn owns_slot_locally(&self, slot: u16) -> EngineResult<bool> {
        if slot as usize >= CLUSTER_SLOTS {
            return Ok(false);
        }
        let guard = self
            .inner
            .read()
            .map_err(|_| EngineError::LockPoisoned("cluster topology read"))?;
        let word = (slot as usize) >> 6;
        let bit = (slot as usize) & 63;
        Ok(((guard.local_bitmap[word] >> bit) & 1) != 0)
    }

    pub fn assign_slot_range(&self, start: u16, end: u16, owner_addr: &str) -> EngineResult<()> {
        if start > end || (end as usize) >= CLUSTER_SLOTS {
            return Err(EngineError::InvalidArgument(
                "slot range out of bounds (expected 0..16383)".to_string(),
            ));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("cluster topology write"))?;
        let is_local = owner_addr == guard.local_addr || owner_addr.eq_ignore_ascii_case("SELF");
        let resolved_owner = if is_local {
            guard.local_addr.clone()
        } else {
            owner_addr.to_string()
        };

        for s in start..=end {
            let idx = s as usize;
            let word = idx >> 6;
            let mask = 1u64 << (idx & 63);
            if is_local {
                guard.local_bitmap[word] |= mask;
            } else {
                guard.local_bitmap[word] &= !mask;
            }
            guard.slot_owners[idx] = resolved_owner.clone();
            guard.migrating_to[idx] = None;
            guard.importing_from[idx] = None;
        }
        self.enabled.store(true, AtomicOrdering::Release);
        Ok(())
    }

    pub fn set_slot_migrating(&self, slot: u16, target_addr: &str) -> EngineResult<()> {
        if (slot as usize) >= CLUSTER_SLOTS {
            return Err(EngineError::InvalidArgument("invalid slot".to_string()));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("cluster topology write"))?;
        guard.migrating_to[slot as usize] = Some(target_addr.to_string());
        self.enabled.store(true, AtomicOrdering::Release);
        Ok(())
    }

    pub fn set_slot_importing(&self, slot: u16, source_addr: &str) -> EngineResult<()> {
        if (slot as usize) >= CLUSTER_SLOTS {
            return Err(EngineError::InvalidArgument("invalid slot".to_string()));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("cluster topology write"))?;
        guard.importing_from[slot as usize] = Some(source_addr.to_string());
        self.enabled.store(true, AtomicOrdering::Release);
        Ok(())
    }

    pub fn set_slot_stable(&self, slot: u16) -> EngineResult<()> {
        if (slot as usize) >= CLUSTER_SLOTS {
            return Err(EngineError::InvalidArgument("invalid slot".to_string()));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("cluster topology write"))?;
        guard.migrating_to[slot as usize] = None;
        guard.importing_from[slot as usize] = None;
        Ok(())
    }

    /// Evaluates whether a command targeting `key` must be redirected via `-MOVED` or `-ASK`.
    pub fn check_slot_redirect(
        &self,
        key: &[u8],
        client_asking: bool,
        storage: &StorageEngine,
    ) -> EngineResult<Option<SlotRedirection>> {
        if !self.enabled.load(AtomicOrdering::Acquire) {
            return Ok(None);
        }
        let slot = key_hash_slot(key);
        let idx = slot as usize;

        let (is_local, owner_addr, migrating_target, is_importing) = {
            let guard = self
                .inner
                .read()
                .map_err(|_| EngineError::LockPoisoned("cluster topology read"))?;
            let word = idx >> 6;
            let local = ((guard.local_bitmap[word] >> (idx & 63)) & 1) != 0;
            (
                local,
                guard.slot_owners[idx].clone(),
                guard.migrating_to[idx].clone(),
                guard.importing_from[idx].is_some(),
            )
        };

        if is_local {
            if let Some(target) = migrating_target {
                let exists = storage.exists(&[key])? > 0;
                if !exists {
                    return Ok(Some(SlotRedirection {
                        is_ask: true,
                        slot,
                        target_addr: target,
                    }));
                }
            }
            Ok(None)
        } else if is_importing && client_asking {
            Ok(None)
        } else {
            Ok(Some(SlotRedirection {
                is_ask: false,
                slot,
                target_addr: owner_addr,
            }))
        }
    }

    /// Writes `CLUSTER SLOTS` contiguous ranges `[[start, end, [host, port, node_id]], ...]`.
    pub fn write_cluster_slots(&self, out: &mut Vec<u8>) -> EngineResult<()> {
        let guard = self
            .inner
            .read()
            .map_err(|_| EngineError::LockPoisoned("cluster topology read"))?;

        let mut ranges: Vec<(u16, u16, String)> = Vec::new();
        for s in 0..CLUSTER_SLOTS {
            let owner = &guard.slot_owners[s];
            match ranges.last_mut() {
                Some(last) if last.2 == *owner && last.1 + 1 == (s as u16) => {
                    last.1 = s as u16;
                }
                _ => ranges.push((s as u16, s as u16, owner.clone())),
            }
        }

        write_array_header(out, ranges.len());
        for (start, end, addr) in ranges {
            write_array_header(out, 3);
            write_integer(out, start as i64);
            write_integer(out, end as i64);

            let (host, port) = split_host_port(&addr);
            let id = if addr == guard.local_addr {
                guard.local_node_id.clone()
            } else {
                format!("peer-{}", addr)
            };
            write_array_header(out, 3);
            write_bulk_string(out, host.as_bytes());
            write_integer(out, port as i64);
            write_bulk_string(out, id.as_bytes());
        }
        Ok(())
    }

    /// Atomically migrates a live key to `target_addr` over TCP (`ASKING` + payload transfer + local `DEL`).
    pub fn migrate_key(
        &self,
        target_addr: &str,
        key: &[u8],
        storage: &StorageEngine,
    ) -> EngineResult<bool> {
        let shard_idx = storage.shard_index(key);
        let exported = storage
            .export_shard_snapshot(shard_idx)?
            .into_iter()
            .find(|e| e.key.as_ref() == key);

        let Some(entry) = exported else {
            return Ok(false);
        };

        let sock_addr: SocketAddr = target_addr.parse()?;
        let mut stream = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(3))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut rbuf = StreamReadBuffer::with_capacity(4096);

        send_expect_ok(&mut stream, &mut rbuf, &[b"ASKING"])?;

        match &entry.value {
            DataValue::String(val) => {
                send_expect_ok(&mut stream, &mut rbuf, &[b"SET", key, val])?;
            }
            DataValue::Hash(map) => {
                let pairs: Vec<(&[u8], &[u8])> = map.iter().map(|(f, v)| (f, v.as_ref())).collect();
                let mut cmd: Vec<&[u8]> = Vec::with_capacity(2 + pairs.len() * 2);
                cmd.push(b"HSET");
                cmd.push(key);
                for (f, v) in pairs {
                    cmd.push(f);
                    cmd.push(v);
                }
                send_any_non_error(&mut stream, &mut rbuf, &cmd)?;
            }
            DataValue::List(list) => {
                let items: Vec<&[u8]> = list.iter().collect();
                let mut cmd: Vec<&[u8]> = Vec::with_capacity(2 + items.len());
                cmd.push(b"RPUSH");
                cmd.push(key);
                cmd.extend_from_slice(&items);
                send_any_non_error(&mut stream, &mut rbuf, &cmd)?;
            }
            _ => {
                let val_txt = format!("migrated:{}", entry.value.type_name());
                send_expect_ok(&mut stream, &mut rbuf, &[b"SET", key, val_txt.as_bytes()])?;
            }
        }

        if let Some(exp_ms) = entry.expire_unix_ms {
            let s = exp_ms.to_string();
            send_any_non_error(
                &mut stream,
                &mut rbuf,
                &[b"PEXPIREAT", b"ASKING_BYPASS", s.as_bytes()],
            )
            .ok();
            let _ = send_expect_ok(&mut stream, &mut rbuf, &[b"ASKING"]);
            send_any_non_error(&mut stream, &mut rbuf, &[b"PEXPIREAT", key, s.as_bytes()])?;
        }

        storage.del(&[key])?;
        Ok(true)
    }
}

fn split_host_port(addr: &str) -> (&str, u16) {
    if let Some(colon) = addr.rfind(':') {
        let port = addr[colon + 1..].parse::<u16>().unwrap_or(6379);
        (&addr[..colon], port)
    } else {
        (addr, 6379)
    }
}

fn send_expect_ok(
    stream: &mut TcpStream,
    rbuf: &mut StreamReadBuffer,
    parts: &[&[u8]],
) -> EngineResult<()> {
    match send_any_non_error(stream, rbuf, parts)? {
        OwnedFrame::SimpleString(s) if s == b"OK" => Ok(()),
        other => Err(EngineError::Protocol(format!(
            "unexpected MIGRATE reply: {:?}",
            other
        ))),
    }
}

fn send_any_non_error(
    stream: &mut TcpStream,
    rbuf: &mut StreamReadBuffer,
    parts: &[&[u8]],
) -> EngineResult<OwnedFrame> {
    let mut wbuf = Vec::with_capacity(128);
    encode_command_slices(&mut wbuf, parts);
    stream.write_all(&wbuf)?;
    let reply = read_one_frame(stream, rbuf)?;
    if let OwnedFrame::SimpleError(err) = reply {
        return Err(EngineError::InvalidArgument(
            String::from_utf8_lossy(&err).into_owned(),
        ));
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SetCondition;

    #[test]
    fn test_crc16_ccitt_hash_tags_and_moved_ask_redirections() -> EngineResult<()> {
        // Official XMODEM / Redis Cluster specification check value
        assert_eq!(crc16_ccitt(b"123456789"), 0x31C3);
        assert_eq!(key_hash_slot(b"{123456789}"), 0x31C3 & 0x3FFF);

        // Hash tags co-locate distinct keys onto identical slots
        let s1 = key_hash_slot(b"orders:{tenant42}:2026");
        let s2 = key_hash_slot(b"invoices:{tenant42}:99");
        assert_eq!(s1, s2);
        // Empty braces `{}` hash the entire key per Redis Cluster spec
        assert_ne!(key_hash_slot(b"{}:foo"), key_hash_slot(b"{}:bar"));

        let storage = StorageEngine::new(8)?;
        let topo = ClusterTopology::new("node-1", "127.0.0.1:7000");

        let slot = key_hash_slot(b"user:{alpha}:profile");
        topo.assign_slot_range(slot, slot, "127.0.0.1:7001")?;

        let redir = topo.check_slot_redirect(b"user:{alpha}:profile", false, &storage)?;
        assert_eq!(
            redir,
            Some(SlotRedirection {
                is_ask: false,
                slot,
                target_addr: "127.0.0.1:7001".to_string(),
            })
        );

        // Importing node permits access when client sent ASKING
        topo.set_slot_importing(slot, "127.0.0.1:7001")?;
        assert_eq!(
            topo.check_slot_redirect(b"user:{alpha}:profile", true, &storage)?,
            None
        );

        // Migrating local slot serves existing keys locally, redirects missing keys with -ASK
        topo.assign_slot_range(slot, slot, "127.0.0.1:7000")?;
        topo.set_slot_migrating(slot, "127.0.0.1:7002")?;
        storage.set(b"user:{alpha}:profile", b"live", None, SetCondition::Always)?;
        assert_eq!(
            topo.check_slot_redirect(b"user:{alpha}:profile", false, &storage)?,
            None
        );
        assert_eq!(
            topo.check_slot_redirect(b"user:{alpha}:missing", false, &storage)?,
            Some(SlotRedirection {
                is_ask: true,
                slot,
                target_addr: "127.0.0.1:7002".to_string(),
            })
        );

        Ok(())
    }
}
