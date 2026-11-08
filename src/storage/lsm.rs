use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::error::{EngineError, EngineResult};
use crate::resp::{write_bulk_string, write_null};
use crate::storage::probabilistic::BloomFilter;

const SST_BLOCK_TARGET_BYTES: usize = 4096;
const SST_FOOTER_BYTES: usize = 40; // 4 * u64 (32B) + crc32 (4B) + magic (4B)
const SST_MAGIC: &[u8; 4] = b"FSST";

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LsmEntry {
    Value(Box<[u8]>),
    Tombstone,
}

#[derive(Clone, Debug)]
struct FencePointer {
    first_key: Box<[u8]>,
    block_offset: u64,
    block_len: u32,
}

#[derive(Debug)]
struct SsTableMeta {
    seq_id: u64,
    path: PathBuf,
    entry_count: usize,
    fence_index: Vec<FencePointer>,
    bloom: BloomFilter,
}

#[derive(Debug)]
struct LsmState {
    memtable: BTreeMap<Box<[u8]>, LsmEntry>,
    memtable_bytes: usize,
    flush_threshold_bytes: usize,
    next_sst_seq: u64,
    sstables: Vec<SsTableMeta>,
}

/// Hybrid Tiered Log-Structured Merge-Tree (`MemTable` + 4KB Block-Checksummed Disk `SSTable`s).
/// Uses `RwLock<LsmState>` so concurrent readers (`get`, `get_into`, `scan`, `stats`) share read access
/// to the `MemTable` and `SSTable` fence/Bloom indices without reader-reader contention.
pub struct LsmEngine {
    dir: PathBuf,
    inner: RwLock<LsmState>,
}

impl LsmEngine {
    pub fn open(dir: impl AsRef<Path>, flush_threshold_bytes: usize) -> EngineResult<Self> {
        let dir_buf = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir_buf)?;

        let mut sstables = Vec::new();
        let mut max_seq = 0u64;

        for entry_res in fs::read_dir(&dir_buf)? {
            let entry = entry_res?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sst") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Some(num_part) = stem.strip_prefix("sst_") {
                        if let Ok(seq) = num_part.parse::<u64>() {
                            let meta = load_sstable_metadata(seq, &path)?;
                            if seq > max_seq {
                                max_seq = seq;
                            }
                            sstables.push(meta);
                        }
                    }
                }
            }
        }
        sstables.sort_by_key(|m| m.seq_id);

        Ok(Self {
            dir: dir_buf,
            inner: RwLock::new(LsmState {
                memtable: BTreeMap::new(),
                memtable_bytes: 0,
                flush_threshold_bytes: flush_threshold_bytes.max(4096),
                next_sst_seq: max_seq + 1,
                sstables,
            }),
        })
    }

    pub fn put(&self, key: &[u8], val: &[u8]) -> EngineResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("LSM RwLock write"))?;
        let added = key.len() + val.len() + 16;
        guard.memtable.insert(
            key.to_vec().into_boxed_slice(),
            LsmEntry::Value(val.to_vec().into_boxed_slice()),
        );
        guard.memtable_bytes += added;
        if guard.memtable_bytes >= guard.flush_threshold_bytes {
            self.flush_locked(&mut guard)?;
        }
        Ok(())
    }

    pub fn delete(&self, key: &[u8]) -> EngineResult<()> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("LSM RwLock write"))?;
        guard
            .memtable
            .insert(key.to_vec().into_boxed_slice(), LsmEntry::Tombstone);
        guard.memtable_bytes += key.len() + 8;
        if guard.memtable_bytes >= guard.flush_threshold_bytes {
            self.flush_locked(&mut guard)?;
        }
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> EngineResult<Option<Box<[u8]>>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| EngineError::LockPoisoned("LSM RwLock read"))?;

        if let Some(entry) = guard.memtable.get(key) {
            return Ok(match entry {
                LsmEntry::Value(v) => Some(v.clone()),
                LsmEntry::Tombstone => None,
            });
        }

        for sst in guard.sstables.iter().rev() {
            if !sst.bloom.exists(key) {
                continue;
            }
            if let Some(entry) = search_sstable_on_disk(sst, key)? {
                return Ok(match entry {
                    LsmEntry::Value(v) => Some(v),
                    LsmEntry::Tombstone => None,
                });
            }
        }
        Ok(None)
    }

    /// Zero-copy MemTable-to-socket serialization under shared `RwLockReadGuard`.
    pub fn get_into(&self, key: &[u8], out: &mut Vec<u8>) -> EngineResult<()> {
        let guard = self
            .inner
            .read()
            .map_err(|_| EngineError::LockPoisoned("LSM RwLock read"))?;

        if let Some(entry) = guard.memtable.get(key) {
            match entry {
                LsmEntry::Value(v) => write_bulk_string(out, v),
                LsmEntry::Tombstone => write_null(out),
            }
            return Ok(());
        }

        for sst in guard.sstables.iter().rev() {
            if !sst.bloom.exists(key) {
                continue;
            }
            if let Some(entry) = search_sstable_on_disk(sst, key)? {
                match entry {
                    LsmEntry::Value(v) => write_bulk_string(out, &v),
                    LsmEntry::Tombstone => write_null(out),
                }
                return Ok(());
            }
        }
        write_null(out);
        Ok(())
    }

    pub fn scan(
        &self,
        start_key: &[u8],
        end_key: &[u8],
        limit: usize,
    ) -> EngineResult<Vec<(Box<[u8]>, Box<[u8]>)>> {
        let guard = self
            .inner
            .read()
            .map_err(|_| EngineError::LockPoisoned("LSM RwLock read"))?;

        let mut merged: BTreeMap<Box<[u8]>, LsmEntry> = BTreeMap::new();
        for sst in &guard.sstables {
            for (k, entry) in read_all_sstable_entries(sst)? {
                if k.as_ref() >= start_key && k.as_ref() <= end_key {
                    merged.insert(k, entry);
                }
            }
        }
        for (k, entry) in guard
            .memtable
            .range(start_key.to_vec().into_boxed_slice()..=end_key.to_vec().into_boxed_slice())
        {
            merged.insert(k.clone(), entry.clone());
        }

        let mut out = Vec::new();
        for (k, entry) in merged {
            if let LsmEntry::Value(val) = entry {
                out.push((k, val));
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    pub fn flush(&self) -> EngineResult<bool> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("LSM RwLock write"))?;
        self.flush_locked(&mut guard)
    }

    fn flush_locked(&self, state: &mut LsmState) -> EngineResult<bool> {
        if state.memtable.is_empty() {
            return Ok(false);
        }
        let seq = state.next_sst_seq;
        state.next_sst_seq += 1;
        let sst_path = self.dir.join(format!("sst_{seq:08}.sst"));

        let items: Vec<(Box<[u8]>, LsmEntry)> =
            std::mem::take(&mut state.memtable).into_iter().collect();
        state.memtable_bytes = 0;

        let meta = write_sstable_file(seq, &sst_path, &items)?;
        state.sstables.push(meta);
        Ok(true)
    }

    /// Merges all SSTables (and MemTable if dirty) into one compacted SSTable while purging tombstones.
    pub fn compact_all(&self) -> EngineResult<usize> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| EngineError::LockPoisoned("LSM RwLock write"))?;

        if !guard.memtable.is_empty() {
            self.flush_locked(&mut guard)?;
        }
        if guard.sstables.is_empty() {
            return Ok(0);
        }

        let mut merged: BTreeMap<Box<[u8]>, LsmEntry> = BTreeMap::new();
        for sst in &guard.sstables {
            for (k, entry) in read_all_sstable_entries(sst)? {
                merged.insert(k, entry);
            }
        }

        let live_items: Vec<(Box<[u8]>, LsmEntry)> = merged
            .into_iter()
            .filter(|(_, entry)| matches!(entry, LsmEntry::Value(_)))
            .collect();

        let old_files: Vec<PathBuf> = guard.sstables.drain(..).map(|s| s.path).collect();

        if !live_items.is_empty() {
            let seq = guard.next_sst_seq;
            guard.next_sst_seq += 1;
            let new_path = self.dir.join(format!("sst_{seq:08}.sst"));
            let meta = write_sstable_file(seq, &new_path, &live_items)?;
            guard.sstables.push(meta);
        }

        for old_path in old_files {
            let _ = fs::remove_file(old_path);
        }

        Ok(guard.sstables.len())
    }

    pub fn stats(&self) -> EngineResult<(usize, usize, usize)> {
        let guard = self
            .inner
            .read()
            .map_err(|_| EngineError::LockPoisoned("LSM RwLock read"))?;
        let sst_entries: usize = guard.sstables.iter().map(|s| s.entry_count).sum();
        Ok((guard.memtable.len(), guard.sstables.len(), sst_entries))
    }
}

fn read_u32_le(buf: &[u8], pos: &mut usize) -> EngineResult<u32> {
    if *pos + 4 > buf.len() {
        return Err(EngineError::CorruptedPersistence(
            "SSTable unexpected EOF reading u32".to_string(),
        ));
    }
    let v = u32::from_le_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn read_u64_le(buf: &[u8], pos: &mut usize) -> EngineResult<u64> {
    if *pos + 8 > buf.len() {
        return Err(EngineError::CorruptedPersistence(
            "SSTable unexpected EOF reading u64".to_string(),
        ));
    }
    let v = u64::from_le_bytes([
        buf[*pos],
        buf[*pos + 1],
        buf[*pos + 2],
        buf[*pos + 3],
        buf[*pos + 4],
        buf[*pos + 5],
        buf[*pos + 6],
        buf[*pos + 7],
    ]);
    *pos += 8;
    Ok(v)
}

fn write_sstable_file(
    seq_id: u64,
    path: &Path,
    sorted_items: &[(Box<[u8]>, LsmEntry)],
) -> EngineResult<SsTableMeta> {
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)?;
    let mut writer = BufWriter::with_capacity(64 * 1024, file);

    let bloom_bits = (sorted_items.len() * 12).max(1024);
    let mut bloom = BloomFilter::with_rate(bloom_bits, 7);
    let mut fence_index: Vec<FencePointer> = Vec::new();

    let mut current_offset = 0u64;
    let mut block_buf = Vec::with_capacity(SST_BLOCK_TARGET_BYTES + 512);
    let mut block_first_key: Option<Box<[u8]>> = None;
    let mut block_records = 0u32;

    let flush_block = |w: &mut BufWriter<File>,
                       offset: &mut u64,
                       fences: &mut Vec<FencePointer>,
                       first_key: &mut Option<Box<[u8]>>,
                       rec_count: &mut u32,
                       payload: &mut Vec<u8>|
     -> EngineResult<()> {
        if *rec_count == 0 {
            return Ok(());
        }
        let mut full_block = Vec::with_capacity(4 + payload.len() + 4);
        full_block.extend_from_slice(&rec_count.to_le_bytes());
        full_block.extend_from_slice(payload);
        let crc = crc32_ieee(&full_block);
        full_block.extend_from_slice(&crc.to_le_bytes());

        w.write_all(&full_block)?;
        if let Some(fk) = first_key.take() {
            fences.push(FencePointer {
                first_key: fk,
                block_offset: *offset,
                block_len: full_block.len() as u32,
            });
        }
        *offset += full_block.len() as u64;
        *rec_count = 0;
        payload.clear();
        Ok(())
    };

    for (key, entry) in sorted_items {
        bloom.add(key);
        if block_first_key.is_none() {
            block_first_key = Some(key.clone());
        }
        block_buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        block_buf.extend_from_slice(key);
        match entry {
            LsmEntry::Value(val) => {
                block_buf.push(1u8);
                block_buf.extend_from_slice(&(val.len() as u32).to_le_bytes());
                block_buf.extend_from_slice(val);
            }
            LsmEntry::Tombstone => {
                block_buf.push(0u8);
            }
        }
        block_records += 1;

        if block_buf.len() >= SST_BLOCK_TARGET_BYTES {
            flush_block(
                &mut writer,
                &mut current_offset,
                &mut fence_index,
                &mut block_first_key,
                &mut block_records,
                &mut block_buf,
            )?;
        }
    }

    flush_block(
        &mut writer,
        &mut current_offset,
        &mut fence_index,
        &mut block_first_key,
        &mut block_records,
        &mut block_buf,
    )?;

    // Sparse Fence-Pointer Index Block
    let index_offset = current_offset;
    let mut index_bytes = Vec::new();
    index_bytes.extend_from_slice(&(sorted_items.len() as u64).to_le_bytes());
    index_bytes.extend_from_slice(&(fence_index.len() as u32).to_le_bytes());
    for fp in &fence_index {
        index_bytes.extend_from_slice(&(fp.first_key.len() as u32).to_le_bytes());
        index_bytes.extend_from_slice(&fp.first_key);
        index_bytes.extend_from_slice(&fp.block_offset.to_le_bytes());
        index_bytes.extend_from_slice(&fp.block_len.to_le_bytes());
    }
    let idx_crc = crc32_ieee(&index_bytes);
    index_bytes.extend_from_slice(&idx_crc.to_le_bytes());
    writer.write_all(&index_bytes)?;
    let index_len = index_bytes.len() as u64;
    current_offset += index_len;

    // Embedded Bloom Filter Block
    let bloom_offset = current_offset;
    let mut bloom_bytes = Vec::new();
    bloom_bytes.extend_from_slice(&bloom.num_probes().to_le_bytes());
    bloom_bytes.extend_from_slice(&(bloom.words().len() as u32).to_le_bytes());
    for &w in bloom.words() {
        bloom_bytes.extend_from_slice(&w.to_le_bytes());
    }
    let bloom_crc = crc32_ieee(&bloom_bytes);
    bloom_bytes.extend_from_slice(&bloom_crc.to_le_bytes());
    writer.write_all(&bloom_bytes)?;
    let bloom_len = bloom_bytes.len() as u64;

    // 40-byte Footer
    let mut footer = Vec::with_capacity(SST_FOOTER_BYTES);
    footer.extend_from_slice(&index_offset.to_le_bytes());
    footer.extend_from_slice(&index_len.to_le_bytes());
    footer.extend_from_slice(&bloom_offset.to_le_bytes());
    footer.extend_from_slice(&bloom_len.to_le_bytes());
    let footer_crc = crc32_ieee(&footer);
    footer.extend_from_slice(&footer_crc.to_le_bytes());
    footer.extend_from_slice(SST_MAGIC);
    writer.write_all(&footer)?;

    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    fs::rename(&tmp_path, path)?;

    Ok(SsTableMeta {
        seq_id,
        path: path.to_path_buf(),
        entry_count: sorted_items.len(),
        fence_index,
        bloom,
    })
}

fn load_sstable_metadata(seq_id: u64, path: &Path) -> EngineResult<SsTableMeta> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len < SST_FOOTER_BYTES as u64 {
        return Err(EngineError::CorruptedPersistence(
            "SSTable smaller than footer".to_string(),
        ));
    }

    file.seek(SeekFrom::End(-(SST_FOOTER_BYTES as i64)))?;
    let mut footer = [0u8; SST_FOOTER_BYTES];
    file.read_exact(&mut footer)?;
    if &footer[36..40] != SST_MAGIC {
        return Err(EngineError::CorruptedPersistence(
            "invalid SSTable footer magic".to_string(),
        ));
    }
    let mut fpos = 0usize;
    let index_offset = read_u64_le(&footer, &mut fpos)?;
    let index_len = read_u64_le(&footer, &mut fpos)?;
    let bloom_offset = read_u64_le(&footer, &mut fpos)?;
    let bloom_len = read_u64_le(&footer, &mut fpos)?;
    let expected_fcrc = read_u32_le(&footer, &mut fpos)?;
    if crc32_ieee(&footer[..32]) != expected_fcrc {
        return Err(EngineError::CorruptedPersistence(
            "SSTable footer CRC32 mismatch".to_string(),
        ));
    }

    // Read & verify Fence-Pointer Index Block
    file.seek(SeekFrom::Start(index_offset))?;
    let mut idx_buf = vec![0u8; index_len as usize];
    file.read_exact(&mut idx_buf)?;
    if idx_buf.len() < 16 {
        return Err(EngineError::CorruptedPersistence(
            "truncated SSTable index block".to_string(),
        ));
    }
    let idx_payload_end = idx_buf.len() - 4;
    let mut cpos = idx_payload_end;
    let idx_crc = read_u32_le(&idx_buf, &mut cpos)?;
    if crc32_ieee(&idx_buf[..idx_payload_end]) != idx_crc {
        return Err(EngineError::CorruptedPersistence(
            "SSTable index block CRC32 mismatch".to_string(),
        ));
    }

    let mut ipos = 0usize;
    let entry_count = read_u64_le(&idx_buf[..idx_payload_end], &mut ipos)? as usize;
    let fence_count = read_u32_le(&idx_buf[..idx_payload_end], &mut ipos)? as usize;
    let mut fence_index = Vec::with_capacity(fence_count);
    for _ in 0..fence_count {
        let klen = read_u32_le(&idx_buf[..idx_payload_end], &mut ipos)? as usize;
        if ipos + klen > idx_payload_end {
            return Err(EngineError::CorruptedPersistence(
                "truncated fence key".to_string(),
            ));
        }
        let fk = idx_buf[ipos..ipos + klen].to_vec().into_boxed_slice();
        ipos += klen;
        let boff = read_u64_le(&idx_buf[..idx_payload_end], &mut ipos)?;
        let blen = read_u32_le(&idx_buf[..idx_payload_end], &mut ipos)?;
        fence_index.push(FencePointer {
            first_key: fk,
            block_offset: boff,
            block_len: blen,
        });
    }

    // Read & verify Embedded Bloom Filter Block
    file.seek(SeekFrom::Start(bloom_offset))?;
    let mut bbuf = vec![0u8; bloom_len as usize];
    file.read_exact(&mut bbuf)?;
    if bbuf.len() < 12 {
        return Err(EngineError::CorruptedPersistence(
            "truncated SSTable bloom block".to_string(),
        ));
    }
    let b_end = bbuf.len() - 4;
    let mut bc_pos = b_end;
    let b_crc = read_u32_le(&bbuf, &mut bc_pos)?;
    if crc32_ieee(&bbuf[..b_end]) != b_crc {
        return Err(EngineError::CorruptedPersistence(
            "SSTable bloom block CRC32 mismatch".to_string(),
        ));
    }
    let mut bpos = 0usize;
    let num_probes = read_u32_le(&bbuf[..b_end], &mut bpos)?;
    let num_words = read_u32_le(&bbuf[..b_end], &mut bpos)? as usize;
    let mut words = Vec::with_capacity(num_words);
    for _ in 0..num_words {
        words.push(read_u64_le(&bbuf[..b_end], &mut bpos)?);
    }

    Ok(SsTableMeta {
        seq_id,
        path: path.to_path_buf(),
        entry_count,
        fence_index,
        bloom: BloomFilter::from_raw_parts(num_probes, words),
    })
}

fn decode_verified_data_block(
    file: &mut File,
    block_offset: u64,
    block_len: u32,
) -> EngineResult<Vec<(Box<[u8]>, LsmEntry)>> {
    if block_len < 8 {
        return Err(EngineError::CorruptedPersistence(
            "corrupted SSTable data block length".to_string(),
        ));
    }
    file.seek(SeekFrom::Start(block_offset))?;
    let mut raw = vec![0u8; block_len as usize];
    file.read_exact(&mut raw)?;

    let body_end = raw.len() - 4;
    let mut cpos = body_end;
    let expected_crc = read_u32_le(&raw, &mut cpos)?;
    if crc32_ieee(&raw[..body_end]) != expected_crc {
        return Err(EngineError::CorruptedPersistence(
            "SSTable 4KB data block CRC32 mismatch".to_string(),
        ));
    }

    let body = &raw[..body_end];
    let mut pos = 0usize;
    let count = read_u32_le(body, &mut pos)? as usize;
    let mut entries = Vec::with_capacity(count);

    for _ in 0..count {
        let klen = read_u32_le(body, &mut pos)? as usize;
        if pos + klen + 1 > body.len() {
            return Err(EngineError::CorruptedPersistence(
                "SSTable data block record truncated".to_string(),
            ));
        }
        let key = body[pos..pos + klen].to_vec().into_boxed_slice();
        pos += klen;
        let tag = body[pos];
        pos += 1;
        let entry = match tag {
            1 => {
                let vlen = read_u32_le(body, &mut pos)? as usize;
                if pos + vlen > body.len() {
                    return Err(EngineError::CorruptedPersistence(
                        "SSTable value truncated".to_string(),
                    ));
                }
                let val = body[pos..pos + vlen].to_vec().into_boxed_slice();
                pos += vlen;
                LsmEntry::Value(val)
            }
            0 => LsmEntry::Tombstone,
            other => {
                return Err(EngineError::CorruptedPersistence(format!(
                    "invalid SSTable entry tag {}",
                    other
                )))
            }
        };
        entries.push((key, entry));
    }
    Ok(entries)
}

/// Zero-copy point lookup inside a CRC32-verified 4 KB SSTable block: borrows `&body[pos..pos+klen]`
/// slices in-place and only allocates a `Box<[u8]>` if `target_key` matches.
fn find_key_in_verified_block(
    file: &mut File,
    block_offset: u64,
    block_len: u32,
    target_key: &[u8],
) -> EngineResult<Option<LsmEntry>> {
    if block_len < 8 {
        return Err(EngineError::CorruptedPersistence(
            "corrupted SSTable data block length".to_string(),
        ));
    }
    file.seek(SeekFrom::Start(block_offset))?;
    let mut raw = vec![0u8; block_len as usize];
    file.read_exact(&mut raw)?;

    let body_end = raw.len() - 4;
    let mut cpos = body_end;
    let expected_crc = read_u32_le(&raw, &mut cpos)?;
    if crc32_ieee(&raw[..body_end]) != expected_crc {
        return Err(EngineError::CorruptedPersistence(
            "SSTable 4KB data block CRC32 mismatch".to_string(),
        ));
    }

    let body = &raw[..body_end];
    let mut pos = 0usize;
    let count = read_u32_le(body, &mut pos)? as usize;

    for _ in 0..count {
        let klen = read_u32_le(body, &mut pos)? as usize;
        if pos + klen + 1 > body.len() {
            return Err(EngineError::CorruptedPersistence(
                "SSTable data block record truncated".to_string(),
            ));
        }
        let key_slice = &body[pos..pos + klen];
        pos += klen;
        let tag = body[pos];
        pos += 1;
        let ord = key_slice.cmp(target_key);
        match tag {
            1 => {
                let vlen = read_u32_le(body, &mut pos)? as usize;
                if pos + vlen > body.len() {
                    return Err(EngineError::CorruptedPersistence(
                        "SSTable value truncated".to_string(),
                    ));
                }
                if ord == std::cmp::Ordering::Equal {
                    let val = body[pos..pos + vlen].to_vec().into_boxed_slice();
                    return Ok(Some(LsmEntry::Value(val)));
                }
                if ord == std::cmp::Ordering::Greater {
                    return Ok(None);
                }
                pos += vlen;
            }
            0 => {
                if ord == std::cmp::Ordering::Equal {
                    return Ok(Some(LsmEntry::Tombstone));
                }
                if ord == std::cmp::Ordering::Greater {
                    return Ok(None);
                }
            }
            other => {
                return Err(EngineError::CorruptedPersistence(format!(
                    "invalid SSTable entry tag {}",
                    other
                )))
            }
        }
    }
    Ok(None)
}

fn search_sstable_on_disk(sst: &SsTableMeta, key: &[u8]) -> EngineResult<Option<LsmEntry>> {
    if sst.fence_index.is_empty() {
        return Ok(None);
    }
    // Binary search fence pointers for the rightmost block whose `first_key <= key`.
    let upper = sst
        .fence_index
        .partition_point(|fp| fp.first_key.as_ref() <= key);
    if upper == 0 {
        return Ok(None);
    }
    let fp = &sst.fence_index[upper - 1];
    let mut file = File::open(&sst.path)?;
    find_key_in_verified_block(&mut file, fp.block_offset, fp.block_len, key)
}

fn read_all_sstable_entries(sst: &SsTableMeta) -> EngineResult<Vec<(Box<[u8]>, LsmEntry)>> {
    let mut file = File::open(&sst.path)?;
    let mut out = Vec::with_capacity(sst.entry_count);
    for fp in &sst.fence_index {
        let mut block = decode_verified_data_block(&mut file, fp.block_offset, fp.block_len)?;
        out.append(&mut block);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::process;

    #[test]
    fn test_lsm_sstable_flush_bloom_compaction_and_tombstone_purge() -> EngineResult<()> {
        let dir = env::temp_dir().join(format!("ferrum_lsm_test_{}", process::id()));
        let _ = fs::remove_dir_all(&dir);

        {
            let lsm = LsmEngine::open(&dir, 4096)?;
            for i in 0..350u32 {
                let k = format!("row:{i:05}");
                let v = format!("payload_generation_1_{i:05}_padding_for_4kb_blocks");
                lsm.put(k.as_bytes(), v.as_bytes())?;
            }
            lsm.flush()?;

            // Overwrite even keys and tombstone-delete multiples of 5 in a second SSTable
            for i in 0..350u32 {
                let k = format!("row:{i:05}");
                if i % 5 == 0 {
                    lsm.delete(k.as_bytes())?;
                } else if i % 2 == 0 {
                    let v = format!("payload_generation_2_{i:05}");
                    lsm.put(k.as_bytes(), v.as_bytes())?;
                }
            }
            lsm.flush()?;

            let (_, sst_count_before, _) = lsm.stats()?;
            assert!(sst_count_before >= 2);

            assert_eq!(lsm.get(b"row:00005")?, None);
            assert_eq!(
                lsm.get(b"row:00002")?.as_deref(),
                Some(b"payload_generation_2_00002".as_slice())
            );

            let remaining_ssts = lsm.compact_all()?;
            assert_eq!(remaining_ssts, 1);
        }

        // Reopen from disk to verify SSTable footer/index/bloom/CRC32 reload & tombstone purge
        let reopened = LsmEngine::open(&dir, 4096)?;
        let (_, sst_count, total_entries) = reopened.stats()?;
        assert_eq!(sst_count, 1);
        assert_eq!(total_entries, 280); // 350 - 70 purged tombstones!
        assert_eq!(reopened.get(b"row:00010")?, None);
        assert_eq!(
            reopened.get(b"row:00004")?.as_deref(),
            Some(b"payload_generation_2_00004".as_slice())
        );

        let scanned = reopened.scan(b"row:00000", b"row:00009", 100)?;
        assert_eq!(scanned.len(), 8); // 00000 & 00005 were deleted

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
