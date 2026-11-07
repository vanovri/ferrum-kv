use crate::storage::hashtable::RawHashTable;

const BM25_K1: f64 = 1.2;
const BM25_B: f64 = 0.75;

const STOP_WORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "is", "it", "of", "on",
    "or", "that", "the", "to", "was", "with",
];

#[inline]
fn is_stop_word(token: &str) -> bool {
    STOP_WORDS.binary_search(&token).is_ok()
}

pub fn tokenize_text(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            for lower in ch.to_lowercase() {
                current.push(lower);
            }
        } else if !current.is_empty() {
            if !is_stop_word(&current) {
                tokens.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if !current.is_empty() && !is_stop_word(&current) {
        tokens.push(current);
    }
    tokens
}

fn write_varint_u32(out: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
}

fn read_varint_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 0u32;
    while *pos < buf.len() {
        let byte = buf[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    None
}

/// LEB128 variable-byte delta-encoded posting list (`(doc_id - prev_doc_id, term_freq)`).
#[derive(Clone, Debug, Default)]
pub struct DeltaPostingList {
    encoded: Vec<u8>,
    last_doc_id: u32,
    doc_freq: u32,
}

impl DeltaPostingList {
    pub fn push_sorted(&mut self, doc_id: u32, tf: u32) {
        let delta = if self.doc_freq == 0 {
            doc_id
        } else {
            doc_id.saturating_sub(self.last_doc_id)
        };
        write_varint_u32(&mut self.encoded, delta);
        write_varint_u32(&mut self.encoded, tf);
        self.last_doc_id = doc_id;
        self.doc_freq += 1;
    }

    #[inline]
    pub fn doc_freq(&self) -> u32 {
        self.doc_freq
    }

    pub fn decode_all(&self) -> Vec<(u32, u32)> {
        let mut out = Vec::with_capacity(self.doc_freq as usize);
        let mut pos = 0usize;
        let mut acc_doc = 0u32;
        let mut first = true;
        while pos < self.encoded.len() {
            let Some(delta) = read_varint_u32(&self.encoded, &mut pos) else {
                break;
            };
            let Some(tf) = read_varint_u32(&self.encoded, &mut pos) else {
                break;
            };
            if first {
                acc_doc = delta;
                first = false;
            } else {
                acc_doc = acc_doc.saturating_add(delta);
            }
            out.push((acc_doc, tf));
        }
        out
    }
}

#[derive(Clone, Debug, Default)]
struct TrieNode {
    children: Vec<(u8, u32)>,
    terminal_freq: u32,
}

/// Arena-backed prefix & fuzzy vocabulary trie.
#[derive(Clone, Debug)]
pub struct VocabularyTrie {
    nodes: Vec<TrieNode>,
}

impl Default for VocabularyTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl VocabularyTrie {
    pub fn new() -> Self {
        Self {
            nodes: vec![TrieNode::default()],
        }
    }

    pub fn insert(&mut self, word: &str, count: u32) {
        let mut curr = 0u32;
        for &b in word.as_bytes() {
            let next = if let Some(&(_, child_idx)) =
                self.nodes[curr as usize].children.iter().find(|&&(ch, _)| ch == b)
            {
                child_idx
            } else {
                let idx = self.nodes.len() as u32;
                self.nodes.push(TrieNode::default());
                self.nodes[curr as usize].children.push((b, idx));
                self.nodes[curr as usize].children.sort_unstable_by_key(|x| x.0);
                idx
            };
            curr = next;
        }
        self.nodes[curr as usize].terminal_freq =
            self.nodes[curr as usize].terminal_freq.saturating_add(count);
    }

    pub fn suggest_prefix(&self, prefix: &str, limit: usize) -> Vec<String> {
        let norm = prefix.to_lowercase();
        let mut curr = 0u32;
        for &b in norm.as_bytes() {
            match self.nodes[curr as usize]
                .children
                .iter()
                .find(|&&(ch, _)| ch == b)
            {
                Some(&(_, next)) => curr = next,
                None => return Vec::new(),
            }
        }

        let mut matches: Vec<(u32, String)> = Vec::new();
        let mut buf = norm.into_bytes();
        self.collect_subtree(curr, &mut buf, &mut matches);
        matches.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        matches.into_iter().take(limit).map(|(_, w)| w).collect()
    }

    fn collect_subtree(&self, idx: u32, buf: &mut Vec<u8>, out: &mut Vec<(u32, String)>) {
        let node = &self.nodes[idx as usize];
        if node.terminal_freq > 0 {
            if let Ok(s) = std::str::from_utf8(buf) {
                out.push((node.terminal_freq, s.to_string()));
            }
        }
        for &(ch, child) in &node.children {
            buf.push(ch);
            self.collect_subtree(child, buf, out);
            buf.pop();
        }
    }
}

/// Optimal String Alignment / Damerau-Levenshtein distance <= 1 check (insert, delete, replace, adjacent transpose).
pub fn damerau_levenshtein_le_1(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab == bb {
        return true;
    }
    let la = ab.len();
    let lb = bb.len();
    if la.abs_diff(lb) > 1 {
        return false;
    }

    let mut i = 0usize;
    while i < la.min(lb) && ab[i] == bb[i] {
        i += 1;
    }
    if la == lb {
        // Either single substitution at `i` OR adjacent transposition at `i` and `i + 1`.
        if ab[i + 1..] == bb[i + 1..] {
            return true;
        }
        if i + 1 < la && ab[i] == bb[i + 1] && ab[i + 1] == bb[i] && ab[i + 2..] == bb[i + 2..] {
            return true;
        }
        false
    } else if la + 1 == lb {
        // Single insertion in `b` at position `i`
        ab[i..] == bb[i + 1..]
    } else {
        // Single deletion from `a` at position `i`
        ab[i + 1..] == bb[i..]
    }
}

#[derive(Clone, Debug)]
struct StoredDoc {
    external_id: Box<[u8]>,
    raw_text: String,
    length: u32,
    deleted: bool,
}

/// Okapi BM25 Inverted Full-Text Search Index with delta-encoded postings and Damerau-Levenshtein-1 fuzzy fallback.
#[derive(Clone, Debug, Default)]
pub struct FullTextIndex {
    docs: Vec<StoredDoc>,
    ext_to_internal: RawHashTable<u32>,
    postings: RawHashTable<DeltaPostingList>,
    trie: VocabularyTrie,
    active_docs: usize,
    total_active_tokens: u64,
}

impl FullTextIndex {
    pub fn new() -> Self {
        Self {
            docs: Vec::new(),
            ext_to_internal: RawHashTable::new(),
            postings: RawHashTable::new(),
            trie: VocabularyTrie::new(),
            active_docs: 0,
            total_active_tokens: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.active_docs
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.active_docs == 0
    }

    pub fn active_documents(&self) -> impl Iterator<Item = (&[u8], &str)> {
        self.docs
            .iter()
            .filter(|d| !d.deleted)
            .map(|d| (d.external_id.as_ref(), d.raw_text.as_str()))
    }

    /// Indexes or replaces `(doc_id, text)`, returning `true` if `doc_id` is new.
    pub fn add_document(&mut self, doc_id: &[u8], text: &str) -> bool {
        let mut is_new = true;
        if let Some(&prev_idx) = self.ext_to_internal.get(doc_id) {
            if !self.docs[prev_idx as usize].deleted {
                self.docs[prev_idx as usize].deleted = true;
                self.active_docs = self.active_docs.saturating_sub(1);
                self.total_active_tokens = self
                    .total_active_tokens
                    .saturating_sub(self.docs[prev_idx as usize].length as u64);
                is_new = false;
            }
        }

        let tokens = tokenize_text(text);
        let doc_len = tokens.len() as u32;
        let internal_id = self.docs.len() as u32;

        let mut term_counts: RawHashTable<u32> = RawHashTable::new();
        for tok in &tokens {
            if let Some(cnt) = term_counts.get_mut(tok.as_bytes()) {
                *cnt += 1;
            } else {
                term_counts.insert(tok.as_bytes().to_vec().into_boxed_slice(), 1);
            }
        }

        for (term_bytes, &tf) in term_counts.iter() {
            if let Ok(term_str) = std::str::from_utf8(term_bytes) {
                self.trie.insert(term_str, tf);
            }
            if let Some(plist) = self.postings.get_mut(term_bytes) {
                plist.push_sorted(internal_id, tf);
            } else {
                let mut plist = DeltaPostingList::default();
                plist.push_sorted(internal_id, tf);
                self.postings
                    .insert(term_bytes.to_vec().into_boxed_slice(), plist);
            }
        }

        self.docs.push(StoredDoc {
            external_id: doc_id.to_vec().into_boxed_slice(),
            raw_text: text.to_string(),
            length: doc_len,
            deleted: false,
        });
        self.ext_to_internal
            .insert(doc_id.to_vec().into_boxed_slice(), internal_id);
        self.active_docs += 1;
        self.total_active_tokens += doc_len as u64;
        is_new
    }

    pub fn search(&self, query: &str, limit: usize) -> Vec<(Box<[u8]>, f64)> {
        if self.active_docs == 0 {
            return Vec::new();
        }
        let q_tokens = tokenize_text(query);
        if q_tokens.is_empty() {
            return Vec::new();
        }

        let n_docs = self.active_docs as f64;
        let avgdl = (self.total_active_tokens as f64 / n_docs).max(1.0);
        let mut doc_scores = vec![0.0f64; self.docs.len()];

        for q_tok in &q_tokens {
            let mut expanded_terms: Vec<(&DeltaPostingList, f64)> = Vec::new();
            if let Some(exact_plist) = self.postings.get(q_tok.as_bytes()) {
                expanded_terms.push((exact_plist, 1.0));
            } else if q_tok.len() >= 3 {
                // Damerau-Levenshtein distance-1 fuzzy expansion when exact term is absent
                for (cand_bytes, plist) in self.postings.iter() {
                    if let Ok(cand_str) = std::str::from_utf8(cand_bytes) {
                        if damerau_levenshtein_le_1(q_tok, cand_str) {
                            expanded_terms.push((plist, 0.75));
                        }
                    }
                }
            }

            for (plist, weight) in expanded_terms {
                let decoded = plist.decode_all();
                let active_df = decoded
                    .iter()
                    .filter(|&&(did, _)| !self.docs[did as usize].deleted)
                    .count() as f64;
                if active_df == 0.0 {
                    continue;
                }
                let idf = (1.0 + (n_docs - active_df + 0.5) / (active_df + 0.5)).ln();

                for (did, tf) in decoded {
                    let doc = &self.docs[did as usize];
                    if doc.deleted {
                        continue;
                    }
                    let tf_f = tf as f64;
                    let dl = doc.length as f64;
                    let norm = tf_f + BM25_K1 * (1.0 - BM25_B + BM25_B * (dl / avgdl));
                    let term_score = weight * idf * ((tf_f * (BM25_K1 + 1.0)) / norm);
                    doc_scores[did as usize] += term_score;
                }
            }
        }

        let mut ranked: Vec<(u32, f64)> = doc_scores
            .into_iter()
            .enumerate()
            .filter(|&(idx, score)| score > 0.0 && !self.docs[idx].deleted)
            .map(|(idx, score)| (idx as u32, score))
            .collect();

        ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        ranked.truncate(limit);

        ranked
            .into_iter()
            .map(|(idx, score)| (self.docs[idx as usize].external_id.clone(), score))
            .collect()
    }

    pub fn suggest(&self, prefix: &str, limit: usize) -> Vec<String> {
        self.trie.suggest_prefix(prefix, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bm25_ranking_delta_postings_and_damerau_fuzzy() {
        let mut fts = FullTextIndex::new();
        fts.add_document(
            b"doc1",
            "Rust systems programming with zero copy memory safety and Rust performance",
        );
        fts.add_document(
            b"doc2",
            "Python scripting for web prototypes and quick data notebooks",
        );
        fts.add_document(
            b"doc3",
            "Rust compiler architecture and lock free concurrent hash tables",
        );

        // Exact BM25 ranking: doc1 mentions "rust" twice, so it outranks doc3 ("rust" once), while doc2 is excluded.
        let results = fts.search("rust", 10);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0.as_ref(), b"doc1");
        assert_eq!(results[1].0.as_ref(), b"doc3");
        assert!(results[0].1 > results[1].1);

        // Damerau-Levenshtein transposition typo: "compilre" -> "compiler" matches doc3!
        let fuzzy = fts.search("compilre", 5);
        assert_eq!(fuzzy.len(), 1);
        assert_eq!(fuzzy[0].0.as_ref(), b"doc3");

        // Prefix autocomplete
        let sugg = fts.suggest("pro", 5);
        assert!(sugg.contains(&"programming".to_string()));
        assert!(sugg.contains(&"prototypes".to_string()));
    }
}
