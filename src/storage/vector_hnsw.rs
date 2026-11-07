use std::cmp::Ordering;
use std::collections::BinaryHeap;

use crate::error::{EngineError, EngineResult};
use crate::storage::hashtable::RawHashTable;

pub const HNSW_M: usize = 16;
pub const HNSW_M_MAX0: usize = 32;
pub const HNSW_EF_CONSTRUCTION: usize = 64;
pub const HNSW_EF_SEARCH: usize = 32;
pub const HNSW_MAX_LAYERS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorMetric {
    Cosine = 0,
    L2 = 1,
    InnerProduct = 2,
}

impl VectorMetric {
    pub fn from_bytes(raw: &[u8]) -> EngineResult<Self> {
        if raw.eq_ignore_ascii_case(b"COSINE") || raw.eq_ignore_ascii_case(b"COS") {
            Ok(VectorMetric::Cosine)
        } else if raw.eq_ignore_ascii_case(b"L2") || raw.eq_ignore_ascii_case(b"EUCLIDEAN") {
            Ok(VectorMetric::L2)
        } else if raw.eq_ignore_ascii_case(b"IP") || raw.eq_ignore_ascii_case(b"DOT") {
            Ok(VectorMetric::InnerProduct)
        } else {
            Err(EngineError::InvalidArgument(
                "unknown vector metric, expected COSINE|L2|IP".to_string(),
            ))
        }
    }

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(c: u8) -> EngineResult<Self> {
        match c {
            0 => Ok(VectorMetric::Cosine),
            1 => Ok(VectorMetric::L2),
            2 => Ok(VectorMetric::InnerProduct),
            _ => Err(EngineError::CorruptedPersistence(
                "invalid HNSW metric tag".to_string(),
            )),
        }
    }
}

/// 8-bit Scalar Quantized (`SQ8`) vector representation: `v_i ~= min_val + (code_i as i32 + 128) * scale`.
#[derive(Clone, Debug)]
pub struct Sq8Vector {
    pub min_val: f32,
    pub scale: f32,
    pub codes: Box<[i8]>,
}

impl Sq8Vector {
    pub fn quantize(vec: &[f32]) -> Self {
        let mut min_v = f32::INFINITY;
        let mut max_v = f32::NEG_INFINITY;
        for &v in vec {
            if v < min_v {
                min_v = v;
            }
            if v > max_v {
                max_v = v;
            }
        }
        if !min_v.is_finite() || !max_v.is_finite() {
            min_v = 0.0;
            max_v = 0.0;
        }
        let span = max_v - min_v;
        let scale = if span <= 1e-12 { 0.0 } else { span / 255.0 };
        let inv = if scale == 0.0 { 0.0 } else { 1.0 / scale };

        let mut codes = Vec::with_capacity(vec.len());
        for &v in vec {
            let q = ((v - min_v) * inv).round().clamp(0.0, 255.0) as i32 - 128;
            codes.push(q as i8);
        }
        Self {
            min_val: min_v,
            scale,
            codes: codes.into_boxed_slice(),
        }
    }

    #[inline]
    pub fn approx_distance(&self, other: &Sq8Vector, metric: VectorMetric) -> f32 {
        match metric {
            VectorMetric::L2 => {
                let mut sum = 0.0f32;
                for i in 0..self.codes.len() {
                    let a = self.min_val + ((self.codes[i] as i32 + 128) as f32) * self.scale;
                    let b = other.min_val + ((other.codes[i] as i32 + 128) as f32) * other.scale;
                    let d = a - b;
                    sum += d * d;
                }
                sum
            }
            VectorMetric::Cosine => {
                let mut dot = 0.0f32;
                let mut na = 0.0f32;
                let mut nb = 0.0f32;
                for i in 0..self.codes.len() {
                    let a = self.min_val + ((self.codes[i] as i32 + 128) as f32) * self.scale;
                    let b = other.min_val + ((other.codes[i] as i32 + 128) as f32) * other.scale;
                    dot += a * b;
                    na += a * a;
                    nb += b * b;
                }
                let denom = (na * nb).sqrt();
                if denom <= 1e-12 {
                    1.0
                } else {
                    (1.0 - (dot / denom)).max(0.0)
                }
            }
            VectorMetric::InnerProduct => {
                let mut dot = 0.0f32;
                for i in 0..self.codes.len() {
                    let a = self.min_val + ((self.codes[i] as i32 + 128) as f32) * self.scale;
                    let b = other.min_val + ((other.codes[i] as i32 + 128) as f32) * other.scale;
                    dot += a * b;
                }
                -dot
            }
        }
    }
}

#[inline]
pub fn exact_distance(a: &[f32], b: &[f32], metric: VectorMetric) -> f32 {
    match metric {
        VectorMetric::L2 => {
            let mut sum = 0.0f32;
            for i in 0..a.len() {
                let d = a[i] - b[i];
                sum += d * d;
            }
            sum
        }
        VectorMetric::Cosine => {
            let mut dot = 0.0f32;
            let mut na = 0.0f32;
            let mut nb = 0.0f32;
            for i in 0..a.len() {
                dot += a[i] * b[i];
                na += a[i] * a[i];
                nb += b[i] * b[i];
            }
            let denom = (na * nb).sqrt();
            if denom <= 1e-12 {
                1.0
            } else {
                (1.0 - (dot / denom)).max(0.0)
            }
        }
        VectorMetric::InnerProduct => {
            let mut dot = 0.0f32;
            for i in 0..a.len() {
                dot += a[i] * b[i];
            }
            -dot
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct DistNode {
    dist: f32,
    node_idx: u32,
}

impl PartialEq for DistNode {
    fn eq(&self, other: &Self) -> bool {
        self.dist.total_cmp(&other.dist) == Ordering::Equal && self.node_idx == other.node_idx
    }
}
impl Eq for DistNode {}

impl PartialOrd for DistNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for DistNode {
    /// Max-heap ordering (`furthest` at top).
    fn cmp(&self, other: &Self) -> Ordering {
        self.dist
            .total_cmp(&other.dist)
            .then_with(|| self.node_idx.cmp(&other.node_idx))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MinDistNode(DistNode);

impl PartialOrd for MinDistNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for MinDistNode {
    /// Min-heap ordering (`nearest` at top).
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.cmp(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct HnswNode {
    pub external_id: Box<[u8]>,
    pub raw_vec: Box<[f32]>,
    pub sq8_vec: Sq8Vector,
    pub deleted: bool,
    pub neighbors: Vec<Vec<u32>>,
}

/// Multi-layer Hierarchical Navigable Small World (HNSW) vector similarity graph.
#[derive(Clone, Debug)]
pub struct HnswIndex {
    dim: usize,
    metric: VectorMetric,
    use_sq8_traversal: bool,
    nodes: Vec<HnswNode>,
    id_to_idx: RawHashTable<u32>,
    entry_point: Option<u32>,
    max_layer: usize,
    active_count: usize,
    rng_state: u64,
}

impl Default for HnswIndex {
    fn default() -> Self {
        Self::new(VectorMetric::Cosine, true)
    }
}

impl HnswIndex {
    pub fn new(metric: VectorMetric, use_sq8_traversal: bool) -> Self {
        Self {
            dim: 0,
            metric,
            use_sq8_traversal,
            nodes: Vec::new(),
            id_to_idx: RawHashTable::new(),
            entry_point: None,
            max_layer: 0,
            active_count: 0,
            rng_state: 0x9e37_79b9_7f4a_7c15,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.active_count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.active_count == 0
    }

    #[inline]
    pub fn dimension(&self) -> usize {
        self.dim
    }

    #[inline]
    pub fn metric(&self) -> VectorMetric {
        self.metric
    }

    #[inline]
    pub fn uses_sq8(&self) -> bool {
        self.use_sq8_traversal
    }

    pub fn active_entries(&self) -> impl Iterator<Item = (&[u8], &[f32])> {
        self.nodes
            .iter()
            .filter(|n| !n.deleted)
            .map(|n| (n.external_id.as_ref(), n.raw_vec.as_ref()))
    }

    fn random_layer(&mut self) -> usize {
        // Exponential decay with m_L = 1 / ln(M = 16): P(level >= l + 1) = 1/16.
        let mut lvl = 0usize;
        while lvl + 1 < HNSW_MAX_LAYERS {
            self.rng_state ^= self.rng_state >> 12;
            self.rng_state ^= self.rng_state << 25;
            self.rng_state ^= self.rng_state >> 27;
            let r = self.rng_state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32;
            if (r & 0x0F) == 0 {
                lvl += 1;
            } else {
                break;
            }
        }
        lvl
    }

    #[inline]
    fn dist_to_query(&self, node_idx: u32, q_raw: &[f32], q_sq8: &Sq8Vector) -> f32 {
        let node = &self.nodes[node_idx as usize];
        if self.use_sq8_traversal {
            node.sq8_vec.approx_distance(q_sq8, self.metric)
        } else {
            exact_distance(&node.raw_vec, q_raw, self.metric)
        }
    }

    fn search_layer(
        &self,
        q_raw: &[f32],
        q_sq8: &Sq8Vector,
        entry_idx: u32,
        ef: usize,
        layer: usize,
    ) -> Vec<DistNode> {
        let total_nodes = self.nodes.len();
        let mut visited = vec![false; total_nodes];
        visited[entry_idx as usize] = true;

        let d0 = self.dist_to_query(entry_idx, q_raw, q_sq8);
        let mut candidates = BinaryHeap::new();
        let mut results = BinaryHeap::new();

        candidates.push(MinDistNode(DistNode {
            dist: d0,
            node_idx: entry_idx,
        }));
        results.push(DistNode {
            dist: d0,
            node_idx: entry_idx,
        });

        while let Some(MinDistNode(curr)) = candidates.pop() {
            let worst_dist = results.peek().map(|n| n.dist).unwrap_or(f32::INFINITY);
            if curr.dist > worst_dist && results.len() >= ef {
                break;
            }

            if let Some(neighs) = self.nodes[curr.node_idx as usize].neighbors.get(layer) {
                for &nb_idx in neighs {
                    if !visited[nb_idx as usize] {
                        visited[nb_idx as usize] = true;
                        let d = self.dist_to_query(nb_idx, q_raw, q_sq8);
                        let cur_worst = results.peek().map(|n| n.dist).unwrap_or(f32::INFINITY);
                        if results.len() < ef || d < cur_worst {
                            candidates.push(MinDistNode(DistNode {
                                dist: d,
                                node_idx: nb_idx,
                            }));
                            results.push(DistNode {
                                dist: d,
                                node_idx: nb_idx,
                            });
                            if results.len() > ef {
                                results.pop();
                            }
                        }
                    }
                }
            }
        }

        let mut vec_res: Vec<DistNode> = results.into_vec();
        vec_res.sort_unstable();
        vec_res
    }

    /// Inserts or updates a vector (`VADD`), returning `true` if `id` is newly inserted.
    pub fn upsert(
        &mut self,
        id: &[u8],
        vec: &[f32],
        metric_override: Option<VectorMetric>,
        sq8_override: Option<bool>,
    ) -> EngineResult<bool> {
        if vec.is_empty() {
            return Err(EngineError::InvalidArgument(
                "vector must contain at least 1 dimension".to_string(),
            ));
        }
        for &x in vec {
            if !x.is_finite() {
                return Err(EngineError::InvalidArgument(
                    "vector coordinates must be finite numbers".to_string(),
                ));
            }
        }
        if self.active_count == 0 && self.nodes.is_empty() {
            self.dim = vec.len();
            if let Some(m) = metric_override {
                self.metric = m;
            }
            if let Some(sq) = sq8_override {
                self.use_sq8_traversal = sq;
            }
        } else if vec.len() != self.dim {
            return Err(EngineError::InvalidArgument(format!(
                "vector dimension mismatch: index expects {}, got {}",
                self.dim,
                vec.len()
            )));
        }

        let was_present = if let Some(&existing_idx) = self.id_to_idx.get(id) {
            if !self.nodes[existing_idx as usize].deleted {
                self.nodes[existing_idx as usize].deleted = true;
                self.active_count = self.active_count.saturating_sub(1);
                true
            } else {
                false
            }
        } else {
            false
        };

        let node_layer = self.random_layer();
        let new_idx = self.nodes.len() as u32;
        let sq8 = Sq8Vector::quantize(vec);

        self.nodes.push(HnswNode {
            external_id: id.to_vec().into_boxed_slice(),
            raw_vec: vec.to_vec().into_boxed_slice(),
            sq8_vec: sq8.clone(),
            deleted: false,
            neighbors: vec![Vec::new(); node_layer + 1],
        });
        self.id_to_idx
            .insert(id.to_vec().into_boxed_slice(), new_idx);
        self.active_count += 1;

        let Some(mut curr_ep) = self.entry_point else {
            self.entry_point = Some(new_idx);
            self.max_layer = node_layer;
            return Ok(!was_present);
        };

        let current_max = self.max_layer;
        if current_max > node_layer {
            for layer in ((node_layer + 1)..=current_max).rev() {
                let nearest = self.search_layer(vec, &sq8, curr_ep, 1, layer);
                if let Some(best) = nearest.first() {
                    curr_ep = best.node_idx;
                }
            }
        }

        let top_connect_layer = node_layer.min(current_max);
        for layer in (0..=top_connect_layer).rev() {
            let max_m = if layer == 0 { HNSW_M_MAX0 } else { HNSW_M };
            let candidates = self.search_layer(vec, &sq8, curr_ep, HNSW_EF_CONSTRUCTION, layer);
            if let Some(best) = candidates.first() {
                curr_ep = best.node_idx;
            }

            let selected: Vec<u32> = candidates
                .iter()
                .filter(|c| c.node_idx != new_idx)
                .take(max_m)
                .map(|c| c.node_idx)
                .collect();

            self.nodes[new_idx as usize].neighbors[layer] = selected.clone();

            for nb_idx in selected {
                if layer >= self.nodes[nb_idx as usize].neighbors.len() {
                    continue;
                }
                if !self.nodes[nb_idx as usize].neighbors[layer].contains(&new_idx) {
                    self.nodes[nb_idx as usize].neighbors[layer].push(new_idx);
                }
                if self.nodes[nb_idx as usize].neighbors[layer].len() > max_m {
                    // Prune furthest neighbor using exact f32 distance to maintain graph navigability.
                    let nb_raw = self.nodes[nb_idx as usize].raw_vec.clone();
                    let current_list = self.nodes[nb_idx as usize].neighbors[layer].clone();
                    let mut scored: Vec<(f32, u32)> = current_list
                        .into_iter()
                        .map(|cand_id| {
                            let d = exact_distance(
                                &nb_raw,
                                &self.nodes[cand_id as usize].raw_vec,
                                self.metric,
                            );
                            (d, cand_id)
                        })
                        .collect();
                    scored.sort_by(|a, b| a.0.total_cmp(&b.0));
                    scored.truncate(max_m);
                    self.nodes[nb_idx as usize].neighbors[layer] =
                        scored.into_iter().map(|(_, id)| id).collect();
                }
            }
        }

        if node_layer > self.max_layer {
            self.entry_point = Some(new_idx);
            self.max_layer = node_layer;
        }

        Ok(!was_present)
    }

    pub fn remove(&mut self, id: &[u8]) -> bool {
        let Some(&idx) = self.id_to_idx.get(id) else {
            return false;
        };
        if self.nodes[idx as usize].deleted {
            return false;
        }
        self.nodes[idx as usize].deleted = true;
        self.id_to_idx.remove(id);
        self.active_count = self.active_count.saturating_sub(1);
        if self.active_count == 0 {
            self.nodes.clear();
            self.entry_point = None;
            self.max_layer = 0;
        }
        true
    }

    /// Searches top-`k` nearest neighbors (`VSEARCH`), reranking final candidates with exact `f32` metric.
    pub fn search(
        &self,
        query: &[f32],
        k: usize,
        ef_override: Option<usize>,
    ) -> EngineResult<Vec<(Box<[u8]>, f64)>> {
        if self.active_count == 0 {
            return Ok(Vec::new());
        }
        if query.len() != self.dim {
            return Err(EngineError::InvalidArgument(format!(
                "query vector dimension mismatch: expected {}, got {}",
                self.dim,
                query.len()
            )));
        }
        let Some(mut curr_ep) = self.entry_point else {
            return Ok(Vec::new());
        };

        let q_sq8 = Sq8Vector::quantize(query);
        for layer in (1..=self.max_layer).rev() {
            let best = self.search_layer(query, &q_sq8, curr_ep, 1, layer);
            if let Some(first) = best.first() {
                curr_ep = first.node_idx;
            }
        }

        let ef = ef_override
            .unwrap_or(HNSW_EF_SEARCH)
            .max(k.saturating_mul(2))
            .max(16);
        let raw_candidates = self.search_layer(query, &q_sq8, curr_ep, ef, 0);

        let mut reranked: Vec<(f32, u32)> = raw_candidates
            .into_iter()
            .filter(|c| !self.nodes[c.node_idx as usize].deleted)
            .map(|c| {
                let exact = exact_distance(
                    query,
                    &self.nodes[c.node_idx as usize].raw_vec,
                    self.metric,
                );
                (exact, c.node_idx)
            })
            .collect();

        reranked.sort_by(|a, b| a.0.total_cmp(&b.0));
        reranked.truncate(k);

        Ok(reranked
            .into_iter()
            .map(|(d, idx)| {
                let reported = match self.metric {
                    VectorMetric::Cosine => (1.0 - d) as f64,
                    VectorMetric::InnerProduct => (-d) as f64,
                    VectorMetric::L2 => (d.max(0.0).sqrt()) as f64,
                };
                (self.nodes[idx as usize].external_id.clone(), reported)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hnsw_sq8_recall_at_5_above_90_percent() -> EngineResult<()> {
        let mut hnsw = HnswIndex::new(VectorMetric::L2, true);
        let dim = 16usize;
        let count = 400usize;
        let mut dataset: Vec<(String, Vec<f32>)> = Vec::with_capacity(count);

        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next_f32 = || -> f32 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ((seed & 0xFFFF) as f32 / 32768.0) - 1.0
        };

        for i in 0..count {
            let v: Vec<f32> = (0..dim).map(|_| next_f32()).collect();
            let id = format!("vec:{i}");
            hnsw.upsert(id.as_bytes(), &v, None, None)?;
            dataset.push((id, v));
        }

        let num_queries = 30usize;
        let mut hits = 0usize;
        for _ in 0..num_queries {
            let q: Vec<f32> = (0..dim).map(|_| next_f32()).collect();
            let mut exact: Vec<(f32, &str)> = dataset
                .iter()
                .map(|(id, v)| (exact_distance(&q, v, VectorMetric::L2), id.as_str()))
                .collect();
            exact.sort_by(|a, b| a.0.total_cmp(&b.0));
            let truth_top5: Vec<&str> = exact.iter().take(5).map(|x| x.1).collect();

            let approx_top5 = hnsw.search(&q, 5, None)?;
            for (found_id, _) in &approx_top5 {
                let s = std::str::from_utf8(found_id)?;
                if truth_top5.contains(&s) {
                    hits += 1;
                }
            }
        }

        let recall = (hits as f64) / ((num_queries * 5) as f64);
        assert!(
            recall > 0.90,
            "expected HNSW recall@5 > 0.90, got {:.3}",
            recall
        );
        Ok(())
    }
}
