use std::cmp::Ordering;
use crate::storage::hashtable::RawHashTable;

const MAX_LEVEL: usize = 32;
const HEAD_IDX: u32 = 0;
const NIL_IDX: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
struct SkipLink {
    forward: u32,
    span: usize,
}

#[derive(Clone, Debug)]
struct SkipNode {
    score: f64,
    member: Box<[u8]>,
    backward: u32,
    levels: Vec<SkipLink>,
}

#[inline]
fn compare_score_member(a_score: f64, a_mem: &[u8], b_score: f64, b_mem: &[u8]) -> Ordering {
    match a_score.total_cmp(&b_score) {
        Ordering::Equal => a_mem.cmp(b_mem),
        other => other,
    }
}

/// Arena-allocated multi-level probabilistic SkipList with O(log N) rank spans.
#[derive(Clone, Debug)]
pub struct SkipList {
    nodes: Vec<SkipNode>,
    free_list: Vec<u32>,
    tail: u32,
    level: usize,
    len: usize,
    rng_state: u64,
}

impl Default for SkipList {
    fn default() -> Self {
        Self::new()
    }
}

impl SkipList {
    pub fn new() -> Self {
        let head = SkipNode {
            score: f64::NEG_INFINITY,
            member: Box::new([]),
            backward: NIL_IDX,
            levels: vec![
                SkipLink {
                    forward: NIL_IDX,
                    span: 0,
                };
                MAX_LEVEL
            ],
        };
        Self {
            nodes: vec![head],
            free_list: Vec::new(),
            tail: NIL_IDX,
            level: 1,
            len: 0,
            rng_state: 0x853c_49e6_748f_ea9b,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn next_rand_u32(&mut self) -> u32 {
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }

    /// Branching factor p = 0.25 (matching Redis ZSKIPLIST_P).
    fn random_level(&mut self) -> usize {
        let mut lvl = 1;
        while lvl < MAX_LEVEL && (self.next_rand_u32() & 0xFFFF) < 0x4000 {
            lvl += 1;
        }
        lvl
    }

    fn alloc_node(&mut self, score: f64, member: Box<[u8]>, lvl: usize) -> u32 {
        let links = vec![
            SkipLink {
                forward: NIL_IDX,
                span: 0,
            };
            lvl
        ];
        if let Some(reused) = self.free_list.pop() {
            self.nodes[reused as usize] = SkipNode {
                score,
                member,
                backward: NIL_IDX,
                levels: links,
            };
            reused
        } else {
            let idx = self.nodes.len() as u32;
            self.nodes.push(SkipNode {
                score,
                member,
                backward: NIL_IDX,
                levels: links,
            });
            idx
        }
    }

    pub fn insert(&mut self, score: f64, member: Box<[u8]>) {
        let mut update = [HEAD_IDX; MAX_LEVEL];
        let mut rank = [0usize; MAX_LEVEL];
        let mut curr = HEAD_IDX;

        for i in (0..self.level).rev() {
            rank[i] = if i == self.level - 1 { 0 } else { rank[i + 1] };
            loop {
                let link = self.nodes[curr as usize].levels[i];
                if link.forward == NIL_IDX {
                    break;
                }
                let next_node = &self.nodes[link.forward as usize];
                if compare_score_member(next_node.score, &next_node.member, score, &member)
                    == Ordering::Less
                {
                    rank[i] += link.span;
                    curr = link.forward;
                } else {
                    break;
                }
            }
            update[i] = curr;
        }

        let node_lvl = self.random_level();
        if node_lvl > self.level {
            for i in self.level..node_lvl {
                rank[i] = 0;
                update[i] = HEAD_IDX;
                self.nodes[HEAD_IDX as usize].levels[i].span = self.len;
            }
            self.level = node_lvl;
        }

        let new_idx = self.alloc_node(score, member, node_lvl);
        for i in 0..node_lvl {
            let pred = update[i] as usize;
            let pred_link = self.nodes[pred].levels[i];
            self.nodes[new_idx as usize].levels[i].forward = pred_link.forward;
            let delta = rank[0] - rank[i];
            self.nodes[new_idx as usize].levels[i].span = pred_link.span.saturating_sub(delta);
            self.nodes[pred].levels[i].forward = new_idx;
            self.nodes[pred].levels[i].span = delta + 1;
        }

        for i in node_lvl..self.level {
            let pred = update[i] as usize;
            self.nodes[pred].levels[i].span += 1;
        }

        self.nodes[new_idx as usize].backward = if update[0] == HEAD_IDX {
            NIL_IDX
        } else {
            update[0]
        };

        let next_lvl0 = self.nodes[new_idx as usize].levels[0].forward;
        if next_lvl0 != NIL_IDX {
            self.nodes[next_lvl0 as usize].backward = new_idx;
        } else {
            self.tail = new_idx;
        }

        self.len += 1;
    }

    pub fn remove(&mut self, score: f64, member: &[u8]) -> bool {
        let mut update = [HEAD_IDX; MAX_LEVEL];
        let mut curr = HEAD_IDX;

        for i in (0..self.level).rev() {
            loop {
                let fwd = self.nodes[curr as usize].levels[i].forward;
                if fwd == NIL_IDX {
                    break;
                }
                let next_node = &self.nodes[fwd as usize];
                if compare_score_member(next_node.score, &next_node.member, score, member)
                    == Ordering::Less
                {
                    curr = fwd;
                } else {
                    break;
                }
            }
            update[i] = curr;
        }

        let target = self.nodes[update[0] as usize].levels[0].forward;
        if target == NIL_IDX {
            return false;
        }
        let matches = {
            let node = &self.nodes[target as usize];
            node.score.total_cmp(&score) == Ordering::Equal && node.member.as_ref() == member
        };
        if !matches {
            return false;
        }

        for i in 0..self.level {
            let pred = update[i] as usize;
            if self.nodes[pred].levels[i].forward == target {
                let target_link = self.nodes[target as usize].levels[i];
                self.nodes[pred].levels[i].span =
                    self.nodes[pred].levels[i].span + target_link.span - 1;
                self.nodes[pred].levels[i].forward = target_link.forward;
            } else {
                self.nodes[pred].levels[i].span =
                    self.nodes[pred].levels[i].span.saturating_sub(1);
            }
        }

        let next_lvl0 = self.nodes[target as usize].levels[0].forward;
        let prev_lvl0 = self.nodes[target as usize].backward;
        if next_lvl0 != NIL_IDX {
            self.nodes[next_lvl0 as usize].backward = prev_lvl0;
        } else {
            self.tail = prev_lvl0;
        }

        while self.level > 1
            && self.nodes[HEAD_IDX as usize].levels[self.level - 1].forward == NIL_IDX
        {
            self.level -= 1;
        }

        self.nodes[target as usize].member = Box::new([]);
        self.nodes[target as usize].levels.clear();
        self.free_list.push(target);
        self.len -= 1;
        true
    }

    /// Returns 0-based rank in O(log N).
    pub fn rank_of(&self, score: f64, member: &[u8]) -> Option<usize> {
        let mut rank = 0usize;
        let mut curr = HEAD_IDX;

        for i in (0..self.level).rev() {
            loop {
                let link = self.nodes[curr as usize].levels[i];
                if link.forward == NIL_IDX {
                    break;
                }
                let next_node = &self.nodes[link.forward as usize];
                let ord = compare_score_member(next_node.score, &next_node.member, score, member);
                if ord != Ordering::Greater {
                    rank += link.span;
                    curr = link.forward;
                    if ord == Ordering::Equal {
                        return Some(rank - 1);
                    }
                } else {
                    break;
                }
            }
        }
        None
    }

    /// Jumps to 0-based index `start_rank` in O(log N) using level spans.
    fn node_at_rank(&self, zero_based_rank: usize) -> u32 {
        let target_traversed = zero_based_rank + 1;
        let mut traversed = 0usize;
        let mut curr = HEAD_IDX;

        for i in (0..self.level).rev() {
            loop {
                let link = self.nodes[curr as usize].levels[i];
                if link.forward != NIL_IDX && traversed + link.span <= target_traversed {
                    traversed += link.span;
                    curr = link.forward;
                } else {
                    break;
                }
            }
            if traversed == target_traversed {
                return curr;
            }
        }
        NIL_IDX
    }

    pub fn range_by_rank(&self, start: i64, stop: i64) -> Vec<(&[u8], f64)> {
        if self.len == 0 {
            return Vec::new();
        }
        let len_i64 = self.len as i64;
        let mut s = if start < 0 { len_i64 + start } else { start };
        let mut e = if stop < 0 { len_i64 + stop } else { stop };
        if s < 0 {
            s = 0;
        }
        if e >= len_i64 {
            e = len_i64 - 1;
        }
        if s > e || s >= len_i64 {
            return Vec::new();
        }

        let count = (e - s + 1) as usize;
        let mut out = Vec::with_capacity(count);
        let mut curr = self.node_at_rank(s as usize);
        for _ in 0..count {
            if curr == NIL_IDX {
                break;
            }
            let node = &self.nodes[curr as usize];
            out.push((node.member.as_ref(), node.score));
            curr = node.levels[0].forward;
        }
        out
    }

    pub fn range_by_score(&self, min_score: f64, max_score: f64) -> Vec<(&[u8], f64)> {
        if self.len == 0 || min_score > max_score {
            return Vec::new();
        }
        let mut curr = HEAD_IDX;
        for i in (0..self.level).rev() {
            loop {
                let fwd = self.nodes[curr as usize].levels[i].forward;
                if fwd == NIL_IDX {
                    break;
                }
                if self.nodes[fwd as usize].score < min_score {
                    curr = fwd;
                } else {
                    break;
                }
            }
        }

        curr = self.nodes[curr as usize].levels[0].forward;
        let mut out = Vec::new();
        while curr != NIL_IDX {
            let node = &self.nodes[curr as usize];
            if node.score > max_score {
                break;
            }
            out.push((node.member.as_ref(), node.score));
            curr = node.levels[0].forward;
        }
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], f64)> {
        let mut curr = self.nodes[HEAD_IDX as usize].levels[0].forward;
        std::iter::from_fn(move || {
            if curr == NIL_IDX {
                None
            } else {
                let node = &self.nodes[curr as usize];
                curr = node.levels[0].forward;
                Some((node.member.as_ref(), node.score))
            }
        })
    }
}

/// Composite SortedSet (`ZSET`) pairing O(1) member hash lookup with O(log N) SkipList ordering.
#[derive(Clone, Debug, Default)]
pub struct SortedSet {
    dict: RawHashTable<f64>,
    skiplist: SkipList,
}

impl SortedSet {
    pub fn new() -> Self {
        Self {
            dict: RawHashTable::new(),
            skiplist: SkipList::new(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.skiplist.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.skiplist.is_empty()
    }

    /// Inserts or updates `(member, score)`. Returns `true` if `member` is newly inserted.
    pub fn zadd(&mut self, score: f64, member: Box<[u8]>) -> bool {
        if let Some(&old_score) = self.dict.get(&member) {
            if old_score.total_cmp(&score) != Ordering::Equal {
                self.skiplist.remove(old_score, &member);
                self.skiplist.insert(score, member.clone());
                self.dict.insert(member, score);
            }
            false
        } else {
            self.skiplist.insert(score, member.clone());
            self.dict.insert(member, score);
            true
        }
    }

    pub fn zrem(&mut self, member: &[u8]) -> bool {
        if let Some((_, old_score)) = self.dict.remove(member) {
            self.skiplist.remove(old_score, member);
            true
        } else {
            false
        }
    }

    pub fn zscore(&self, member: &[u8]) -> Option<f64> {
        self.dict.get(member).copied()
    }

    pub fn zrank(&self, member: &[u8]) -> Option<usize> {
        let score = *self.dict.get(member)?;
        self.skiplist.rank_of(score, member)
    }

    pub fn zrange(&self, start: i64, stop: i64) -> Vec<(&[u8], f64)> {
        self.skiplist.range_by_rank(start, stop)
    }

    pub fn zrange_by_score(&self, min: f64, max: f64) -> Vec<(&[u8], f64)> {
        self.skiplist.range_by_score(min, max)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], f64)> {
        self.skiplist.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skiplist_zset_rank_and_range_invariants() {
        let mut zset = SortedSet::new();
        for i in 0..500u32 {
            let score = ((i * 37) % 113) as f64;
            let mem = format!("member:{i:04}").into_bytes().into_boxed_slice();
            assert!(zset.zadd(score, mem));
        }
        assert_eq!(zset.len(), 500);

        // Update scores of a subset
        for i in (0..500u32).step_by(5) {
            let mem = format!("member:{i:04}").into_bytes().into_boxed_slice();
            assert!(!zset.zadd(-10.0 - (i as f64), mem));
        }
        // Delete another subset
        for i in (1..500u32).step_by(7) {
            let mem = format!("member:{i:04}");
            assert!(zset.zrem(mem.as_bytes()));
        }

        let all = zset.zrange(0, -1);
        assert_eq!(all.len(), zset.len());
        for idx in 1..all.len() {
            let prev = all[idx - 1];
            let curr = all[idx];
            assert_eq!(
                compare_score_member(prev.1, prev.0, curr.1, curr.0),
                Ordering::Less
            );
        }
        for (expected_rank, (mem, _)) in all.iter().enumerate() {
            assert_eq!(zset.zrank(mem), Some(expected_rank));
        }
    }
}
