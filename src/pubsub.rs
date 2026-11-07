use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Condvar, Mutex, RwLock};

use crate::error::{EngineError, EngineResult};
use crate::resp::{write_bulk_string, write_integer, write_push_header};
use crate::storage::hashtable::RawHashTable;

/// Lock-minimized per-connection outbound queue for asynchronous Pub/Sub frame delivery.
pub struct ClientOutbox {
    has_pending: AtomicBool,
    buffer: Mutex<Vec<u8>>,
}

impl Default for ClientOutbox {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientOutbox {
    pub fn new() -> Self {
        Self {
            has_pending: AtomicBool::new(false),
            buffer: Mutex::new(Vec::new()),
        }
    }

    pub fn push_bytes(&self, data: &[u8]) -> EngineResult<()> {
        let mut guard = self
            .buffer
            .lock()
            .map_err(|_| EngineError::LockPoisoned("pubsub client outbox"))?;
        guard.extend_from_slice(data);
        self.has_pending.store(true, AtomicOrdering::Release);
        Ok(())
    }

    #[inline]
    pub fn drain_into(&self, dst: &mut Vec<u8>) -> EngineResult<usize> {
        if !self.has_pending.load(AtomicOrdering::Acquire) {
            return Ok(0);
        }
        let mut guard = self
            .buffer
            .lock()
            .map_err(|_| EngineError::LockPoisoned("pubsub client outbox"))?;
        let count = guard.len();
        if count > 0 {
            dst.extend_from_slice(&guard);
            guard.clear();
        }
        self.has_pending.store(false, AtomicOrdering::Release);
        Ok(count)
    }
}

/// Per-connection subscription state owned exclusively by the active connection state machine.
#[derive(Default)]
pub struct ClientSubscriptions {
    pub channels: RawHashTable<()>,
    pub patterns: RawHashTable<()>,
}

impl ClientSubscriptions {
    pub fn new() -> Self {
        Self {
            channels: RawHashTable::new(),
            patterns: RawHashTable::new(),
        }
    }

    #[inline]
    pub fn total_count(&self) -> usize {
        self.channels.len() + self.patterns.len()
    }
}

#[derive(Clone)]
struct SubscriberEntry {
    client_id: u64,
    outbox: Arc<ClientOutbox>,
}

/// Thread-safe Pub/Sub broker supporting exact channels (`SUBSCRIBE`) and glob patterns (`PSUBSCRIBE`).
pub struct PubSubBroker {
    channels: RwLock<RawHashTable<Vec<SubscriberEntry>>>,
    patterns: RwLock<RawHashTable<Vec<SubscriberEntry>>>,
    reactor_wakeup: Option<Arc<(Mutex<u64>, Condvar)>>,
}

impl PubSubBroker {
    pub fn new(reactor_wakeup: Option<Arc<(Mutex<u64>, Condvar)>>) -> Arc<Self> {
        Arc::new(Self {
            channels: RwLock::new(RawHashTable::new()),
            patterns: RwLock::new(RawHashTable::new()),
            reactor_wakeup,
        })
    }

    fn notify_reactor(&self) {
        if let Some(ref pair) = self.reactor_wakeup {
            let (lock, cvar) = &**pair;
            if let Ok(mut epoch) = lock.lock() {
                *epoch = epoch.wrapping_add(1);
                cvar.notify_all();
            }
        }
    }

    pub fn subscribe(
        &self,
        client_id: u64,
        outbox: &Arc<ClientOutbox>,
        client_subs: &mut ClientSubscriptions,
        targets: &[&[u8]],
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let mut guard = self
            .channels
            .write()
            .map_err(|_| EngineError::LockPoisoned("pubsub channels write lock"))?;

        for &chan in targets {
            if !client_subs.channels.contains_key(chan) {
                client_subs
                    .channels
                    .insert(chan.to_vec().into_boxed_slice(), ());
                if let Some(list) = guard.get_mut(chan) {
                    if !list.iter().any(|s| s.client_id == client_id) {
                        list.push(SubscriberEntry {
                            client_id,
                            outbox: Arc::clone(outbox),
                        });
                    }
                } else {
                    guard.insert(
                        chan.to_vec().into_boxed_slice(),
                        vec![SubscriberEntry {
                            client_id,
                            outbox: Arc::clone(outbox),
                        }],
                    );
                }
            }
            write_push_header(out, 3);
            write_bulk_string(out, b"subscribe");
            write_bulk_string(out, chan);
            write_integer(out, client_subs.total_count() as i64);
        }
        Ok(())
    }

    pub fn unsubscribe(
        &self,
        client_id: u64,
        client_subs: &mut ClientSubscriptions,
        targets: &[&[u8]],
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let owned_targets: Vec<Box<[u8]>> = if targets.is_empty() {
            client_subs
                .channels
                .iter()
                .map(|(k, _)| k.to_vec().into_boxed_slice())
                .collect()
        } else {
            targets
                .iter()
                .map(|t| t.to_vec().into_boxed_slice())
                .collect()
        };

        if owned_targets.is_empty() {
            write_push_header(out, 3);
            write_bulk_string(out, b"unsubscribe");
            crate::resp::write_null(out);
            write_integer(out, client_subs.total_count() as i64);
            return Ok(());
        }

        let mut guard = self
            .channels
            .write()
            .map_err(|_| EngineError::LockPoisoned("pubsub channels write lock"))?;

        for chan in owned_targets {
            client_subs.channels.remove(&chan);
            let mut remove_chan = false;
            if let Some(list) = guard.get_mut(&chan) {
                list.retain(|s| s.client_id != client_id);
                remove_chan = list.is_empty();
            }
            if remove_chan {
                guard.remove(&chan);
            }
            write_push_header(out, 3);
            write_bulk_string(out, b"unsubscribe");
            write_bulk_string(out, &chan);
            write_integer(out, client_subs.total_count() as i64);
        }
        Ok(())
    }

    pub fn psubscribe(
        &self,
        client_id: u64,
        outbox: &Arc<ClientOutbox>,
        client_subs: &mut ClientSubscriptions,
        patterns: &[&[u8]],
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let mut guard = self
            .patterns
            .write()
            .map_err(|_| EngineError::LockPoisoned("pubsub patterns write lock"))?;

        for &pat in patterns {
            if !client_subs.patterns.contains_key(pat) {
                client_subs
                    .patterns
                    .insert(pat.to_vec().into_boxed_slice(), ());
                if let Some(list) = guard.get_mut(pat) {
                    if !list.iter().any(|s| s.client_id == client_id) {
                        list.push(SubscriberEntry {
                            client_id,
                            outbox: Arc::clone(outbox),
                        });
                    }
                } else {
                    guard.insert(
                        pat.to_vec().into_boxed_slice(),
                        vec![SubscriberEntry {
                            client_id,
                            outbox: Arc::clone(outbox),
                        }],
                    );
                }
            }
            write_push_header(out, 3);
            write_bulk_string(out, b"psubscribe");
            write_bulk_string(out, pat);
            write_integer(out, client_subs.total_count() as i64);
        }
        Ok(())
    }

    pub fn punsubscribe(
        &self,
        client_id: u64,
        client_subs: &mut ClientSubscriptions,
        patterns: &[&[u8]],
        out: &mut Vec<u8>,
    ) -> EngineResult<()> {
        let owned_pats: Vec<Box<[u8]>> = if patterns.is_empty() {
            client_subs
                .patterns
                .iter()
                .map(|(k, _)| k.to_vec().into_boxed_slice())
                .collect()
        } else {
            patterns
                .iter()
                .map(|p| p.to_vec().into_boxed_slice())
                .collect()
        };

        if owned_pats.is_empty() {
            write_push_header(out, 3);
            write_bulk_string(out, b"punsubscribe");
            crate::resp::write_null(out);
            write_integer(out, client_subs.total_count() as i64);
            return Ok(());
        }

        let mut guard = self
            .patterns
            .write()
            .map_err(|_| EngineError::LockPoisoned("pubsub patterns write lock"))?;

        for pat in owned_pats {
            client_subs.patterns.remove(&pat);
            let mut remove_pat = false;
            if let Some(list) = guard.get_mut(&pat) {
                list.retain(|s| s.client_id != client_id);
                remove_pat = list.is_empty();
            }
            if remove_pat {
                guard.remove(&pat);
            }
            write_push_header(out, 3);
            write_bulk_string(out, b"punsubscribe");
            write_bulk_string(out, &pat);
            write_integer(out, client_subs.total_count() as i64);
        }
        Ok(())
    }

    pub fn disconnect_client(
        &self,
        client_id: u64,
        client_subs: &mut ClientSubscriptions,
    ) -> EngineResult<()> {
        if client_subs.total_count() == 0 {
            return Ok(());
        }
        if !client_subs.channels.is_empty() {
            let mut guard = self
                .channels
                .write()
                .map_err(|_| EngineError::LockPoisoned("pubsub channels write lock"))?;
            let chans: Vec<Box<[u8]>> = client_subs
                .channels
                .iter()
                .map(|(k, _)| k.to_vec().into_boxed_slice())
                .collect();
            for chan in chans {
                let mut empty = false;
                if let Some(list) = guard.get_mut(&chan) {
                    list.retain(|s| s.client_id != client_id);
                    empty = list.is_empty();
                }
                if empty {
                    guard.remove(&chan);
                }
            }
            client_subs.channels.clear();
        }
        if !client_subs.patterns.is_empty() {
            let mut guard = self
                .patterns
                .write()
                .map_err(|_| EngineError::LockPoisoned("pubsub patterns write lock"))?;
            let pats: Vec<Box<[u8]>> = client_subs
                .patterns
                .iter()
                .map(|(k, _)| k.to_vec().into_boxed_slice())
                .collect();
            for pat in pats {
                let mut empty = false;
                if let Some(list) = guard.get_mut(&pat) {
                    list.retain(|s| s.client_id != client_id);
                    empty = list.is_empty();
                }
                if empty {
                    guard.remove(&pat);
                }
            }
            client_subs.patterns.clear();
        }
        Ok(())
    }

    /// Publishes `payload` to exact subscribers of `channel` and all matching `PSUBSCRIBE` glob subscribers.
    pub fn publish(&self, channel: &[u8], payload: &[u8]) -> EngineResult<usize> {
        let mut delivered = 0usize;

        let exact_targets: Vec<Arc<ClientOutbox>> = {
            let guard = self
                .channels
                .read()
                .map_err(|_| EngineError::LockPoisoned("pubsub channels read lock"))?;
            match guard.get(channel) {
                Some(subs) => subs.iter().map(|s| Arc::clone(&s.outbox)).collect(),
                None => Vec::new(),
            }
        };

        if !exact_targets.is_empty() {
            let mut frame = Vec::with_capacity(32 + channel.len() + payload.len());
            write_push_header(&mut frame, 3);
            write_bulk_string(&mut frame, b"message");
            write_bulk_string(&mut frame, channel);
            write_bulk_string(&mut frame, payload);

            for outbox in exact_targets {
                outbox.push_bytes(&frame)?;
                delivered += 1;
            }
        }

        let pattern_targets: Vec<(Box<[u8]>, Vec<Arc<ClientOutbox>>)> = {
            let guard = self
                .patterns
                .read()
                .map_err(|_| EngineError::LockPoisoned("pubsub patterns read lock"))?;
            let mut matched = Vec::new();
            for (pat, subs) in guard.iter() {
                if glob_match(pat, channel) && !subs.is_empty() {
                    let targets = subs.iter().map(|s| Arc::clone(&s.outbox)).collect();
                    matched.push((pat.to_vec().into_boxed_slice(), targets));
                }
            }
            matched
        };

        for (pat, targets) in pattern_targets {
            let mut frame = Vec::with_capacity(40 + pat.len() + channel.len() + payload.len());
            write_push_header(&mut frame, 4);
            write_bulk_string(&mut frame, b"pmessage");
            write_bulk_string(&mut frame, &pat);
            write_bulk_string(&mut frame, channel);
            write_bulk_string(&mut frame, payload);

            for outbox in targets {
                outbox.push_bytes(&frame)?;
                delivered += 1;
            }
        }

        if delivered > 0 {
            self.notify_reactor();
        }
        Ok(delivered)
    }

    pub fn numpat(&self) -> EngineResult<usize> {
        let guard = self
            .patterns
            .read()
            .map_err(|_| EngineError::LockPoisoned("pubsub patterns read lock"))?;
        let mut total = 0usize;
        for (_, subs) in guard.iter() {
            total += subs.len();
        }
        Ok(total)
    }
}

/// Non-backtracking O(|P| * |T|) Redis-compatible byte glob matcher (`*`, `?`, `[abc]`, `[a-z]`, `[^x]`, `\`).
pub fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut p = 0usize;
    let mut t = 0usize;
    let mut star_p: Option<usize> = None;
    let mut star_t: usize = 0;

    while t < text.len() {
        if p < pattern.len() {
            match pattern[p] {
                b'*' => {
                    while p < pattern.len() && pattern[p] == b'*' {
                        p += 1;
                    }
                    star_p = Some(p);
                    star_t = t;
                    continue;
                }
                b'?' => {
                    p += 1;
                    t += 1;
                    continue;
                }
                b'\\' => {
                    p += 1;
                    if p < pattern.len() && pattern[p] == text[t] {
                        p += 1;
                        t += 1;
                        continue;
                    }
                }
                b'[' => {
                    if let Some((matched, next_p)) = match_char_class(pattern, p + 1, text[t]) {
                        if matched {
                            p = next_p;
                            t += 1;
                            continue;
                        }
                    }
                }
                literal if literal == text[t] => {
                    p += 1;
                    t += 1;
                    continue;
                }
                _ => {}
            }
        }

        if let Some(sp) = star_p {
            p = sp;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn match_char_class(pattern: &[u8], mut idx: usize, ch: u8) -> Option<(bool, usize)> {
    if idx >= pattern.len() {
        return None;
    }
    let mut negate = false;
    if pattern[idx] == b'^' || pattern[idx] == b'!' {
        negate = true;
        idx += 1;
    }
    let mut matched = false;
    let mut first = true;
    while idx < pattern.len() {
        if pattern[idx] == b']' && !first {
            return Some((if negate { !matched } else { matched }, idx + 1));
        }
        first = false;
        let start_ch = if pattern[idx] == b'\\' && idx + 1 < pattern.len() {
            idx += 1;
            pattern[idx]
        } else {
            pattern[idx]
        };

        if idx + 2 < pattern.len() && pattern[idx + 1] == b'-' && pattern[idx + 2] != b']' {
            idx += 2;
            let end_ch = if pattern[idx] == b'\\' && idx + 1 < pattern.len() {
                idx += 1;
                pattern[idx]
            } else {
                pattern[idx]
            };
            let (lo, hi) = if start_ch <= end_ch {
                (start_ch, end_ch)
            } else {
                (end_ch, start_ch)
            };
            if ch >= lo && ch <= hi {
                matched = true;
            }
        } else if ch == start_ch {
            matched = true;
        }
        idx += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_matching_and_pubsub_delivery() -> EngineResult<()> {
        assert!(glob_match(b"news.*", b"news.tech.rust"));
        assert!(glob_match(b"user:[0-9]?:login", b"user:4a:login"));
        assert!(!glob_match(b"user:[^0-9]*", b"user:9abc"));
        assert!(glob_match(b"a*a*a*a*b", b"aaaaaaaaaaaaab"));
        assert!(!glob_match(b"a*a*a*a*b", b"aaaaaaaaaaaaac"));

        let broker = PubSubBroker::new(None);
        let outbox1 = Arc::new(ClientOutbox::new());
        let outbox2 = Arc::new(ClientOutbox::new());
        let mut subs1 = ClientSubscriptions::new();
        let mut subs2 = ClientSubscriptions::new();
        let mut ack = Vec::new();

        broker.subscribe(1, &outbox1, &mut subs1, &[b"orders.eu"], &mut ack)?;
        broker.psubscribe(2, &outbox2, &mut subs2, &[b"orders.*"], &mut ack)?;

        let count = broker.publish(b"orders.eu", b"paid")?;
        assert_eq!(count, 2);

        let mut recv1 = Vec::new();
        let mut recv2 = Vec::new();
        assert!(outbox1.drain_into(&mut recv1)? > 0);
        assert!(outbox2.drain_into(&mut recv2)? > 0);
        Ok(())
    }
}
