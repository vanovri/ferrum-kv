use crate::error::{EngineError, EngineResult};
use crate::storage::{StorageEngine, WatchedKeyStamp};

/// Per-connection optimistic concurrency transaction state (`WATCH`, `UNWATCH`, `MULTI`, `EXEC`, `DISCARD`).
#[derive(Default)]
pub struct TransactionState {
    watched: Vec<WatchedKeyStamp>,
    in_multi: bool,
    syntax_aborted: bool,
    queued: Vec<Vec<Vec<u8>>>,
}

impl TransactionState {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn in_multi(&self) -> bool {
        self.in_multi
    }

    #[inline]
    pub fn watched_keys(&self) -> &[WatchedKeyStamp] {
        &self.watched
    }

    pub fn watch_keys(&mut self, keys: &[&[u8]], storage: &StorageEngine) -> EngineResult<()> {
        if self.in_multi {
            return Err(EngineError::InvalidArgument(
                "WATCH inside MULTI is not allowed".to_string(),
            ));
        }
        for &k in keys {
            if !self.watched.iter().any(|w| w.key.as_ref() == k) {
                let stamp = storage.watch_stamp(k)?;
                self.watched.push(stamp);
            }
        }
        Ok(())
    }

    pub fn unwatch(&mut self) {
        self.watched.clear();
    }

    pub fn begin_multi(&mut self) -> EngineResult<()> {
        if self.in_multi {
            return Err(EngineError::InvalidArgument(
                "MULTI calls can not be nested".to_string(),
            ));
        }
        self.in_multi = true;
        self.syntax_aborted = false;
        self.queued.clear();
        Ok(())
    }

    pub fn mark_abort(&mut self) {
        if self.in_multi {
            self.syntax_aborted = true;
        }
    }

    pub fn enqueue(&mut self, args: &[&[u8]]) {
        let owned = args.iter().map(|s| s.to_vec()).collect();
        self.queued.push(owned);
    }

    pub fn discard(&mut self) -> EngineResult<()> {
        if !self.in_multi {
            return Err(EngineError::InvalidArgument(
                "DISCARD without MULTI".to_string(),
            ));
        }
        self.in_multi = false;
        self.syntax_aborted = false;
        self.queued.clear();
        self.watched.clear();
        Ok(())
    }

    pub fn take_for_exec(&mut self) -> EngineResult<(Vec<WatchedKeyStamp>, Vec<Vec<Vec<u8>>>)> {
        if !self.in_multi {
            return Err(EngineError::InvalidArgument(
                "EXEC without MULTI".to_string(),
            ));
        }
        let aborted = self.syntax_aborted;
        self.in_multi = false;
        self.syntax_aborted = false;
        let watched = std::mem::take(&mut self.watched);
        let commands = std::mem::take(&mut self.queued);
        if aborted {
            return Err(EngineError::InvalidArgument(
                "EXECABORT Transaction discarded because of previous errors.".to_string(),
            ));
        }
        Ok((watched, commands))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SetCondition;

    #[test]
    fn test_watch_epoch_conflict_detection_across_shards() -> EngineResult<()> {
        let storage = StorageEngine::new(16)?;
        storage.set(b"k1", b"v1", None, SetCondition::Always)?;
        storage.set(b"k2", b"v2", None, SetCondition::Always)?;

        let mut tx = TransactionState::new();
        tx.watch_keys(&[b"k1", b"k2", b"nonexistent_k3"], &storage)?;
        tx.begin_multi()?;
        tx.enqueue(&[b"SET", b"k1", b"updated"]);

        // Before concurrent modification, all watched stamps match
        assert!(storage.verify_watched_stamps_sorted(tx.watched_keys())?);

        // Simulate concurrent writer creating and immediately deleting `nonexistent_k3` (ABA check!)
        storage.set(b"nonexistent_k3", b"temp", None, SetCondition::Always)?;
        storage.del(&[b"nonexistent_k3"])?;

        let (stamps, _) = tx.take_for_exec()?;
        assert!(!storage.verify_watched_stamps_sorted(&stamps)?);
        Ok(())
    }
}
