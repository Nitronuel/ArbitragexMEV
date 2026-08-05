use std::collections::HashSet;

use domain::CycleId;

/// Bounded dirty-cycle batch with deduplication and overload degradation.
///
/// Reserve updates mark pools; this queue expands each pool to its indexed
/// cycles, coalesces duplicates, and reports overload instead of dropping
/// state. A drained batch is returned in deterministic cycle-ID order.
#[derive(Debug)]
pub struct DirtyQueue {
    capacity: usize,
    pending: HashSet<CycleId>,
    degraded: bool,
}

impl DirtyQueue {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pending: HashSet::new(),
            degraded: false,
        }
    }

    /// Queues one cycle and flags degradation when capacity is exceeded.
    pub fn enqueue(&mut self, cycle_id: CycleId) {
        self.pending.insert(cycle_id);
        if self.pending.len() > self.capacity {
            self.degraded = true;
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Returns and clears the degradation flag for this batch.
    #[must_use]
    pub fn take_degraded(&mut self) -> bool {
        let degraded = self.degraded;
        self.degraded = false;
        degraded
    }

    /// Drains the batch, deduplicated, in ascending cycle-ID order.
    pub fn drain(&mut self) -> Vec<CycleId> {
        let mut ids: Vec<_> = self.pending.drain().collect();
        ids.sort_unstable_by_key(|id| id.0);
        ids
    }
}
