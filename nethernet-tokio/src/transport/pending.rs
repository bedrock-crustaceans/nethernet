use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

type Counts = Arc<Mutex<HashMap<String, usize>>>;

/// Offers answered but not yet established, counted per network id.
#[derive(Clone, Default)]
pub(crate) struct PendingOffers {
    counts: Counts,
}

/// Holds one pending slot until dropped.
pub(crate) struct PendingSlot {
    counts: Counts,
    network_id: String,
}

impl PendingOffers {
    pub(crate) fn try_admit(
        &self,
        network_id: &str,
        max_pending: usize,
        max_per_network_id: usize,
    ) -> Option<PendingSlot> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let total: usize = counts.values().sum();
        let from_network_id = counts.get(network_id).copied().unwrap_or(0);
        if total >= max_pending || from_network_id >= max_per_network_id {
            return None;
        }
        *counts.entry(network_id.to_string()).or_insert(0) += 1;

        Some(PendingSlot {
            counts: self.counts.clone(),
            network_id: network_id.to_string(),
        })
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.network_id) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.network_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_network_id_is_held_to_its_own_cap() {
        let pending = PendingOffers::default();

        let first = pending.try_admit("1", 8, 2);
        let second = pending.try_admit("1", 8, 2);
        assert!(first.is_some() && second.is_some());
        assert!(pending.try_admit("1", 8, 2).is_none());
        assert!(pending.try_admit("2", 8, 2).is_some());
    }

    #[test]
    fn the_total_is_capped_across_network_ids() {
        let pending = PendingOffers::default();

        let slots: Vec<_> = (0..3)
            .filter_map(|id| pending.try_admit(&id.to_string(), 3, 2))
            .collect();
        assert_eq!(slots.len(), 3);
        assert!(pending.try_admit("9", 3, 2).is_none());
    }

    #[test]
    fn a_dropped_slot_is_freed() {
        let pending = PendingOffers::default();

        let slot = pending.try_admit("1", 8, 1);
        assert!(pending.try_admit("1", 8, 1).is_none());
        drop(slot);
        assert!(pending.try_admit("1", 8, 1).is_some());
    }
}
