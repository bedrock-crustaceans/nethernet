use nethernet::protocol::constants::{DEFAULT_MAX_PENDING, DEFAULT_MAX_PENDING_PER_NETWORK_ID};

#[derive(Clone, Copy, Debug)]
pub struct PendingLimits {
    /// Offers answered but not yet established; more are refused.
    pub max_pending: usize,
    /// The same cap for offers from one network id.
    pub max_pending_per_network_id: usize,
}

impl Default for PendingLimits {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_PENDING,
            max_pending_per_network_id: DEFAULT_MAX_PENDING_PER_NETWORK_ID,
        }
    }
}

/// `pending` holds the network id of each unestablished session.
pub(crate) fn admits_offer<'a>(
    pending: impl IntoIterator<Item = &'a str>,
    network_id: &str,
    limits: PendingLimits,
) -> bool {
    let (total, from_network_id) = pending.into_iter().fold((0, 0), |(total, from), id| {
        (total + 1, from + usize::from(id == network_id))
    });
    total < limits.max_pending && from_network_id < limits.max_pending_per_network_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offers_past_the_pending_limits_are_refused() {
        let limits = PendingLimits {
            max_pending: 3,
            max_pending_per_network_id: 2,
        };

        assert!(!admits_offer(["1", "1"], "1", limits));
        assert!(admits_offer(["1", "1"], "2", limits));
        assert!(!admits_offer(["1", "1", "2"], "3", limits));
    }
}
