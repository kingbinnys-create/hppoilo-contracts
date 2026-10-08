#![cfg(test)]
extern crate std;

use crate::{
    quorum, BatchCall, GovernanceChange, MultiSigContract, MultiSigContractClient, QuorumStatus,
    SignerWeight,
};
use astroid_shared::constants::{
    GOVERNANCE_GRACE_PERIOD, MAX_BATCH_CALLS, MAX_SIGNERS, MAX_TIMELOCK_DELAY, MIN_TIMELOCK_DELAY,
    THRESHOLD_CHANGE_DELAY_LEDGERS,
};
use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, AuthorizedFunction, Events, Ledger};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, Bytes, Env, IntoVal, Symbol,
    Val, Vec,
};

/// Minimal stateful contract used as a batch sub-call target: it stores values
/// keyed by id and exposes a couple of always-failing functions to exercise the
/// atomic rollback and error-mapping paths.
#[contract]
pub struct BatchHelper;

#[contracttype]
#[derive(Clone)]
enum HKey {
    Value(u64),
}

#[contractimpl]
impl BatchHelper {
    pub fn store(env: Env, key: u64, value: u64) {
        env.storage().instance().set(&HKey::Value(key), &value);
    }

    pub fn get(env: Env, key: u64) -> u64 {
        env.storage().instance().get(&HKey::Value(key)).unwrap_or(0)
    }

    /// Always fails with a contract error (atomic rollback + error propagation).
    pub fn fail(_env: Env) -> Result<(), Error> {
        Err(Error::InvalidInput)
    }

    /// Always panics (maps to [`Error::BatchCallFailed`]).
    pub fn boom(_env: Env) {
        panic!("boom");
    }
}

struct Harness {
    env: Env,
    client: MultiSigContractClient<'static>,
    signers: std::vec::Vec<Address>,
}

fn sw(a: &Address, w: u32) -> SignerWeight {
    SignerWeight {
        address: a.clone(),
        weight: w,
    }
}

fn setup(weights: &[u32], threshold: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let mut signers = std::vec::Vec::new();
    let mut sv = Vec::new(&env);
    for w in weights {
        let a = Address::generate(&env);
        sv.push_back(sw(&a, *w));
        signers.push(a);
    }
    client.initialize(&sv, &threshold);
    Harness {
        env,
        client,
        signers,
    }
}

fn payload(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1, 2, 3, 4])
}

#[test]
fn initialize_state() {
    let h = setup(&[1, 1, 1], 2);
    assert_eq!(h.client.get_threshold(), 2);
    assert_eq!(h.client.get_signers().len(), 3);
    assert!(h.client.is_signer(&h.signers[0]));
    assert!(!h.client.is_locked());
}

#[test]
fn bad_threshold_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sv = Vec::new(&env);
    // Total weight = 2, threshold 3 > total rejected.
    sv.push_back(sw(&Address::generate(&env), 1));
    sv.push_back(sw(&Address::generate(&env), 1));
    let res = client.try_initialize(&sv, &3);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn zero_weight_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sv = Vec::new(&env);
    sv.push_back(sw(&Address::generate(&env), 0));
    sv.push_back(sw(&Address::generate(&env), 1));
    let res = client.try_initialize(&sv, &1);
    assert_eq!(res, Err(Ok(Error::InsufficientWeight)));
}

#[test]
fn duplicate_signer_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let a = Address::generate(&env);
    let mut sv = Vec::new(&env);
    sv.push_back(sw(&a, 1));
    sv.push_back(sw(&a, 1));
    let res = client.try_initialize(&sv, &1);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn weighted_approval_met_by_single_heavy_signer() {
    // Weights 5, 1, 1 with threshold 5: proposer (weight 5) alone executes.
    let h = setup(&[5, 1, 1], 5);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer's own weight (5) already meets threshold 5.
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn weighted_threshold_requires_combined_weight() {
    // Weights 2, 2, 1 with threshold 3.
    let h = setup(&[2, 2, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer contributes 2; one more signer (2) -> total 4 >= 3.
    let weight = h.client.approve(&h.signers[1], &id);
    assert_eq!(weight, 4);
    h.client.execute(&h.signers[2], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn execute_below_weight_threshold_fails() {
    // Weights 2, 2, 1 with threshold 3.
    let h = setup(&[2, 2, 1], 3);
    let _id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Only the weight-1 signer approves -> total 3 (proposer 2 + 1) < 3? 2+1=3 == threshold.
    // Use the lightest signer only so total stays below threshold.
    let id2 = h.client.propose(
        &h.signers[2],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // proposer weight 1; approve with weight-2 signer -> 1+2 = 3 meets threshold.
    // Instead approve with weight-2 signer only on a proposal from weight-1 signer gives 3.
    // To stay below, approve with no one: just proposer weight 1 < 3.
    let res = h.client.try_execute(&h.signers[0], &id2);
    assert_eq!(res, Err(Ok(Error::InsufficientWeight)));
}

#[test]
fn non_signer_cannot_propose_or_approve() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    let res = h
        .client
        .try_propose(&stranger, &symbol_short!("payment"), &payload(&h.env), &0);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
    // Approving is gated the same way, before the proposal is even loaded.
    let res = h.client.try_approve(&stranger, &1);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn double_approval_rejected() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer already auto-approved.
    let res = h.client.try_approve(&h.signers[0], &id);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn time_lock_blocks_early_execution() {
    let h = setup(&[2, 2], 4);
    h.env.ledger().set_timestamp(1_000);
    let unlock = 5_000u64;
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &unlock,
    );
    h.client.approve(&h.signers[1], &id);
    // Threshold met (4), but time lock not reached.
    let res = h.client.try_execute(&h.signers[0], &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));

    // Advance past the lock.
    h.env.ledger().set_timestamp(6_000);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn emergency_lock_blocks_actions() {
    let h = setup(&[1, 1], 2);
    h.client.set_emergency_lock(&h.signers[0], &true);
    assert!(h.client.is_locked());
    let res = h.client.try_propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(res, Err(Ok(Error::EmergencyLock)));

    // Unlock and resume.
    h.client.set_emergency_lock(&h.signers[0], &false);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    h.client.approve(&h.signers[1], &id);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

/// Move the ledger clock forward by `seconds`.
fn advance(h: &Harness, seconds: u64) {
    let now = h.env.ledger().timestamp();
    h.env.ledger().set_timestamp(now + seconds);
}

/// Assert an event with the given `(category, action)` tuple topic was emitted.
fn assert_event(env: &Env, category: Symbol, action: Symbol) {
    let want_category: Val = category.into_val(env);
    let want_action: Val = action.into_val(env);
    let found =
        env.events().all().iter().any(|(_id, topics, _data)| {
            topics.contains(want_category) && topics.contains(want_action)
        });
    assert!(found, "expected a matching event to be emitted");
}

// --- quorum edge cases (threshold verification) ---

#[test]
fn minimal_quorum_executes_with_proposer_alone() {
    // MIN_THRESHOLD is 1, so the lightest possible configuration lets the
    // proposer's weight alone satisfy the threshold.
    let h = setup(&[1, 1, 1], 1);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn unanimous_quorum_requires_every_signer() {
    // Weights 1, 1, 1 with threshold 3 == total weight: nothing short of
    // unanimous approval reaches the threshold.
    let h = setup(&[1, 1, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), 2);
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );

    // The last approval lands exactly on the threshold.
    assert_eq!(h.client.approve(&h.signers[2], &id), 3);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn quorum_boundary_is_exact_threshold_or_bust() {
    // Weights 5, 3, 2 with threshold 10 == total weight: a weighted quorum
    // that is one signer short must not slip through.
    let h = setup(&[5, 3, 2], 10);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), 8);
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );
    // 5 + 3 + 2 == 10: exactly at the threshold is enough.
    assert_eq!(h.client.approve(&h.signers[2], &id), 10);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn duplicate_approval_cannot_stack_weight() {
    // Weights 1, 1, 1 with threshold 3: a double approval from the same
    // signer would fabricate the missing quorum, so the duplicate is rejected
    // and the recorded weight is left untouched.
    let h = setup(&[1, 1, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), 2);
    assert_eq!(
        h.client.try_approve(&h.signers[1], &id),
        Err(Ok(Error::AlreadySigned))
    );
    assert_eq!(h.client.get_proposal(&id).approval_weight, 2);
    // The proposer already auto-approved at proposal time, too.
    assert_eq!(
        h.client.try_approve(&h.signers[0], &id),
        Err(Ok(Error::AlreadySigned))
    );
    assert_eq!(h.client.get_proposal(&id).approval_weight, 2);
    // Still one weight short of the quorum.
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );
}

#[test]
fn weight_sum_at_u32_max_still_verifies() {
    // Weights u32::MAX - 1 and 1 sum to exactly u32::MAX with a threshold of
    // u32::MAX: the checked accumulator must land on the boundary without
    // wrapping (a wrapped sum of 0 would fail the quorum check).
    let h = setup(&[u32::MAX - 1, 1], u32::MAX);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), u32::MAX);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn zero_threshold_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sv = Vec::new(&env);
    sv.push_back(sw(&Address::generate(&env), 1));
    sv.push_back(sw(&Address::generate(&env), 1));
    // Below MIN_THRESHOLD: a threshold of 0 would let a proposal execute with
    // no approval weight at all, so it is refused up front.
    let res = client.try_initialize(&sv, &0);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn signer_weight_sum_overflow_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sv = Vec::new(&env);
    // u32::MAX + 1 has no representable total weight: the checked accumulation
    // refuses the signer set instead of wrapping it down to 1.
    sv.push_back(sw(&Address::generate(&env), u32::MAX));
    sv.push_back(sw(&Address::generate(&env), 1));
    let res = client.try_initialize(&sv, &1);
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

#[test]
fn max_weight_quorum_and_capacity_edge() {
    // A lone signer holding u32::MAX weight with a threshold of u32::MAX is a
    // valid (if extreme) quorum configuration.
    let h = setup(&[u32::MAX], u32::MAX);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);

    // Admitting one more signer would push the total weight past u32::MAX, so
    // the governance change is refused rather than wrapping the capacity.
    let extra = Address::generate(&h.env);
    assert_eq!(
        h.client
            .try_propose_signer_addition(&h.signers[0], &extra, &1),
        Err(Ok(Error::Overflow))
    );
}

#[test]
fn full_capacity_unanimous_quorum_and_one_signer_too_many() {
    // A signer set sitting exactly on MAX_SIGNERS with a unanimous threshold is
    // the largest quorum configuration the contract admits.
    let n = MAX_SIGNERS as usize;
    let h = setup(&std::vec![1u32; n], MAX_SIGNERS);
    assert_eq!(h.client.get_signers().len(), MAX_SIGNERS);
    assert_eq!(h.client.get_total_weight(), MAX_SIGNERS);

    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Every remaining signer but the last: one weight short of unanimity.
    for i in 1..n - 1 {
        h.client.approve(&h.signers[i], &id);
    }
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );
    // The last approval lands exactly on the threshold.
    h.client.approve(&h.signers[n - 1], &id);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);

    // A set already at capacity admits nobody else, on either path.
    let extra = Address::generate(&h.env);
    assert_eq!(
        h.client.try_add_signer(&h.signers[0], &extra, &1),
        Err(Ok(Error::TooManySigners))
    );
    assert_eq!(
        h.client
            .try_propose_signer_addition(&h.signers[0], &extra, &1),
        Err(Ok(Error::TooManySigners))
    );
    assert!(!h.client.is_signer(&extra));
    assert_eq!(h.client.get_signers().len(), MAX_SIGNERS);
}

// --- timelocked governance ---

#[test]
fn threshold_change_applies_only_after_the_timelock() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);

    // Parked, not applied: the live threshold is untouched.
    assert_eq!(h.client.get_threshold(), 2);
    let pending = h.client.get_pending_change(&id);
    assert_eq!(pending.proposer, h.signers[0]);
    assert_eq!(pending.change, GovernanceChange::Threshold(3));
    assert_eq!(pending.eta, pending.proposed_at + MIN_TIMELOCK_DELAY);
    assert_eq!(pending.expires_at, pending.eta + GOVERNANCE_GRACE_PERIOD);
    assert!(!pending.executed);
    assert!(!pending.cancelled);

    // One second short of the delay is still too early.
    advance(&h, MIN_TIMELOCK_DELAY - 1);
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[1], &id),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(h.client.get_threshold(), 2);

    // Exactly at the eta the change goes through.
    advance(&h, 1);
    h.client.execute_threshold_change(&h.signers[1], &id);
    assert_eq!(h.client.get_threshold(), 3);
    assert!(h.client.get_pending_change(&id).executed);
}

#[test]
fn cancelled_change_never_executes() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);

    // Any signer may veto during the review window.
    h.client.cancel_threshold_change(&h.signers[1], &id);
    let pending = h.client.get_pending_change(&id);
    assert!(pending.cancelled);
    assert!(!pending.executed);

    advance(&h, MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(h.client.get_threshold(), 2);
}

#[test]
fn a_change_can_only_be_settled_once() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &id);

    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(
        h.client.try_cancel_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
}

#[test]
fn matured_change_expires_after_the_grace_period() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    advance(&h, MIN_TIMELOCK_DELAY + GOVERNANCE_GRACE_PERIOD);
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(h.client.get_threshold(), 2);
}

#[test]
fn set_threshold_stores_pending_change() {
    let h = setup(&[1, 1, 1], 2);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // Threshold is not yet changed.
    assert_eq!(h.client.get_threshold(), 2);
    let pending = h.client.get_pending_threshold();
    assert_eq!(pending.new_threshold, 3);
    assert_eq!(pending.effective_from, 100);
}

#[test]
fn set_threshold_same_value_fails() {
    let h = setup(&[1, 1, 1], 2);
    let res = h.client.try_set_threshold(&h.signers[0], &2);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn set_threshold_bounds_enforced() {
    let h = setup(&[1, 1, 1], 2);
    // Threshold larger than signer count is rejected.
    let res = h.client.try_set_threshold(&h.signers[0], &4);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
    // Threshold of 0 is rejected (below MIN_THRESHOLD).
    let res = h.client.try_set_threshold(&h.signers[0], &0);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn finalize_threshold_before_delay_fails() {
    let h = setup(&[1, 1, 1], 2);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // Try to finalize immediately — not enough ledgers have passed.
    let res = h.client.try_finalize_threshold(&h.signers[0]);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    // Threshold unchanged.

    assert_eq!(h.client.get_threshold(), 2);
}

#[test]
fn cancellation_still_works_while_emergency_locked() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    h.client.set_emergency_lock(&h.signers[0], &true);

    // Proposing and executing are frozen, but a hostile change can still be
    // withdrawn — freezing the multisig must not trap a pending modification.
    assert_eq!(
        h.client.try_propose_threshold_change(&h.signers[0], &1),
        Err(Ok(Error::EmergencyLock))
    );
    advance(&h, MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &id),
        Err(Ok(Error::EmergencyLock))
    );
    h.client.cancel_threshold_change(&h.signers[1], &id);
    assert!(h.client.get_pending_change(&id).cancelled);
}

#[test]
fn non_signer_cannot_touch_governance() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    let extra = Address::generate(&h.env);

    assert_eq!(
        h.client.try_propose_threshold_change(&stranger, &1),
        Err(Ok(Error::UnauthorizedModification))
    );
    assert_eq!(
        h.client.try_propose_signer_addition(&stranger, &extra, &1),
        Err(Ok(Error::UnauthorizedModification))
    );
    assert_eq!(
        h.client
            .try_propose_weight_change(&stranger, &h.signers[0], &5),
        Err(Ok(Error::UnauthorizedModification))
    );

    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    assert_eq!(
        h.client.try_cancel_threshold_change(&stranger, &id),
        Err(Ok(Error::UnauthorizedModification))
    );
    advance(&h, MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.client.try_execute_threshold_change(&stranger, &id),
        Err(Ok(Error::UnauthorizedModification))
    );
}

#[test]
fn threshold_bounds_enforced_at_proposal_time() {
    // Weights 1, 1, 1 total 3, threshold 2.
    let h = setup(&[1, 1, 1], 2);
    // A threshold above the total weight can never be met, so it is not parked.
    assert_eq!(
        h.client.try_propose_threshold_change(&h.signers[0], &4),
        Err(Ok(Error::InvalidThreshold))
    );
    // Zero is below MIN_THRESHOLD.
    assert_eq!(
        h.client.try_propose_threshold_change(&h.signers[0], &0),
        Err(Ok(Error::InvalidThreshold))
    );
    assert_eq!(h.client.get_change_count(), 0);

    let id = h.client.propose_threshold_change(&h.signers[0], &3);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &id);
    assert_eq!(h.client.get_threshold(), 3);
}

#[test]
fn finalize_threshold_after_delay_succeeds() {
    let h = setup(&[1, 1, 1], 2);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // Advance past the delay.
    h.env
        .ledger()
        .set_sequence_number(100 + THRESHOLD_CHANGE_DELAY_LEDGERS);
    h.client.finalize_threshold(&h.signers[0]);
    assert_eq!(h.client.get_threshold(), 3);
}

#[test]
fn execution_revalidates_against_live_state() {
    // Weights 2, 1, 1 (total 4) with threshold 2.
    let h = setup(&[2, 1, 1], 2);
    // Removing signer[0] leaves total weight 2, which satisfies the threshold
    // that is live right now, so the proposal is accepted.
    let removal = h
        .client
        .propose_signer_removal(&h.signers[1], &h.signers[0]);
    // Concurrently, the threshold is raised to 4.
    let raise = h.client.propose_threshold_change(&h.signers[1], &4);

    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[1], &raise);
    assert_eq!(h.client.get_threshold(), 4);

    // The removal is now unsafe — it would leave the multisig unusable — and is
    // rejected on the re-validation performed just before it is applied.
    assert_eq!(
        h.client
            .try_execute_threshold_change(&h.signers[1], &removal),
        Err(Ok(Error::InvalidThreshold))
    );
    assert!(h.client.is_signer(&h.signers[0]));
}

#[test]
fn finalize_threshold_no_pending_fails() {
    let h = setup(&[1, 1, 1], 2);
    let res = h.client.try_finalize_threshold(&h.signers[0]);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn set_threshold_overwrites_pending_change() {
    let h = setup(&[1, 1, 1], 2);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // Change mind before finalization.
    h.env.ledger().set_sequence_number(150);
    h.client.set_threshold(&h.signers[0], &1);
    let pending = h.client.get_pending_threshold();
    assert_eq!(pending.new_threshold, 1);
    assert_eq!(pending.effective_from, 150);
    // Finalize the new pending change after the delay.
    h.env
        .ledger()
        .set_sequence_number(150 + THRESHOLD_CHANGE_DELAY_LEDGERS);
    h.client.finalize_threshold(&h.signers[0]);
    assert_eq!(h.client.get_threshold(), 1);
}

#[test]
fn non_signer_cannot_set_or_finalize_threshold() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_set_threshold(&stranger, &3),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_finalize_threshold(&stranger),
        Err(Ok(Error::NotASigner))
    );
}

#[test]
fn non_signer_cannot_change_config() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_set_threshold(&stranger, &3),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_finalize_threshold(&stranger),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_execute_threshold_change(&stranger, &1),
        Err(Ok(Error::UnauthorizedModification))
    );
}

#[test]
fn timelock_delay_is_itself_governed() {
    let h = setup(&[1, 1, 1], 2);
    assert_eq!(h.client.get_timelock_delay(), MIN_TIMELOCK_DELAY);

    // Out-of-range delays are refused up front.
    assert_eq!(
        h.client
            .try_propose_timelock_delay_change(&h.signers[0], &(MIN_TIMELOCK_DELAY - 1)),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        h.client
            .try_propose_timelock_delay_change(&h.signers[0], &(MAX_TIMELOCK_DELAY + 1)),
        Err(Ok(Error::InvalidInput))
    );

    // A change raised under the old delay keeps the eta it was given...
    let early = h.client.propose_threshold_change(&h.signers[0], &3);
    let longer = 3 * MIN_TIMELOCK_DELAY;
    let delay_change = h
        .client
        .propose_timelock_delay_change(&h.signers[0], &longer);

    advance(&h, MIN_TIMELOCK_DELAY);
    h.client
        .execute_threshold_change(&h.signers[0], &delay_change);
    assert_eq!(h.client.get_timelock_delay(), longer);

    // ...so it still executes on its original schedule.
    h.client.execute_threshold_change(&h.signers[0], &early);
    assert_eq!(h.client.get_threshold(), 3);

    // New proposals pick up the longer delay.
    let later = h.client.propose_threshold_change(&h.signers[0], &2);
    let pending = h.client.get_pending_change(&later);
    assert_eq!(pending.eta, pending.proposed_at + longer);
}

// --- timelocked signer-set changes ---

#[test]
fn add_and_remove_signer_with_weight() {
    let h = setup(&[1, 1, 1], 2);
    let new_signer = Address::generate(&h.env);

    let add = h
        .client
        .propose_signer_addition(&h.signers[0], &new_signer, &3);
    assert!(!h.client.is_signer(&new_signer));
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &add);

    assert!(h.client.is_signer(&new_signer));
    let stored = h.client.get_signers();
    assert!(stored
        .iter()
        .any(|s| s.address == new_signer && s.weight == 3));

    let remove = h.client.propose_signer_removal(&h.signers[0], &new_signer);
    assert!(h.client.is_signer(&new_signer));
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &remove);
    assert!(!h.client.is_signer(&new_signer));
}

#[test]
fn cannot_add_signer_with_zero_weight() {
    let h = setup(&[1, 1, 1], 2);
    let extra = Address::generate(&h.env);
    let res = h
        .client
        .try_propose_signer_addition(&h.signers[0], &extra, &0);
    assert_eq!(res, Err(Ok(Error::InvalidSignerWeight)));
}

#[test]
fn cannot_add_duplicate_signer() {
    let h = setup(&[1, 1, 1], 2);
    let res = h
        .client
        .try_propose_signer_addition(&h.signers[0], &h.signers[1], &1);
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn update_signer_weight_and_reach_threshold() {
    // Weights 1, 1 with threshold 2.
    let h = setup(&[1, 1], 2);
    // Bump signer[0] to weight 5; must keep total >= threshold (ok).
    let id = h
        .client
        .propose_weight_change(&h.signers[1], &h.signers[0], &5);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[1], &id);
    let stored = h.client.get_signers();
    assert!(stored
        .iter()
        .any(|s| s.address == h.signers[0] && s.weight == 5));

    // A proposal from signer[0] now meets threshold alone.
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    h.client.execute(&h.signers[1], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn cannot_drop_total_weight_below_threshold() {
    // Weights 2, 1 with threshold 3.
    let h = setup(&[2, 1], 3);
    // Removing signer[0] (weight 2) leaves 1 < 3 -> rejected.
    let res = h
        .client
        .try_propose_signer_removal(&h.signers[1], &h.signers[0]);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));

    // Lowering signer[0] weight to 1 would drop total to 2 < 3 -> rejected.
    let res = h
        .client
        .try_propose_weight_change(&h.signers[1], &h.signers[0], &1);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));

    // Zero weights are never admissible.
    let res = h
        .client
        .try_propose_weight_change(&h.signers[1], &h.signers[0], &0);
    assert_eq!(res, Err(Ok(Error::InvalidSignerWeight)));
}

#[test]
fn governance_changes_for_unknown_signers_and_ids_are_rejected() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client
            .try_propose_signer_removal(&h.signers[0], &stranger),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client
            .try_propose_weight_change(&h.signers[0], &stranger, &2),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_execute_threshold_change(&h.signers[0], &99),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn governance_events_are_emitted() {
    let h = setup(&[1, 1, 1], 2);
    let proposed = h.client.propose_threshold_change(&h.signers[0], &3);
    assert_event(
        &h.env,
        symbol_short!("govchange"),
        symbol_short!("proposed"),
    );

    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &proposed);
    assert_event(
        &h.env,
        symbol_short!("govchange"),
        symbol_short!("executed"),
    );
    // The pre-timelock effect event is still published on application.
    assert_event(&h.env, symbol_short!("threshold"), symbol_short!("changed"));

    let cancelled = h.client.propose_threshold_change(&h.signers[0], &2);
    h.client.cancel_threshold_change(&h.signers[1], &cancelled);
    assert_event(
        &h.env,
        symbol_short!("govchange"),
        symbol_short!("cancelled"),
    );
}

// --- batch execution ---

struct BatchHarness {
    env: Env,
    client: MultiSigContractClient<'static>,
    helper: Address,
    helper_client: BatchHelperClient<'static>,
    signers: std::vec::Vec<Address>,
}

/// Register the multisig plus a stateful helper contract and initialize with
/// `n` signers of weight 1 and the given threshold.
fn setup_batch(n: u32, threshold: u32) -> BatchHarness {
    let weights: std::vec::Vec<u32> = (0..n).map(|_| 1).collect();
    setup_batch_weighted(&weights, threshold)
}

/// As [`setup_batch`], but with an explicit voting weight per signer.
fn setup_batch_weighted(weights: &[u32], threshold: u32) -> BatchHarness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let helper = env.register_contract(None, BatchHelper);
    let helper_client = BatchHelperClient::new(&env, &helper);

    let mut signers = std::vec::Vec::new();
    let mut sv = Vec::new(&env);
    for w in weights {
        let a = Address::generate(&env);
        sv.push_back(sw(&a, *w));
        signers.push(a);
    }
    client.initialize(&sv, &threshold);
    BatchHarness {
        env,
        client,
        helper,
        helper_client,
        signers,
    }
}

/// Build a `Vec<Address>` from indices into the harness signer list.
fn approvers(env: &Env, signers: &[Address], idx: &[usize]) -> Vec<Address> {
    let mut v = Vec::new(env);
    for i in idx {
        v.push_back(signers[*i].clone());
    }
    v
}

fn store_call(env: &Env, helper: &Address, key: u64, value: u64) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("store"),
        args: vec![env, key.into_val(env), value.into_val(env)],
    }
}

fn fail_call(env: &Env, helper: &Address) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("fail"),
        args: Vec::new(env),
    }
}

fn boom_call(env: &Env, helper: &Address) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("boom"),
        args: Vec::new(env),
    }
}

#[test]
fn batch_executes_all_calls_under_single_threshold_check() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    // Caller (s0) plus one approver (s1) reach threshold 2.
    h.client.execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(h.helper_client.get(&1), 100);
    assert_eq!(h.helper_client.get(&2), 200);
    assert_eq!(h.client.get_last_batch_nonce(), 1);
}

#[test]
fn batch_below_threshold_rejected() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    // Only the caller's signature (weight 1) < threshold 2.
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[]),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
    // Nothing was executed and the nonce was not consumed.
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_rejects_non_signer_approver() {
    let h = setup_batch(3, 2);
    let stranger = Address::generate(&h.env);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let app = vec![&h.env, h.signers[1].clone(), stranger];
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn batch_duplicate_approvers_do_not_stack_weight() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    // The caller listed as approver too must still count once: 1 < threshold 2.
    let app = vec![&h.env, h.signers[0].clone()];
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

#[test]
fn batch_unanimous_quorum_requires_every_signer() {
    let h = setup_batch(3, 3);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    // Caller plus one approver is a single signature short of a quorum of 3.
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
    assert_eq!(h.helper_client.get(&1), 0);

    // Caller plus every remaining signer meets the threshold exactly.
    h.client.execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1, 2]),
    );
    assert_eq!(h.helper_client.get(&1), 100);
}

#[test]
fn batch_nonce_replay_rejected() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let app = approvers(&h.env, &h.signers, &[1]);
    h.client.execute_batch(&h.signers[0], &1, &calls, &app);

    // Replaying the same nonce is rejected.
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));
    // A nonce below the initial counter is rejected too.
    let res = h.client.try_execute_batch(&h.signers[0], &0, &calls, &app);
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));

    // Nonces are monotonic, not strictly sequential: gaps are allowed.
    let calls2 = vec![&h.env, store_call(&h.env, &h.helper, 2, 200)];
    h.client.execute_batch(&h.signers[0], &5, &calls2, &app);
    assert_eq!(h.client.get_last_batch_nonce(), 5);
}

#[test]
fn batch_rolls_back_all_calls_on_sub_call_failure() {
    let h = setup_batch(3, 2);
    // store(1) succeeds, then the middle call fails, then store(2) would run.
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        fail_call(&h.env, &h.helper),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    // The callee's own contract error is surfaced...
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    // ...and no partial state was committed (atomicity).
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.helper_client.get(&2), 0);
    // The nonce was rolled back too, so the same batch can be retried.
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_sub_call_panic_maps_to_batch_call_failed() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        boom_call(&h.env, &h.helper),
    ];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::BatchCallFailed)));
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_signatures_cover_the_entire_payload() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    let app = approvers(&h.env, &h.signers, &[1]);
    h.client.execute_batch(&h.signers[0], &7, &calls, &app);

    let auths = h.env.auths();
    // The caller AND every approver authorized exactly the batch payload
    // `(nonce, calls)` — the same payload the contract re-derives internally.
    let expected: Vec<Val> = vec![&h.env, 7u64.into_val(&h.env), calls.to_val()];
    for signer in [&h.signers[0], &h.signers[1]] {
        assert!(
            auths.iter().any(|(addr, inv)| {
                addr == signer
                    && inv.function
                        == AuthorizedFunction::Contract((
                            h.client.address.clone(),
                            Symbol::new(&h.env, "execute_batch"),
                            expected.clone(),
                        ))
            }),
            "signer {signer:?} did not authorize the exact batch payload"
        );
    }
}

#[test]
fn batch_rejects_empty_calls() {
    let h = setup_batch(3, 2);
    let calls = Vec::new(&h.env);
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn batch_rejects_too_many_calls() {
    let h = setup_batch(3, 2);
    let mut calls = Vec::new(&h.env);
    for i in 0..MAX_BATCH_CALLS + 1 {
        calls.push_back(store_call(&h.env, &h.helper, i as u64, i as u64));
    }
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn batch_requires_signer_caller() {
    let h = setup_batch(3, 2);
    let stranger = Address::generate(&h.env);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let res =
        h.client
            .try_execute_batch(&stranger, &1, &calls, &approvers(&h.env, &h.signers, &[1]));
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn batch_blocked_by_emergency_lock() {
    let h = setup_batch(3, 2);
    h.client.set_emergency_lock(&h.signers[0], &true);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::EmergencyLock)));
}

#[test]
fn batch_execution_uses_signer_weights() {
    // A single heavy signer carries the batch on its own.
    let h = setup_batch_weighted(&[5, 1, 1], 5);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    h.client.execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[]),
    );
    assert_eq!(h.helper_client.get(&1), 100);

    // The two light signers together fall short of the same threshold.
    let res = h.client.try_execute_batch(
        &h.signers[1],
        &2,
        &calls,
        &approvers(&h.env, &h.signers, &[2]),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

// --- standalone threshold verification ---

#[test]
fn verify_threshold_accumulates_weight_of_distinct_signers() {
    let h = setup(&[3, 2, 1], 5);
    let weight = h.client.verify_threshold(
        &h.signers[0],
        &approvers(&h.env, &h.signers, &[1]),
        &payload(&h.env),
    );
    assert_eq!(weight, 5);
}

#[test]
fn verify_threshold_returns_weight_above_threshold() {
    let h = setup(&[3, 2, 1], 5);
    let weight = h.client.verify_threshold(
        &h.signers[0],
        &approvers(&h.env, &h.signers, &[1, 2]),
        &payload(&h.env),
    );
    assert_eq!(weight, 6);
}

#[test]
fn verify_threshold_accepts_exact_u32_max_without_duplicate_weight() {
    let h = setup(&[u32::MAX], u32::MAX);
    let repeated_signer = vec![&h.env, h.signers[0].clone(), h.signers[0].clone()];

    assert_eq!(
        h.client
            .verify_threshold(&h.signers[0], &repeated_signer, &payload(&h.env)),
        u32::MAX
    );
}

#[test]
fn verify_threshold_below_threshold_is_refused() {
    let h = setup(&[3, 2, 1], 5);
    let res = h.client.try_verify_threshold(
        &h.signers[1],
        &approvers(&h.env, &h.signers, &[2]),
        &payload(&h.env),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

#[test]
fn verify_threshold_counts_a_repeated_signatory_once() {
    let h = setup(&[3, 2, 1], 5);
    // s0 listed as its own signatory must not stack its weight to 6.
    let res = h.client.try_verify_threshold(
        &h.signers[0],
        &approvers(&h.env, &h.signers, &[0]),
        &payload(&h.env),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

#[test]
fn verify_threshold_rejects_unregistered_signatories() {
    let h = setup(&[3, 2, 1], 5);
    let stranger = Address::generate(&h.env);
    let signatories = vec![&h.env, stranger];
    let res = h
        .client
        .try_verify_threshold(&h.signers[0], &signatories, &payload(&h.env));
    assert_eq!(res, Err(Ok(Error::NotASigner)));

    let stranger = Address::generate(&h.env);
    let res = h.client.try_verify_threshold(
        &stranger,
        &approvers(&h.env, &h.signers, &[1]),
        &payload(&h.env),
    );
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn verify_threshold_is_blocked_by_the_emergency_lock() {
    let h = setup(&[3, 2, 1], 5);
    h.client.set_emergency_lock(&h.signers[0], &true);
    let res = h.client.try_verify_threshold(
        &h.signers[0],
        &approvers(&h.env, &h.signers, &[1]),
        &payload(&h.env),
    );
    assert_eq!(res, Err(Ok(Error::EmergencyLock)));
}

#[test]
fn weight_views_report_the_configured_weights() {
    let h = setup(&[3, 2, 1], 5);
    assert_eq!(h.client.get_signer_weight(&h.signers[0]), 3);
    assert_eq!(h.client.get_signer_weight(&h.signers[2]), 1);
    assert_eq!(h.client.get_signer_weight(&Address::generate(&h.env)), 0);
    assert_eq!(h.client.get_total_weight(), 6);
}

// ---------------------------------------------------------------------------
// Threshold verification against the live signer set (issue #326)
// ---------------------------------------------------------------------------

#[test]
fn quorum_met_executes_and_one_short_fails() {
    let h = setup(&[2, 1, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer's weight (2) alone is one short of the threshold.
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), 3);
    h.client.execute(&h.signers[0], &id);
    let p = h.client.get_proposal(&id);
    assert!(p.executed);
    assert_eq!(p.approval_weight, 3);
}

#[test]
fn approval_from_removed_signer_no_longer_counts() {
    let h = setup(&[2, 1, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), 3);

    // Signer 1 leaves after approving: the remaining set can still reach the
    // threshold, but signer 1's approval must not.
    h.client.remove_signer(&h.signers[0], &h.signers[1]);
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );

    // A current signer tops it back up to quorum.
    h.client.approve(&h.signers[2], &id);
    h.client.execute(&h.signers[0], &id);
    assert_eq!(h.client.get_proposal(&id).approval_weight, 3);
}

#[test]
fn reduced_signer_weight_is_applied_at_execution() {
    let h = setup(&[1, 2, 1], 2);
    let id = h.client.propose(
        &h.signers[1],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.get_proposal(&id).approval_weight, 2);

    let change = h
        .client
        .propose_weight_change(&h.signers[0], &h.signers[1], &1);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &change);
    assert_eq!(h.client.get_signer_weight(&h.signers[1]), 1);

    assert_eq!(
        h.client.try_execute(&h.signers[1], &id),
        Err(Ok(Error::InsufficientWeight))
    );
}

#[test]
fn approval_weight_uses_current_signer_weights() {
    let h = setup(&[u32::MAX - 2, 1, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), u32::MAX - 1);

    let change = h
        .client
        .propose_weight_change(&h.signers[1], &h.signers[0], &1);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[1], &change);

    let newcomer = Address::generate(&h.env);
    h.client.add_signer(&h.signers[0], &newcomer, &2);
    // Historical weights would overflow u32; approvals are recomputed using
    // the current weights of the signers who actually approved.
    assert_eq!(h.client.approve(&newcomer, &id), 4);
    assert_eq!(h.client.get_proposal(&id).approval_weight, 4);
}

#[test]
fn pending_threshold_is_revalidated_on_finalize() {
    let h = setup(&[1, 1, 1], 1);
    h.env.ledger().set_sequence_number(100);
    h.client.set_threshold(&h.signers[0], &3);
    // The signer set shrinks while the change is pending (current threshold 1
    // is still satisfiable, so the removal itself is allowed).
    h.client.remove_signer(&h.signers[0], &h.signers[2]);

    h.env
        .ledger()
        .set_sequence_number(100 + THRESHOLD_CHANGE_DELAY_LEDGERS);
    assert_eq!(
        h.client.try_finalize_threshold(&h.signers[0]),
        Err(Ok(Error::InvalidThreshold))
    );
    assert_eq!(h.client.get_threshold(), 1);
}

#[test]
fn adding_signer_that_overflows_total_weight_is_rejected() {
    let h = setup(&[u32::MAX - 1], 1);
    let newcomer = Address::generate(&h.env);
    assert_eq!(
        h.client.try_add_signer(&h.signers[0], &newcomer, &2),
        Err(Ok(Error::Overflow))
    );
    assert!(!h.client.is_signer(&newcomer));
    // Threshold checks keep working afterwards.
    assert_eq!(h.client.get_total_weight(), u32::MAX - 1);
}

#[test]
fn signer_set_with_invalid_weights_or_duplicates_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &id);
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    assert_eq!(
        client.try_initialize(&vec![&env, sw(&a, 1), sw(&a, 1)], &1),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        client.try_initialize(&vec![&env, sw(&a, 1), sw(&b, 0)], &1),
        Err(Ok(Error::InsufficientWeight))
    );
    assert_eq!(
        client.try_initialize(&vec![&env, sw(&a, u32::MAX), sw(&b, 1)], &1),
        Err(Ok(Error::Overflow))
    );
    // Nothing was stored by the rejected attempts.
    client.initialize(&vec![&env, sw(&a, 1), sw(&b, 1)], &2);
    assert_eq!(client.get_threshold(), 2);
}

// ---------------------------------------------------------------------------
// Issue #280: Threshold voting validation & duplicate vote prevention tests
// ---------------------------------------------------------------------------

#[test]
fn threshold_voting_duplicate_ballot_rejected_for_multiple_signers() {
    let h = setup(&[2, 3, 4], 7);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("action"),
        &payload(&h.env),
        &0,
    );

    // Proposer (signers[0]) weight = 2. Duplicate vote from proposer is rejected.
    assert_eq!(
        h.client.try_approve(&h.signers[0], &id),
        Err(Ok(Error::AlreadySigned))
    );

    // signers[1] (weight = 3) approves -> total weight 5 < 7
    let w1 = h.client.approve(&h.signers[1], &id);
    assert_eq!(w1, 5);

    // Duplicate vote from signers[1] is rejected
    assert_eq!(
        h.client.try_approve(&h.signers[1], &id),
        Err(Ok(Error::AlreadySigned))
    );

    // Proposal cannot execute yet because weight 5 < threshold 7
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );

    // signers[2] (weight = 4) approves -> total weight 9 >= 7
    let w2 = h.client.approve(&h.signers[2], &id);
    assert_eq!(w2, 9);

    // Duplicate vote from signers[2] is also rejected
    assert_eq!(
        h.client.try_approve(&h.signers[2], &id),
        Err(Ok(Error::AlreadySigned))
    );

    // Now proposal successfully executes and transitions state
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);

    // Cannot approve an already executed proposal
    assert_eq!(
        h.client.try_approve(&h.signers[1], &id),
        Err(Ok(Error::InvalidProposalState))
    );
}

#[test]
fn threshold_voting_exact_boundary_transitions_state() {
    // Exactly meeting threshold: 3 + 2 = 5, threshold = 5
    let h = setup(&[3, 2, 1], 5);
    let id = h
        .client
        .propose(&h.signers[0], &symbol_short!("pay"), &payload(&h.env), &0);

    // Total weight currently 3 (proposer only) < 5
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );

    // signers[1] (weight 2) approves -> total weight is exactly 5 == threshold
    let total = h.client.approve(&h.signers[1], &id);
    assert_eq!(total, 5);

    // Execution succeeds and proposal is marked executed
    h.client.execute(&h.signers[2], &id);
    let proposal = h.client.get_proposal(&id);
    assert!(proposal.executed);
    assert_eq!(proposal.approval_weight, 5);
}

// ---------------------------------------------------------------------------
// Multisig quorum weight adjustments with timelock protection tests
// ---------------------------------------------------------------------------

#[test]
fn weight_update_timelock_creation_queuing_premature_failure_and_success() {
    let h = setup(&[2, 2], 3);
    h.env.ledger().set_timestamp(1_000);

    // 1. Propose signer weight update
    let prop_id = h
        .client
        .propose_weight_change(&h.signers[0], &h.signers[1], &5);

    // 2. Queuing state verification: verify change is queued with eta = proposed_at + MIN_TIMELOCK_DELAY
    let pending = h.client.get_pending_change(&prop_id);
    assert_eq!(pending.proposer, h.signers[0]);
    assert_eq!(
        pending.change,
        GovernanceChange::SignerWeight(h.signers[1].clone(), 5)
    );
    assert_eq!(pending.proposed_at, 1_000);
    assert_eq!(pending.eta, 1_000 + MIN_TIMELOCK_DELAY);
    assert!(!pending.executed);

    // 3. Premature execution failure: attempting to execute before timelock expires fails with TIMELOCK_NOT_EXPIRED
    advance(&h, MIN_TIMELOCK_DELAY - 1);
    let res = h
        .client
        .try_execute_threshold_change(&h.signers[0], &prop_id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));

    // Verify weight remains unchanged prematurely
    let signers_before = h.client.get_signers();
    assert!(signers_before
        .iter()
        .any(|s| s.address == h.signers[1] && s.weight == 2));

    // 4. Successful post-timelock execution: advance timestamp to eta and execute successfully
    advance(&h, 1);
    h.client.execute_threshold_change(&h.signers[0], &prop_id);

    let pending_after = h.client.get_pending_change(&prop_id);
    assert!(pending_after.executed);

    let signers_after = h.client.get_signers();
    assert!(signers_after
        .iter()
        .any(|s| s.address == h.signers[1] && s.weight == 5));
}

#[test]
fn quorum_modification_proposal_enforces_timelock_delay() {
    let h = setup(&[2, 2], 3);
    h.env.ledger().set_timestamp(10_000);

    // Propose a proposal with quorum/weight action and unlock_at = 0
    let prop_id = h.client.propose(
        &h.signers[0],
        &symbol_short!("weight"),
        &payload(&h.env),
        &0,
    );

    let prop = h.client.get_proposal(&prop_id);
    assert_eq!(prop.unlock_at, 10_000 + MIN_TIMELOCK_DELAY);

    h.client.approve(&h.signers[1], &prop_id);

    // Premature execution returns TimelockNotExpired
    let res = h.client.try_execute(&h.signers[0], &prop_id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));

    // Post-timelock execution succeeds
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute(&h.signers[0], &prop_id);
    assert!(h.client.get_proposal(&prop_id).executed);
}

// ---------------------------------------------------------------------------
// Threshold verification and approval tracking (issue #290)
//
// The quorum primitives live in `crate::quorum`. The cases below pin the three
// things a quorum must never do — count one key twice, trust a sum it cannot
// represent, or fire one short of the bar — plus the two events a consumer
// reads: an approval being recorded, and the threshold actually being met.
// ---------------------------------------------------------------------------

/// How many events carry the `(category, action)` topic pair.
fn count_events(env: &Env, category: &str, action: &str) -> u32 {
    let want_category: Val = Symbol::new(env, category).into_val(env);
    let want_action: Val = Symbol::new(env, action).into_val(env);
    env.events()
        .all()
        .iter()
        .filter(|(_id, topics, _data)| {
            topics.contains(want_category) && topics.contains(want_action)
        })
        .count() as u32
}

#[test]
fn weight_accumulation_is_checked_and_narrowing_refuses_to_truncate() {
    // Ordinary accumulation, in the wide type it is computed in.
    assert_eq!(quorum::add_weight(0, 5), Ok(5));
    assert_eq!(quorum::add_weight(5, 3), Ok(8));
    assert_eq!(
        quorum::add_weight(u32::MAX as i128 - 1, 1),
        Ok(u32::MAX as i128)
    );

    // Narrowing: the exact boundary is fine, one past it is refused rather
    // than wrapped down into a value that could falsely fail a quorum.
    assert_eq!(quorum::narrow(0), Ok(0));
    assert_eq!(quorum::narrow(u32::MAX as i128), Ok(u32::MAX));
    assert_eq!(quorum::narrow(u32::MAX as i128 + 1), Err(Error::Overflow));
    assert_eq!(quorum::narrow(i128::MAX), Err(Error::Overflow));
}

#[test]
fn the_threshold_comparison_is_inclusive_and_saturating() {
    // `>=`: an exact match is met, one short is not, overshooting is fine.
    assert!(!quorum::is_met(9, 10));
    assert!(quorum::is_met(10, 10));
    assert!(quorum::is_met(u32::MAX, 10));

    // Remaining saturates at zero rather than wrapping below it.
    assert_eq!(quorum::remaining(0, 10), 10);
    assert_eq!(quorum::remaining(9, 10), 1);
    assert_eq!(quorum::remaining(10, 10), 0);
    assert_eq!(quorum::remaining(u32::MAX, 10), 0);

    // Each flow reports its own shortfall code through the one helper.
    assert_eq!(
        quorum::require(9, 10, Error::InsufficientWeight),
        Err(Error::InsufficientWeight)
    );
    assert_eq!(
        quorum::require(9, 10, Error::ThresholdNotMet),
        Err(Error::ThresholdNotMet)
    );
    assert!(quorum::require(10, 10, Error::ThresholdNotMet).is_ok());
    assert!(quorum::require(u32::MAX, 10, Error::ThresholdNotMet).is_ok());
}

#[test]
fn exact_threshold_and_exceeding_threshold_both_verify() {
    // Weights 4, 3, 3 with threshold 10 — the last two approvals together land
    // exactly on the bar, the third pushes past it, and neither is a failure.
    let h = setup(&[4, 3, 3], 10);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), 7);
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );
    // 4 + 3 == 7, + 3 == 10: exactly at the threshold.
    assert_eq!(h.client.approve(&h.signers[2], &id), 10);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);

    // A second proposal that overshoots: 4 + 3 + 3 == 10 is exact, but a
    // threshold of 8 is exceeded by the first two approvals alone.
    let over = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &over), 7);
    h.client.approve(&h.signers[2], &over);
    h.client.execute(&h.signers[0], &over);
    assert!(h.client.get_proposal(&over).executed);
    // The recorded tally is the real sum, never clamped down to the threshold.
    assert_eq!(h.client.get_proposal(&over).approval_weight, 10);
}

#[test]
fn quorum_status_reports_the_verified_tally_on_both_sides_of_the_bar() {
    let short = QuorumStatus::evaluate(7, 2, 10, 12);
    assert!(short.was_short());
    assert_eq!(short.remaining, 3);
    assert_eq!(
        short.ensure_met(Error::ThresholdNotMet),
        Err(Error::ThresholdNotMet)
    );

    let exact = QuorumStatus::evaluate(10, 3, 10, 12);
    assert!(!exact.was_short());
    assert_eq!(exact.remaining, 0);
    assert!(exact.ensure_met(Error::ThresholdNotMet).is_ok());

    // Exceeding the bar is met, with nothing outstanding.
    let over = QuorumStatus::evaluate(u32::MAX, 3, 10, u32::MAX);
    assert!(!over.was_short());
    assert_eq!(over.remaining, 0);
    assert_eq!(over.total_weight, u32::MAX);
}

#[test]
fn an_approval_added_and_a_threshold_met_are_distinct_events() {
    let h = setup(&[4, 3, 3], 10);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );

    // Creation with a sub-threshold proposer: no quorum yet.
    assert_eq!(count_events(&h.env, "proposal", "quorum"), 0);

    // One approval recorded, still short of the bar: an approval event, no
    // quorum event.
    h.client.approve(&h.signers[1], &id);
    assert_eq!(count_events(&h.env, "proposal", "approved"), 1);
    assert_eq!(count_events(&h.env, "proposal", "quorum"), 0);

    // The second approval lands exactly on the threshold: both events fire.
    h.client.approve(&h.signers[2], &id);
    assert_eq!(count_events(&h.env, "proposal", "approved"), 2);
    assert_eq!(count_events(&h.env, "proposal", "quorum"), 1);

    // Executing does not re-announce a quorum that was already reached.
    h.client.execute(&h.signers[0], &id);
    assert_eq!(count_events(&h.env, "proposal", "quorum"), 1);
    assert_eq!(count_events(&h.env, "proposal", "executed"), 1);
}

#[test]
fn the_proposers_own_weight_can_meet_the_threshold_at_creation() {
    // A single heavy signer is the whole quorum: the threshold is met the
    // moment the proposal exists, and announced exactly once, at creation.
    let h = setup(&[10, 1], 10);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.get_proposal(&id).approval_weight, 10);
    assert_eq!(count_events(&h.env, "proposal", "quorum"), 1);

    // A further approval pushes the tally past the bar without re-announcing.
    assert_eq!(h.client.approve(&h.signers[1], &id), 11);
    assert_eq!(count_events(&h.env, "proposal", "approved"), 1);
    assert_eq!(count_events(&h.env, "proposal", "quorum"), 1);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn an_unauthorized_signer_never_reaches_the_tally_or_the_quorum_event() {
    let h = setup(&[4, 3, 3], 10);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    let stranger = Address::generate(&h.env);

    // An unregistered address is refused on the signer-set lookup, before any
    // approval flag is written.
    assert_eq!(
        h.client.try_approve(&stranger, &id),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_execute(&stranger, &id),
        Err(Ok(Error::NotASigner))
    );
    // The tally is untouched and no quorum was announced.
    assert_eq!(h.client.get_proposal(&id).approval_weight, 4);
    assert_eq!(count_events(&h.env, "proposal", "approved"), 0);
    assert_eq!(count_events(&h.env, "proposal", "quorum"), 0);

    // Nor may an unregistered address propose in the first place.
    assert_eq!(
        h.client
            .try_propose(&stranger, &symbol_short!("payment"), &payload(&h.env), &0,),
        Err(Ok(Error::NotASigner))
    );
}

#[test]
fn approval_tracking_follows_the_live_signer_set() {
    // Weights 1, 2, 2, 1 with threshold 3: the proposer plus one approver land
    // exactly on the bar.
    let h = setup(&[1, 2, 2, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[1], &id), 3);
    assert_eq!(count_events(&h.env, "proposal", "approved"), 1);
    assert_eq!(count_events(&h.env, "proposal", "quorum"), 1);

    // Now drop that approver. The remaining total weight (4) still clears the
    // threshold, so the removal is admissible — but their approval flag is
    // still on disk while the tally is rebuilt from the live signer set, so it
    // stops counting. Approval tracking follows the current owners, not a
    // cached total.
    h.client.remove_signer(&h.signers[0], &h.signers[1]);
    assert!(!h.client.is_signer(&h.signers[1]));
    assert_eq!(
        h.client.try_execute(&h.signers[0], &id),
        Err(Ok(Error::InsufficientWeight))
    );
    assert!(!h.client.get_proposal(&id).executed);

    // A re-weighted signer is credited at its *current* weight: promoting
    // signer[2] to 3 makes its single approval carry the whole quorum.
    let reweigh = h
        .client
        .propose_weight_change(&h.signers[0], &h.signers[2], &3);
    advance(&h, MIN_TIMELOCK_DELAY);
    h.client.execute_threshold_change(&h.signers[0], &reweigh);
    assert_eq!(h.client.get_signer_weight(&h.signers[2]), 3);

    let second = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.approve(&h.signers[2], &second), 4);
    h.client.execute(&h.signers[0], &second);
    assert!(h.client.get_proposal(&second).executed);
}

#[test]
fn a_batch_quorum_is_announced_with_its_verified_tally() {
    let h = setup_batch_weighted(&[4, 3, 3], 7);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 7)];
    // Caller (weight 4) + one approver (weight 3) == 7: exactly the threshold.
    h.client.execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(h.helper_client.get(&1), 7);
    assert_eq!(count_events(&h.env, "batch", "quorum"), 1);
    assert_eq!(count_events(&h.env, "batch", "executed"), 1);
}

#[test]
fn a_batch_below_the_threshold_never_announces_a_quorum() {
    let h = setup_batch_weighted(&[4, 3, 3], 8);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 2, 9)];
    // 4 + 3 == 7 is one short: refused, nothing executed, no quorum event.
    assert_eq!(
        h.client.try_execute_batch(
            &h.signers[0],
            &1,
            &calls,
            &approvers(&h.env, &h.signers, &[1])
        ),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(h.helper_client.get(&2), 0);
    assert_eq!(count_events(&h.env, "batch", "quorum"), 0);
    assert_eq!(count_events(&h.env, "batch", "executed"), 0);

    // The same batch with the third signer listed reaches 10, past the bar.
    h.client.execute_batch(
        &h.signers[0],
        &2,
        &calls,
        &approvers(&h.env, &h.signers, &[1, 2]),
    );
    assert_eq!(h.helper_client.get(&2), 9);
    assert_eq!(count_events(&h.env, "batch", "quorum"), 1);
}

#[test]
fn batch_signature_weight_is_checked_and_duplicates_count_once() {
    // Weights 4, 3 with threshold 4: the caller alone reaches the bar, so a
    // repeated entry for the same key must not be able to manufacture one.
    let h = setup_batch_weighted(&[4, 3], 4);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 3, 3)];
    h.client.execute_batch(
        &h.signers[0],
        &1,
        &calls,
        // The caller listed three times over: counted once, and it clears the
        // bar on its own without help from anyone.
        &approvers(&h.env, &h.signers, &[0, 0, 0]),
    );
    assert_eq!(h.helper_client.get(&3), 3);
    assert_eq!(count_events(&h.env, "batch", "quorum"), 1);

    // Raise the bar past what one key can reach, and the same duplication is
    // still worth nothing: the batch is short, not quorate.
    let strict = setup_batch_weighted(&[4, 3], 5);
    let calls = vec![&strict.env, store_call(&strict.env, &strict.helper, 4, 4)];
    assert_eq!(
        strict.client.try_execute_batch(
            &strict.signers[0],
            &1,
            &calls,
            &approvers(&strict.env, &strict.signers, &[0, 0, 0]),
        ),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(strict.helper_client.get(&4), 0);
    assert_eq!(count_events(&strict.env, "batch", "quorum"), 0);
}
