#![cfg(test)]
extern crate std;

use crate::{timelock, ProposalContract, ProposalContractClient, ProposalState, VoteBars};
use astroid_multisig::{MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_shared::constants::{MAX_DEPENDENCIES, MAX_PRUNE_BATCH, MAX_SIGNERS};
use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{vec, Address, Env, IntoVal, String, Symbol, Val, Vec};

struct Harness {
    env: Env,
    client: ProposalContractClient<'static>,
    multisig: Address,
    proposer: Address,
    approvers: std::vec::Vec<Address>,
}

fn setup(num_approvers: u32) -> Harness {
    setup_with_weights(&std::vec![1; num_approvers as usize], 1, 0)
}

fn setup_with_weights(weights: &[u32], multisig_threshold: u32, timelock: u64) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let mut approvers = std::vec::Vec::new();
    for _ in weights {
        approvers.push(Address::generate(&env));
    }
    let multisig_id = env.register_contract(None, MultiSigContract);
    let multisig = MultiSigContractClient::new(&env, &multisig_id);
    let mut signers = Vec::new(&env);
    for (index, address) in approvers.iter().enumerate() {
        signers.push_back(SignerWeight {
            address: address.clone(),
            weight: weights[index],
        });
    }
    multisig.initialize(&signers, &multisig_threshold);

    let contract_id = env.register_contract(None, ProposalContract);
    let client = ProposalContractClient::new(&env, &contract_id);
    client.initialize(&timelock, &multisig_id);

    let proposer = Address::generate(&env);
    Harness {
        env,
        client,
        multisig: multisig_id,
        proposer,
        approvers,
    }
}

/// Like [`setup`], but with a mandatory non-zero timelock configured at
/// initialization.
fn setup_timelocked(num_approvers: u32, timelock: u64) -> Harness {
    setup_with_weights(&std::vec![1; num_approvers as usize], 1, timelock)
}

fn approver_vec(h: &Harness) -> Vec<Address> {
    let mut v = Vec::new(&h.env);
    for a in &h.approvers {
        v.push_back(a.clone());
    }
    v
}

/// Create an independent proposal (no prerequisites).
fn create(h: &Harness, threshold: u32, expires_at: u64) -> u64 {
    create_with_deps(h, threshold, expires_at, &[])
}

/// Create a proposal that depends on `deps`.
fn create_with_deps(h: &Harness, threshold: u32, expires_at: u64, deps: &[u64]) -> u64 {
    create_with_grace_and_deps(h, threshold, expires_at, 0, deps)
}

/// Create an independent proposal with an explicit cancellation grace window.
fn create_with_grace(h: &Harness, threshold: u32, expires_at: u64, grace_period: u64) -> u64 {
    create_with_grace_and_deps(h, threshold, expires_at, grace_period, &[])
}

fn create_with_grace_and_deps(
    h: &Harness,
    threshold: u32,
    expires_at: u64,
    grace_period: u64,
    deps: &[u64],
) -> u64 {
    h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(h),
        &dep_vec(h, deps),
        &threshold,
        &vec![&h.env],
        &expires_at,
        &grace_period,
    )
}

/// `create_with_deps` in its fallible form, for the rejection paths.
fn try_create_with_deps(h: &Harness, deps: &[u64]) -> Result<u64, Error> {
    h.client
        .try_create(
            &h.proposer,
            &String::from_str(&h.env, "acme"),
            &String::from_str(&h.env, "wallet-1"),
            &String::from_str(&h.env, "policy-1"),
            &approver_vec(h),
            &dep_vec(h, deps),
            &2,
            &vec![&h.env],
            &0,
            &0,
        )
        .map(|ok| ok.unwrap())
        .map_err(|err| err.unwrap())
}

fn dep_vec(h: &Harness, deps: &[u64]) -> Vec<u64> {
    let mut v = Vec::new(&h.env);
    for d in deps {
        v.push_back(*d);
    }
    v
}

/// Whether any event carrying `symbol` in its topics has been emitted.
fn emitted(env: &Env, symbol: &str) -> bool {
    let want: Val = Symbol::new(env, symbol).into_val(env);
    env.events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want))
}

/// Drive a proposal all the way to `Executed`.
fn approve_and_execute(h: &Harness, id: u64) {
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.execute(&h.proposer, &id);
}

#[test]
fn create_starts_pending() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn full_lifecycle_to_closed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    let approvals = h.client.approve(&h.approvers[1], &id);
    assert_eq!(approvals, 2);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);

    h.client.close(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Closed);
}

#[test]
fn execute_before_approved_fails() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id); // only 1 of 2
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::ProposalNotApproved)));
}

#[test]
fn non_approver_cannot_approve() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    let stranger = Address::generate(&h.env);
    let res = h.client.try_approve(&stranger, &id);
    assert_eq!(res, Err(Ok(Error::NotAnApprover)));
}

#[test]
fn double_approval_rejected() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    let res = h.client.try_approve(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn weighted_multisig_threshold_accepts_exact_and_excess_weight() {
    let exact = setup_with_weights(&[3, 2, 1], 5, 0);
    let exact_id = create(&exact, 2, 5_000);
    exact.client.approve(&exact.approvers[0], &exact_id);
    assert_eq!(exact.client.state(&exact_id), ProposalState::Pending);
    exact.client.approve(&exact.approvers[1], &exact_id);
    assert_eq!(exact.client.get(&exact_id).approval_weight, 5);
    assert_eq!(exact.client.state(&exact_id), ProposalState::Approved);
    assert!(emitted(&exact.env, "weightok"));

    let excess = setup_with_weights(&[3, 2, 1], 4, 0);
    let excess_id = create(&excess, 2, 5_000);
    excess.client.approve(&excess.approvers[0], &excess_id);
    excess.client.approve(&excess.approvers[1], &excess_id);
    assert_eq!(excess.client.get(&excess_id).approval_weight, 5);
    assert_eq!(excess.client.state(&excess_id), ProposalState::Approved);
}

#[test]
fn proposal_waits_for_weight_threshold_and_checks_it_at_execution() {
    let h = setup_with_weights(&[1, 2, 3], 6, 0);
    let id = create(&h, 2, 5_000);

    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert_eq!(h.client.get(&id).approval_weight, 3);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ThresholdNotMet))
    );

    h.client.approve(&h.approvers[2], &id);
    assert_eq!(h.client.get(&id).approval_weight, 6);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn weighted_threshold_crossing_starts_the_timelock() {
    let h = setup_with_weights(&[1, 2, 3], 6, 100);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert_eq!(h.client.get(&id).approved_at, 1_000);

    h.env.ledger().set_timestamp(2_000);
    h.client.approve(&h.approvers[2], &id);
    assert_eq!(h.client.get(&id).approved_at, 2_000);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::TimelockNotExpired))
    );

    h.env.ledger().set_timestamp(2_100);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn execution_recalculates_votes_after_signer_set_changes() {
    let h = setup_with_weights(&[3, 2, 1], 4, 0);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.get(&id).approval_weight, 5);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    MultiSigContractClient::new(&h.env, &h.multisig)
        .remove_signer(&h.approvers[0], &h.approvers[1]);

    assert_eq!(h.client.get(&id).approvals, 1);
    assert_eq!(h.client.get(&id).approval_weight, 3);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ThresholdNotMet))
    );
}

#[test]
fn proposal_rejects_non_multisig_approvers_and_duplicate_allowlist_entries() {
    let h = setup(3);
    let stranger = Address::generate(&h.env);
    let res = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &vec![&h.env, h.approvers[0].clone(), stranger],
        &dep_vec(&h, &[]),
        &1,
        &vec![&h.env],
        &0,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::NotASigner)));

    let res = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &vec![&h.env, h.approvers[0].clone(), h.approvers[0].clone()],
        &dep_vec(&h, &[]),
        &1,
        &vec![&h.env],
        &0,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn reject_moves_to_rejected() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.reject(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Rejected);
    // Cannot approve a rejected proposal.
    let res = h.client.try_approve(&h.approvers[1], &id);
    assert_eq!(res, Err(Ok(Error::InvalidProposalState)));
}

#[test]
fn only_proposer_can_cancel() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    let res = h.client.try_cancel(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    h.client.cancel(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Cancelled);
}

#[test]
fn expired_proposal_cannot_be_approved() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    // Advance beyond expiry.
    h.env.ledger().set_timestamp(6_000);
    let approvals = h.client.approve(&h.approvers[0], &id);
    assert_eq!(approvals, 0);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(emitted(&h.env, "expired"));
}

#[test]
fn expired_state_query_transitions_at_the_exact_deadline() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.env.ledger().set_timestamp(5_000);

    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(h.client.is_expired(&id));
    assert!(emitted(&h.env, "expired"));
}

#[test]
fn explicit_expire_transition() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    // Cannot expire before the deadline: the proposal has not entered the
    // Expired state, so the transition does not apply yet.
    let early = h.client.try_expire(&id);
    assert_eq!(early, Err(Ok(Error::InvalidProposalState)));
    h.env.ledger().set_timestamp(6_000);
    h.client.expire(&id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
}

#[test]
fn create_with_bad_threshold_fails() {
    let h = setup(2);
    // threshold 3 > 2 approvers
    let res = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &3,
        &vec![&h.env],
        &5_000,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn create_with_past_expiry_fails() {
    let h = setup(2);
    let res = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &1,
        &vec![&h.env],
        &500, // in the past (now = 1000)
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

// ---------------------------------------------------------------------------
// Dependency chaining
// ---------------------------------------------------------------------------

#[test]
fn independent_proposal_declares_no_dependencies() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(h.client.dependencies(&id), dep_vec(&h, &[]));
    assert!(h.client.dependencies_met(&id));
}

#[test]
fn chain_executes_in_order() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);
    let third = create_with_deps(&h, 2, 5_000, &[second]);

    assert_eq!(h.client.dependencies(&second), dep_vec(&h, &[first]));

    approve_and_execute(&h, first);
    assert_eq!(h.client.state(&first), ProposalState::Executed);

    assert!(h.client.dependencies_met(&second));
    approve_and_execute(&h, second);

    assert!(h.client.dependencies_met(&third));
    approve_and_execute(&h, third);
    assert_eq!(h.client.state(&third), ProposalState::Executed);
}

#[test]
fn execution_blocked_until_prerequisite_executes() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    // Fully approved, but its prerequisite has not executed.
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert_eq!(h.client.state(&second), ProposalState::Approved);
    assert!(!h.client.dependencies_met(&second));
    // The executability view agrees: an unmet prerequisite blocks it too.
    assert!(!h.client.can_execute(&second));

    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
    // The blocked proposal stays Approved and remains executable later.
    assert_eq!(h.client.state(&second), ProposalState::Approved);

    approve_and_execute(&h, first);
    assert!(h.client.can_execute(&second));
    h.client.execute(&h.proposer, &second);
    assert_eq!(h.client.state(&second), ProposalState::Executed);
}

#[test]
fn approval_is_not_blocked_by_dependencies() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    // A dependent proposal can still gather approvals ahead of its
    // prerequisite; only execution is sequenced.
    h.client.approve(&h.approvers[0], &second);
    let approvals = h.client.approve(&h.approvers[1], &second);
    assert_eq!(approvals, 2);
    assert_eq!(h.client.state(&second), ProposalState::Approved);
}

#[test]
fn all_prerequisites_must_execute() {
    let h = setup(3);
    let a = create(&h, 2, 5_000);
    let b = create(&h, 2, 5_000);
    let dependent = create_with_deps(&h, 2, 5_000, &[a, b]);

    h.client.approve(&h.approvers[0], &dependent);
    h.client.approve(&h.approvers[1], &dependent);

    approve_and_execute(&h, a);
    // One of two prerequisites done is not enough.
    assert!(!h.client.dependencies_met(&dependent));
    assert_eq!(
        h.client.try_execute(&h.proposer, &dependent),
        Err(Ok(Error::PrerequisiteNotMet))
    );

    approve_and_execute(&h, b);
    h.client.execute(&h.proposer, &dependent);
    assert_eq!(h.client.state(&dependent), ProposalState::Executed);
}

#[test]
fn failed_prerequisite_blocks_the_chain_permanently() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    h.client.approve(&h.approvers[0], &first);
    h.client.approve(&h.approvers[1], &first);
    h.client.fail(&h.proposer, &first);
    assert_eq!(h.client.state(&first), ProposalState::Failed);

    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert!(!h.client.dependencies_met(&second));
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
    // Failed is terminal, so the prerequisite can never be satisfied.
    assert_eq!(
        h.client.try_execute(&h.proposer, &first),
        Err(Ok(Error::ProposalNotApproved))
    );
}

#[test]
fn cancelled_prerequisite_blocks_the_chain() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);
    h.client.cancel(&h.proposer, &first);

    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
}

#[test]
fn closed_prerequisite_still_satisfies_dependents() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    approve_and_execute(&h, first);
    // Tidying an executed prerequisite away must not block its dependents.
    h.client.close(&h.proposer, &first);
    assert_eq!(h.client.state(&first), ProposalState::Closed);

    assert!(h.client.dependencies_met(&second));
    approve_and_execute(&h, second);
    assert_eq!(h.client.state(&second), ProposalState::Executed);
}

#[test]
fn self_reference_is_rejected_as_circular() {
    let h = setup(3);
    // The next id would be 1, so depending on 1 is a self-reference.
    assert_eq!(
        try_create_with_deps(&h, &[1]),
        Err(Error::CircularDependencyDetected)
    );
}

#[test]
fn forward_reference_is_rejected_as_circular() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    // Depending on a not-yet-created proposal is the only way an edge could
    // point forward, which is the only way a cycle could form.
    assert_eq!(
        try_create_with_deps(&h, &[first + 5]),
        Err(Error::CircularDependencyDetected)
    );
}

#[test]
fn duplicate_dependencies_are_collapsed() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let dependent = create_with_deps(&h, 2, 5_000, &[first, first, first]);
    // Stored once, so execution reads the prerequisite exactly once.
    assert_eq!(h.client.dependencies(&dependent), dep_vec(&h, &[first]));
}

#[test]
fn too_many_dependencies_rejected() {
    let h = setup(3);
    let mut deps = std::vec::Vec::new();
    for _ in 0..=MAX_DEPENDENCIES {
        deps.push(create(&h, 2, 5_000));
    }
    assert_eq!(try_create_with_deps(&h, &deps), Err(Error::InvalidInput));
}

#[test]
fn blocked_execution_emits_dependency_failure_event() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    // Fully approved, but the prerequisite has not executed.
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
    assert!(emitted(&h.env, "dep_fail"));
    assert!(!emitted(&h.env, "dep_ok"));
}

#[test]
fn satisfied_chain_emits_dependency_success_event() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    approve_and_execute(&h, first);
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    h.client.execute(&h.proposer, &second);
    assert_eq!(h.client.state(&second), ProposalState::Executed);

    assert!(emitted(&h.env, "dep_ok"));
    assert!(!emitted(&h.env, "dep_fail"));
}

#[test]
fn is_executed_reflects_completion_states() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);

    // Not executed while pending or merely approved.
    assert!(!h.client.is_executed(&id));
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert!(!h.client.is_executed(&id));

    // Executed, and still satisfied once tidied away into Closed.
    h.client.execute(&h.proposer, &id);
    assert!(h.client.is_executed(&id));
    h.client.close(&h.proposer, &id);
    assert!(h.client.is_executed(&id));
}

#[test]
fn failed_is_never_executed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
    assert!(!h.client.is_executed(&id));
}

#[test]
fn fail_requires_approval_and_the_proposer() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);

    // Pending, not yet approved.
    assert_eq!(
        h.client.try_fail(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );

    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(
        h.client.try_fail(&h.approvers[0], &id),
        Err(Ok(Error::Unauthorized))
    );

    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

#[test]
fn test_cancellation_grace_window() {
    let h = setup(3);
    h.env.ledger().set_timestamp(100);
    let id = h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "org"),
        &String::from_str(&h.env, "w1"),
        &String::from_str(&h.env, "p1"),
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &2,
        &vec![&h.env],
        &0,
        &50, // 50 seconds grace period
    );

    // Fast forward 51 seconds
    h.env.ledger().set_timestamp(151);

    // Cancel should fail
    let res = h.client.try_cancel(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::CancellationWindowClosed)));

    // Create a new one and cancel inside window
    let id2 = h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "org"),
        &String::from_str(&h.env, "w1"),
        &String::from_str(&h.env, "p1"),
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &2,
        &vec![&h.env],
        &0,
        &50,
    );

    h.env.ledger().set_timestamp(160);
    h.client.cancel(&h.proposer, &id2); // works since 160 < 151 + 50 (created at 151)

    assert_eq!(h.client.state(&id2), crate::ProposalState::Cancelled);
}

// ---------------------------------------------------------------------------
// Expiration gating
//
// The deadline is read from `env.ledger().timestamp()` at the moment of each
// call, so the tests drive the deterministic ledger forward with
// `env.ledger().with_mut` — sequence and timestamp together, exactly as the
// host fixes them for a real invocation — and assert that every interaction
// settles expiry without applying its requested transition.
// ---------------------------------------------------------------------------

/// Advance the mock ledger to `sequence` / `timestamp`.
fn advance(h: &Harness, sequence: u32, timestamp: u64) {
    h.env.ledger().with_mut(|l| {
        l.sequence_number = sequence;
        l.timestamp = timestamp;
    });
}

#[test]
fn expired_proposal_cannot_be_rejected() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);
    h.client.reject(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(emitted(&h.env, "expired"));
}

#[test]
fn expired_proposal_cannot_be_cancelled() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);
    h.client.cancel(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(emitted(&h.env, "expired"));
}

#[test]
fn expired_proposal_cannot_be_executed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    advance(&h, 6, 6_000);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(emitted(&h.env, "expired"));
}

#[test]
fn expired_proposal_cannot_be_failed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);

    advance(&h, 6, 6_000);
    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(emitted(&h.env, "expired"));
}

#[test]
fn expiry_boundary_is_inclusive() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);

    advance(&h, 5, 4_999);
    h.client.approve(&h.approvers[0], &id);

    // One second later the deadline has been reached, so it counts as stale.
    advance(&h, 6, 5_000);
    assert_eq!(h.client.approve(&h.approvers[1], &id), 1);
    assert!(h.client.is_expired(&id));
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(emitted(&h.env, "expired"));
}

#[test]
fn ledger_timeline_blocks_every_stale_transition() {
    let h = setup(3);
    let id = create(&h, 2, 5_000); // created on sequence 1 at t = 1_000

    // Milestone 1 — ledger 2, well before the deadline: approvals flow.
    advance(&h, 2, 2_000);
    h.client.approve(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // Milestone 2 — ledger 6, past the deadline: votes are not recorded and
    // every interaction settles the same terminal state.
    advance(&h, 6, 5_001);
    assert_eq!(h.client.approve(&h.approvers[1], &id), 1);
    h.client.reject(&h.approvers[1], &id);
    h.client.cancel(&h.proposer, &id);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    h.client.fail(&h.proposer, &id);
    // Stale operations are no-ops; the vote count remains unchanged.
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert_eq!(h.client.get(&id).approvals, 1);
    assert!(emitted(&h.env, "expired"));

    // Explicit expiry is idempotent after another interaction settled it.
    assert_eq!(h.client.try_expire(&id), Ok(Ok(())));
}

#[test]
fn proposal_without_deadline_never_expires() {
    let h = setup(3);
    let id = create(&h, 2, 0); // no deadline
    advance(&h, 99, 4_000_000_000);
    assert!(!h.client.is_expired(&id));
    assert_eq!(
        h.client.try_expire(&id),
        Err(Ok(Error::InvalidProposalState))
    );
    // Still fully live: an approval lands normally.
    h.client.approve(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn is_expired_view_tracks_ledger_deadline() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert!(!h.client.is_expired(&id));
    advance(&h, 5, 4_999);
    assert!(!h.client.is_expired(&id));
    advance(&h, 6, 5_000);
    assert!(h.client.is_expired(&id));
}

#[test]
fn cleanup_requires_a_passed_deadline() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(
        h.client.try_cleanup_expired(&id),
        Err(Ok(Error::InvalidProposalState))
    );
    // A proposal without a deadline can never be purged either.
    let never = create(&h, 2, 0);
    assert_eq!(
        h.client.try_cleanup_expired(&never),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn cleanup_settles_and_purges_a_stale_proposal() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);
    // Cleanup first records expiry and returns any deposit, then removes the
    // now-settled record in the same successful invocation.
    h.client.cleanup_expired(&id);
    assert!(emitted(&h.env, "expired"));
    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
}

#[test]
fn cleanup_purges_the_record_and_its_approval_flags() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    advance(&h, 6, 6_000);
    h.client.expire(&id);
    h.client.cleanup_expired(&id);

    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
    // With the record gone, the approval flag can no longer be consulted.
    assert_eq!(
        h.client.try_approve(&h.approvers[1], &id),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn stale_prerequisite_blocks_the_dependent_chain() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    // The dependent proposal carries no deadline of its own, so only the
    // prerequisite's expiry is under test.
    let second = create_with_deps(&h, 2, 0, &[first]);

    advance(&h, 6, 6_000);
    // The prerequisite is stale: it can neither execute nor be approved, so
    // the dependent proposal stays blocked rather than inheriting a stale step.
    assert_eq!(
        h.client.try_execute(&h.proposer, &first),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(h.client.state(&first), ProposalState::Expired);

    // Approving the dependent is unaffected by its prerequisite's expiry ...
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    // ... but execution is still gated on the prerequisite having executed.
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
}

// ------------------------------------------------------------- timelock ----

/// Full approval, then a `get` view handy for timelock assertions.
fn approve_to_threshold(h: &Harness, id: u64) {
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
}

#[test]
fn approval_records_timestamp_used_by_the_timelock() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    assert_eq!(h.client.get(&id).approved_at, 0);

    // Ledger time is 1_000 from setup: approval stamps exactly that moment.
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert_eq!(h.client.get(&id).approved_at, 1_000);

    // Execution is refused well inside the 100s window.
    h.env.ledger().set_timestamp(1_050);
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // approved_at survives execution, recorded in the executed state too.
    h.env.ledger().set_timestamp(1_100);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
    assert_eq!(h.client.get(&id).approved_at, 1_000);
}

#[test]
fn execute_within_timelock_window_is_refused() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    approve_to_threshold(&h, id);

    // One second before the delay elapses the proposal is still locked.
    h.env.ledger().set_timestamp(1_099);
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // Exactly at release time execution is allowed (gate is `< release_at`).
    h.env.ledger().set_timestamp(1_100);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn execute_after_timelock_window_succeeds() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    approve_to_threshold(&h, id);

    // Long past the window, execution proceeds normally and emits "executed".
    h.env.ledger().set_timestamp(5_000);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);

    // Close still works from the executed state (timelock is behind us).
    h.client.close(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Closed);
}

#[test]
fn zero_timelock_allows_immediate_execution() {
    let h = setup(3); // timelock 0 — the historical behaviour.
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn timelock_only_gates_execution_not_state_transitions() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    approve_to_threshold(&h, id);

    // The timelock does not affect dependency queries.
    assert!(h.client.dependencies_met(&id));

    // Marking the proposal failed inside the window is still permitted.
    h.env.ledger().set_timestamp(1_050);
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

// ------------------------------------------------------ quorum / majority ----
//
// `execute` re-validates the tally that earned `Approved`: the configured
// threshold, the participation quorum (an integer-scaled percentage of the
// allow-list) and a strict majority. The cases below pin the boundaries — an
// exact tie, tallies one vote short of a bar, and a threshold low enough to
// be gamed on a large allow-list — where a threshold-only check would let a
// barely-supported proposal fire. The `can_execute` view is pinned alongside
// the entrypoint so it can never advertise a tally `execute` would refuse.

#[test]
fn quorum_calculation_rounds_up_with_integer_scaling() {
    // ceil(eligible * percent / 100) — exact shares stay exact ...
    assert_eq!(VoteBars::quorum_required(4, 50), 2);
    assert_eq!(VoteBars::quorum_required(2, 50), 1);
    // ... partial shares round up so they can never slip under the bar.
    assert_eq!(VoteBars::quorum_required(5, 50), 3); // 2.5 -> 3
    assert_eq!(VoteBars::quorum_required(3, 60), 2); // 1.8 -> 2

    // Degenerate bounds: the full allow-list, and no participation at all.
    assert_eq!(VoteBars::quorum_required(7, 100), 7);
    assert_eq!(VoteBars::quorum_required(0, 50), 0);
    assert_eq!(VoteBars::quorum_required(7, 0), 0);
    // A percentage above 100 is clamped: never more than the allow-list.
    assert_eq!(VoteBars::quorum_required(4, 250), 4);
}

#[test]
fn majority_check_never_accepts_a_tie() {
    // The bar is always one past half of the allow-list ...
    assert_eq!(VoteBars::majority_required(4), 3);
    assert_eq!(VoteBars::majority_required(5), 3);
    // ... an empty allow-list can never be reached by any tally ...
    assert_eq!(VoteBars::majority_required(0), 1);
    // Exactly half of an even allow-list is a tie, not a majority ...
    assert!(!VoteBars::has_majority(2, 4));
    assert!(VoteBars::has_majority(3, 4));
    // ... and one short of an odd one is still short.
    assert!(!VoteBars::has_majority(2, 5));
    assert!(VoteBars::has_majority(3, 5));
    assert!(!VoteBars::has_majority(1, 3));
    assert!(VoteBars::has_majority(2, 3));
    // A sole voter is its own majority.
    assert!(VoteBars::has_majority(1, 1));
}

#[test]
fn tied_vote_blocks_execution() {
    let h = setup(4);
    let id = create(&h, 2, 5_000); // threshold 2 — exactly half of 4
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // 2 in favour, 2 not voted: the configured threshold and the quorum (2 of
    // 4) are both met, but a tie is not a majority, so execution is refused
    // with the threshold code and nothing changes.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert_eq!(h.client.get(&id).approvals, 2);
}

#[test]
fn narrowly_missing_the_quorum_blocks_execution() {
    let h = setup(5);
    let id = create(&h, 2, 5_000); // clears its own threshold: 2 of 5
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // Quorum for 5 voters at 50% is ceil(2.5) == 3, so two approvals fall
    // exactly one vote short of the participation bar — the tally may not
    // execute despite `Approved` (the protocol-wide threshold code covers
    // every vote bar, quorum included).
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // The tally cannot be topped up either (the state gate owns approvals
    // now), so the proposer's escape hatch is to fail the proposal.
    assert_eq!(
        h.client.try_approve(&h.approvers[2], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

#[test]
fn exact_quorum_and_majority_boundary_executes() {
    let h = setup(5);
    // 5 voters: quorum = 3 and majority = 3 — this tally sits exactly on
    // both bars rather than clearing them with room to spare.
    let id = create(&h, 3, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.approve(&h.approvers[2], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // One approval fewer would be refused; exactly three clears every bar.
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn narrowly_missing_the_threshold_never_approves_and_cannot_execute() {
    let h = setup(4);
    let id = create(&h, 3, 5_000); // needs 3 of 4
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id); // 2 of 3 — one vote short
    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // Below the configured threshold the proposal never reached `Approved`,
    // so the state gate refuses execution before quorum even applies.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // The missing approval completes the threshold and, with it, quorum and
    // majority — the same proposal then executes normally.
    h.client.approve(&h.approvers[2], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn low_threshold_on_a_large_allow_list_cannot_execute_on_one_signature() {
    // The motivating case for the whole gate: `threshold = 1` on a ten-person
    // allow-list reaches `Approved` on a single signature, but that signature
    // is neither the quorum (ceil(10 * 50%) == 5 of 10) nor a majority
    // (10 / 2 + 1 == 6 of 10), so it must never fire.
    let h = setup(10);
    let id = create(&h, 1, 5_000);
    h.client.approve(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert!(!h.client.can_execute(&id));
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert_eq!(h.client.get(&id).approvals, 1);
}

#[test]
fn quorum_met_but_majority_missing_blocks_execution() {
    let h = setup(6);
    // 6 voters: quorum is ceil(6 * 50%) == 3 and a strict majority is
    // 6 / 2 + 1 == 4, so this three-signature tally clears the configured
    // threshold *and* the participation bar while still falling one vote
    // short of the majority.
    let id = create(&h, 3, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.approve(&h.approvers[2], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert!(!h.client.can_execute(&id));
    // Nothing was consumed: the proposal stays approved and re-attemptable.
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert_eq!(h.client.get(&id).approvals, 3);
}

#[test]
fn can_execute_view_agrees_with_execute_on_every_vote_bar() {
    // Tie: threshold and quorum met, strict majority missed (2 of 4).
    let tie = setup(4);
    let tie_id = create(&tie, 2, 5_000);
    tie.client.approve(&tie.approvers[0], &tie_id);
    tie.client.approve(&tie.approvers[1], &tie_id);
    assert_eq!(tie.client.state(&tie_id), ProposalState::Approved);
    assert!(!tie.client.can_execute(&tie_id));

    // Quorum short by exactly one vote (2 of 5, bar is 3).
    let quorum = setup(5);
    let quorum_id = create(&quorum, 2, 5_000);
    quorum.client.approve(&quorum.approvers[0], &quorum_id);
    quorum.client.approve(&quorum.approvers[1], &quorum_id);
    assert_eq!(quorum.client.state(&quorum_id), ProposalState::Approved);
    assert!(!quorum.client.can_execute(&quorum_id));

    // Exactly on both bars: the view reports executable and the entrypoint
    // then agrees, so the two can never contradict each other.
    let ok = setup(5);
    let ok_id = create(&ok, 3, 5_000);
    ok.client.approve(&ok.approvers[0], &ok_id);
    ok.client.approve(&ok.approvers[1], &ok_id);
    ok.client.approve(&ok.approvers[2], &ok_id);
    assert!(ok.client.can_execute(&ok_id));
    ok.client.execute(&ok.proposer, &ok_id);
    assert_eq!(ok.client.state(&ok_id), ProposalState::Executed);
}

#[test]
fn vote_bar_helpers_compose_threshold_quorum_and_majority() {
    let h = setup(6);
    let id = create(&h, 3, 5_000);
    let bars = VoteBars::for_proposal(&h.client.get(&id));

    // All three bars, derived from the stored record: threshold 3, quorum
    // ceil(6 * 50%) == 3 and majority 6 / 2 + 1 == 4.
    assert_eq!(bars.threshold, 3);
    assert_eq!(bars.quorum, VoteBars::quorum_required(6, 50));
    assert_eq!(bars.majority, VoteBars::majority_required(6));
    assert_eq!((bars.quorum, bars.majority), (3, 4));

    // Clearing every bar passes ...
    assert!(bars.met_by(4));
    assert_eq!(bars.ensure_met(4), Ok(()));
    // ... and every shorter tally is refused with the protocol-wide code,
    // whether it misses the majority alone (3), the quorum too (2) or the
    // configured threshold as well (0).
    for approvals in [0u32, 1, 2, 3] {
        assert!(!bars.met_by(approvals));
        assert_eq!(bars.ensure_met(approvals), Err(Error::ThresholdNotMet));
    }
}

#[test]
fn vote_bars_view_reports_the_bars_execute_enforces() {
    let h = setup(5);

    // The view derives the bars from the stored record — quorum and majority
    // are both ceil(2.5) == 3 and 5 / 2 + 1 == 3 for a five-person list.
    let short = create(&h, 2, 5_000);
    let bars = h.client.vote_bars(&short);
    assert_eq!(
        bars,
        VoteBars {
            threshold: 2,
            quorum: 3,
            majority: 3,
        }
    );
    // Two approvals clear the threshold but not the other two bars ...
    assert!(!bars.met_by(2));

    h.client.approve(&h.approvers[0], &short);
    h.client.approve(&h.approvers[1], &short);
    assert!(!h.client.can_execute(&short));
    assert_eq!(
        h.client.try_execute(&h.proposer, &short),
        Err(Ok(Error::ThresholdNotMet))
    );

    // ... while a tally sitting exactly on all three bars executes, so the
    // view never advertises a verdict the entrypoint would contradict.
    let exact = create(&h, 3, 5_000);
    let exact_bars = h.client.vote_bars(&exact);
    assert_eq!(
        exact_bars,
        VoteBars {
            threshold: 3,
            quorum: 3,
            majority: 3,
        }
    );
    assert!(exact_bars.met_by(3));
    h.client.approve(&h.approvers[0], &exact);
    h.client.approve(&h.approvers[1], &exact);
    h.client.approve(&h.approvers[2], &exact);
    assert!(h.client.can_execute(&exact));
    h.client.execute(&h.proposer, &exact);
    assert_eq!(h.client.state(&exact), ProposalState::Executed);
}

// ------------------------------------------- timelock / expiry boundary ----

#[test]
fn execution_window_follows_the_ledger_sequence_and_timestamp() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);

    // Sequence and timestamp move together, exactly as the host fixes them for
    // a real invocation: still inside the 100s delay, so execution is refused
    // with the dedicated premature-execution code.
    advance(&h, 2, 1_050);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // One ledger later the release instant (approved_at + timelock = 1_100)
    // has been reached.
    advance(&h, 3, 1_100);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn expiry_gate_wins_over_the_timelock_gate() {
    // Timelock 1_000s from an approval at t = 1_000, but the deadline lands at
    // t = 1_500 — the release instant (2_000) lies beyond the validity window,
    // so a late attempt must report the deadline rather than the (still true)
    // timelock: the proposal cannot wait out its own expiry.
    let h = setup_timelocked(3, 1_000);
    let id = create(&h, 2, 1_500);
    approve_to_threshold(&h, id);
    assert_eq!(h.client.get(&id).approved_at, 1_000);

    advance(&h, 2, 1_400); // live, but the delay has not elapsed
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::TimelockNotExpired))
    );

    advance(&h, 3, 1_500); // deadline reached, delay still running
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(h.client.state(&id), ProposalState::Expired);
}

#[test]
fn can_execute_tracks_timelock_and_expiry() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 5_000);

    // Pending is never executable, however much time has passed.
    assert!(!h.client.can_execute(&id));

    approve_to_threshold(&h, id); // approved at t = 1_000
    assert!(!h.client.can_execute(&id)); // delay still running

    advance(&h, 2, 1_100); // exactly at approved_at + timelock
    assert!(h.client.can_execute(&id));

    advance(&h, 6, 5_000); // past the deadline
    assert!(!h.client.can_execute(&id));
}

#[test]
fn unrepresentable_timelock_fails_closed_instead_of_wrapping() {
    // `approved_at + timelock` cannot be expressed as a ledger timestamp. The
    // delay must fail closed with the deterministic `Overflow` code — if the
    // sum were truncated into the past, execution would be allowed the moment
    // the proposal is approved.
    let h = setup_timelocked(3, u64::MAX);
    let id = create(&h, 2, 0);
    approve_to_threshold(&h, id);

    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::Overflow))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert!(!h.client.can_execute(&id));
}

// ------------------------------------------------- cancellation window ----

#[test]
fn cancellation_window_is_inclusive_and_then_closes() {
    let h = setup(3);
    h.env.ledger().set_timestamp(1_000);
    // Both created at t = 1_000 with a 50s grace window: the window ends at
    // t = 1_050 inclusive.
    let inside = create_with_grace(&h, 2, 8_000, 50);
    let outside = create_with_grace(&h, 2, 8_000, 50);

    advance(&h, 2, 1_050);
    h.client.cancel(&h.proposer, &inside);
    assert_eq!(h.client.state(&inside), ProposalState::Cancelled);

    // One second later the window has closed for the untouched twin.
    advance(&h, 3, 1_051);
    assert_eq!(
        h.client.try_cancel(&h.proposer, &outside),
        Err(Ok(Error::CancellationWindowClosed))
    );
    assert_eq!(h.client.state(&outside), ProposalState::Pending);
}

#[test]
fn unrepresentable_grace_window_does_not_trap_cancellation() {
    // `created_at + grace_period` overflows a ledger timestamp. The window is
    // treated as never closing (the deadline still bounds the proposal) and
    // the arithmetic must not trap the host.
    let h = setup(3);
    let id = create_with_grace(&h, 2, 0, u64::MAX);
    h.client.cancel(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Cancelled);
}

// ------------------------------------------------- execution guards (#226) ----
//
// `execute` must never fire for a proposal that is missing, not authorised by
// its proposer, not (or no longer) `Approved`, or past its deadline. Its only
// value movement is the deposit refund, so the tests with a deposit count that
// refund to prove a proposal settles exactly once, however often `execute` is
// called.

use astroid_shared::types::AssetAmount;
use soroban_sdk::testutils::AuthorizedFunction;
use soroban_sdk::token::{StellarAssetClient, TokenClient};

const DEPOSIT: i128 = 500;

/// Register a test token and mint `DEPOSIT` to the proposer.
fn deposit_token(h: &Harness) -> Address {
    let admin = Address::generate(&h.env);
    let token = h.env.register_stellar_asset_contract_v2(admin).address();
    StellarAssetClient::new(&h.env, &token).mint(&h.proposer, &DEPOSIT);
    token
}

/// Create an independent proposal that escrows `DEPOSIT` of `token`.
fn create_with_deposit(h: &Harness, threshold: u32, expires_at: u64, token: &Address) -> u64 {
    h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(h),
        &dep_vec(h, &[]),
        &threshold,
        &soroban_sdk::vec![
            &h.env,
            AssetAmount {
                asset: token.clone(),
                amount: DEPOSIT,
            }
        ],
        &expires_at,
        &0,
    )
}

/// How many `expired` events the test environment currently reports.
fn expired_events(env: &Env) -> usize {
    let want: Val = Symbol::new(env, "expired").into_val(env);
    env.events()
        .all()
        .iter()
        .filter(|(_contract_id, topics, _data)| topics.contains(want))
        .count()
}

#[test]
fn execute_unknown_proposal_reports_not_found() {
    let h = setup(3);
    assert_eq!(
        h.client.try_execute(&h.proposer, &42),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn execute_requires_the_proposer_authorization() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);
    h.client.execute(&h.proposer, &id);

    // Exactly one authorization was demanded: the proposer's, for `execute`
    // on this contract.
    let auths = h.env.auths();
    assert_eq!(auths.len(), 1);
    let (signer, invocation) = &auths[0];
    assert_eq!(signer, &h.proposer);
    match &invocation.function {
        AuthorizedFunction::Contract((contract, name, _args)) => {
            assert_eq!(contract, &h.client.address);
            assert_eq!(name, &Symbol::new(&h.env, "execute"));
        }
        _ => panic!("expected a contract authorization"),
    }
}

#[test]
fn only_the_proposer_may_execute() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);

    // An approver, even one who voted for it, cannot fire the proposal.
    assert_eq!(
        h.client.try_execute(&h.approvers[0], &id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);
}

#[test]
fn threshold_equal_to_the_whole_allow_list_executes_only_when_unanimous() {
    // Here the configured threshold (3 of 3) is the binding bar, stricter
    // than both the quorum (2) and the majority (2).
    let h = setup(3);
    let id = create(&h, 3, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);

    // One below the threshold: still pending, so the state gate refuses.
    assert_eq!(h.client.state(&id), ProposalState::Pending);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );

    // Exactly the threshold: approved and executable.
    h.client.approve(&h.approvers[2], &id);
    assert_eq!(h.client.get(&id).approvals, 3);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn executing_twice_is_refused_and_refunds_the_deposit_once() {
    let h = setup(3);
    let token = deposit_token(&h);
    let tc = TokenClient::new(&h.env, &token);
    let id = create_with_deposit(&h, 2, 5_000, &token);
    assert_eq!(tc.balance(&h.proposer), 0);
    assert_eq!(tc.balance(&h.client.address), DEPOSIT);

    approve_to_threshold(&h, id);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
    assert_eq!(tc.balance(&h.proposer), DEPOSIT);
    assert_eq!(tc.balance(&h.client.address), 0);

    // The second attempt fails the `Approved` state gate before anything
    // moves: nothing is refunded again and the record is unchanged.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Executed);
    assert_eq!(tc.balance(&h.proposer), DEPOSIT);
    assert_eq!(tc.balance(&h.client.address), 0);
}

#[test]
fn closed_proposal_cannot_be_executed_again() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_and_execute(&h, id);
    h.client.close(&h.proposer, &id);

    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Closed);
}

#[test]
fn rejected_proposal_cannot_be_executed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.reject(&h.approvers[1], &id);

    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Rejected);
    assert!(!h.client.is_executed(&id));
}

#[test]
fn cancelled_proposal_cannot_be_executed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);
    h.client.cancel(&h.proposer, &id);

    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Cancelled);
    assert!(!h.client.is_executed(&id));
}

#[test]
fn failed_proposal_cannot_be_executed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);
    h.client.fail(&h.proposer, &id);

    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

#[test]
fn expired_execution_returns_error_and_never_executes() {
    let h = setup(3);
    let token = deposit_token(&h);
    let tc = TokenClient::new(&h.env, &token);
    let id = create_with_deposit(&h, 2, 5_000, &token);
    approve_to_threshold(&h, id);
    assert!(h.client.can_execute(&id));

    // Past the deadline the approved tally no longer matters: `execute`
    // returns ProposalExpired without executing. A state query settles the
    // expiration and refunds the deposit.
    advance(&h, 6, 5_000);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(expired_events(&h.env), 0);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert_eq!(expired_events(&h.env), 1);
    assert!(!h.client.is_executed(&id));
    assert!(!h.client.can_execute(&id));
    assert_eq!(tc.balance(&h.proposer), DEPOSIT);
    assert_eq!(tc.balance(&h.client.address), 0);

    // A repeat attempt is a no-op: no second refund, no second event, and
    // the proposal never becomes executed.
    let events_before = expired_events(&h.env);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(expired_events(&h.env), events_before);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(!h.client.is_executed(&id));
    assert_eq!(tc.balance(&h.proposer), DEPOSIT);
    assert_eq!(tc.balance(&h.client.address), 0);
}

#[test]
fn vote_bars_hold_at_the_approver_cap_and_do_not_overflow() {
    // Integer scaling is done in `u64`, so even an out-of-range allow-list
    // size cannot overflow the quorum or majority arithmetic.
    assert_eq!(VoteBars::quorum_required(u32::MAX, 100), u32::MAX);
    assert_eq!(VoteBars::quorum_required(u32::MAX, 50), u32::MAX / 2 + 1);
    assert_eq!(VoteBars::majority_required(u32::MAX), u32::MAX / 2 + 1);

    // At the largest signer set `create` can accept, the bars still land on
    // the exact boundary: half is a tie, one more is a strict majority.
    let h = setup(MAX_SIGNERS);
    let half = MAX_SIGNERS / 2;
    let tie = create(&h, half, 0);
    let win = create(&h, half + 1, 0);
    for approver in h.approvers.iter().take(half as usize) {
        h.client.approve(approver, &tie);
        h.client.approve(approver, &win);
    }
    assert_eq!(h.client.state(&tie), ProposalState::Approved);
    assert_eq!(
        h.client.try_execute(&h.proposer, &tie),
        Err(Ok(Error::ThresholdNotMet))
    );

    assert_eq!(h.client.state(&win), ProposalState::Pending);
    h.client.approve(&h.approvers[half as usize], &win);
    h.client.execute(&h.proposer, &win);
    assert_eq!(h.client.state(&win), ProposalState::Executed);
}

// ---------------------------------------------------------------------------
// Multi-Sig Threshold Verification & Double-Voting Prevention Tests
// ---------------------------------------------------------------------------

#[test]
fn multisig_threshold_verification_and_double_voting_prevention() {
    let h = setup(5);
    // 5 approvers, threshold = 3
    let id = create(&h, 3, 5_000);

    // First voter approves
    let count1 = h.client.approve(&h.approvers[0], &id);
    assert_eq!(count1, 1);
    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // Duplicate vote attempt by same approver must be rejected with AlreadySigned
    let dup_res = h.client.try_approve(&h.approvers[0], &id);
    assert_eq!(dup_res, Err(Ok(Error::AlreadySigned)));

    // Second voter approves (tally = 2, still below threshold 3)
    let count2 = h.client.approve(&h.approvers[1], &id);
    assert_eq!(count2, 2);
    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // Execution request fails because proposal is not yet approved
    let exec_res1 = h.client.try_execute(&h.proposer, &id);
    assert_eq!(exec_res1, Err(Ok(Error::ProposalNotApproved)));

    // Third distinct voter approves (tally = 3, meets threshold 3, quorum 3, majority 3)
    let count3 = h.client.approve(&h.approvers[2], &id);
    assert_eq!(count3, 3);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // Execution now succeeds atomically
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn execution_rejected_when_approval_tally_below_threshold() {
    let h = setup(5);
    // Proposal requiring threshold of 4 approvals out of 5 approvers
    let id = create(&h, 4, 10_000);

    // 3 out of 5 approvers vote (1 short of threshold 4)
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.approve(&h.approvers[2], &id);

    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // Execution is rejected since proposal remains Pending (not Approved)
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::ProposalNotApproved)));

    // Fourth approval completes threshold requirement
    h.client.approve(&h.approvers[3], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // Now execution succeeds
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn prune_requires_a_passed_deadline() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(
        h.client.try_prune_expired(&id),
        Err(Ok(Error::InvalidProposalState))
    );
    // A proposal without a deadline can never be pruned.
    let never = create(&h, 2, 0);
    assert_eq!(
        h.client.try_prune_expired(&never),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn prune_settles_and_purges_a_stale_proposal() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);
    h.client.prune_expired(&id);
    assert!(emitted(&h.env, "expired"));
    assert!(emitted(&h.env, "pruned"));
    assert!(emitted(&h.env, "cleaned"));
    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
    // Repeat pruning returns NotFound because storage was purged
    assert_eq!(h.client.try_prune_expired(&id), Err(Ok(Error::NotFound)));
}

#[test]
fn prune_purges_the_record_and_its_approval_flags() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    advance(&h, 6, 6_000);
    h.client.prune_expired(&id);

    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
    assert_eq!(
        h.client.try_approve(&h.approvers[1], &id),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn prune_expired_refunds_deposit_to_proposer() {
    let h = setup(3);
    let token = deposit_token(&h);
    let id = create_with_deposit(&h, 2, 5_000, &token);
    assert_eq!(
        soroban_sdk::token::TokenClient::new(&h.env, &token).balance(&h.proposer),
        0
    );

    advance(&h, 6, 6_000);
    h.client.prune_expired(&id);

    // Deposit is refunded on pruning
    assert_eq!(
        soroban_sdk::token::TokenClient::new(&h.env, &token).balance(&h.proposer),
        DEPOSIT
    );
    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
}

#[test]
fn permissionless_pruning_by_any_caller() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);

    // Prune triggered permissionlessly by third party
    let _stranger = Address::generate(&h.env);
    // ProposalContract::prune_expired does not require caller auth
    h.client.prune_expired(&id);
    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
}

#[test]
fn post_expiration_execution_rejection_and_storage_pruning() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // Advance time past expiration deadline
    advance(&h, 6, 6_000);
    assert!(h.client.is_expired(&id));
    assert!(!h.client.can_execute(&id));

    // Execution rejects the already-expired proposal without executing.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert!(!h.client.is_executed(&id));

    // Clean up / prune from persistent storage
    h.client.prune_expired(&id);
    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));

    // Post-pruning execution fails with NotFound
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn prune_expired_batch_cleans_eligible_and_skips_ineligible() {
    let h = setup(3);
    let p1 = create(&h, 2, 5_000);
    let p2 = create(&h, 2, 10_000); // not yet expired at t=6_000
    let p3 = create(&h, 2, 5_000);
    let non_existent = 999u64;

    advance(&h, 6, 6_000);

    let batch = vec![&h.env, p1, p2, p3, non_existent];
    let pruned_count = h.client.prune_expired_batch(&batch);
    assert_eq!(pruned_count, 2);

    // p1 and p3 were pruned
    assert_eq!(h.client.try_get(&p1), Err(Ok(Error::NotFound)));
    assert_eq!(h.client.try_get(&p3), Err(Ok(Error::NotFound)));
    // p2 is still alive and Pending
    assert_eq!(h.client.state(&p2), ProposalState::Pending);
}

#[test]
fn prune_expired_batch_size_limits() {
    let h = setup(3);
    let empty = vec![&h.env];
    assert_eq!(h.client.prune_expired_batch(&empty), 0);

    let mut oversized = vec![&h.env];
    for _ in 0..(MAX_PRUNE_BATCH + 1) {
        oversized.push_back(1);
    }
    assert_eq!(
        h.client.try_prune_expired_batch(&oversized),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn prune_expired_range_cleans_consecutive_records() {
    let h = setup(3);
    let p1 = create(&h, 2, 5_000);
    let p2 = create(&h, 2, 5_000);
    let p3 = create(&h, 2, 5_000);

    advance(&h, 6, 6_000);

    // Prune range [p1, p1 + 3)
    let pruned = h.client.prune_expired_range(&p1, &3);
    assert_eq!(pruned, 3);

    assert_eq!(h.client.try_get(&p1), Err(Ok(Error::NotFound)));
    assert_eq!(h.client.try_get(&p2), Err(Ok(Error::NotFound)));
    assert_eq!(h.client.try_get(&p3), Err(Ok(Error::NotFound)));

    // Limit 0 or oversized fails
    assert_eq!(
        h.client.try_prune_expired_range(&1, &0),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        h.client.try_prune_expired_range(&1, &(MAX_PRUNE_BATCH + 1)),
        Err(Ok(Error::InvalidInput))
    );
}

// ---------------------------------------------------------------------------
// Issue #329 — state machine transitions and validation.
//
// The canonical transition table lives in `ProposalState::may_transition`;
// every state-changing entrypoint validates its edge against it. These tests
// pin the table itself and the observable behavior on both sides: legal
// transitions proceed and emit their event, illegal ones are refused with
// explicit contract errors and leave the record untouched.
// ---------------------------------------------------------------------------

#[test]
fn state_machine_admits_exactly_the_documented_edges() {
    use astroid_interfaces::proposal::ProposalState as PS;

    // Every legal edge of the lifecycle diagram.
    let legal = [
        (PS::Created, PS::Pending),
        (PS::Pending, PS::Approved),
        (PS::Pending, PS::Rejected),
        (PS::Pending, PS::Cancelled),
        (PS::Pending, PS::Expired),
        (PS::Approved, PS::Executed),
        (PS::Approved, PS::Failed),
        (PS::Approved, PS::Cancelled),
        (PS::Approved, PS::Expired),
        (PS::Executed, PS::Closed),
    ];
    for (from, to) in legal {
        assert!(
            from.may_transition(to),
            "{:?} -> {:?} must be legal",
            from,
            to
        );
    }

    // Every other pair is refused — including the deposit double-spend edge
    // (Rejected -> Cancelled) and all self-loops and backwards edges.
    let states = [
        PS::Created,
        PS::Pending,
        PS::Approved,
        PS::Executed,
        PS::Closed,
        PS::Rejected,
        PS::Cancelled,
        PS::Expired,
        PS::Failed,
    ];
    for from in states {
        for to in states {
            let is_legal = legal.iter().any(|&(f, t)| f == from && t == to);
            assert_eq!(
                from.may_transition(to),
                is_legal,
                "{:?} -> {:?} disagrees with the documented table",
                from,
                to
            );
        }
    }
}

#[test]
fn terminal_states_have_no_outgoing_transitions() {
    use astroid_interfaces::proposal::ProposalState as PS;

    let all = [
        PS::Created,
        PS::Pending,
        PS::Approved,
        PS::Executed,
        PS::Closed,
        PS::Rejected,
        PS::Cancelled,
        PS::Expired,
        PS::Failed,
    ];

    // Fully frozen terminals: no outgoing edge at all.
    for terminal in [
        PS::Closed,
        PS::Rejected,
        PS::Cancelled,
        PS::Expired,
        PS::Failed,
    ] {
        assert!(terminal.is_terminal());
        for next in all {
            assert!(
                !terminal.may_transition(next),
                "terminal {:?} must not transition to {:?}",
                terminal,
                next
            );
        }
    }

    // `Executed` is terminal for callers but keeps exactly one tidy-up edge:
    // closing the record. Nothing else may leave it.
    assert!(PS::Executed.is_terminal());
    assert!(PS::Executed.may_transition(PS::Closed));
    for next in all.iter().filter(|s| **s != PS::Closed) {
        assert!(
            !PS::Executed.may_transition(*next),
            "Executed must not transition to {:?}",
            next
        );
    }
}

#[test]
fn every_transition_emits_its_event() {
    // Pending -> Approved -> Executed -> Closed with the matching event each
    // time; expiry adds its own below.
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert!(emitted(&h.env, "created"));

    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert!(emitted(&h.env, "approved"));
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    h.client.execute(&h.proposer, &id);
    assert!(emitted(&h.env, "executed"));
    assert_eq!(h.client.state(&id), ProposalState::Executed);

    h.client.close(&h.proposer, &id);
    assert!(emitted(&h.env, "closed"));
    assert_eq!(h.client.state(&id), ProposalState::Closed);

    // Pending -> Rejected and Pending -> Expired emit theirs.
    let h2 = setup(3);
    let id2 = create(&h2, 2, 5_000);
    h2.client.reject(&h2.approvers[0], &id2);
    assert!(emitted(&h2.env, "rejected"));

    let h3 = setup(3);
    let id3 = create(&h3, 2, 5_000);
    advance(&h3, 6, 6_000);
    h3.client.expire(&id3);
    assert!(emitted(&h3.env, "expired"));
}

#[test]
fn rejected_proposal_cannot_be_cancelled_double_refund_prevented() {
    // The #329 bug: `cancel` used to admit Rejected -> Cancelled, and both
    // transitions refund the deposit — a double spend. Cancelling a rejected
    // proposal is now refused with InvalidProposalState.
    let h = setup(3);
    let token = deposit_token(&h);
    let tc = TokenClient::new(&h.env, &token);
    let id = create_with_deposit(&h, 2, 5_000, &token);
    assert_eq!(tc.balance(&h.proposer), 0);

    h.client.reject(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Rejected);
    assert_eq!(tc.balance(&h.proposer), DEPOSIT); // refunded exactly once

    let res = h.client.try_cancel(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::InvalidProposalState)));
    assert_eq!(h.client.state(&id), ProposalState::Rejected); // unchanged
    assert_eq!(tc.balance(&h.proposer), DEPOSIT); // NOT refunded twice
}

#[test]
fn failed_proposal_cannot_be_cancelled() {
    // Failed is terminal (a failed action must stay visible to dependents);
    // cancelling it would also re-refund a deposit that was never taken back.
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);
    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);

    assert_eq!(
        h.client.try_cancel(&h.proposer, &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

#[test]
fn approved_proposal_can_still_be_cancelled() {
    // The legitimate escape hatch survives: cancel stays legal from the two
    // live states (Pending and Approved).
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);
    h.client.cancel(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Cancelled);
    assert!(emitted(&h.env, "cancelled"));

    // And from Pending.
    let h2 = setup(3);
    let id2 = create(&h2, 2, 5_000);
    h2.client.cancel(&h2.proposer, &id2);
    assert_eq!(h2.client.state(&id2), ProposalState::Cancelled);
}

#[test]
fn executed_then_closed_proposal_refuses_every_late_transition() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_and_execute(&h, id);
    h.client.close(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Closed);

    // A closed record is terminal: no re-approval, rejection, cancellation,
    // re-execution or failure.
    assert_eq!(
        h.client.try_approve(&h.approvers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(
        h.client.try_reject(&h.approvers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(
        h.client.try_cancel(&h.proposer, &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(
        h.client.try_fail(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Closed);
}

#[test]
fn rejected_proposal_refuses_every_late_transition() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.reject(&h.approvers[0], &id);

    // Approving a rejected proposal is invalid-state (already covered
    // elsewhere); failing and executing it must not resurrect it either.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(
        h.client.try_fail(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Rejected);
}

#[test]
fn cancelled_proposal_refuses_approval_and_rejection() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.cancel(&h.proposer, &id);

    assert_eq!(
        h.client.try_approve(&h.approvers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(
        h.client.try_reject(&h.approvers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(h.client.state(&id), ProposalState::Cancelled);
}

#[test]
fn expired_proposal_refuses_rejection_and_cancellation() {
    // Every entrypoint settles the stale record through `expire_if_due`;
    // the requests that would mutate an expired proposal become no-ops
    // rather than resurrecting it.
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);

    h.client.reject(&h.approvers[0], &id); // settles Expired, no-op otherwise
    h.client.cancel(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
}

#[test]
fn only_the_documented_edge_leaves_pending_and_approved() {
    // One exact grep of the matrix through the contract surface: from
    // `Approved`, only execute / fail / cancel / expiry-settle are legal;
    // rejecting an approved proposal is an invalid-state jump and stays one.
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);
    assert_eq!(
        h.client.try_reject(&h.approvers[0], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);
}

// ---------------------------------------------------------------------------
// Time-lock enforcement (issue #209)
//
// The release criteria live in `crate::timelock`; the cases below pin them
// from three sides — the pure arithmetic helpers, the on-chain views that
// expose the stored threshold, and the `execute` entrypoint that enforces it
// against the deterministic ledger clock. The boundary is the point: one
// second early is refused with the dedicated code, the exact release instant
// runs cleanly.
// ---------------------------------------------------------------------------

/// Drive the mock ledger to `timestamp` with a fresh env, for the pure
/// time-lock helpers that need no contract deployed.
fn ledger_at(timestamp: u64) -> Env {
    let env = Env::default();
    env.ledger().set_timestamp(timestamp);
    env
}

#[test]
fn time_lock_is_armed_only_once_approved_with_a_non_zero_delay() {
    // Not approved yet, or a disabled delay: nothing to wait for.
    assert!(!timelock::is_armed(0, 100));
    assert!(!timelock::is_armed(1_000, 0));
    assert!(!timelock::is_armed(0, 0));
    // Approved under a live delay.
    assert!(timelock::is_armed(1_000, 100));
}

#[test]
fn release_instant_is_approval_stamp_plus_delay() {
    assert_eq!(timelock::release_at(1_000, 100), Ok(1_100));
    assert_eq!(timelock::release_at(1_000, 1), Ok(1_001));
    // Unarmed inputs report the "nothing to wait for" sentinel.
    assert_eq!(timelock::release_at(0, 100), Ok(0));
    assert_eq!(timelock::release_at(1_000, 0), Ok(0));
    // The largest representable instant still succeeds ...
    assert_eq!(timelock::release_at(u64::MAX - 1, 1), Ok(u64::MAX));
    // ... and one more fails closed rather than wrapping into the past.
    assert_eq!(timelock::release_at(u64::MAX, 1), Err(Error::Overflow));
    assert_eq!(
        timelock::release_at(u64::MAX, u64::MAX),
        Err(Error::Overflow)
    );
}

#[test]
fn remaining_counts_down_to_the_release_instant() {
    // Approved at 1_000 with a 100s delay -> release at 1_100.
    let early = timelock::time_lock_status(&ledger_at(1_000), 1_000, 100).unwrap();
    assert_eq!(early.release_at, 1_100);
    assert_eq!(early.remaining, 100);
    assert!(early.armed && !early.released && early.blocking());

    let later = timelock::time_lock_status(&ledger_at(1_099), 1_000, 100).unwrap();
    assert_eq!(later.remaining, 1);
    assert!(later.blocking());

    // Exactly at the release instant: inclusive boundary, nothing left to wait.
    let exact = timelock::time_lock_status(&ledger_at(1_100), 1_000, 100).unwrap();
    assert_eq!(exact.remaining, 0);
    assert!(exact.released);
    assert!(!exact.blocking());

    // Long past it: still released, and `remaining` saturates at zero rather
    // than wrapping into a huge number.
    let after = timelock::time_lock_status(&ledger_at(9_999), 1_000, 100).unwrap();
    assert_eq!(after.remaining, 0);
    assert!(after.released);
}

#[test]
fn disabled_time_lock_never_blocks() {
    // Delay of 0, and an unapproved record: both leave the time-lock unarmed
    // and immediately released, whatever the clock says.
    for now in [0u64, 1_000, u64::MAX] {
        let env = ledger_at(now);
        assert!(timelock::is_released(&env, 1_000, 0).unwrap());
        assert!(!timelock::is_active(&env, 1_000, 0).unwrap());
        assert!(timelock::require_released(&env, 1_000, 0).is_ok());

        assert!(timelock::is_released(&env, 0, 100).unwrap());
        assert!(!timelock::is_active(&env, 0, 100).unwrap());
        assert!(timelock::require_released(&env, 0, 100).is_ok());
    }
}

#[test]
fn require_released_reports_the_deterministic_premature_code() {
    // Every second before the release instant is the same, stable error —
    // never a state code, never a panic — and the instant itself passes.
    for now in [1_000u64, 1_001, 1_050, 1_099] {
        assert_eq!(
            timelock::require_released(&ledger_at(now), 1_000, 100),
            Err(Error::TimelockNotExpired)
        );
    }
    assert!(timelock::require_released(&ledger_at(1_100), 1_000, 100).is_ok());
    // Fail closed on an unrepresentable release instant.
    assert_eq!(
        timelock::require_released(&ledger_at(1_000), u64::MAX, u64::MAX),
        Err(Error::Overflow)
    );
}

#[test]
fn timelock_view_reports_the_configured_delay() {
    let disabled = setup(3);
    assert_eq!(disabled.client.timelock(), 0);

    let h = setup_timelocked(3, 100);
    assert_eq!(h.client.timelock(), 100);
}

#[test]
fn release_at_view_tracks_the_approval_stamp() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);

    // Pending: not approved, so there is no release instant to report.
    assert_eq!(h.client.release_at(&id), 0);
    assert_eq!(
        h.client.timelock_status(&id),
        timelock::TimeLockStatus {
            approved_at: 0,
            delay: 100,
            release_at: 0,
            remaining: 0,
            armed: false,
            released: true,
        }
    );

    // Approved at the setup timestamp: the threshold is now fixed on-chain.
    approve_to_threshold(&h, id);
    assert_eq!(h.client.release_at(&id), 1_100);
    let status = h.client.timelock_status(&id);
    assert_eq!(status.approved_at, 1_000);
    assert_eq!(status.delay, 100);
    assert_eq!(status.release_at, 1_100);
    assert!(status.armed && !status.released);
}

#[test]
fn timelock_status_view_flips_exactly_at_the_release_instant() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    approve_to_threshold(&h, id);

    // One second early: the view advertises the wait and execution is refused
    // with the dedicated premature-execution code.
    advance(&h, 2, 1_099);
    let blocked = h.client.timelock_status(&id);
    assert_eq!(blocked.remaining, 1);
    assert!(blocked.blocking());
    assert!(!h.client.can_execute(&id));
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // Exactly at the release instant: nothing left to wait, the proposal
    // executes cleanly and the stamp survives the transition.
    advance(&h, 3, 1_100);
    let mature = h.client.timelock_status(&id);
    assert_eq!(mature.remaining, 0);
    assert!(mature.released);
    assert!(!mature.blocking());
    assert!(h.client.can_execute(&id));
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
    assert_eq!(h.client.release_at(&id), 1_100);
}

#[test]
fn a_zero_time_lock_settles_cleanly_for_every_proposal_stage() {
    let h = setup(3); // timelock 0 — the disabled configuration.
    let id = create(&h, 2, 10_000);

    // Pending: unarmed, nothing to wait for.
    let pending = h.client.timelock_status(&id);
    assert!(!pending.armed);
    assert_eq!(pending.release_at, 0);

    // Approved: still unarmed, so execution is immediate as before.
    approve_to_threshold(&h, id);
    let approved = h.client.timelock_status(&id);
    assert!(!approved.armed);
    assert!(approved.released);
    assert_eq!(approved.release_at, 0);
    assert!(h.client.can_execute(&id));

    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn an_unrepresentable_release_instant_is_visible_and_fails_closed() {
    // A delay that cannot be added to the approval stamp must never wrap into
    // the past. The view reports the deterministic `Overflow` code and the
    // entrypoint refuses for the same reason.
    let h = setup_timelocked(3, u64::MAX);
    let id = create(&h, 2, 0);
    approve_to_threshold(&h, id);

    assert_eq!(h.client.try_release_at(&id), Err(Ok(Error::Overflow)));
    assert_eq!(h.client.try_timelock_status(&id), Err(Ok(Error::Overflow)));
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::Overflow))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);
}

#[test]
fn a_late_approval_does_not_buy_a_fresh_cooling_off_window() {
    // The delay is measured from the instant the threshold was reached, so
    // approving later in the window shortens the remaining wait rather than
    // restarting it: a proposer cannot buy a longer veto period by slowing
    // the vote down.
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);

    h.client.approve(&h.approvers[0], &id); // still Pending at t = 1_000
    advance(&h, 5, 1_050);
    h.client.approve(&h.approvers[1], &id); // reaches the threshold at 1_050

    assert_eq!(h.client.release_at(&id), 1_150);
    assert_eq!(h.client.timelock_status(&id).remaining, 100);
    advance(&h, 6, 1_149);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::TimelockNotExpired))
    );
    advance(&h, 7, 1_150);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}
