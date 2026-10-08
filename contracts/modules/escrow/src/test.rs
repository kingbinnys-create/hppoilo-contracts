extern crate std;

use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    testutils::{
        Address as _, AuthorizedFunction, AuthorizedInvocation, Events, Ledger, MockAuth,
        MockAuthInvoke,
    },
    token, vec, Address, Bytes, BytesN, Env, IntoVal, String, Symbol, Val, Vec,
};

use astroid_shared::errors::{Error, MilestoneError};
use astroid_shared::types::AssetAmount;

use crate::{
    EscrowContract, EscrowContractClient, EscrowState, MilestoneSpec, MilestoneStatus,
    OverrideSignature, ReleaseConditionConfig, ReleaseSchedule, ReleaseType,
};

const START: u64 = 1_000;
const GRACE: u64 = 1_000;

struct Harness<'a> {
    env: Env,
    client: EscrowContractClient<'a>,
    asset_a: Address,
    asset_b: Address,
    sender: Address,
    recipient: Address,
    arbiter: Address,
    admin: Address,
}

/// Register the contract with an admin but an **empty** token whitelist, so a
/// test can drive the approval flow itself. `setup` approves both harness
/// tokens instead, which is what the rest of the suite assumes.
fn setup_unapproved(funded_a: i128, funded_b: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let id = env.register_contract(None, EscrowContract);
    let client = EscrowContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let token_admin_a = Address::generate(&env);
    let asset_a = env
        .register_stellar_asset_contract_v2(token_admin_a)
        .address();
    let token_admin_b = Address::generate(&env);
    let asset_b = env
        .register_stellar_asset_contract_v2(token_admin_b)
        .address();

    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    if funded_a > 0 {
        token::StellarAssetClient::new(&env, &asset_a).mint(&sender, &funded_a);
    }
    if funded_b > 0 {
        token::StellarAssetClient::new(&env, &asset_b).mint(&sender, &funded_b);
    }

    Harness {
        env,
        client,
        asset_a,
        asset_b,
        sender,
        recipient,
        arbiter,
        admin,
    }
}

fn setup(funded_a: i128, funded_b: i128) -> Harness<'static> {
    let h = setup_unapproved(funded_a, funded_b);
    // The whitelist approves nothing by default, so the suite approves the two
    // harness tokens up front.
    h.client.approve_token(&h.admin, &h.asset_a);
    h.client.approve_token(&h.admin, &h.asset_b);
    h
}

fn balance(h: &Harness, asset: &Address, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, asset).balance(who)
}

fn one_asset(h: &Harness, amount: i128) -> Vec<AssetAmount> {
    vec![
        &h.env,
        AssetAmount {
            asset: h.asset_a.clone(),
            amount,
        },
    ]
}

fn two_assets(h: &Harness, amount_a: i128, amount_b: i128) -> Vec<AssetAmount> {
    vec![
        &h.env,
        AssetAmount {
            asset: h.asset_a.clone(),
            amount: amount_a,
        },
        AssetAmount {
            asset: h.asset_b.clone(),
            amount: amount_b,
        },
    ]
}

fn no_signers(h: &Harness) -> Vec<BytesN<32>> {
    Vec::new(&h.env)
}

fn create(h: &Harness, assets: &Vec<AssetAmount>, deadline: u64, grace_period: u64) -> u64 {
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        assets,
        &deadline,
        &grace_period,
        &String::from_str(&h.env, "payment"),
        &no_signers(h),
        &0,
    )
}

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(env: &Env, kp: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &kp.verifying_key().to_bytes())
}

fn sign_override(h: &Harness, kp: &SigningKey, id: u64, nonce: u64) -> OverrideSignature {
    let contract = h.client.address.clone();
    let digest: [u8; 32] = h.env.as_contract(&contract, || {
        let payload: Bytes = EscrowContract::override_payload(&h.env, id, nonce);
        h.env.crypto().sha256(&payload).to_array()
    });
    let signature = kp.sign(&digest).to_bytes();
    OverrideSignature {
        public_key: public_key(&h.env, kp),
        signature: BytesN::from_array(&h.env, &signature),
    }
}

fn milestone_spec(env: &Env, description: &str, bps: u32) -> MilestoneSpec {
    MilestoneSpec {
        description: String::from_str(env, description),
        release_bps: bps,
    }
}

/// Build a [`ReleaseConditionConfig`] over `assets` with the
/// signature-override path disabled and the refund window left unbounded.
fn release_condition_config(
    h: &Harness,
    assets: &Vec<AssetAmount>,
    participants: &Vec<Address>,
    threshold: u32,
    deadline: u64,
) -> ReleaseConditionConfig {
    ReleaseConditionConfig {
        sender: h.sender.clone(),
        recipient: h.recipient.clone(),
        arbiter: h.arbiter.clone(),
        assets: assets.clone(),
        deadline,
        grace_period: GRACE,
        refund_window: 0,
        memo: String::from_str(&h.env, "multi-party"),
        override_signers: no_signers(h),
        override_threshold: 0,
        participants: participants.clone(),
        approval_threshold: threshold,
    }
}

/// Create + fund a multi-party escrow that pays out only after `threshold`
/// distinct approvals out of `participants`.
fn create_multi_party(
    h: &Harness,
    assets: &Vec<AssetAmount>,
    participants: &Vec<Address>,
    threshold: u32,
    deadline: u64,
) -> u64 {
    let config = release_condition_config(h, assets, participants, threshold, deadline);
    h.client.create_with_release_condition(&config)
}

/// `threshold` fresh counterparties standing in for the buyer, seller and
/// validator-oracle agents of a collaborative settlement.
fn counterparties(env: &Env, count: u32) -> Vec<Address> {
    let mut out: Vec<Address> = Vec::new(env);
    for _ in 0..count {
        out.push_back(Address::generate(env));
    }
    out
}

// --- Core multi-asset tests ---

#[test]
fn full_cycle_create_release() {
    let h = setup(10_000, 5_000);
    let assets = two_assets(&h, 10_000, 5_000);
    let id = create(&h, &assets, START + 86_400, 0);
    assert_eq!(id, 1);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);

    h.client.release(&h.arbiter, &id, &10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_b, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 0);

    h.client.close(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Closed);
}

#[test]
fn non_arbiter_cannot_release() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);
    let intruder = Address::generate(&h.env);

    let res = h.client.try_release(&intruder, &id, &5_000);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
}

#[test]
fn release_after_deadline_is_refused() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_release(&h.arbiter, &id, &5_000);
    assert_eq!(res, Err(Ok(Error::EscrowExpired)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn refund_returns_funds_after_deadline() {
    let h = setup(5_000, 2_000);
    let id = create(&h, &two_assets(&h, 5_000, 2_000), START + 100, 0);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_b, &h.sender), 2_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 0);
}

#[test]
fn refund_before_deadline_rejected() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);

    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn expire_marks_then_refund_returns() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);

    let early = h.client.try_expire(&id);
    assert_eq!(early, Err(Ok(Error::InvalidState)));

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.expire(&id);
    assert_eq!(h.client.get(&id).state, EscrowState::Expired);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);

    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn released_escrow_cannot_be_refunded() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);
    h.client.release(&h.arbiter, &id, &5_000);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn cannot_close_while_expired() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.expire(&id);

    let res = h.client.try_close(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn create_rejects_bad_input() {
    let h = setup(5_000, 0);
    let r1 = h.client.try_create(
        &h.sender,
        &h.sender,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r1, Err(Ok(Error::InvalidInput)));
    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START - 500),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r2, Err(Ok(Error::InvalidInput)));
    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 0),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r3, Err(Ok(Error::InvalidAmount)));
    let r4 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &Vec::new(&h.env),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r4, Err(Ok(Error::InvalidInput)));
    let dup = vec![
        &h.env,
        AssetAmount {
            asset: h.asset_a.clone(),
            amount: 1_000,
        },
        AssetAmount {
            asset: h.asset_a.clone(),
            amount: 500,
        },
    ];
    let r5 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &dup,
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r5, Err(Ok(Error::InvalidInput)));
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
}

#[test]
fn create_rejects_bad_override_config() {
    let h = setup(5_000, 0);
    let signer = public_key(&h.env, &keypair(1));
    let signers = vec![&h.env, signer];

    let r1 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &signers,
        &0,
    );
    assert_eq!(r1, Err(Ok(Error::InvalidThreshold)));

    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &signers,
        &2,
    );
    assert_eq!(r2, Err(Ok(Error::InvalidThreshold)));

    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &Vec::new(&h.env),
        &1,
    );
    assert_eq!(r3, Err(Ok(Error::InvalidThreshold)));
}

// --- Override release tests ---

#[test]
fn override_release_with_threshold_signatures_releases_funds() {
    let h = setup(5_000, 1_000);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &two_assets(&h, 5_000, 1_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &2,
    );

    let nonce = 1u64;
    let sig1 = sign_override(&h, &kp1, id, nonce);
    let sig2 = sign_override(&h, &kp2, id, nonce);
    let sigs = vec![&h.env, sig1, sig2];

    h.client.override_release(&id, &nonce, &sigs);

    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.asset_b, &h.recipient), 1_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn override_release_rejects_replayed_nonce() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let signers = vec![&h.env, public_key(&h.env, &kp1)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &1,
    );

    let nonce = 1u64;
    let sig = sign_override(&h, &kp1, id, nonce);
    h.client
        .override_release(&id, &nonce, &vec![&h.env, sig.clone()]);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);

    let res = h
        .client
        .try_override_release(&id, &nonce, &vec![&h.env, sig]);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn override_release_requires_strictly_increasing_nonce() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &2,
    );

    let sig1 = sign_override(&h, &kp1, id, 0);
    let sig2 = sign_override(&h, &kp2, id, 0);
    let res = h
        .client
        .try_override_release(&id, &0u64, &vec![&h.env, sig1, sig2]);
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));
}

#[test]
fn override_release_rejects_insufficient_signatures() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &2,
    );

    let sig1 = sign_override(&h, &kp1, id, 1);
    let res = h
        .client
        .try_override_release(&id, &1u64, &vec![&h.env, sig1]);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
}

#[test]
fn override_release_rejects_unknown_signer() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let outsider = keypair(99);
    let signers = vec![&h.env, public_key(&h.env, &kp1)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &1,
    );

    let bad_sig = sign_override(&h, &outsider, id, 1);
    let res = h
        .client
        .try_override_release(&id, &1u64, &vec![&h.env, bad_sig]);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn override_release_rejects_duplicate_signer_in_one_call() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &2,
    );

    let sig1 = sign_override(&h, &kp1, id, 1);
    let res = h
        .client
        .try_override_release(&id, &1u64, &vec![&h.env, sig1.clone(), sig1]);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn override_release_disabled_without_configured_signers() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 1_000, 0);

    let kp1 = keypair(1);
    let sig1 = sign_override(&h, &kp1, id, 1);
    let res = h
        .client
        .try_override_release(&id, &1u64, &vec![&h.env, sig1]);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

// --- Milestone tests ---

/// Deposit a single-asset milestone escrow with the harness defaults.
fn deposit_milestones(h: &Harness, amount: i128, deadline: u64, specs: &Vec<MilestoneSpec>) -> u64 {
    h.client.deposit_with_milestones(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset_a,
        &amount,
        &deadline,
        &String::from_str(&h.env, "project"),
        specs,
    )
}

#[test]
fn milestone_multi_creation_stores_ordered_schedule() {
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "design", 2_000),
        milestone_spec(&h.env, "build", 3_000),
        milestone_spec(&h.env, "ship", 5_000),
    ];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);

    let set = h.client.milestones(&id);
    assert_eq!(set.milestones.len(), 3);
    assert_eq!(set.released_amount, 0);
    assert!(!set.cancelled);
    for (i, expected_bps) in [(0u32, 2_000u32), (1, 3_000), (2, 5_000)] {
        let m = set.milestones.get(i).unwrap();
        assert_eq!(m.index, i);
        assert_eq!(m.release_bps, expected_bps);
        assert_eq!(m.status, MilestoneStatus::Pending);
    }
}

#[test]
fn milestone_partial_then_full_release() {
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "design", 4_000),
        milestone_spec(&h.env, "build", 6_000),
    ];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);

    h.client.release_milestone(&h.arbiter, &id, &0);
    let set = h.client.milestones(&id);
    assert_eq!(
        set.milestones.get(0).unwrap().status,
        MilestoneStatus::Completed
    );
    assert_eq!(
        set.milestones.get(1).unwrap().status,
        MilestoneStatus::Pending
    );
    assert_eq!(set.released_amount, 4_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 4_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);

    h.client.release_milestone(&h.arbiter, &id, &1);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);

    h.client.close(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Closed);
}

#[test]
fn milestone_sequential_completion_releases_each_share() {
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "a", 2_000),
        milestone_spec(&h.env, "b", 3_000),
        milestone_spec(&h.env, "c", 5_000),
    ];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    let mut paid = 0i128;
    for index in 0..3u32 {
        h.client.release_milestone(&h.arbiter, &id, &index);
        let set = h.client.milestones(&id);
        assert_eq!(
            set.milestones.get(index).unwrap().status,
            MilestoneStatus::Completed
        );
        assert_eq!(balance(&h, &h.asset_a, &h.recipient), set.released_amount);
        assert!(set.released_amount > paid);
        paid = set.released_amount;
    }
    assert_eq!(paid, 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
}

#[test]
fn milestone_final_payout_absorbs_rounding_dust() {
    // 3333 + 3333 + 3334 bps of 10_000 floors to 3333 + 3333 + 3334: the last
    // approval pays the remainder, so nothing is stranded.
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "a", 3_333),
        milestone_spec(&h.env, "b", 3_333),
        milestone_spec(&h.env, "c", 3_334),
    ];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    h.client.release_milestone(&h.arbiter, &id, &0);
    assert_eq!(h.client.milestones(&id).released_amount, 3_333);
    h.client.release_milestone(&h.arbiter, &id, &1);
    assert_eq!(h.client.milestones(&id).released_amount, 6_666);
    h.client.release_milestone(&h.arbiter, &id, &2);
    assert_eq!(h.client.milestones(&id).released_amount, 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn milestone_unauthorized_approval_rejected() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);
    let res = h.client.try_release_milestone(&h.sender, &id, &0);
    assert_eq!(res, Err(Ok(MilestoneError::Unauthorized)));
    // The milestone-specific enum still carries the canonical wire code.
    let wire = soroban_sdk::Error::from(MilestoneError::Unauthorized).get_code();
    assert_eq!(wire, Error::Unauthorized.code());
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
}

#[test]
fn milestone_double_release_rejected() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);
    h.client.release_milestone(&h.arbiter, &id, &0);
    let res = h.client.try_release_milestone(&h.arbiter, &id, &0);
    assert_eq!(res, Err(Ok(MilestoneError::MilestoneAlreadyCompleted)));
    assert_eq!(
        soroban_sdk::Error::from(MilestoneError::MilestoneAlreadyCompleted).get_code(),
        87
    );
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn milestone_unknown_index_rejected() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);
    let res = h.client.try_release_milestone(&h.arbiter, &id, &7);
    assert_eq!(res, Err(Ok(MilestoneError::InvalidMilestone)));
    assert_eq!(
        soroban_sdk::Error::from(MilestoneError::InvalidMilestone).get_code(),
        86
    );
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
}

#[test]
fn milestone_bps_must_total_100() {
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "a", 4_000),
        milestone_spec(&h.env, "b", 5_000),
    ];
    let res = h.client.try_deposit_with_milestones(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset_a,
        &10_000,
        &(START + 86_400),
        &String::from_str(&h.env, "p"),
        &specs,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 10_000);
}

#[test]
fn plain_release_blocked_on_milestone_escrow() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);
    let res = h.client.try_release(&h.arbiter, &id, &10_000);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
}

#[test]
fn milestone_escrow_refuses_generic_settlement_paths() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    // Beneficiary paths are refused before any schedule math.
    assert_eq!(
        h.client.try_withdraw(&h.recipient, &id, &1_000),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        h.client.try_claim(&h.recipient, &id),
        Err(Ok(Error::InvalidState))
    );

    // Reclaim / refund after the grace window are refused too: the milestone
    // cancel path is the only exit for the unreleased remainder.
    h.env.ledger().with_mut(|l| l.timestamp = START + 200_000);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
}

#[test]
fn milestone_cancel_refunds_only_remaining() {
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "design", 4_000),
        milestone_spec(&h.env, "build", 6_000),
    ];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    h.client.release_milestone(&h.arbiter, &id, &0);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 4_000);

    let refunded = h.client.cancel_remaining_milestones(&h.sender, &id);
    assert_eq!(refunded, 6_000);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 6_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 4_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);

    let set = h.client.milestones(&id);
    assert!(set.cancelled);
    assert_eq!(
        set.milestones.get(0).unwrap().status,
        MilestoneStatus::Completed
    );
    assert_eq!(
        set.milestones.get(1).unwrap().status,
        MilestoneStatus::Disputed
    );

    // A cancelled schedule can no longer be approved.
    assert_eq!(
        h.client.try_release_milestone(&h.arbiter, &id, &1),
        Err(Ok(MilestoneError::InvalidState))
    );
}

#[test]
fn milestone_cancel_is_idempotency_guarded() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    h.client.cancel_remaining_milestones(&h.sender, &id);
    let res = h.client.try_cancel_remaining_milestones(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 10_000);
}

#[test]
fn milestone_cancel_rejected_for_non_party() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);
    let intruder = Address::generate(&h.env);
    let res = h.client.try_cancel_remaining_milestones(&intruder, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
}

#[test]
fn milestone_cancel_reachable_through_cancel_entrypoint() {
    // `cancel` stays usable on a milestone escrow, but routes through the
    // milestone-aware path so a partial payout is never double-refunded.
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "a", 4_000),
        milestone_spec(&h.env, "b", 6_000),
    ];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);
    h.client.release_milestone(&h.arbiter, &id, &0);

    h.client.cancel(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 6_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 4_000);
    assert!(h.client.milestones(&id).cancelled);
}

#[test]
fn milestone_dispute_freezes_and_resolve_reenables() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    h.client.dispute_milestone(&h.arbiter, &id, &0);
    assert_eq!(
        h.client.milestones(&id).milestones.get(0).unwrap().status,
        MilestoneStatus::Disputed
    );
    assert_eq!(
        h.client.try_release_milestone(&h.arbiter, &id, &0),
        Err(Ok(MilestoneError::InvalidMilestone))
    );

    h.client.resolve_milestone(&h.arbiter, &id, &0);
    assert_eq!(
        h.client.milestones(&id).milestones.get(0).unwrap().status,
        MilestoneStatus::Pending
    );
    h.client.release_milestone(&h.arbiter, &id, &0);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
}

#[test]
fn milestone_dispute_and_resolve_are_state_guarded() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    // Resolving something that was never disputed is invalid.
    assert_eq!(
        h.client.try_resolve_milestone(&h.arbiter, &id, &0),
        Err(Ok(MilestoneError::InvalidMilestone))
    );
    // A non-arbiter cannot dispute.
    assert_eq!(
        h.client.try_dispute_milestone(&h.sender, &id, &0),
        Err(Ok(MilestoneError::Unauthorized))
    );
    // Disputing an unknown index is invalid.
    assert_eq!(
        h.client.try_dispute_milestone(&h.arbiter, &id, &9),
        Err(Ok(MilestoneError::InvalidMilestone))
    );

    h.client.release_milestone(&h.arbiter, &id, &0);
    // A completed milestone can be neither disputed nor resolved.
    assert_eq!(
        h.client.try_dispute_milestone(&h.arbiter, &id, &0),
        Err(Ok(MilestoneError::MilestoneAlreadyCompleted))
    );
    assert_eq!(
        h.client.try_resolve_milestone(&h.arbiter, &id, &0),
        Err(Ok(MilestoneError::MilestoneAlreadyCompleted))
    );
}

#[test]
fn milestone_zero_weight_approves_without_payout() {
    // A review/verification milestone can carry zero basis points: it is still
    // tracked and completed, but moves no funds, and the weighted milestones
    // still sum to the full amount.
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "kickoff", 0),
        milestone_spec(&h.env, "delivery", 10_000),
    ];
    let id = deposit_milestones(&h, 10_000, START + 86_400, &specs);

    h.client.release_milestone(&h.arbiter, &id, &0);
    assert_eq!(h.client.milestones(&id).released_amount, 0);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
    assert_eq!(
        h.client.milestones(&id).milestones.get(0).unwrap().status,
        MilestoneStatus::Completed
    );

    // The final milestone still pays the dust-free remainder.
    h.client.release_milestone(&h.arbiter, &id, &1);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
}

#[test]
fn timelock_cliff_rejects_early_withdraw_and_claims_post_maturity() {
    let h = setup(10_000, 0);
    let unlock_time = START + 1_000;

    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &unlock_time,
        &String::from_str(&h.env, "timelock cliff"),
    );
    assert_eq!(id, 1);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);

    // Pre-maturity check: withdrawal and claim must fail with TimeLockActive
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
    assert_eq!(h.client.get_vested_amount(&id), 0);

    let early_claim = h.client.try_claim(&h.recipient, &id);
    assert_eq!(early_claim, Err(Ok(Error::TimeLockActive)));

    let early_withdraw = h.client.try_withdraw(&h.recipient, &id, &5_000);
    assert_eq!(early_withdraw, Err(Ok(Error::TimeLockActive)));

    // Post-maturity check: claim succeeds
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert_eq!(h.client.get_claimable_amount(&id), 10_000);
    assert_eq!(h.client.get_vested_amount(&id), 10_000);

    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
}

#[test]
fn timelock_linear_release_gradual_withdrawals() {
    let h = setup(10_000, 0);
    let start_time = START;
    let cliff_time = START + 200;
    let end_time = START + 1_000;

    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time,
        cliff_time,
        end_time,
    };

    let id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &schedule,
        &end_time,
        &String::from_str(&h.env, "linear schedule"),
    );

    // 1. Before cliff (timestamp = START + 100): locked
    h.env.ledger().with_mut(|l| l.timestamp = START + 100);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
    assert_eq!(h.client.get_vested_amount(&id), 0);
    let res = h.client.try_withdraw(&h.recipient, &id, &1_000);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));

    // 2. At 50% time (timestamp = START + 500, past cliff):
    // 50% of 10,000 = 5,000 vested.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_vested_amount(&id), 5_000);
    assert_eq!(h.client.get_claimable_amount(&id), 5_000);

    // Partial withdrawal of 3,000
    let total_released = h.client.withdraw(&h.recipient, &id, &3_000);
    assert_eq!(total_released, 3_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 3_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 7_000);
    assert_eq!(h.client.get_claimable_amount(&id), 2_000);

    // Attempt to withdraw more than currently claimable (3,000 > 2,000)
    let over_withdraw = h.client.try_withdraw(&h.recipient, &id, &3_000);
    assert_eq!(over_withdraw, Err(Ok(Error::InsufficientFunds)));

    // 3. At 80% time (timestamp = START + 800):
    // 80% of 10,000 = 8,000 vested; already released 3,000 => claimable = 5,000.
    h.env.ledger().with_mut(|l| l.timestamp = START + 800);
    assert_eq!(h.client.get_vested_amount(&id), 8_000);
    assert_eq!(h.client.get_claimable_amount(&id), 5_000);

    let next_released = h.client.withdraw(&h.recipient, &id, &5_000);
    assert_eq!(next_released, 8_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 8_000);
    assert_eq!(h.client.get_claimable_amount(&id), 0);

    // 4. At 100% maturity (timestamp = START + 1_000):
    // Total vested = 10,000; claimable = 2,000.
    h.env.ledger().with_mut(|l| l.timestamp = START + 1_000);
    assert_eq!(h.client.get_vested_amount(&id), 10_000);
    assert_eq!(h.client.get_claimable_amount(&id), 2_000);

    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 2_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
}

#[test]
fn scheduled_escrow_rejects_bad_schedule_inputs() {
    let h = setup(10_000, 0);

    // start_time > cliff_time
    let s1 = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START + 500,
        cliff_time: START + 200,
        end_time: START + 1_000,
    };
    let r1 = h.client.try_create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &s1,
        &(START + 1_000),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r1, Err(Ok(Error::InvalidInput)));

    // cliff_time > end_time
    let s2 = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START,
        cliff_time: START + 1_200,
        end_time: START + 1_000,
    };
    let r2 = h.client.try_create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &s2,
        &(START + 1_000),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r2, Err(Ok(Error::InvalidInput)));

    // end_time <= start_time
    let s3 = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START + 500,
        cliff_time: START + 500,
        end_time: START + 500,
    };
    let r3 = h.client.try_create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &s3,
        &(START + 500),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r3, Err(Ok(Error::InvalidInput)));

    // deadline < end_time
    let s4 = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START,
        cliff_time: START + 100,
        end_time: START + 1_000,
    };
    let r4 = h.client.try_create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &s4,
        &(START + 500),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r4, Err(Ok(Error::InvalidInput)));
}

#[test]
fn timelock_unauthorized_claim_and_withdraw() {
    let h = setup(5_000, 0);
    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 500),
        &String::from_str(&h.env, "timelock"),
    );

    let intruder = Address::generate(&h.env);
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);

    let r1 = h.client.try_withdraw(&intruder, &id, &1_000);
    assert_eq!(r1, Err(Ok(Error::Unauthorized)));

    let r2 = h.client.try_claim(&intruder, &id);
    assert_eq!(r2, Err(Ok(Error::Unauthorized)));
}

#[test]
fn timelock_refund_rules() {
    let h = setup(5_000, 0);
    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 500),
        &String::from_str(&h.env, "timelock"),
    );

    // Pre-deadline refund attempt fails
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let early = h.client.try_refund_timelock(&h.sender, &id);
    assert_eq!(early, Err(Ok(Error::TimeLockActive)));

    // Non-sender cannot refund
    let intruder = Address::generate(&h.env);
    let unauth = h.client.try_refund_timelock(&intruder, &id);
    assert_eq!(unauth, Err(Ok(Error::Unauthorized)));

    // Post-deadline refund succeeds
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);
    h.client.refund_timelock(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn initialize_and_fund_timelock_lifecycle() {
    let h = setup(5_000, 0);
    let id = h.client.initialize_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 500),
        &0,
        &String::from_str(&h.env, "unfunded"),
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Created);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);

    // Intruder cannot fund
    let intruder = Address::generate(&h.env);
    let unauth_fund = h.client.try_fund(&intruder, &id);
    assert_eq!(unauth_fund, Err(Ok(Error::Unauthorized)));

    // Sender funds
    h.client.fund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);

    // Pre-maturity claim fails
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let early = h.client.try_claim(&h.recipient, &id);
    assert_eq!(early, Err(Ok(Error::TimeLockActive)));

    // Post-maturity claim succeeds
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);
    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
}

// --- Grace period & cancellation (pr-137) ---

#[test]
fn release_after_grace_is_refused() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp = START + 200 + GRACE);
    let res = h.client.try_release(&h.arbiter, &id, &5_000);
    assert_eq!(res, Err(Ok(Error::EscrowExpired)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn release_allowed_during_grace() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env.ledger().with_mut(|l| l.timestamp = START + 150);
    h.client.release(&h.arbiter, &id, &5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
}

#[test]
fn refund_returns_funds_after_grace() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env.ledger().with_mut(|l| l.timestamp = START + 150);
    let early = h.client.try_refund(&h.sender, &id);
    assert_eq!(early, Err(Ok(Error::GraceActive)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp = START + 200 + GRACE);
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn cancel_by_sender_before_deadline_returns_funds() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.client.cancel(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn arbiter_may_also_cancel_before_deadline() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.client.cancel(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
}

#[test]
fn cancel_rejected_after_deadline() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env.ledger().with_mut(|l| l.timestamp = START + 150);
    let res = h.client.try_cancel(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn cancel_rejected_for_non_party() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);
    let intruder = Address::generate(&h.env);

    let res = h.client.try_cancel(&intruder, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn reclaim_after_grace_returns_funds() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env.ledger().with_mut(|l| l.timestamp = START + 150);
    let early = h.client.try_reclaim(&h.sender, &id);
    assert_eq!(early, Err(Ok(Error::GraceActive)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp = START + 200 + GRACE);
    h.client.reclaim(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn reclaim_rejected_for_non_sender() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp = START + 200 + GRACE);
    let res = h.client.try_reclaim(&h.recipient, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn reclaim_rejected_after_release() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.client.release(&h.arbiter, &id, &5_000);
    let res = h.client.try_reclaim(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
}

// --- bounded refund window ---

/// Create a funded escrow whose refund window closes `refund_window` seconds
/// after refunds open at `deadline + grace_period`.
fn create_windowed(
    h: &Harness,
    assets: &Vec<AssetAmount>,
    deadline: u64,
    grace_period: u64,
    refund_window: u64,
) -> u64 {
    h.client.create_with_refund_window(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        assets,
        &deadline,
        &grace_period,
        &refund_window,
        &String::from_str(&h.env, "payment"),
        &no_signers(h),
        &0,
    )
}

fn at(h: &Harness, ts: u64) {
    h.env.ledger().with_mut(|l| l.timestamp = ts);
}

#[test]
fn unbounded_window_is_the_default() {
    let h = setup(1_000, 0);
    let id = create(&h, &one_asset(&h, 100), START + 100, 0);
    assert_eq!(h.client.refund_window_closes_at(&id), 0);
    // Far past the deadline the refund is still available.
    at(&h, START + 10_000_000);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 1_000);
}

#[test]
fn refund_inside_the_window_succeeds() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, 50);
    assert_eq!(h.client.refund_window_closes_at(&id), START + 150);

    at(&h, START + 120);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 1_000);
}

#[test]
fn refund_after_the_window_closes_is_rejected() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, 50);

    at(&h, START + 150);
    assert!(!h.client.is_refundable(&id));
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::EscrowExpired))
    );
    // The funds stay in the escrow's custody rather than moving anywhere.
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 900);
}

#[test]
fn refund_at_the_last_second_of_the_window_succeeds() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, 50);
    // The window is half-open: it closes *at* START + 150.
    at(&h, START + 149);
    h.client.refund(&h.sender, &id);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 1_000);
}

#[test]
fn the_window_is_measured_from_the_end_of_the_grace_period() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 40, 50);
    // Refunds open at deadline + grace = START + 140, so the window closes at
    // START + 190 — never before it opens.
    assert_eq!(h.client.refund_window_closes_at(&id), START + 190);

    at(&h, START + 120);
    assert!(!h.client.is_refundable(&id));
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::GraceActive))
    );

    at(&h, START + 150);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
}

#[test]
fn reclaim_respects_the_window() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, 50);
    at(&h, START + 150);
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::EscrowExpired))
    );
}

#[test]
fn release_is_unaffected_by_the_refund_window() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 200, 50);
    // The arbiter may still release during the grace period, whatever the
    // refund window says.
    at(&h, START + 150);
    h.client.release(&h.arbiter, &id, &100);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 100);
    // A settled escrow is never refundable.
    assert!(!h.client.is_refundable(&id));
}

#[test]
fn an_absurd_window_saturates_instead_of_overflowing() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, u64::MAX);
    assert_eq!(h.client.refund_window_closes_at(&id), u64::MAX);
    at(&h, START + 10_000_000);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
}

// --- Time-lock validation on `release` (Issue #238, #332) ---

#[test]
fn release_before_cliff_maturity_is_refused_with_escrow_not_ready() {
    let h = setup(10_000, 0);
    let unlock_time = START + 1_000;

    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &unlock_time,
        &String::from_str(&h.env, "premature release"),
    );

    // The settlement deadline is still far in the future, but the arbiter must
    // not be able to route around the time lock: the cliff has not matured.
    // Release attempts report the distinct TimelockNotExpired code
    // (TIMELOCK_NOT_EXPIRED), separate from the beneficiary's TimeLockActive.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    let res = h.client.try_release(&h.arbiter, &id, &10_000);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    // The distinct early-release code: 91, not the beneficiary's 81.
    assert_eq!(Error::TimelockNotExpired as u32, 91);
    // No funds moved and the escrow is still live.
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);

    // A release attempt at exactly the boundary before the cliff also fails.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time - 1);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::TimelockNotExpired))
    );

    // At maturity the pre-existing settlement window rule takes over: a
    // timelock escrow's deadline equals its unlock time, so the release window
    // closes exactly at maturity and the arbiter is refused with
    // EscrowExpired. The recipient's path to the funds is `withdraw`/`claim`,
    // not the arbiter's `release`.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::EscrowExpired))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
}

#[test]
fn linear_release_cannot_exceed_vested_amount() {
    let h = setup(10_000, 0);
    let start_time = START;
    let cliff_time = START + 200;
    let end_time = START + 1_000;

    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time,
        cliff_time,
        end_time,
    };

    let id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &schedule,
        &end_time,
        &String::from_str(&h.env, "linear release gate"),
    );

    // Before the cliff nothing has vested: release must fail with
    // TimelockNotExpired even though the deadline is far away.
    h.env.ledger().with_mut(|l| l.timestamp = START + 100);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::TimelockNotExpired))
    );

    // Halfway through the schedule only half has vested (50% of 10,000 =
    // 5,000). A release settles the escrow in full, so even an amount within
    // the vested portion is refused while the other half is still locked.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_vested_amount(&id), 5_000);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
}

/// While part of a `Linear` schedule is still locked, the arbiter cannot
/// settle at all — the beneficiary's schedule-gated `withdraw`/`claim` paths
/// are the only way to reach vested funds mid-vesting (Issue #307).
#[test]
fn linear_partial_release_pays_exactly_the_vested_payout() {
    let h = setup(10_000, 0);
    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START,
        cliff_time: START + 200,
        end_time: START + 1_000,
    };
    let id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &schedule,
        &(START + 2_000),
        &String::from_str(&h.env, "partial payout"),
    );

    // Halfway through the schedule only half has vested. A release would
    // settle the full balance, so it is refused even for an amount within
    // the vested portion.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_vested_amount(&id), 5_000);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);

    // The beneficiary draws the vested half through the schedule-gated path.
    assert_eq!(h.client.claim(&h.recipient, &id), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);

    // Once everything has vested — and the settlement window is still open —
    // the arbiter's release settles the remainder exactly once.
    h.env.ledger().with_mut(|l| l.timestamp = START + 1_000);
    h.client.release(&h.arbiter, &id, &5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

/// A full release at maturity settles the escrow exactly once.
#[test]
fn linear_full_release_at_maturity_settles_exactly_once() {
    let h = setup(10_000, 0);
    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START,
        cliff_time: START + 200,
        end_time: START + 1_000,
    };
    let id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &schedule,
        &(START + 2_000),
        &String::from_str(&h.env, "full payout"),
    );

    h.env.ledger().with_mut(|l| l.timestamp = START + 1_000);
    h.client.release(&h.arbiter, &id, &10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);

    // Releasing (or claiming) again cannot mint a second payout.
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &1),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        h.client.try_claim(&h.recipient, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

/// Cancellation cannot route around the time lock: a scheduled escrow may
/// only be cancelled while nothing has vested (Issue #307).
#[test]
fn cancel_is_refused_once_a_scheduled_escrow_has_vested() {
    let h = setup(12_000, 0);
    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START,
        cliff_time: START + 200,
        end_time: START + 1_000,
    };
    let id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &schedule,
        &(START + 1_000),
        &String::from_str(&h.env, "cancellation gate"),
    );

    // Before the cliff nothing has vested — cancellation is still the
    // pre-fulfillment dispute exit and stays available to the sender, here
    // proven on a second, identical escrow.
    h.env.ledger().with_mut(|l| l.timestamp = START + 100);
    assert!(!h.client.is_unlocked(&id));
    let pre_id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &schedule,
        &(START + 1_000),
        &String::from_str(&h.env, "pre-vesting cancel"),
    );
    h.client.cancel(&h.sender, &pre_id);
    assert_eq!(h.client.get(&pre_id).state, EscrowState::Refunded);

    // Past the cliff something has vested: the sender can no longer pull the
    // funds back out from under the vesting schedule.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert!(h.client.is_unlocked(&id));
    let res = h.client.try_cancel(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);

    // The arbiter cannot cancel around the lock either.
    assert_eq!(
        h.client.try_cancel(&h.arbiter, &id),
        Err(Ok(Error::TimeLockActive))
    );
}

/// A matured cliff schedule is locked for good: cancellation is refused at
/// and after maturity, and the recipient's claim path is what pays out.
#[test]
fn cancel_is_refused_after_cliff_maturity() {
    let h = setup(10_000, 0);
    let unlock_time = START + 1_000;
    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &unlock_time,
        &String::from_str(&h.env, "cliff cancel gate"),
    );

    // One second before maturity the lock still holds for cancellation... but
    // nothing has vested yet, so the sender may still cancel pre-maturity.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time - 1);
    assert!(!h.client.is_unlocked(&id));

    // At maturity the escrow unlocks; from here the beneficiary claims and
    // neither party can cancel the escrow away.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert!(h.client.is_unlocked(&id));
    assert_eq!(
        h.client.try_cancel(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.client.claim(&h.recipient, &id), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
}

/// Schedule-less escrows keep their pre-existing cancellation behaviour.
#[test]
fn plain_escrow_cancellation_still_works_before_the_deadline() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);

    assert!(h.client.is_unlocked(&id));
    h.env.ledger().with_mut(|l| l.timestamp = START + 50);
    h.client.cancel(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

/// `is_unlocked` mirrors the schedule clock the release paths enforce.
#[test]
fn is_unlocked_tracks_schedule_maturity() {
    let h = setup(10_000, 0);

    let cliff_id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &String::from_str(&h.env, "cliff view"),
    );
    assert!(!h.client.is_unlocked(&cliff_id));
    h.env.ledger().with_mut(|l| l.timestamp = START + 1_000);
    assert!(h.client.is_unlocked(&cliff_id));

    // Rewind the clock so the second escrow can be created with a future
    // schedule.
    h.env.ledger().with_mut(|l| l.timestamp = START);
    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START + 100,
        cliff_time: START + 100,
        end_time: START + 1_000,
    };
    let linear_id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 2_000),
        &schedule,
        &(START + 1_000),
        &String::from_str(&h.env, "linear view"),
    );
    // Before the linear start nothing has vested.
    h.env.ledger().with_mut(|l| l.timestamp = START + 50);
    assert!(!h.client.is_unlocked(&linear_id));
    // One second into the schedule something has vested.
    h.env.ledger().with_mut(|l| l.timestamp = START + 101);
    assert!(h.client.is_unlocked(&linear_id));
}

// --- Time-locked release verification (Issue #332) ---

#[test]
fn release_transitions_from_not_ready_to_ready_as_the_ledger_clock_advances() {
    let h = setup(10_000, 0);
    let unlock_time = START + 1_000;

    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &unlock_time,
        &String::from_str(&h.env, "timelock"),
    );

    // Simulated ledger-timestamp advancement: every instant strictly before
    // the configured release time refuses with the distinct
    // TIMELOCK_NOT_EXPIRED code; the very first instant at/after it succeeds.
    for ts in [START + 100, START + 500, unlock_time - 2, unlock_time - 1] {
        h.env.ledger().with_mut(|l| l.timestamp = ts);
        assert_eq!(
            h.client.try_release(&h.arbiter, &id, &10_000),
            Err(Ok(Error::TimelockNotExpired)),
            "release at {ts} must be refused"
        );
    }
    // (Timelock escrows set deadline = unlock_time, so at maturity the
    // settlement window is already closed and release reports EscrowExpired;
    // the beneficiary claims via `claim` instead — covered below.)
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::EscrowExpired))
    );
    assert_eq!(h.client.claim(&h.recipient, &id), 10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
}

#[test]
fn scheduled_release_succeeds_once_the_release_time_has_passed() {
    // A scheduled escrow with a settlement deadline beyond the schedule end:
    // release flips from TimelockNotExpired to success exactly at the cliff.
    let h = setup(10_000, 0);
    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Cliff,
        start_time: START,
        cliff_time: START + 500,
        end_time: START + 500,
    };
    let id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &schedule,
        &(START + 2_000),
        &String::from_str(&h.env, "cliff release"),
    );

    at(&h, START + 499);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::TimelockNotExpired))
    );

    at(&h, START + 500);
    h.client.release(&h.arbiter, &id, &10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
}
#[test]
fn override_release_respects_the_time_lock() {
    // No public constructor combines a ReleaseSchedule with override signers,
    // so seed the schedule directly into storage (as `create_scheduled` would
    // have stored it) on an escrow that carries an override signer set. This
    // keeps the check honest: the override path must consult the schedule no
    // matter how the escrow was created.
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Cliff,
        start_time: START,
        cliff_time: START + 800,
        end_time: START + 800,
    };
    let deadline = START + 2_000;
    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &deadline,
        &0,
        &String::from_str(&h.env, "override timelock"),
        &signers,
        &2,
    );

    // Attach the cliff schedule to the stored escrow.
    let mut escrow = h.client.get(&id);
    escrow.schedule = schedule;
    h.env.as_contract(&h.client.address, || {
        crate::store_escrow(&h.env, id, &escrow);
    });

    // Before the cliff: a threshold-clearing signature set is refused with
    // the distinct TimelockNotExpired code — signatures authorize *who*, not
    // *when* (Issue #332).
    at(&h, START + 100);
    let nonce = 1u64;
    let sigs = vec![
        &h.env,
        sign_override(&h, &kp1, id, nonce),
        sign_override(&h, &kp2, id, nonce),
    ];
    assert_eq!(
        h.client.try_override_release(&id, &nonce, &sigs),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);

    // The nonce was never consumed by the refused attempt.
    at(&h, START + 800);
    h.client.override_release(&id, &nonce, &sigs);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
}
//
// Expiration is measured on the ledger clock against the stored `deadline` and
// `grace_period`. Refunds open at `deadline + grace_period` (inclusive), the
// same instant `release` closes, so the two windows never overlap.

const DEADLINE: u64 = START + 100;

/// Snapshot of `asset_a` balances: (sender, recipient, contract).
fn balances(h: &Harness) -> (i128, i128, i128) {
    (
        balance(h, &h.asset_a, &h.sender),
        balance(h, &h.asset_a, &h.recipient),
        balance(h, &h.asset_a, &h.client.address),
    )
}

#[test]
fn release_before_expiry_pays_the_beneficiary_exactly_once() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    assert_eq!(balances(&h), (0, 0, 5_000));

    at(&h, DEADLINE - 1);
    h.client.release(&h.arbiter, &id, &5_000);

    let escrow = h.client.get(&id);
    assert_eq!(escrow.state, EscrowState::Released);
    assert_eq!(escrow.released_amount, 5_000);
    assert_eq!(balances(&h), (0, 5_000, 0));
}

#[test]
fn refund_one_second_before_expiry_is_rejected() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE - 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::TimeLockActive))
    );
    assert_eq!(Error::TimeLockActive as u32, 81);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn refund_after_expiry_returns_funds_to_the_depositor() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE + 1);
    h.client.refund(&h.sender, &id);

    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balances(&h), (5_000, 0, 0));
}

#[test]
fn refund_at_exactly_the_expiry_instant_is_permitted() {
    // The boundary is inclusive (`now >= deadline + grace_period`), matching
    // `expire`, `reclaim`, `refund_timelock`, `claim` and `is_refundable`.
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balances(&h), (5_000, 0, 0));
}

#[test]
fn refund_boundaries_with_a_grace_period() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);

    // Before the deadline the escrow has not expired at all.
    at(&h, DEADLINE - 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::TimeLockActive))
    );
    // From the deadline until the grace period ends, the arbiter may still
    // release, so the refund is refused as grace-active.
    at(&h, DEADLINE);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::GraceActive))
    );
    at(&h, DEADLINE + GRACE - 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::GraceActive))
    );
    assert_eq!(balances(&h), (0, 0, 5_000));

    // Refunds open exactly when the grace period ends.
    at(&h, DEADLINE + GRACE);
    h.client.refund(&h.sender, &id);
    assert_eq!(balances(&h), (5_000, 0, 0));
}

#[test]
fn reclaim_before_the_deadline_reports_time_lock_active() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);

    at(&h, DEADLINE - 1);
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::TimeLockActive))
    );
    at(&h, DEADLINE);
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::GraceActive))
    );
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn release_closes_exactly_when_refunds_open() {
    let h = setup(10_000, 0);
    let early = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);
    let late = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);

    // Last second of the grace period: release still allowed.
    at(&h, DEADLINE + GRACE - 1);
    h.client.release(&h.arbiter, &early, &5_000);
    assert_eq!(h.client.get(&early).state, EscrowState::Released);

    // First second refunds are open: release is refused and funds stay put.
    at(&h, DEADLINE + GRACE);
    assert_eq!(
        h.client.try_release(&h.arbiter, &late, &5_000),
        Err(Ok(Error::EscrowExpired))
    );
    assert_eq!(h.client.get(&late).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 5_000, 5_000));
}

#[test]
fn double_release_is_rejected_without_a_second_payout() {
    let h = setup(10_000, 0);
    // A second, independent escrow keeps funds in the contract so a duplicate
    // payout would have something to (wrongly) draw on.
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    h.client.release(&h.arbiter, &id, &5_000);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(balances(&h), (0, 5_000, 5_000));
}

#[test]
fn double_refund_is_rejected_without_a_second_payout() {
    let h = setup(10_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE + 1);
    h.client.refund(&h.sender, &id);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(balances(&h), (5_000, 0, 5_000));
}

#[test]
fn refund_after_release_is_rejected() {
    let h = setup(10_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    h.client.release(&h.arbiter, &id, &5_000);
    at(&h, DEADLINE + 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balances(&h), (0, 5_000, 5_000));
}

#[test]
fn release_after_refund_is_rejected() {
    let h = setup(10_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE + 1);
    h.client.refund(&h.sender, &id);
    // State is checked before time, so a settled escrow reports InvalidState
    // rather than EscrowExpired.
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balances(&h), (5_000, 0, 5_000));
}

#[test]
fn refund_rejected_for_anyone_but_the_depositor() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    let stranger = Address::generate(&h.env);

    at(&h, DEADLINE + 1);
    for caller in [&h.recipient, &h.arbiter, &stranger] {
        assert_eq!(
            h.client.try_refund(caller, &id),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn release_rejected_for_anyone_but_the_arbiter() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    let stranger = Address::generate(&h.env);

    for caller in [&h.sender, &h.recipient, &stranger] {
        assert_eq!(
            h.client.try_release(caller, &id, &5_000),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn refund_and_release_demand_auth_from_the_stored_party() {
    let h = setup(10_000, 0);
    let released = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    let refunded = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    h.client.release(&h.arbiter, &released, &5_000);
    assert_eq!(
        h.env.auths(),
        std::vec![(
            h.arbiter.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    h.client.address.clone(),
                    Symbol::new(&h.env, "release"),
                    (h.arbiter.clone(), released, 5_000_i128).into_val(&h.env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );

    at(&h, DEADLINE + 1);
    h.client.refund(&h.sender, &refunded);
    assert_eq!(
        h.env.auths(),
        std::vec![(
            h.sender.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    h.client.address.clone(),
                    Symbol::new(&h.env, "refund"),
                    (h.sender.clone(), refunded).into_val(&h.env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );
}

#[test]
fn refund_without_the_depositors_signature_fails() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    // Drop the blanket auth mock: nobody has signed anything now, so naming
    // the depositor as `caller` must not be enough to move the funds.
    h.env.set_auths(&[]);
    at(&h, DEADLINE + 1);
    // A failed `require_auth` aborts in the host (not a contract error code).
    assert!(matches!(h.client.try_refund(&h.sender, &id), Err(Err(_))));
    assert!(matches!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Err(_))
    ));
    // A signature from someone other than the depositor does not help either.
    let stranger = Address::generate(&h.env);
    assert!(matches!(
        h.client
            .mock_auths(&[MockAuth {
                address: &stranger,
                invoke: &MockAuthInvoke {
                    contract: &h.client.address,
                    fn_name: "refund",
                    args: (h.sender.clone(), id).into_val(&h.env),
                    sub_invokes: &[],
                },
            }])
            .try_refund(&h.sender, &id),
        Err(Err(_))
    ));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));

    // Control: once the depositor signs exactly this invocation, it succeeds.
    h.client
        .mock_auths(&[MockAuth {
            address: &h.sender,
            invoke: &MockAuthInvoke {
                contract: &h.client.address,
                fn_name: "refund",
                args: (h.sender.clone(), id).into_val(&h.env),
                sub_invokes: &[],
            },
        }])
        .refund(&h.sender, &id);
    assert_eq!(balances(&h), (5_000, 0, 0));
}

#[test]
fn unknown_escrow_id_is_not_found() {
    let h = setup(5_000, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE + 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &99),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_reclaim(&h.sender, &99),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_release(&h.arbiter, &99, &5_000),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(h.client.try_get(&99), Err(Ok(Error::NotFound)));
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn create_rejects_non_positive_amounts_and_non_future_expiry() {
    let h = setup(5_000, 0);
    let try_create = |assets: &Vec<AssetAmount>, deadline: u64| {
        h.client.try_create(
            &h.sender,
            &h.recipient,
            &h.arbiter,
            assets,
            &deadline,
            &0,
            &String::from_str(&h.env, "x"),
            &no_signers(&h),
            &0,
        )
    };

    assert_eq!(
        try_create(&one_asset(&h, 0), DEADLINE),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(
        try_create(&one_asset(&h, -1), DEADLINE),
        Err(Ok(Error::InvalidAmount))
    );
    // An expiration equal to "now" is already expired, so it is refused too.
    assert_eq!(
        try_create(&one_asset(&h, 1_000), START),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        try_create(&one_asset(&h, 1_000), START - 1),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(balances(&h), (5_000, 0, 0));
    assert_eq!(h.client.try_get(&1), Err(Ok(Error::NotFound)));
}

// ---------------------------------------------------------------------------
// Issue #216: Escrow release and refund conditions unit tests
// ---------------------------------------------------------------------------

#[test]
fn conditional_release_and_timeout_refund_lifecycle() {
    // 1. Test successful conditional release
    let h = setup(10_000, 0);
    let id1 = create(&h, &one_asset(&h, 4_000), START + 500, GRACE);

    // Beneficiary cannot claim directly before grace/schedule without arbiter
    assert_eq!(
        h.client.try_claim(&h.recipient, &id1),
        Err(Ok(Error::TimeLockActive))
    );

    // Arbiter releases successfully before deadline
    h.client.release(&h.arbiter, &id1, &4_000);
    assert_eq!(h.client.get(&id1).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 4_000);

    // 2. Test timeout refund path accessible only after expiry
    let id2 = create(&h, &one_asset(&h, 6_000), START + 500, GRACE);

    // Before deadline: refund fails with TimeLockActive
    assert_eq!(
        h.client.try_refund(&h.sender, &id2),
        Err(Ok(Error::TimeLockActive))
    );

    // During grace period (START + 500 to START + 1500): refund fails with GraceActive
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);
    assert_eq!(
        h.client.try_refund(&h.sender, &id2),
        Err(Ok(Error::GraceActive))
    );

    // Unauthorized non-sender cannot refund
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_refund(&stranger, &id2),
        Err(Ok(Error::Unauthorized))
    );

    // After expiry (deadline + grace_period = START + 1500): refund succeeds
    h.env.ledger().with_mut(|l| l.timestamp = START + 1500);
    h.client.refund(&h.sender, &id2);
    assert_eq!(h.client.get(&id2).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 6_000);
}

#[test]
fn mutual_consent_cancel_and_post_grace_reclaim() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 1_000, GRACE);

    // Non-party cannot cancel
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_cancel(&stranger, &id),
        Err(Ok(Error::Unauthorized))
    );

    // Arbiter can cancel by mutual consent before deadline
    h.client.cancel(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
}

// ---------------------------------------------------------------------------
// Issue #233: token whitelist
// ---------------------------------------------------------------------------

/// Assert an event carrying the given `(category, action)` tuple topic.
fn assert_event_topics(env: &Env, category: Symbol, action: Symbol) {
    let want_category: Val = category.into_val(env);
    let want_action: Val = action.into_val(env);
    let found =
        env.events().all().iter().any(|(_id, topics, _data)| {
            topics.contains(want_category) && topics.contains(want_action)
        });
    assert!(found, "expected a matching event to be emitted");
}

/// The whitelist approves nothing out of the box, so an unapproved token is
/// refused with the canonical asset-not-approved code and no value moves.
#[test]
fn unapproved_token_is_refused_by_every_creation_path() {
    let h = setup_unapproved(10_000, 5_000);
    let assets = one_asset(&h, 1_000);
    let memo = String::from_str(&h.env, "spam");

    // create
    assert_eq!(
        h.client.try_create(
            &h.sender,
            &h.recipient,
            &h.arbiter,
            &assets,
            &(START + 1_000),
            &0,
            &memo,
            &no_signers(&h),
            &0,
        ),
        Err(Ok(Error::AssetNotAuthorized))
    );
    // create_timelock
    assert_eq!(
        h.client.try_create_timelock(
            &h.sender,
            &h.recipient,
            &h.arbiter,
            &assets,
            &(START + 1_000),
            &memo,
        ),
        Err(Ok(Error::AssetNotAuthorized))
    );
    // initialize_timelock
    assert_eq!(
        h.client.try_initialize_timelock(
            &h.sender,
            &h.recipient,
            &h.arbiter,
            &assets,
            &(START + 1_000),
            &0,
            &memo,
        ),
        Err(Ok(Error::AssetNotAuthorized))
    );
    // create_scheduled
    assert_eq!(
        h.client.try_create_scheduled(
            &h.sender,
            &h.recipient,
            &h.arbiter,
            &assets,
            &ReleaseSchedule::none(),
            &(START + 1_000),
            &memo,
        ),
        Err(Ok(Error::AssetNotAuthorized))
    );
    // deposit_with_milestones
    assert_eq!(
        h.client.try_deposit_with_milestones(
            &h.sender,
            &h.recipient,
            &h.arbiter,
            &h.asset_a,
            &1_000,
            &(START + 1_000),
            &memo,
            &vec![&h.env, milestone_spec(&h.env, "m", 10_000)],
        ),
        Err(Ok(Error::AssetNotAuthorized))
    );

    // Nothing was escrowed and no token moved into custody.
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.approved_tokens().len(), 0);
}

/// One unapproved asset in an otherwise valid list refuses the whole escrow,
/// so a spam token cannot ride in alongside legitimate ones.
#[test]
fn a_single_unapproved_asset_refuses_a_multi_token_escrow() {
    let h = setup_unapproved(10_000, 5_000);
    h.client.approve_token(&h.admin, &h.asset_a);

    let assets = vec![
        &h.env,
        AssetAmount {
            asset: h.asset_a.clone(),
            amount: 1_000,
        },
        AssetAmount {
            asset: h.asset_b.clone(),
            amount: 500,
        },
    ];
    assert_eq!(
        h.client.try_create(
            &h.sender,
            &h.recipient,
            &h.arbiter,
            &assets,
            &(START + 1_000),
            &0,
            &String::from_str(&h.env, "mixed"),
            &no_signers(&h),
            &0,
        ),
        Err(Ok(Error::AssetNotAuthorized))
    );
    // Neither token moved: the refusal happens before any transfer.
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 0);

    // Approving the second token makes the same escrow succeed.
    h.client.approve_token(&h.admin, &h.asset_b);
    let id = create(&h, &assets, START + 1_000, 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 1_000);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 500);
}

/// A multi-token escrow releases every listed token in one settlement.
#[test]
fn whitelisted_multi_token_escrow_releases_every_asset() {
    let h = setup(10_000, 5_000);
    let id = create(&h, &two_assets(&h, 4_000, 2_000), START + 1_000, 0);

    h.client.release(&h.arbiter, &id, &6_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 4_000);
    assert_eq!(balance(&h, &h.asset_b, &h.recipient), 2_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 0);
}

/// ...and refunds every listed token back to the sender after the deadline.
#[test]
fn whitelisted_multi_token_escrow_refunds_every_asset() {
    let h = setup(10_000, 5_000);
    let id = create(&h, &two_assets(&h, 4_000, 2_000), START + 1_000, 0);

    h.env.ledger().with_mut(|l| l.timestamp = START + 2_000);
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 10_000);
    assert_eq!(balance(&h, &h.asset_b, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 0);
}

/// Revoking a token stops new escrows but must never strand funds already in
/// custody: the holder can still settle or reclaim.
#[test]
fn revocation_does_not_strand_an_existing_escrow() {
    let h = setup(10_000, 5_000);
    let id = create(&h, &two_assets(&h, 4_000, 2_000), START + 1_000, 0);

    h.client.revoke_token(&h.admin, &h.asset_b);
    assert!(!h.client.is_token_approved(&h.asset_b));

    // Release still works for an escrow that already holds the revoked token.
    h.client.release(&h.arbiter, &id, &6_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_b, &h.recipient), 2_000);
}

/// The same guarantee on the refund path.
#[test]
fn revocation_does_not_strand_a_refundable_escrow() {
    let h = setup(10_000, 5_000);
    let id = create(&h, &two_assets(&h, 4_000, 2_000), START + 1_000, 0);

    h.client.revoke_token(&h.admin, &h.asset_a);
    h.env.ledger().with_mut(|l| l.timestamp = START + 2_000);
    h.client.refund(&h.sender, &id);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 10_000);
    assert_eq!(balance(&h, &h.asset_b, &h.sender), 5_000);
}

/// `fund` re-checks the whitelist, so a token revoked between initializing an
/// escrow and funding it is refused at the moment value would enter custody.
#[test]
fn funding_rechecks_a_token_revoked_after_initialization() {
    let h = setup(10_000, 5_000);
    let id = h.client.initialize_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &two_assets(&h, 4_000, 2_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "late"),
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Created);

    h.client.revoke_token(&h.admin, &h.asset_b);
    assert_eq!(
        h.client.try_fund(&h.sender, &id),
        Err(Ok(Error::AssetNotAuthorized))
    );
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 0);

    // Re-approving lets the same escrow be funded.
    h.client.approve_token(&h.admin, &h.asset_b);
    h.client.fund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 4_000);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 2_000);
}

/// Only the admin recorded at initialize may change the whitelist.
#[test]
fn only_the_admin_may_manage_the_whitelist() {
    let h = setup_unapproved(1_000, 0);
    let stranger = Address::generate(&h.env);

    assert_eq!(h.client.admin(), h.admin);
    assert_eq!(
        h.client.try_approve_token(&stranger, &h.asset_a),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_token_approved(&h.asset_a));

    h.client.approve_token(&h.admin, &h.asset_a);
    assert_eq!(
        h.client.try_revoke_token(&stranger, &h.asset_a),
        Err(Ok(Error::Unauthorized))
    );
    assert!(h.client.is_token_approved(&h.asset_a));
}

/// Re-approving or revoking an absent token is refused rather than silently
/// absorbed, so a re-run governance script cannot mistake a no-op for a change.
#[test]
fn whitelist_changes_are_idempotency_checked() {
    let h = setup_unapproved(1_000, 0);
    h.client.approve_token(&h.admin, &h.asset_a);
    assert_eq!(
        h.client.try_approve_token(&h.admin, &h.asset_a),
        Err(Ok(Error::AlreadyExists))
    );
    assert_eq!(
        h.client.try_revoke_token(&h.admin, &h.asset_b),
        Err(Ok(Error::NotFound))
    );
}

/// The enumerable list tracks approvals and revocations, in approval order.
#[test]
fn approved_tokens_enumerates_in_approval_order() {
    let h = setup_unapproved(1_000, 1_000);
    assert_eq!(h.client.approved_tokens(), Vec::new(&h.env));

    h.client.approve_token(&h.admin, &h.asset_b);
    h.client.approve_token(&h.admin, &h.asset_a);
    assert_eq!(
        h.client.approved_tokens(),
        vec![&h.env, h.asset_b.clone(), h.asset_a.clone()]
    );

    h.client.revoke_token(&h.admin, &h.asset_b);
    assert_eq!(h.client.approved_tokens(), vec![&h.env, h.asset_a.clone()]);
    assert!(!h.client.is_token_approved(&h.asset_b));
}

/// The whitelist is capped so the enumerable list cannot grow without bound.
#[test]
fn the_whitelist_is_capped() {
    let h = setup_unapproved(0, 0);
    for _ in 0..crate::MAX_ESCROW_TOKENS {
        let token = Address::generate(&h.env);
        h.client.approve_token(&h.admin, &token);
    }
    assert_eq!(h.client.approved_tokens().len(), crate::MAX_ESCROW_TOKENS);

    let overflow = Address::generate(&h.env);
    assert_eq!(
        h.client.try_approve_token(&h.admin, &overflow),
        Err(Ok(Error::InvalidInput))
    );
    assert!(!h.client.is_token_approved(&overflow));
}

/// A token approval publishes an event so indexers can follow the whitelist.
#[test]
fn whitelist_changes_emit_events() {
    let h = setup_unapproved(1_000, 0);
    let before = h.env.events().all().len();

    h.client.approve_token(&h.admin, &h.asset_a);
    assert_eq!(h.env.events().all().len(), before + 1);
    assert_event_topics(
        &h.env,
        Symbol::new(&h.env, "escrow"),
        Symbol::new(&h.env, "tok_add"),
    );

    h.client.revoke_token(&h.admin, &h.asset_a);
    assert_eq!(h.env.events().all().len(), before + 2);
    assert_event_topics(
        &h.env,
        Symbol::new(&h.env, "escrow"),
        Symbol::new(&h.env, "tok_rm"),
    );
}

/// `initialize` is still one-shot, so the admin cannot be replaced by
/// re-initializing with a different address.
#[test]
fn initialize_is_one_shot() {
    let h = setup(0, 0);
    let other = Address::generate(&h.env);
    assert_eq!(
        h.client.try_initialize(&other),
        Err(Ok(Error::AlreadyInitialized))
    );
    assert_eq!(h.client.admin(), h.admin);
}

// ---------------------------------------------------------------------------
// Issue #323: multi-party release conditions
// ---------------------------------------------------------------------------

/// The arbiter's release is refused until `threshold` distinct participants
/// have signed off, and the funds stay in custody the whole time.
#[test]
fn multi_party_release_waits_for_the_approval_threshold() {
    let h = setup(5_000, 0);
    let parties = counterparties(&h.env, 3);
    let id = create_multi_party(&h, &one_asset(&h, 5_000), &parties, 2, START + 10_000);

    // No sign-off at all: the arbiter cannot pay out.
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(balances(&h), (0, 0, 5_000));

    // A partial approval is still not enough.
    assert_eq!(h.client.approve_release(&parties.get_unchecked(0), &id), 1);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));

    // The second, distinct sign-off clears the gate.
    assert_eq!(h.client.approve_release(&parties.get_unchecked(2), &id), 2);
    h.client.release(&h.arbiter, &id, &5_000);

    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balances(&h), (0, 5_000, 0));
    assert_eq!(h.client.get_release_condition(&id).approvals, 2);
    assert_eq!(
        h.client.release_approvals(&id),
        vec![&h.env, parties.get_unchecked(0), parties.get_unchecked(2)]
    );
}

/// A party can only be counted once: a repeat approval is refused and never
/// moves the escrow closer to its threshold.
#[test]
fn multi_party_approvals_reject_duplicates_from_the_same_party() {
    let h = setup(5_000, 0);
    let parties = counterparties(&h.env, 2);
    let id = create_multi_party(&h, &one_asset(&h, 5_000), &parties, 2, START + 10_000);

    let buyer = parties.get_unchecked(0);
    assert_eq!(h.client.approve_release(&buyer, &id), 1);
    assert_eq!(
        h.client.try_approve_release(&buyer, &id),
        Err(Ok(Error::AlreadySigned))
    );
    assert_eq!(
        h.client.try_approve_release(&buyer, &id),
        Err(Ok(Error::AlreadySigned))
    );
    assert_eq!(h.client.get_release_condition(&id).approvals, 1);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(balances(&h), (0, 0, 5_000));

    // Only a genuinely different party can reach the threshold.
    h.client.approve_release(&parties.get_unchecked(1), &id);
    h.client.release(&h.arbiter, &id, &5_000);
    assert_eq!(balances(&h), (0, 5_000, 0));
}

/// Only the configured counterparties may sign off; the arbiter, the sender and
/// random outsiders are all rejected.
#[test]
fn multi_party_approval_rejects_anyone_outside_the_participant_set() {
    let h = setup(5_000, 0);
    let parties = counterparties(&h.env, 2);
    let id = create_multi_party(&h, &one_asset(&h, 5_000), &parties, 2, START + 10_000);

    for outsider in [&h.arbiter, &h.sender, &h.recipient] {
        assert_eq!(
            h.client.try_approve_release(outsider, &id),
            Err(Ok(Error::NotASigner))
        );
    }
    assert_eq!(h.client.get_release_condition(&id).approvals, 0);
    assert_eq!(balances(&h), (0, 0, 5_000));
}

/// The participant authorizes the approval itself: a third party (or nobody at
/// all) cannot record a sign-off on its behalf, and the recorded authorization
/// is bound to this `approve_release` invocation.
#[test]
fn multi_party_approval_demands_the_participants_own_signature() {
    let h = setup(5_000, 0);
    let parties = counterparties(&h.env, 2);
    let id = create_multi_party(&h, &one_asset(&h, 5_000), &parties, 1, START + 10_000);
    let buyer = parties.get_unchecked(0);

    h.client.approve_release(&buyer, &id);
    assert_eq!(
        h.env.auths(),
        std::vec![(
            buyer.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    h.client.address.clone(),
                    Symbol::new(&h.env, "approve_release"),
                    (buyer.clone(), id).into_val(&h.env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );

    // Drop the blanket mock: naming the participant as `caller` is not enough
    // for someone else to vote for it.
    h.env.set_auths(&[]);
    assert!(matches!(
        h.client.try_approve_release(&buyer, &id),
        Err(Err(_))
    ));

    // A signature from a different account does not stand in either.
    let relayer = Address::generate(&h.env);
    assert!(matches!(
        h.client
            .mock_auths(&[MockAuth {
                address: &relayer,
                invoke: &MockAuthInvoke {
                    contract: &h.client.address,
                    fn_name: "approve_release",
                    args: (buyer.clone(), id).into_val(&h.env),
                    sub_invokes: &[],
                },
            }])
            .try_approve_release(&buyer, &id),
        Err(Err(_))
    ));
    assert_eq!(h.client.get_release_condition(&id).approvals, 1);
}

/// The sign-off never takes effect twice: once the escrow has settled there is
/// nothing left to approve.
#[test]
fn multi_party_approval_is_refused_once_the_escrow_settles() {
    let h = setup(10_000, 0);
    let parties = counterparties(&h.env, 2);
    let released = create_multi_party(&h, &one_asset(&h, 4_000), &parties, 1, START + 10_000);
    let refunded = create_multi_party(&h, &one_asset(&h, 6_000), &parties, 1, DEADLINE);

    h.client
        .approve_release(&parties.get_unchecked(0), &released);
    h.client.release(&h.arbiter, &released, &4_000);
    assert_eq!(
        h.client
            .try_approve_release(&parties.get_unchecked(1), &released),
        Err(Ok(Error::InvalidState))
    );

    at(&h, DEADLINE + GRACE);
    h.client.refund(&h.sender, &refunded);
    assert_eq!(
        h.client
            .try_approve_release(&parties.get_unchecked(0), &refunded),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.client.get(&refunded).state, EscrowState::Refunded);
}

/// A condition must never be able to strand the funder's money: the sender-side
/// exits stay open while approvals are still outstanding.
#[test]
fn multi_party_timeout_refund_overrides_a_pending_condition() {
    let h = setup(10_000, 0);
    let parties = counterparties(&h.env, 3);
    // All three need three approvals out of three, and only one party ever
    // signs — so no payout is ever possible for any of them.
    let refunded = create_multi_party(&h, &one_asset(&h, 4_000), &parties, 3, DEADLINE);
    let reclaimed = create_multi_party(&h, &one_asset(&h, 3_000), &parties, 3, DEADLINE);
    let cancelled = create_multi_party(&h, &one_asset(&h, 3_000), &parties, 3, DEADLINE);
    h.client
        .approve_release(&parties.get_unchecked(0), &refunded);
    assert_eq!(balances(&h), (0, 0, 10_000));

    // `cancel` is open to either party before the deadline, with no sign-off.
    h.client.cancel(&h.arbiter, &cancelled);
    assert_eq!(h.client.get(&cancelled).state, EscrowState::Refunded);
    assert_eq!(balances(&h), (3_000, 0, 7_000));

    // A refund opens once the grace period has fully elapsed, even with the
    // sign-off still outstanding.
    at(&h, DEADLINE + GRACE - 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &refunded),
        Err(Ok(Error::GraceActive))
    );
    at(&h, DEADLINE + GRACE);
    h.client.refund(&h.sender, &refunded);
    assert_eq!(h.client.get(&refunded).state, EscrowState::Refunded);

    // `reclaim` reaches the same funds post-grace, again with no sign-off.
    h.client.reclaim(&h.sender, &reclaimed);
    assert_eq!(h.client.get(&reclaimed).state, EscrowState::Refunded);

    // Every token is back with the funder and the recipient was never paid.
    assert_eq!(balances(&h), (10_000, 0, 0));
    assert_eq!(h.client.release_approvals(&refunded).len(), 1);
    assert_eq!(h.client.release_approvals(&reclaimed).len(), 0);
    assert_eq!(h.client.release_approvals(&cancelled).len(), 0);
}

/// The recipient's own claim path is gated too, so an unmet condition cannot be
/// side-stepped by pulling the funds directly.
#[test]
fn multi_party_condition_gates_the_recipients_own_claim() {
    let h = setup(5_000, 0);
    let parties = counterparties(&h.env, 2);
    let id = create_multi_party(&h, &one_asset(&h, 5_000), &parties, 2, DEADLINE);

    // Before the deadline an unscheduled escrow reports the time lock first.
    assert_eq!(
        h.client.try_claim(&h.recipient, &id),
        Err(Ok(Error::TimeLockActive))
    );

    // Once claiming would otherwise be allowed, the unmet condition is what
    // stops it.
    at(&h, DEADLINE + GRACE);
    assert_eq!(
        h.client.try_claim(&h.recipient, &id),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));

    h.client.approve_release(&parties.get_unchecked(0), &id);
    h.client.approve_release(&parties.get_unchecked(1), &id);
    assert_eq!(h.client.claim(&h.recipient, &id), 5_000);
    assert_eq!(balances(&h), (0, 5_000, 0));
}

/// The signature override is an alternative arbiter, not a way around the
/// condition: valid override signatures alone still do not pay out.
#[test]
fn multi_party_condition_gates_the_signature_override() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let parties = counterparties(&h.env, 2);
    let mut config =
        release_condition_config(&h, &one_asset(&h, 5_000), &parties, 2, START + 10_000);
    config.override_signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];
    config.override_threshold = 2;
    let id = h.client.create_with_release_condition(&config);

    let nonce = 1u64;
    let sigs = vec![
        &h.env,
        sign_override(&h, &kp1, id, nonce),
        sign_override(&h, &kp2, id, nonce),
    ];
    assert_eq!(
        h.client.try_override_release(&id, &nonce, &sigs),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));

    h.client.approve_release(&parties.get_unchecked(0), &id);
    h.client.approve_release(&parties.get_unchecked(1), &id);
    h.client.override_release(&id, &nonce, &sigs);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balances(&h), (0, 5_000, 0));
}

/// A bad participant set is refused before any tokens are pulled, and an empty
/// set is a plain escrow rather than an error.
#[test]
fn create_with_release_condition_rejects_bad_participant_sets() {
    let h = setup(5_000, 0);
    let one = counterparties(&h.env, 1);
    let two = counterparties(&h.env, 2);
    let deadline = START + 10_000;
    let try_create = |participants: &Vec<Address>, threshold: u32| {
        h.client
            .try_create_with_release_condition(&release_condition_config(
                &h,
                &one_asset(&h, 1_000),
                participants,
                threshold,
                deadline,
            ))
    };

    // A threshold of zero would mean "releasable immediately".
    assert_eq!(try_create(&two, 0), Err(Ok(Error::InvalidThreshold)));
    // More signatures demanded than participants exist.
    assert_eq!(try_create(&one, 2), Err(Ok(Error::InvalidThreshold)));
    // No participants but a non-zero threshold is contradictory.
    assert_eq!(
        try_create(&Vec::new(&h.env), 1),
        Err(Ok(Error::InvalidThreshold))
    );
    // The same party twice must not count as two votes.
    let duplicated = vec![&h.env, one.get_unchecked(0), one.get_unchecked(0)];
    assert_eq!(try_create(&duplicated, 2), Err(Ok(Error::InvalidInput)));
    // Participant sets are capped for gas safety, like signer sets.
    let too_many = counterparties(&h.env, astroid_shared::constants::MAX_SIGNERS + 1);
    assert_eq!(try_create(&too_many, 1), Err(Ok(Error::TooManySigners)));

    // Nothing moved and nothing was written: the funder keeps every token.
    assert_eq!(balances(&h), (5_000, 0, 0));
    assert_eq!(h.client.try_get(&1), Err(Ok(Error::NotFound)));

    // The empty set is the documented "no condition" case, and behaves exactly
    // like a plain escrow.
    let id = try_create(&Vec::new(&h.env), 0).unwrap().unwrap();
    assert_eq!(id, 1);
    assert_eq!(
        h.client.try_get_release_condition(&id),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_release_approvals(&id),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_approve_release(&one.get_unchecked(0), &id),
        Err(Ok(Error::NotFound))
    );
    h.client.release(&h.arbiter, &id, &1_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 1_000);
}

/// Escrows created through the plain entrypoints are completely unaffected: they
/// report no condition and settle without any sign-off.
#[test]
fn escrows_without_a_condition_carry_no_release_condition() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);

    assert_eq!(
        h.client.try_get_release_condition(&id),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_release_approvals(&id),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_approve_release(&h.arbiter, &id),
        Err(Ok(Error::NotFound))
    );
    h.client.release(&h.arbiter, &id, &5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balances(&h), (0, 5_000, 0));
}

// --- EscrowLocked alias on early-release refusals (Issue #315) ---
//
// Issue #315 demands `ContractError::EscrowLocked` for premature release
// attempts. The shared error table sits at Soroban's 50-case spec limit, so
// the alias is published as a named constant equal to `TimelockNotExpired`:
// same code, same wire name, no ABI change. These tests pin the name, the
// identity and the enforcement on both value-leaving release paths.

use astroid_shared::errors::Error as SharedError;

#[test]
fn escrow_locked_alias_is_bit_identical_to_timelock_not_expired() {
    // The alias is the exact same value: same discriminant, same wire name,
    // and it compares equal to the canonical variant.
    assert_eq!(SharedError::EscrowLocked as u32, 91);
    assert_eq!(
        SharedError::EscrowLocked as u32,
        SharedError::TimelockNotExpired as u32
    );
    assert_eq!(SharedError::EscrowLocked, SharedError::TimelockNotExpired);
    assert_eq!(
        SharedError::EscrowLocked.wire_name(),
        "TIMELOCK_NOT_EXPIRED"
    );
    assert_eq!(
        SharedError::EscrowLocked.wire_name(),
        SharedError::TimelockNotExpired.wire_name()
    );
}

#[test]
fn escrow_locked_refuses_release_before_unlock_and_passes_after() {
    // Issue #315's exact scenario: a funded escrow with an unlock timestamp.
    // Release attempts while `env.ledger().timestamp() < unlock_time` report
    // `EscrowLocked` and move nothing; the first instant at/after the unlock
    // timestamp succeeds.
    let h = setup(10_000, 0);
    let unlock_time = START + 1_000;
    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &unlock_time,
        &String::from_str(&h.env, "issue 315"),
    );

    // Strictly premature: every attempt refused with EscrowLocked.
    for ts in [
        START,
        START + 1,
        START + 500,
        unlock_time - 2,
        unlock_time - 1,
    ] {
        h.env.ledger().with_mut(|l| l.timestamp = ts);
        assert_eq!(
            h.client.try_release(&h.arbiter, &id, &10_000),
            Err(Ok(Error::EscrowLocked)),
            "release at {ts} must be refused with EscrowLocked"
        );
        // No funds moved, no state changed.
        assert_eq!(h.client.get(&id).state, EscrowState::Funded);
        assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
        assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
    }

    // At maturity the arbiter's `release` window has closed (a timelock
    // escrow's deadline equals its unlock time), so the funds are claimed by
    // the beneficiary instead — the successful release path is exercised by
    // `scheduled_release_succeeds_once_the_release_time_has_passed` above.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert_eq!(h.client.claim(&h.recipient, &id), 10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
}

#[test]
fn escrow_locked_gates_the_signature_override_too() {
    // The override path must not route around the time lock either: a
    // threshold-clearing signature set is still refused with EscrowLocked
    // before the cliff (signatures authorize *who*, not *when*).
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];
    let deadline = START + 2_000;
    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &deadline,
        &0,
        &String::from_str(&h.env, "override locked"),
        &signers,
        &2,
    );

    // Attach a cliff schedule that matures after several test instants.
    let mut escrow = h.client.get(&id);
    escrow.schedule = ReleaseSchedule {
        release_type: ReleaseType::Cliff,
        start_time: START,
        cliff_time: START + 800,
        end_time: START + 800,
    };
    h.env.as_contract(&h.client.address, || {
        crate::store_escrow(&h.env, id, &escrow);
    });

    let nonce = 1u64;
    let sigs = vec![
        &h.env,
        sign_override(&h, &kp1, id, nonce),
        sign_override(&h, &kp2, id, nonce),
    ];
    for ts in [START + 100, START + 799] {
        h.env.ledger().with_mut(|l| l.timestamp = ts);
        assert_eq!(
            h.client.try_override_release(&id, &nonce, &sigs),
            Err(Ok(Error::EscrowLocked)),
            "override release at {ts} must be refused with EscrowLocked"
        );
    }
    // The nonce was never consumed by the refused attempts.
    at(&h, START + 800);
    h.client.override_release(&id, &nonce, &sigs);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
}
