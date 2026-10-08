#![cfg(test)]
extern crate std;

use crate::access::Role;
use crate::{BatchAction, BatchReceipt, ContractCall, WalletContract, WalletContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ResourceState;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, testutils::Events, token, Address, Env,
    IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

/// Number of times the canonical single-topic `variant` event was published,
/// ignoring the payload.
fn count_event(env: &Env, variant: &str) -> usize {
    let topic: Val = Symbol::new(env, variant).into_val(env);
    env.events()
        .all()
        .iter()
        .filter(|(_contract_id, topics, _data)| topics.len() == 1 && topics.contains(topic))
        .count()
}

/// Number of times the canonical `variant` event was published with a payload
/// that decodes to `expected`.
///
/// Decoding into a concrete Rust type is the point: it proves the published
/// payload really is the documented shape, not merely that some bytes landed
/// under that topic. `Val` itself is not `PartialEq`, so comparing raw
/// encodings is not possible.
fn count_event_data<T>(env: &Env, variant: &str, expected: &T) -> usize
where
    T: TryFromVal<Env, Val> + PartialEq,
{
    let topic: Val = Symbol::new(env, variant).into_val(env);
    env.events()
        .all()
        .iter()
        .filter(|(_contract_id, topics, _data)| topics.len() == 1 && topics.contains(topic))
        .filter(|(_contract_id, _topics, data)| {
            T::try_from_val(env, data)
                .map(|got| &got == expected)
                .unwrap_or(false)
        })
        .count()
}

/// Assert the canonical `variant` event was published exactly `expected` time(s)
/// with exactly the payload `want`. A count of `0` catches a dropped event, and
/// a count above `1` catches a fact that is still being emitted twice under two
/// different encodings.
fn assert_event_data<T>(env: &Env, variant: &str, expected: usize, want: T)
where
    T: TryFromVal<Env, Val> + PartialEq,
{
    let seen = count_event_data(env, variant, &want);
    assert_eq!(
        seen, expected,
        "expected ContractEvent::{variant} {expected} time(s) with that payload, saw {seen}"
    );
}

/// The wallet must not publish ad-hoc `("wallet", "<x>")` topics any more:
/// every wallet-owned event is a single canonical topic equal to its variant
/// name, so an indexer can dispatch on `topic[0]` alone.
///
/// The repo-wide `("transfer", "executed")` helper is deliberately exempt. It
/// is a cross-contract convention shared with escrow and treasury, so
/// converting only the wallet's call sites would emit the same fact under two
/// encodings across the protocol - worse than leaving it consistent. That
/// migration belongs to all three contracts together, not to the wallet alone.
fn assert_no_legacy_wallet_topics(env: &Env, contract_id: &Address) {
    let legacy: Val = symbol_short!("wallet").into_val(env);
    for (emitter, topics, _data) in env.events().all().iter() {
        if emitter != *contract_id {
            continue;
        }
        assert!(
            !topics.contains(legacy),
            "wallet published a legacy (\"wallet\", ...) topic, which an indexer cannot map to a variant"
        );
    }
}

struct Harness {
    env: Env,
    client: WalletContractClient<'static>,
    admin: Address,
    token: Address,
    contract_id: Address,
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, WalletContract);
    let client = WalletContractClient::new(&env, &contract_id);
    client.initialize(&admin);

    // A test SAC token whose admin can mint funds to users.
    let token_admin = Address::generate(&env);
    let token = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();

    Harness {
        env,
        client,
        admin,
        token,
        contract_id,
    }
}

fn mint(h: &Harness, to: &Address, amount: i128) {
    let sac = token::StellarAssetClient::new(&h.env, &h.token);
    sac.mint(to, &amount);
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.token).balance(who)
}

#[test]
fn create_wallet_starts_active() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let w = h.client.get_wallet(&id);
    assert_eq!(w.owner, owner);
    assert_eq!(w.state, ResourceState::Active);
}

#[test]
fn deposit_credits_internal_balance_and_moves_tokens() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);

    h.client.deposit(&id, &owner, &h.token, &400);
    assert_eq!(h.client.balance(&id, &h.token), 400);
    assert_eq!(token_balance(&h, &owner), 600);
}

#[test]
fn transfer_moves_value_and_debits_wallet() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    h.client.transfer(&owner, &id, &recipient, &h.token, &250);
    assert_eq!(h.client.balance(&id, &h.token), 750);
    assert_eq!(token_balance(&h, &recipient), 250);
}

#[test]
fn withdraw_returns_to_owner() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    h.client.withdraw(&owner, &id, &h.token, &300);
    assert_eq!(h.client.balance(&id, &h.token), 700);
    assert_eq!(token_balance(&h, &owner), 300);
}

#[test]
fn transfer_more_than_balance_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &500);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
}

#[test]
fn non_owner_cannot_transfer() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let intruder = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    let res = h
        .client
        .try_transfer(&intruder, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn transfer_while_frozen_fails_wallet_frozen() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.freeze(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Frozen);

    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::WalletFrozen)));
}

#[test]
fn admin_can_freeze_then_owner_unfreezes() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    // Owner freezes, then unfreezes back to Active.
    h.client.freeze(&owner, &id);
    h.client.unfreeze(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
}

#[test]
fn transfer_while_paused_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.pause(&owner, &id);
    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::WalletPaused)));

    h.client.unpause(&owner, &id);
    h.client.transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(token_balance(&h, &recipient), 10);
}

#[test]
fn archived_wallet_rejects_transfer_and_deposit() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.archive(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Archived);

    assert_eq!(
        h.client
            .try_transfer(&owner, &id, &recipient, &h.token, &10),
        Err(Ok(Error::WalletArchived))
    );
    mint(&h, &owner, 100);
    assert_eq!(
        h.client.try_deposit(&id, &owner, &h.token, &10),
        Err(Ok(Error::WalletArchived))
    );
}

#[test]
fn zero_amount_transfer_rejected() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let res = h.client.try_transfer(&owner, &id, &recipient, &h.token, &0);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn unknown_wallet_fails_not_found() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let res = h.client.try_get_wallet(&999);
    assert_eq!(res, Err(Ok(Error::NotFound)));
    let res2 = h.client.try_freeze(&stranger, &999);
    assert_eq!(res2, Err(Ok(Error::NotFound)));
}

#[test]
fn standard_events_emitted() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    assert_event(&h.env, "WalletCreated");

    h.client.freeze(&owner, &id);
    assert_event(&h.env, "WalletStateChanged");
}

// ---------------------------------------------------------------------------
// Role-based access control
// ---------------------------------------------------------------------------

/// A wallet funded with `amount`, plus its owner.
fn funded_wallet(h: &Harness, amount: i128) -> (Address, u64) {
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(h, &owner, amount);
    h.client.deposit(&id, &owner, &h.token, &amount);
    (owner, id)
}

#[test]
fn breaker_starts_reset_and_guardian_defaults_to_admin() {
    let h = setup();
    assert!(!h.client.is_paused());
    assert_eq!(h.client.get_guardian(), h.admin);
}

#[test]
fn paused_wallet_contract_blocks_all_outgoing_value() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let recipient = Address::generate(&h.env);

    h.client.emergency_pause(&h.admin);
    assert!(h.client.is_paused());

    assert_eq!(
        h.client
            .try_transfer(&owner, &id, &recipient, &h.token, &100),
        Err(Ok(Error::WalletPaused))
    );
    assert_eq!(
        h.client.try_withdraw(&owner, &id, &h.token, &100),
        Err(Ok(Error::WalletPaused))
    );
    // No value moved on any rejected path.
    assert_eq!(h.client.balance(&id, &h.token), 1_000);
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn paused_wallet_contract_blocks_new_wallets() {
    let h = setup();
    h.client.emergency_pause(&h.admin);
    let owner = Address::generate(&h.env);
    assert_eq!(
        h.client.try_create_wallet(&owner),
        Err(Ok(Error::WalletPaused))
    );
}

#[test]
fn inspection_and_recovery_stay_available_while_paused() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    h.client.emergency_pause(&h.admin);

    // Read-only inspection is unaffected.
    assert_eq!(h.client.balance(&id, &h.token), 1_000);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
    assert!(h.client.is_paused());

    // Funding a wallet is inbound, so it stays open.
    mint(&h, &owner, 500);
    h.client.deposit(&id, &owner, &h.token, &500);
    assert_eq!(h.client.balance(&id, &h.token), 1_500);

    // Per-wallet quarantine still works, so an operator can act on a specific
    // compromised wallet while the breaker holds the line globally.
    h.client.freeze(&h.admin, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Frozen);
    h.client.unfreeze(&h.admin, &id);
    h.client.pause(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Paused);
}

#[test]
fn normal_operation_resumes_after_unpause() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let recipient = Address::generate(&h.env);

    h.client.emergency_pause(&h.admin);
    h.client.emergency_unpause(&h.admin);
    assert!(!h.client.is_paused());

    h.client.transfer(&owner, &id, &recipient, &h.token, &400);
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(h.client.balance(&id, &h.token), 600);
}

#[test]
fn designated_guardian_can_trip_but_not_reset_the_breaker() {
    let h = setup();
    let guardian = Address::generate(&h.env);
    h.client.set_guardian(&h.admin, &guardian);
    assert_eq!(h.client.get_guardian(), guardian);

    // Containment is fast: one guardian key is enough.
    h.client.emergency_pause(&guardian);
    assert!(h.client.is_paused());

    // Releasing funds back into motion is not.
    assert_eq!(
        h.client.try_emergency_unpause(&guardian),
        Err(Ok(Error::Unauthorized))
    );
    assert!(h.client.is_paused());

    h.client.emergency_unpause(&h.admin);
    assert!(!h.client.is_paused());
}

#[test]
fn strangers_cannot_touch_the_breaker() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let owner = Address::generate(&h.env);
    // Owning a wallet grants no emergency authority.
    h.client.create_wallet(&owner);

    assert_eq!(
        h.client.try_emergency_pause(&stranger),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_emergency_pause(&owner),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_paused());

    h.client.emergency_pause(&h.admin);
    assert_eq!(
        h.client.try_emergency_unpause(&stranger),
        Err(Ok(Error::Unauthorized))
    );
    assert!(h.client.is_paused());
}

#[test]
fn only_the_admin_designates_the_guardian() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let res = h.client.try_set_guardian(&stranger, &stranger);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(h.client.get_guardian(), h.admin);
}

#[test]
fn redundant_breaker_transitions_are_rejected() {
    let h = setup();
    assert_eq!(
        h.client.try_emergency_unpause(&h.admin),
        Err(Ok(Error::InvalidState))
    );
    h.client.emergency_pause(&h.admin);
    assert_eq!(
        h.client.try_emergency_pause(&h.admin),
        Err(Ok(Error::InvalidState))
    );
}

#[test]
fn owner_is_implicitly_admin() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    assert_eq!(h.client.get_role(&id, &owner), Some(Role::Admin));
    assert!(h.client.has_role(&id, &owner, &Role::Admin));
    assert!(h.client.has_role(&id, &owner, &Role::Agent));

    // A stranger holds nothing at all.
    let stranger = Address::generate(&h.env);
    assert_eq!(h.client.get_role(&id, &stranger), None);
    assert!(!h.client.has_role(&id, &stranger, &Role::Auditor));
}

#[test]
fn granted_role_is_readable_and_revocable() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 100);
    let agent = Address::generate(&h.env);

    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    assert_eq!(h.client.get_role(&id, &agent), Some(Role::Agent));

    // Re-granting replaces the role rather than stacking.
    h.client.grant_role(&owner, &id, &agent, &Role::Auditor);
    assert_eq!(h.client.get_role(&id, &agent), Some(Role::Auditor));

    h.client.revoke_role(&owner, &id, &agent);
    assert_eq!(h.client.get_role(&id, &agent), None);

    // Revoking again is an explicit failure, not a silent no-op.
    assert_eq!(
        h.client.try_revoke_role(&owner, &id, &agent),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn agent_can_transfer_but_not_withdraw() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let agent = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);

    // Routine operational spend: permitted.
    h.client.transfer(&agent, &id, &recipient, &h.token, &250);
    assert_eq!(token_balance(&h, &recipient), 250);
    assert_eq!(h.client.balance(&id, &h.token), 750);

    // Withdrawing funds to the owner is administrative: refused.
    assert_eq!(
        h.client.try_withdraw(&agent, &id, &h.token, &100),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.balance(&id, &h.token), 750);
}

#[test]
fn agent_cannot_administer_lifecycle_or_roles() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 100);
    let agent = Address::generate(&h.env);
    let outsider = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);

    assert_eq!(
        h.client.try_pause(&agent, &id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_archive(&agent, &id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client
            .try_grant_role(&agent, &id, &outsider, &Role::Agent),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_revoke_role(&agent, &id, &agent),
        Err(Ok(Error::Unauthorized))
    );

    // None of the rejected calls changed anything.
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
    assert_eq!(h.client.get_role(&id, &outsider), None);
    assert_eq!(h.client.get_role(&id, &agent), Some(Role::Agent));
}

#[test]
fn agent_may_freeze_as_a_safety_action() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 100);
    let agent = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);

    h.client.freeze(&agent, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Frozen);
    h.client.unfreeze(&agent, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
}

#[test]
fn auditor_holds_no_mutating_power() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let auditor = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &auditor, &Role::Auditor);

    // The role is recorded and readable...
    assert_eq!(h.client.get_role(&id, &auditor), Some(Role::Auditor));
    assert!(h.client.has_role(&id, &auditor, &Role::Auditor));
    // ...but satisfies no guard on a mutating entrypoint.
    assert!(!h.client.has_role(&id, &auditor, &Role::Agent));
    assert_eq!(
        h.client
            .try_transfer(&auditor, &id, &recipient, &h.token, &10),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_withdraw(&auditor, &id, &h.token, &10),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_freeze(&auditor, &id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(h.client.balance(&id, &h.token), 1_000);
}

#[test]
fn delegated_admin_has_full_control() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let manager = Address::generate(&h.env);
    let agent = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &manager, &Role::Admin);

    // A delegated admin may withdraw - and the funds still go to the owner.
    h.client.withdraw(&manager, &id, &h.token, &400);
    assert_eq!(token_balance(&h, &owner), 400);
    assert_eq!(h.client.balance(&id, &h.token), 600);

    // ...and may administer roles in turn.
    h.client.grant_role(&manager, &id, &agent, &Role::Agent);
    assert_eq!(h.client.get_role(&id, &agent), Some(Role::Agent));

    // ...and lifecycle.
    h.client.pause(&manager, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Paused);
}

#[test]
fn revoked_agent_loses_access_immediately() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let agent = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    h.client.transfer(&agent, &id, &recipient, &h.token, &100);

    h.client.revoke_role(&owner, &id, &agent);
    assert_eq!(
        h.client
            .try_transfer(&agent, &id, &recipient, &h.token, &100),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn roles_do_not_leak_between_wallets() {
    let h = setup();
    let (owner_a, wallet_a) = funded_wallet(&h, 500);
    let (_owner_b, wallet_b) = funded_wallet(&h, 500);
    let agent = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);

    h.client
        .grant_role(&owner_a, &wallet_a, &agent, &Role::Agent);

    h.client
        .transfer(&agent, &wallet_a, &recipient, &h.token, &50);
    assert_eq!(
        h.client
            .try_transfer(&agent, &wallet_b, &recipient, &h.token, &50),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.get_role(&wallet_b, &agent), None);
}

#[test]
fn owner_cannot_be_assigned_a_role() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    // The owner is implicitly Admin; a demotion attempt is refused outright
    // rather than recorded and then ignored by the guards.
    assert_eq!(
        h.client.try_grant_role(&owner, &id, &owner, &Role::Auditor),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(h.client.get_role(&id, &owner), Some(Role::Admin));
}

#[test]
fn role_checks_report_unknown_wallets_as_not_found() {
    let h = setup();
    let account = Address::generate(&h.env);
    assert_eq!(
        h.client.try_get_role(&999, &account),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client
            .try_grant_role(&account, &999, &account, &Role::Agent),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn breaker_events_are_emitted() {
    let h = setup();
    h.client.emergency_pause(&h.admin);
    assert_event(&h.env, "WalletPaused");
    h.client.emergency_unpause(&h.admin);
    assert_event(&h.env, "WalletUnpaused");
}

#[test]
fn granting_on_an_archived_wallet_is_refused() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let agent = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    h.client.archive(&owner, &id);

    let other = Address::generate(&h.env);
    assert_eq!(
        h.client.try_grant_role(&owner, &id, &other, &Role::Agent),
        Err(Ok(Error::WalletArchived))
    );
    // Revocation still works so stale grants can be cleaned up.
    h.client.revoke_role(&owner, &id, &agent);
    assert_eq!(h.client.get_role(&id, &agent), None);
}

// --- Pre-execution policy check hook (Issue #207) ---

/// A minimal standalone policy contract used to exercise the wallet's
/// pre-execution hook against a real cross-contract callee. It allows any
/// transfer of at most 1_000 and denies everything else.
#[contract]
pub struct StubPolicyContract;

#[contractimpl]
impl StubPolicyContract {
    pub fn check_transfer(
        env: Env,
        _policy_id: String,
        _asset: Address,
        _recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        if amount > 1_000 {
            return Err(Error::PolicyDenied);
        }
        env.events()
            .publish((Symbol::new(&env, "stub_ok"),), amount);
        Ok(())
    }
}

fn register_stub(h: &Harness) -> Address {
    let id = h.env.register_contract(None, StubPolicyContract);
    StubPolicyContractClient::new(&h.env, &id).address
}

/// Fund a fresh wallet owned by a fresh owner and grant `agent` the Agent
/// role, returning (wallet_id, owner, agent).
fn funded_agent_wallet(h: &Harness, deposit: i128) -> (u64, Address, Address) {
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let agent = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    mint(h, &owner, deposit);
    h.client.deposit(&id, &owner, &h.token, &deposit);
    (id, owner, agent)
}

#[test]
fn transfer_passes_when_policy_allows() {
    let h = setup();
    let policy_id = register_stub(&h);
    h.client.set_policy(&h.admin, &policy_id.clone());
    assert_eq!(h.client.get_policy(), Some(policy_id));

    let (id, _owner, agent) = funded_agent_wallet(&h, 5_000);

    // At the cap the stub allows the spend.
    let to = Address::generate(&h.env);
    h.client.transfer(&agent, &id, &to, &h.token, &1_000);
    assert_eq!(token_balance(&h, &to), 1_000);
    assert_eq!(h.client.balance(&id, &h.token), 4_000);
}

#[test]
fn transfer_rejected_when_policy_denies_and_nothing_moves() {
    let h = setup();
    h.client.set_policy(&h.admin, &register_stub(&h));

    let (id, _owner, agent) = funded_agent_wallet(&h, 5_000);

    // Above the stub's cap: the policy veto propagates out of the wallet.
    let to = Address::generate(&h.env);
    let res = h.client.try_transfer(&agent, &id, &to, &h.token, &2_000);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    // No debit and no token movement — the hook fired before the ledger was
    // touched.
    assert_eq!(h.client.balance(&id, &h.token), 5_000);
    assert_eq!(token_balance(&h, &to), 0);
}

#[test]
fn withdraw_is_policy_gated_and_bypass_excuses_a_wallet() {
    let h = setup();
    h.client.set_policy(&h.admin, &register_stub(&h));

    let (id, owner, _agent) = funded_agent_wallet(&h, 3_000);

    // Withdrawals are outbound movements, so they are gated too; 2_000
    // breaches the stub cap.
    let res = h.client.try_withdraw(&owner, &id, &h.token, &2_000);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(h.client.balance(&id, &h.token), 3_000);

    // Excusing the wallet removes the gate for that wallet only.
    h.client.set_policy_bypass(&h.admin, &id, &true);
    assert!(h.client.get_policy_bypass(&id));
    h.client.withdraw(&owner, &id, &h.token, &2_000);
    assert_eq!(token_balance(&h, &owner), 2_000);
    assert_eq!(h.client.balance(&id, &h.token), 1_000);

    // A different wallet stays gated.
    let other = h.client.create_wallet(&Address::generate(&h.env));
    assert!(!h.client.get_policy_bypass(&other));
}

#[test]
fn no_policy_wired_means_ungated_spending() {
    let h = setup();
    assert_eq!(h.client.get_policy(), None);

    let (id, _owner, agent) = funded_agent_wallet(&h, 5_000);

    // Without a wired policy, amounts above any cap still move.
    let to = Address::generate(&h.env);
    h.client.transfer(&agent, &id, &to, &h.token, &4_000);
    assert_eq!(token_balance(&h, &to), 4_000);
    assert_eq!(h.client.balance(&id, &h.token), 1_000);
}

#[test]
fn clear_policy_removes_the_gate() {
    let h = setup();
    h.client.set_policy(&h.admin, &register_stub(&h));

    let (id, owner, agent) = funded_agent_wallet(&h, 5_000);

    let to = Address::generate(&h.env);
    assert_eq!(
        h.client.try_transfer(&agent, &id, &to, &h.token, &2_000),
        Err(Ok(Error::PolicyDenied))
    );

    // Clearing the gate needs the admin; afterwards the same spend passes.
    let res = h.client.try_clear_policy(&owner);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    h.client.clear_policy(&h.admin);
    assert_eq!(h.client.get_policy(), None);

    h.client.transfer(&agent, &id, &to, &h.token, &2_000);
    assert_eq!(token_balance(&h, &to), 2_000);
}

#[test]
fn set_policy_requires_admin_and_existing_wallets_for_bypass() {
    let h = setup();
    let policy_id = register_stub(&h);

    let stranger = Address::generate(&h.env);
    let res = h.client.try_set_policy(&stranger, &policy_id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    h.client.set_policy(&h.admin, &policy_id);

    // Bypass can only be configured for wallets that exist.
    let res = h.client.try_set_policy_bypass(&h.admin, &999u64, &true);
    assert_eq!(res, Err(Ok(Error::NotFound)));

    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    h.client.set_policy_bypass(&h.admin, &id, &true);
    assert!(h.client.get_policy_bypass(&id));
    // Clearing a bypass that is set just flips the flag off.
    h.client.set_policy_bypass(&h.admin, &id, &false);
    assert!(!h.client.get_policy_bypass(&id));
}
// --- Batch execution tests ---

/// Helper: build a `ContractCall` targeting the token's `transfer`.
///
/// Soroban forbids a contract from re-entering itself, so batch sub-calls must
/// target external contracts. Transfers out of a wallet therefore call the
/// Stellar Asset Contract directly, moving real custody held at the wallet
/// contract's address.
fn token_transfer_call(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> ContractCall {
    let mut args: Vec<soroban_sdk::Val> = Vec::new(env);
    args.push_back(from.clone().into_val(env));
    args.push_back(to.clone().into_val(env));
    args.push_back(amount.into_val(env));
    ContractCall {
        contract_addr: token_addr.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args,
    }
}

// ---------------------------------------------------------------- stubs ----

// `#[contractimpl]` emits one `__check_transfer` / `__consume` symbol per crate,
// so this second policy stub needs its own namespace to coexist with
// `StubPolicyContract` above.
mod batch_stubs {
    use super::*;

    /// Storage keys for the policy stub.
    #[contracttype]
    #[derive(Clone)]
    enum PolicyKey {
        /// Approved value cap for a policy envelope id.
        Cap(String),
    }

    /// A configurable policy stub: every envelope id has a cap, and any check for
    /// an amount above the cap is denied so tests can force a policy rejection.
    #[contract]
    pub struct TestPolicy;

    #[contractimpl]
    impl TestPolicy {
        /// Set the approved value cap for `policy_id`.
        pub fn set_cap(env: Env, policy_id: String, cap: i128) {
            env.storage()
                .persistent()
                .set(&PolicyKey::Cap(policy_id), &cap);
        }

        /// Mirrors `PolicyInterface::check_transfer`, denying spends above the
        /// envelope's approved cap.
        pub fn check_transfer(
            env: Env,
            policy_id: String,
            _asset: Address,
            _recipient: Address,
            amount: i128,
        ) -> Result<(), Error> {
            let cap: i128 = env
                .storage()
                .persistent()
                .get(&PolicyKey::Cap(policy_id))
                .unwrap_or(0);
            if amount > cap {
                return Err(Error::PolicyDenied);
            }
            Ok(())
        }
    }

    /// Storage keys for the budget stub.
    #[contracttype]
    #[derive(Clone)]
    enum BudgetKey {
        /// Allocation still available for a budget envelope id.
        Remaining(String),
    }

    /// A budget stub with a top-up-able allocation: `consume` debits the remaining
    /// allocation, returning `BudgetExceeded` when the batch asks for too much.
    #[contract]
    pub struct TestBudget;

    #[contractimpl]
    impl TestBudget {
        /// Credit `amount` to `budget_id`'s remaining allocation.
        pub fn top_up(env: Env, budget_id: String, amount: i128) {
            let key = BudgetKey::Remaining(budget_id.clone());
            let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
            env.storage().persistent().set(&key, &(current + amount));
        }

        /// Mirrors `BudgetInterface::consume`, returning the new remaining balance
        /// and refusing when the requested amount exceeds what is left.
        pub fn consume(
            env: Env,
            _caller: Address,
            budget_id: String,
            amount: i128,
        ) -> Result<i128, Error> {
            let key = BudgetKey::Remaining(budget_id.clone());
            let remaining: i128 = env.storage().persistent().get(&key).unwrap_or(0);
            if amount > remaining {
                return Err(Error::BudgetExceeded);
            }
            let new_remaining = remaining - amount;
            env.storage().persistent().set(&key, &new_remaining);
            Ok(new_remaining)
        }

        /// Read the allocation still available for `budget_id`.
        pub fn remaining(env: Env, budget_id: String) -> i128 {
            env.storage()
                .persistent()
                .get(&BudgetKey::Remaining(budget_id))
                .unwrap_or(0)
        }
    }
} // mod batch_stubs

use self::batch_stubs::{TestBudget, TestBudgetClient, TestPolicy, TestPolicyClient};

// ------------------------------------------------------- validated batch ----

/// Register and wire the policy/budget stubs as the wallet's gates.
fn wire_gates(h: &Harness) -> (Address, Address) {
    let policy = h.env.register_contract(None, TestPolicy);
    let budget = h.env.register_contract(None, TestBudget);
    h.client.set_policy(&h.admin, &policy);
    h.client.set_budget(&h.admin, &budget);
    (policy, budget)
}

/// Build a validated `BatchAction` moving `amount` of `token` from the wallet
/// to `to`, checked against the given policy/budget envelopes (empty ids skip
/// the corresponding gate).
fn validated_action(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
    policy_id: &str,
    budget_id: &str,
) -> BatchAction {
    BatchAction {
        call: token_transfer_call(env, token_addr, from, to, amount),
        policy_id: String::from_str(env, policy_id),
        budget_id: String::from_str(env, budget_id),
        asset: token_addr.clone(),
        recipient: to.clone(),
        amount,
    }
}

#[test]
fn validated_batch_executes_and_reports_aggregates() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let (policy, budget) = wire_gates(&h);
    TestPolicyClient::new(&h.env, &policy).set_cap(&String::from_str(&h.env, "p1"), &500);
    TestBudgetClient::new(&h.env, &budget).top_up(&String::from_str(&h.env, "b1"), &1_000);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        200,
        "p1",
        "b1",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r2,
        150,
        "p1",
        "b1",
    ));

    let receipt = h.client.batch_execute_validated(&owner, &id, &actions);
    assert_eq!(
        receipt,
        BatchReceipt {
            executed: 2,
            total_amount: 350,
            budget_remaining: 650,
        }
    );
    assert_eq!(token_balance(&h, &r1), 200);
    assert_eq!(token_balance(&h, &r2), 150);
    assert_eq!(token_balance(&h, &h.contract_id), 650);
    assert_eq!(
        TestBudgetClient::new(&h.env, &budget).remaining(&String::from_str(&h.env, "b1")),
        650
    );

    // The aggregated outcome is published once for the whole batch, under the
    // canonical `WalletBatchValidated` topic (issue #243 replaced the old
    // `("wallet", "batch_validated")` topic).
    assert_event(&h.env, "WalletBatchValidated");
}

#[test]
fn validated_batch_policy_denial_reverts_atomically() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let (policy, budget) = wire_gates(&h);
    // Cap of 100: the first action passes, the second is denied by policy.
    TestPolicyClient::new(&h.env, &policy).set_cap(&String::from_str(&h.env, "p1"), &100);
    TestBudgetClient::new(&h.env, &budget).top_up(&String::from_str(&h.env, "b1"), &1_000);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        50,
        "p1",
        "b1",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        200,
        "p1",
        "b1",
    ));

    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));

    // Nothing moved and the budget was never debited — full rollback.
    assert_eq!(token_balance(&h, &r1), 0);
    assert_eq!(token_balance(&h, &h.contract_id), 1_000);
    assert_eq!(
        TestBudgetClient::new(&h.env, &budget).remaining(&String::from_str(&h.env, "b1")),
        1_000
    );
}

#[test]
fn validated_batch_budget_insufficiency_reverts() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let (policy, budget) = wire_gates(&h);
    TestPolicyClient::new(&h.env, &policy).set_cap(&String::from_str(&h.env, "p1"), &1_000);
    // Only 100 available: 80 fits, the second action's 60 does not.
    TestBudgetClient::new(&h.env, &budget).top_up(&String::from_str(&h.env, "b1"), &100);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        80,
        "p1",
        "b1",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r2,
        60,
        "p1",
        "b1",
    ));

    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));

    // Full rollback: no tokens moved, budget untouched.
    assert_eq!(token_balance(&h, &r1), 0);
    assert_eq!(token_balance(&h, &r2), 0);
    assert_eq!(token_balance(&h, &h.contract_id), 1_000);
    assert_eq!(
        TestBudgetClient::new(&h.env, &budget).remaining(&String::from_str(&h.env, "b1")),
        100
    );
}

#[test]
fn validated_batch_cumulative_overflow_reverts() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, i128::MAX);
    h.client.deposit(&id, &owner, &h.token, &i128::MAX);

    // The cumulative total exceeds i128 before any call executes. The checked
    // aggregate must abort the batch with Overflow, before any value moves.
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        i128::MAX,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        1,
        "",
        "",
    ));

    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::Overflow)));
    assert_eq!(token_balance(&h, &r1), 0);
    assert_eq!(token_balance(&h, &h.contract_id), i128::MAX);
}

#[test]
fn validated_batch_unwired_gate_is_refused() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    // No policy contract wired, yet an action declares a policy envelope.
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        10,
        "p1",
        "",
    ));
    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(token_balance(&h, &h.contract_id), 100);
}

#[test]
fn validated_batch_without_envelopes_passes_unwired() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    // No gates wired and no envelope ids: behaves like the raw path, but still
    // reports the aggregated totals.
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        40,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        60,
        "",
        "",
    ));

    let receipt = h.client.batch_execute_validated(&owner, &id, &actions);
    assert_eq!(
        receipt,
        BatchReceipt {
            executed: 2,
            total_amount: 100,
            budget_remaining: 0,
        }
    );
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.contract_id), 0);
}

#[test]
fn validated_batch_mixed_assets_aggregate_total() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    let token_admin = Address::generate(&h.env);
    let token_b = h
        .env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    let sac_b = token::StellarAssetClient::new(&h.env, &token_b);
    sac_b.mint(&owner, &1_000);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &500);
    h.client.deposit(&id, &owner, &token_b, &500);

    // Cumulative value is aggregated across assets with checked math.
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        200,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &token_b,
        &h.contract_id,
        &recipient,
        100,
        "",
        "",
    ));

    let receipt = h.client.batch_execute_validated(&owner, &id, &actions);
    assert_eq!(
        receipt,
        BatchReceipt {
            executed: 2,
            total_amount: 300,
            budget_remaining: 0,
        }
    );
    assert_eq!(token_balance(&h, &recipient), 200);
    assert_eq!(
        token::TokenClient::new(&h.env, &token_b).balance(&recipient),
        100
    );
}

#[test]
fn validated_batch_empty_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let empty: Vec<BatchAction> = Vec::new(&h.env);
    let res = h.client.try_batch_execute_validated(&owner, &id, &empty);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn validated_batch_non_agent_rejected() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        50,
        "",
        "",
    ));
    let res = h
        .client
        .try_batch_execute_validated(&stranger, &id, &actions);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn validated_batch_frozen_wallet_rejected() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);
    h.client.freeze(&owner, &id);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        10,
        "",
        "",
    ));
    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::WalletFrozen)));
}

// --- Spending velocity limits (Issue #229) ---

/// Velocity window used by these tests: one hour, i.e. four 900 s buckets.
const WINDOW: u64 = 3_600;
const BUCKET: u64 = WINDOW / crate::VELOCITY_BUCKETS as u64;
/// Bucket-aligned start time, so bucket boundaries are easy to reason about.
const T0: u64 = 40 * BUCKET;

fn at(h: &Harness, timestamp: u64) {
    h.env.ledger().set_timestamp(timestamp);
}

/// A funded agent wallet with a velocity ceiling of `max` per hour on the
/// harness token, clock at `T0`. Returns (wallet_id, owner, agent).
fn velocity_wallet(h: &Harness, deposit: i128, max: i128) -> (u64, Address, Address) {
    at(h, T0);
    let (id, owner, agent) = funded_agent_wallet(h, deposit);
    h.client
        .set_velocity_limit(&owner, &id, &h.token, &max, &WINDOW);
    (id, owner, agent)
}

fn pay(h: &Harness, agent: &Address, id: u64, amount: i128) -> Result<(), Error> {
    let to = Address::generate(&h.env);
    match h.client.try_transfer(agent, &id, &to, &h.token, &amount) {
        Ok(Ok(())) => Ok(()),
        Err(Ok(e)) => Err(e),
        other => panic!("unexpected result {:?}", other),
    }
}

fn usage(h: &Harness, id: u64) -> i128 {
    h.client.get_velocity_usage(&id, &h.token)
}

#[test]
fn velocity_is_unlimited_until_configured() {
    let h = setup();
    let (id, _owner, agent) = funded_agent_wallet(&h, 10_000);
    assert_eq!(h.client.get_velocity_limit(&id, &h.token), None);
    assert_eq!(pay(&h, &agent, id, 10_000), Ok(()));
    assert_eq!(usage(&h, id), 0);
}

#[test]
fn first_transfer_within_the_limit_succeeds_and_is_recorded() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(
        h.client.get_velocity_limit(&id, &h.token),
        Some(crate::VelocityLimit {
            max_amount: 1_000,
            window_seconds: WINDOW,
        })
    );
    assert_eq!(pay(&h, &agent, id, 400), Ok(()));
    assert_eq!(usage(&h, id), 400);
    assert_eq!(h.client.balance(&id, &h.token), 9_600);
}

#[test]
fn transfers_in_the_same_window_accumulate() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 300), Ok(()));
    at(&h, T0 + 100);
    assert_eq!(pay(&h, &agent, id, 300), Ok(()));
    at(&h, T0 + 2 * BUCKET + 5);
    assert_eq!(pay(&h, &agent, id, 300), Ok(()));
    assert_eq!(usage(&h, id), 900);
}

#[test]
fn reaching_exactly_the_limit_succeeds_and_one_unit_more_fails() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 600), Ok(()));
    assert_eq!(pay(&h, &agent, id, 400), Ok(()));
    assert_eq!(usage(&h, id), 1_000);

    let recipient = Address::generate(&h.env);
    assert_eq!(
        h.client.try_transfer(&agent, &id, &recipient, &h.token, &1),
        Err(Ok(Error::VelocityLimitExceeded))
    );
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(h.client.balance(&id, &h.token), 9_000);
}

#[test]
fn single_transfer_above_the_limit_is_rejected() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(
        pay(&h, &agent, id, 1_001),
        Err(Error::VelocityLimitExceeded)
    );
    assert_eq!(usage(&h, id), 0);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));
}

#[test]
fn rejected_transfers_do_not_consume_allowance() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 500, 1_000);

    // Over the ceiling: refused, nothing recorded.
    assert_eq!(
        pay(&h, &agent, id, 1_500),
        Err(Error::VelocityLimitExceeded)
    );
    assert_eq!(usage(&h, id), 0);

    // Fits the ceiling but not the balance: the debit fails after the
    // velocity hook ran, and the revert of the invocation takes the recorded
    // usage with it.
    assert_eq!(pay(&h, &agent, id, 600), Err(Error::InsufficientFunds));
    assert_eq!(usage(&h, id), 0);

    // The full ceiling is still available.
    assert_eq!(pay(&h, &agent, id, 500), Ok(()));
    assert_eq!(usage(&h, id), 500);
}

#[test]
fn allowance_returns_exactly_when_the_window_slides_past() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));

    // One second before the bucket of the spend leaves the window: counted.
    at(&h, T0 + WINDOW - 1);
    assert_eq!(usage(&h, id), 1_000);
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::VelocityLimitExceeded));

    // At the boundary the bucket slides out and the full ceiling returns.
    at(&h, T0 + WINDOW);
    assert_eq!(usage(&h, id), 0);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::VelocityLimitExceeded));
}

#[test]
fn buckets_age_out_one_at_a_time() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 400), Ok(())); // bucket 40
    at(&h, T0 + 2 * BUCKET);
    assert_eq!(pay(&h, &agent, id, 600), Ok(())); // bucket 42

    // Bucket 44: the 400 has aged out, the 600 has not.
    at(&h, T0 + 4 * BUCKET);
    assert_eq!(usage(&h, id), 600);
    assert_eq!(pay(&h, &agent, id, 401), Err(Error::VelocityLimitExceeded));
    assert_eq!(pay(&h, &agent, id, 400), Ok(()));

    // Bucket 46: the 600 is gone too; only the latest 400 remains.
    at(&h, T0 + 6 * BUCKET);
    assert_eq!(usage(&h, id), 400);
}

#[test]
fn no_double_burst_across_a_window_boundary() {
    // A fixed window would allow ~2x the ceiling in two consecutive seconds.
    // The rolling window does not.
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
    at(&h, T0 + WINDOW - 1);
    assert_eq!(pay(&h, &agent, id, 999), Ok(()));
    at(&h, T0 + WINDOW);
    // Only the 1 unit from T0 aged out.
    assert_eq!(usage(&h, id), 999);
    assert_eq!(pay(&h, &agent, id, 2), Err(Error::VelocityLimitExceeded));
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
}

#[test]
fn a_long_idle_gap_resets_all_buckets() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 700), Ok(()));
    at(&h, T0 + 100 * WINDOW);
    assert_eq!(usage(&h, id), 0);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));
}

#[test]
fn a_clock_moving_backwards_never_frees_allowance() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    at(&h, T0 + 3 * BUCKET);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));
    at(&h, T0);
    assert_eq!(usage(&h, id), 1_000);
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::VelocityLimitExceeded));
}

#[test]
fn withdrawals_share_the_window_with_transfers() {
    let h = setup();
    let (id, owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 700), Ok(()));
    assert_eq!(
        h.client.try_withdraw(&owner, &id, &h.token, &301),
        Err(Ok(Error::VelocityLimitExceeded))
    );
    h.client.withdraw(&owner, &id, &h.token, &300);
    assert_eq!(usage(&h, id), 1_000);
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::VelocityLimitExceeded));
}

#[test]
fn limits_are_per_asset_and_per_wallet() {
    let h = setup();
    let (id, owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));

    // Another asset in the same wallet is not limited by the first ceiling.
    let other_admin = Address::generate(&h.env);
    let other = h
        .env
        .register_stellar_asset_contract_v2(other_admin)
        .address();
    token::StellarAssetClient::new(&h.env, &other).mint(&owner, &5_000);
    h.client.deposit(&id, &owner, &other, &5_000);
    let to = Address::generate(&h.env);
    h.client.transfer(&agent, &id, &to, &other, &5_000);

    // Another wallet with its own ceiling has its own window.
    let (id2, owner2, agent2) = funded_agent_wallet(&h, 5_000);
    h.client
        .set_velocity_limit(&owner2, &id2, &h.token, &2_000, &WINDOW);
    assert_eq!(pay(&h, &agent2, id2, 2_000), Ok(()));
    assert_eq!(usage(&h, id), 1_000);
    assert_eq!(usage(&h, id2), 2_000);
}

#[test]
fn policy_denial_still_wins_and_consumes_nothing() {
    let h = setup();
    h.client.set_policy(&h.admin, &register_stub(&h));
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 5_000);

    // The stub policy caps each spend at 1_000; the velocity ceiling is
    // looser, so the policy is what refuses and nothing is recorded.
    assert_eq!(pay(&h, &agent, id, 2_000), Err(Error::PolicyDenied));
    assert_eq!(usage(&h, id), 0);

    // Five policy-compliant spends fill the ceiling; the sixth is refused by
    // the velocity check even though the policy would allow it.
    for _ in 0..5 {
        assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));
    }
    assert_eq!(
        pay(&h, &agent, id, 1_000),
        Err(Error::VelocityLimitExceeded)
    );
    assert_eq!(h.client.balance(&id, &h.token), 5_000);
}

#[test]
fn policy_bypass_does_not_lift_the_velocity_ceiling() {
    let h = setup();
    h.client.set_policy(&h.admin, &register_stub(&h));
    let (id, _owner, agent) = velocity_wallet(&h, 10_000, 1_500);
    h.client.set_policy_bypass(&h.admin, &id, &true);
    assert_eq!(pay(&h, &agent, id, 1_500), Ok(()));
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::VelocityLimitExceeded));
}

#[test]
fn validated_batch_actions_count_toward_velocity() {
    let h = setup();
    let (id, owner, agent) = velocity_wallet(&h, 1_000, 500);
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);

    // Two actions with no policy/budget envelope: velocity still applies,
    // and the second action sees the volume of the first.
    let mut over: Vec<BatchAction> = Vec::new(&h.env);
    over.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        300,
        "",
        "",
    ));
    over.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r2,
        201,
        "",
        "",
    ));
    assert_eq!(
        h.client.try_batch_execute_validated(&agent, &id, &over),
        Err(Ok(Error::VelocityLimitExceeded))
    );
    // Atomic: nothing moved and nothing was recorded.
    assert_eq!(token_balance(&h, &r1), 0);
    assert_eq!(usage(&h, id), 0);

    let mut fits: Vec<BatchAction> = Vec::new(&h.env);
    fits.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        300,
        "",
        "",
    ));
    fits.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r2,
        200,
        "",
        "",
    ));
    h.client.batch_execute_validated(&agent, &id, &fits);
    assert_eq!(usage(&h, id), 500);
    assert_eq!(token_balance(&h, &r2), 200);
    assert_eq!(
        h.client.try_withdraw(&owner, &id, &h.token, &1),
        Err(Ok(Error::VelocityLimitExceeded))
    );
}

/// A batch spanning several assets keeps each asset's window its own: a
/// ceiling reached on one asset must not refuse an action in another, and
/// every charged asset ends up with its own usage record.
#[test]
fn validated_batch_charges_each_asset_its_own_ceiling() {
    let h = setup();
    at(&h, T0);
    let token_admin = Address::generate(&h.env);
    let token_b = h
        .env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    let sac_b = token::StellarAssetClient::new(&h.env, &token_b);

    let (id, owner, agent) = funded_agent_wallet(&h, 1_000);
    sac_b.mint(&owner, &2_000);
    h.client.deposit(&id, &owner, &token_b, &2_000);
    // Token A's ceiling is tight enough to be reached; token B's leaves room.
    h.client
        .set_velocity_limit(&owner, &id, &h.token, &400, &WINDOW);
    h.client
        .set_velocity_limit(&owner, &id, &token_b, &1_500, &WINDOW);

    // Four actions over two assets, interleaved, so both cache entries have to
    // stay live at once and neither can be answered from the other's.
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        200,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &token_b,
        &h.contract_id,
        &r1,
        500,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r2,
        200,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &token_b,
        &h.contract_id,
        &r2,
        400,
        "",
        "",
    ));
    h.client.batch_execute_validated(&agent, &id, &actions);

    // Each asset recorded only its own volume, and value moved for both.
    assert_eq!(h.client.get_velocity_usage(&id, &h.token), 400);
    assert_eq!(h.client.get_velocity_usage(&id, &token_b), 900);
    assert_eq!(token_balance(&h, &r2), 200);
    assert_eq!(token::TokenClient::new(&h.env, &token_b).balance(&r2), 400);

    // Token A is at its ceiling and refuses.
    let mut over_a: Vec<BatchAction> = Vec::new(&h.env);
    over_a.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        1,
        "",
        "",
    ));
    assert_eq!(
        h.client.try_batch_execute_validated(&agent, &id, &over_a),
        Err(Ok(Error::VelocityLimitExceeded))
    );
    // Token A's refusal left token B's record untouched, and B still has room.
    assert_eq!(h.client.get_velocity_usage(&id, &token_b), 900);
    let mut more_b: Vec<BatchAction> = Vec::new(&h.env);
    more_b.push_back(validated_action(
        &h.env,
        &token_b,
        &h.contract_id,
        &r2,
        600,
        "",
        "",
    ));
    h.client.batch_execute_validated(&agent, &id, &more_b);
    assert_eq!(h.client.get_velocity_usage(&id, &token_b), 1_500);
}

/// A limited and an unlimited asset can share one batch: the unlimited asset
/// is never charged and never grows a usage record, while the limited one is
/// still enforced. A batch may not use the unlimited asset to launder volume
/// past the limited asset's ceiling.
#[test]
fn validated_batch_leaves_an_unlimited_asset_untracked() {
    let h = setup();
    at(&h, T0);
    let token_admin = Address::generate(&h.env);
    let token_b = h
        .env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    let sac_b = token::StellarAssetClient::new(&h.env, &token_b);

    let (id, owner, agent) = funded_agent_wallet(&h, 1_000);
    sac_b.mint(&owner, &2_000);
    h.client.deposit(&id, &owner, &token_b, &2_000);
    // Only token A carries a ceiling.
    h.client
        .set_velocity_limit(&owner, &id, &h.token, &400, &WINDOW);

    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        300,
        "",
        "",
    ));
    // Far beyond token A's ceiling, and legal because it is a different asset.
    actions.push_back(validated_action(
        &h.env,
        &token_b,
        &h.contract_id,
        &r2,
        1_500,
        "",
        "",
    ));
    h.client.batch_execute_validated(&agent, &id, &actions);

    // The limited asset is charged, the unlimited one has no record at all.
    assert_eq!(h.client.get_velocity_usage(&id, &h.token), 300);
    assert_eq!(h.client.get_velocity_usage(&id, &token_b), 0);
    assert_eq!(h.client.get_velocity_limit(&id, &token_b), None);
    assert_eq!(
        token::TokenClient::new(&h.env, &token_b).balance(&r2),
        1_500
    );

    // Token A's ceiling still counts only token A.
    let mut over_a: Vec<BatchAction> = Vec::new(&h.env);
    over_a.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        101,
        "",
        "",
    ));
    assert_eq!(
        h.client.try_batch_execute_validated(&agent, &id, &over_a),
        Err(Ok(Error::VelocityLimitExceeded))
    );
}

#[test]
fn window_sum_that_would_overflow_is_a_velocity_breach() {
    let h = setup();
    let (id, owner, agent) = velocity_wallet(&h, i128::MAX, i128::MAX);
    assert_eq!(pay(&h, &agent, id, i128::MAX), Ok(()));
    mint(&h, &owner, 1);
    h.client.deposit(&id, &owner, &h.token, &1);
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::VelocityLimitExceeded));
    assert_eq!(usage(&h, id), i128::MAX);
}

#[test]
fn only_wallet_admins_configure_velocity() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 1_000, 500);
    let stranger = Address::generate(&h.env);
    for caller in [&agent, &stranger] {
        assert_eq!(
            h.client
                .try_set_velocity_limit(caller, &id, &h.token, &1_000_000, &WINDOW),
            Err(Ok(Error::Unauthorized))
        );
        assert_eq!(
            h.client.try_clear_velocity_limit(caller, &id, &h.token),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert_eq!(
        h.client
            .get_velocity_limit(&id, &h.token)
            .unwrap()
            .max_amount,
        500
    );
    assert_eq!(
        h.client
            .try_set_velocity_limit(&h.admin, &999, &h.token, &1, &WINDOW),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn velocity_configuration_is_validated() {
    let h = setup();
    let (id, owner, _agent) = funded_agent_wallet(&h, 1_000);
    for max in [0, -1, i128::MIN] {
        assert_eq!(
            h.client
                .try_set_velocity_limit(&owner, &id, &h.token, &max, &WINDOW),
            Err(Ok(Error::InvalidAmount))
        );
    }
    for window in [0u64, 1, 3, 3_601] {
        assert_eq!(
            h.client
                .try_set_velocity_limit(&owner, &id, &h.token, &100, &window),
            Err(Ok(Error::InvalidInput))
        );
    }
    // The smallest valid window is one second per bucket.
    h.client.set_velocity_limit(
        &owner,
        &id,
        &h.token,
        &100,
        &(crate::VELOCITY_BUCKETS as u64),
    );

    h.client.archive(&owner, &id);
    assert_eq!(
        h.client
            .try_set_velocity_limit(&owner, &id, &h.token, &100, &WINDOW),
        Err(Ok(Error::WalletArchived))
    );
}

#[test]
fn raising_the_ceiling_keeps_usage_and_changing_the_window_resets_it() {
    let h = setup();
    let (id, owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));

    h.client
        .set_velocity_limit(&owner, &id, &h.token, &1_500, &WINDOW);
    assert_eq!(usage(&h, id), 1_000);
    assert_eq!(pay(&h, &agent, id, 501), Err(Error::VelocityLimitExceeded));
    assert_eq!(pay(&h, &agent, id, 500), Ok(()));

    // Lowering below recorded usage blocks spending until it ages out.
    h.client
        .set_velocity_limit(&owner, &id, &h.token, &1_000, &WINDOW);
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::VelocityLimitExceeded));

    // A new window length re-buckets time, so recorded usage restarts.
    h.client
        .set_velocity_limit(&owner, &id, &h.token, &1_000, &(2 * WINDOW));
    assert_eq!(usage(&h, id), 0);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));
}

#[test]
fn clearing_the_ceiling_removes_limit_and_usage() {
    let h = setup();
    let (id, owner, agent) = velocity_wallet(&h, 10_000, 1_000);
    assert_eq!(pay(&h, &agent, id, 1_000), Ok(()));
    h.client.clear_velocity_limit(&owner, &id, &h.token);
    assert_eq!(h.client.get_velocity_limit(&id, &h.token), None);
    assert_eq!(usage(&h, id), 0);
    assert_eq!(pay(&h, &agent, id, 5_000), Ok(()));
    assert_eq!(
        h.client.try_clear_velocity_limit(&owner, &id, &h.token),
        Err(Ok(Error::NotFound))
    );

    // Re-enabling starts from a clean window.
    h.client
        .set_velocity_limit(&owner, &id, &h.token, &1_000, &WINDOW);
    assert_eq!(usage(&h, id), 0);
}

#[test]
fn velocity_storage_stays_constant_size() {
    let h = setup();
    let (id, _owner, agent) = velocity_wallet(&h, 100_000, 1_000_000);
    for i in 0..40u64 {
        at(&h, T0 + i * BUCKET);
        assert_eq!(pay(&h, &agent, id, 10), Ok(()));
    }
    // After many spends across many buckets there is still exactly one
    // usage record holding VELOCITY_BUCKETS entries.
    let record: crate::VelocityUsage = h.env.as_contract(&h.contract_id, || {
        h.env
            .storage()
            .persistent()
            .get(&crate::DataKey::VelocityUsage(id, h.token.clone()))
            .unwrap()
    });
    assert_eq!(record.spent.len(), crate::VELOCITY_BUCKETS);
    assert_eq!(record.bucket, (T0 + 39 * BUCKET) / BUCKET);
    // The trailing window holds the last four spends only.
    assert_eq!(usage(&h, id), 40);
}

// --- Standardized event schemas for off-chain indexing (Issue #243) ---

#[test]
fn a_deposit_is_reported_as_exactly_one_standard_funded_event() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let payer = Address::generate(&h.env);
    mint(&h, &payer, 1_000);

    h.client.deposit(&id, &payer, &h.token, &400);

    assert_event_data(
        &h.env,
        "WalletFunded",
        1,
        (id, payer.clone(), h.token.clone(), 400i128),
    );
    // The old ad-hoc `("wallet", "deposit")` topic is gone, and the funded
    // event is not double-reported under the legacy encoding.
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
    assert_eq!(h.client.balance(&id, &h.token), 400);
}

#[test]
fn a_withdrawal_is_reported_as_exactly_one_standard_withdrawn_event() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    h.client.withdraw(&owner, &id, &h.token, &250);

    assert_event_data(
        &h.env,
        "WalletWithdrawn",
        1,
        (id, owner.clone(), h.token.clone(), 250i128),
    );
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
    assert_eq!(token_balance(&h, &owner), 250);
    assert_eq!(h.client.balance(&id, &h.token), 750);
}

#[test]
fn wiring_and_unwiring_the_policy_gate_report_distinct_standard_events() {
    let h = setup();
    let policy = register_stub(&h);

    h.client.set_policy(&h.admin, &policy);
    assert_event_data(&h.env, "WalletPolicyConfigured", 1, (policy.clone(),));
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);

    h.client.clear_policy(&h.admin);
    // A dedicated variant with an empty payload: the old encoding reused the
    // `("wallet", "policy")` topic for both set and clear with two different
    // payload shapes, which no indexer could decode unambiguously.
    assert_eq!(count_event(&h.env, "WalletPolicyCleared"), 1);
    assert_event_data(&h.env, "WalletPolicyConfigured", 1, (policy,));
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
    assert_eq!(h.client.get_policy(), None);
}

#[test]
fn flipping_the_policy_bypass_reports_a_typed_standard_event() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    h.client.set_policy_bypass(&h.admin, &id, &true);
    h.client.set_policy_bypass(&h.admin, &id, &false);

    assert_event_data(&h.env, "WalletPolicyBypassChanged", 1, (id, true));
    assert_event_data(&h.env, "WalletPolicyBypassChanged", 1, (id, false));
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
}

#[test]
fn a_spend_that_clears_the_policy_gate_records_the_check() {
    let h = setup();
    h.client.set_policy(&h.admin, &register_stub(&h));
    let (id, _owner, agent) = funded_agent_wallet(&h, 5_000);

    let to = Address::generate(&h.env);
    h.client.transfer(&agent, &id, &to, &h.token, &600);

    assert_event_data(
        &h.env,
        "WalletPolicyChecked",
        1,
        (id, h.token.clone(), 600i128),
    );
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
}

#[test]
fn a_denied_spend_records_no_policy_check() {
    let h = setup();
    h.client.set_policy(&h.admin, &register_stub(&h));
    let (id, _owner, agent) = funded_agent_wallet(&h, 5_000);

    // Above the stub's cap the gate refuses and the whole invocation reverts.
    let to = Address::generate(&h.env);
    assert_eq!(
        h.client.try_transfer(&agent, &id, &to, &h.token, &2_000),
        Err(Ok(Error::PolicyDenied))
    );

    // A passing check is the only thing this event reports, so a refusal must
    // not leave one behind for an agent to mistake for an approval.
    assert_event_data(
        &h.env,
        "WalletPolicyChecked",
        0,
        (id, h.token.clone(), 2_000i128),
    );
    assert_eq!(h.client.balance(&id, &h.token), 5_000);
}

#[test]
fn velocity_ceilings_report_distinct_standard_events_for_set_and_clear() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    h.client
        .set_velocity_limit(&owner, &id, &h.token, &1_000, &3_600);
    assert_event_data(
        &h.env,
        "WalletVelocityLimitSet",
        1,
        (id, h.token.clone(), 1_000i128, 3_600u64),
    );
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);

    h.client.clear_velocity_limit(&owner, &id, &h.token);
    // Previously both directions shared `("wallet", "velocity")` with a
    // 4-field and a 3-field payload respectively.
    assert_event_data(
        &h.env,
        "WalletVelocityLimitCleared",
        1,
        (id, h.token.clone()),
    );
    assert_event_data(
        &h.env,
        "WalletVelocityLimitSet",
        1,
        (id, h.token.clone(), 1_000i128, 3_600u64),
    );
}

#[test]
fn role_grants_and_revocations_share_one_standard_event() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let agent = Address::generate(&h.env);

    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    h.client.revoke_role(&owner, &id, &agent);

    // One topic, one payload shape; `action` carries the direction and
    // `role` is absent on a revocation, where the account simply holds nothing.
    let granted: (u64, Address, Option<Symbol>, Symbol) = (
        id,
        agent.clone(),
        Some(Symbol::new(&h.env, "agent")),
        Symbol::new(&h.env, "granted"),
    );
    let revoked: (u64, Address, Option<Symbol>, Symbol) =
        (id, agent.clone(), None, Symbol::new(&h.env, "revoked"));
    assert_event_data(&h.env, "WalletRoleChanged", 1, granted);
    assert_event_data(&h.env, "WalletRoleChanged", 1, revoked);
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
}

#[test]
fn module_wiring_and_asset_budgets_report_standard_events() {
    let h = setup();
    let budget = Address::generate(&h.env);
    let registry = Address::generate(&h.env);

    h.client.set_budget(&h.admin, &budget);
    h.client.set_registry(&h.admin, &registry);
    assert_event_data(
        &h.env,
        "WalletModuleWired",
        1,
        (Symbol::new(&h.env, "budget"), budget.clone()),
    );
    assert_event_data(
        &h.env,
        "WalletModuleWired",
        1,
        (Symbol::new(&h.env, "registry"), registry),
    );

    let budget_id = String::from_str(&h.env, "budget-1");
    h.client.set_asset_budget_id(&h.admin, &h.token, &budget_id);
    assert_event_data(
        &h.env,
        "WalletAssetBudgetSet",
        1,
        (h.token.clone(), budget_id),
    );
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
}

#[test]
fn designating_a_guardian_reports_a_standard_event() {
    let h = setup();
    let guardian = Address::generate(&h.env);

    h.client.set_guardian(&h.admin, &guardian);
    assert_event_data(&h.env, "WalletGuardianChanged", 1, (guardian,));
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
}

#[test]
fn creating_and_freezing_a_wallet_each_report_one_standard_event() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    // Creation used to emit the same fact twice: once through the legacy
    // `events::wallet_created` helper and once canonically.
    assert_event_data(&h.env, "WalletCreated", 1, (id, owner.clone()));
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);

    let h2 = setup();
    let owner2 = Address::generate(&h2.env);
    let id2 = h2.client.create_wallet(&owner2);
    h2.client.freeze(&owner2, &id2);
    // Likewise for freezing, which emitted both the legacy
    // `("wallet", "frozen")` topic and the canonical state change.
    assert_event_data(
        &h2.env,
        "WalletStateChanged",
        1,
        (id2, Symbol::new(&h2.env, "frozen")),
    );
    assert_no_legacy_wallet_topics(&h2.env, &h2.contract_id);
}

// --- Sliding-window rate limits (Issue #31) ---

/// A funded agent wallet with a rate limit of `max_volume` / `max_count` per
/// [`WINDOW`], clock at `T0`. Returns (wallet_id, owner, agent).
fn rate_wallet(
    h: &Harness,
    deposit: i128,
    max_volume: i128,
    max_count: u32,
) -> (u64, Address, Address) {
    at(h, T0);
    let (id, owner, agent) = funded_agent_wallet(h, deposit);
    h.client
        .set_rate_limit(&owner, &id, &max_volume, &max_count, &WINDOW);
    (id, owner, agent)
}

fn rate_usage(h: &Harness, id: u64) -> (i128, u32) {
    let status = h.client.get_rate_usage(&id);
    (status.volume, status.count)
}

#[test]
fn rate_limit_is_disabled_until_configured() {
    let h = setup();
    let (id, _owner, agent) = funded_agent_wallet(&h, 10_000);
    assert_eq!(h.client.get_rate_limit(&id), None);
    assert_eq!(pay(&h, &agent, id, 10_000), Ok(()));
    assert_eq!(rate_usage(&h, id), (0, 0));
}

#[test]
fn rate_limit_count_cap_rejects_rapid_transactions() {
    let h = setup();
    let (id, _owner, agent) = rate_wallet(&h, 10_000, 0, 3);

    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
    assert_eq!(rate_usage(&h, id), (3, 3));

    // The fourth rapid attempt is refused and consumes nothing.
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::RateLimitExceeded));
    assert_eq!(rate_usage(&h, id), (3, 3));
}

#[test]
fn rate_limit_volume_cap_rejects_and_nothing_moves() {
    let h = setup();
    let (id, _owner, agent) = rate_wallet(&h, 10_000, 500, 0);

    assert_eq!(pay(&h, &agent, id, 300), Ok(()));
    assert_eq!(pay(&h, &agent, id, 300), Err(Error::RateLimitExceeded));
    assert_eq!(rate_usage(&h, id), (300, 1));

    // A spend that fits exactly is allowed; one unit more is not.
    assert_eq!(pay(&h, &agent, id, 200), Ok(()));
    assert_eq!(rate_usage(&h, id), (500, 2));
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::RateLimitExceeded));
    assert_eq!(h.client.balance(&id, &h.token), 9_500);
}

#[test]
fn rate_limit_allowance_returns_as_the_window_slides() {
    let h = setup();
    let (id, _owner, agent) = rate_wallet(&h, 10_000, 500, 0);
    assert_eq!(pay(&h, &agent, id, 500), Ok(()));

    // One second before the spend's bucket leaves the window it is still
    // counted.
    at(&h, T0 + WINDOW - 1);
    assert_eq!(rate_usage(&h, id), (500, 1));
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::RateLimitExceeded));

    // At the boundary the bucket slides out and the full allowance returns.
    at(&h, T0 + WINDOW);
    assert_eq!(rate_usage(&h, id), (0, 0));
    assert_eq!(pay(&h, &agent, id, 500), Ok(()));
}

#[test]
fn rate_limit_count_allowance_returns_as_the_window_slides() {
    let h = setup();
    let (id, _owner, agent) = rate_wallet(&h, 10_000, 0, 2);
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::RateLimitExceeded));

    at(&h, T0 + WINDOW);
    assert_eq!(rate_usage(&h, id), (0, 0));
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
}

#[test]
fn rate_limit_admits_no_double_burst_across_a_boundary() {
    // A fixed window would allow ~2x the ceiling in two consecutive seconds;
    // the rolling window does not.
    let h = setup();
    let (id, _owner, agent) = rate_wallet(&h, 10_000, 1_000, 0);
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
    at(&h, T0 + WINDOW - 1);
    assert_eq!(pay(&h, &agent, id, 999), Ok(()));
    at(&h, T0 + WINDOW);
    // Only the 1 unit from T0 aged out; the 999 from the previous second stays.
    assert_eq!(rate_usage(&h, id), (999, 1));
    assert_eq!(pay(&h, &agent, id, 2), Err(Error::RateLimitExceeded));
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
}

#[test]
fn withdrawals_share_the_rate_window_with_transfers() {
    let h = setup();
    let (id, owner, agent) = rate_wallet(&h, 10_000, 1_000, 0);
    assert_eq!(pay(&h, &agent, id, 700), Ok(()));
    assert_eq!(
        h.client.try_withdraw(&owner, &id, &h.token, &301),
        Err(Ok(Error::RateLimitExceeded))
    );
    h.client.withdraw(&owner, &id, &h.token, &300);
    assert_eq!(rate_usage(&h, id), (1_000, 2));
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::RateLimitExceeded));
}

#[test]
fn rate_limits_are_per_wallet() {
    let h = setup();
    let (id, _owner, agent) = rate_wallet(&h, 10_000, 500, 0);
    assert_eq!(pay(&h, &agent, id, 500), Ok(()));

    let (id2, _owner2, agent2) = rate_wallet(&h, 10_000, 500, 0);
    assert_eq!(pay(&h, &agent2, id2, 500), Ok(()));

    assert_eq!(rate_usage(&h, id), (500, 1));
    assert_eq!(rate_usage(&h, id2), (500, 1));
}

#[test]
fn rate_limit_configuration_is_owner_only() {
    let h = setup();
    let (id, owner, agent) = rate_wallet(&h, 10_000, 1_000, 0);
    assert_eq!(
        h.client.try_set_rate_limit(&agent, &id, &1, &0, &WINDOW),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_clear_rate_limit(&agent, &id),
        Err(Ok(Error::Unauthorized))
    );

    h.client.archive(&owner, &id);
    assert_eq!(
        h.client.try_set_rate_limit(&owner, &id, &1, &0, &WINDOW),
        Err(Ok(Error::WalletArchived))
    );
}

#[test]
fn rate_limit_configuration_is_validated() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    // A negative volume ceiling is malformed.
    assert_eq!(
        h.client.try_set_rate_limit(&owner, &id, &-1, &0, &WINDOW),
        Err(Ok(Error::InvalidInput))
    );
    // A window that is not a whole number of buckets is malformed.
    assert_eq!(
        h.client
            .try_set_rate_limit(&owner, &id, &100, &0, &(WINDOW + 1)),
        Err(Ok(Error::InvalidInput))
    );
    // A window shorter than the bucket count cannot be tracked.
    assert_eq!(
        h.client.try_set_rate_limit(
            &owner,
            &id,
            &100,
            &0,
            &(crate::RATE_LIMIT_BUCKETS as u64 - 1),
        ),
        Err(Ok(Error::InvalidInput))
    );
    // A well-formed config round-trips through the view.
    h.client.set_rate_limit(&owner, &id, &100, &5, &WINDOW);
    assert_eq!(
        h.client.get_rate_limit(&id),
        Some(crate::RateLimitConfig {
            max_volume: 100,
            max_count: 5,
            window_seconds: WINDOW,
        })
    );
}

#[test]
fn zero_window_disables_rate_limiting() {
    let h = setup();
    let (id, owner, agent) = rate_wallet(&h, 10_000, 1, 0);
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));
    assert_eq!(pay(&h, &agent, id, 1), Err(Error::RateLimitExceeded));

    // Re-configuring with a zero window turns the limit off and clears usage.
    h.client.set_rate_limit(&owner, &id, &0, &0, &0);
    assert_eq!(h.client.get_rate_limit(&id), None);
    assert_eq!(rate_usage(&h, id), (0, 0));
    assert_eq!(pay(&h, &agent, id, 5_000), Ok(()));
}

#[test]
fn clearing_a_rate_limit_removes_limit_and_usage() {
    let h = setup();
    let (id, owner, agent) = rate_wallet(&h, 10_000, 1, 0);
    assert_eq!(pay(&h, &agent, id, 1), Ok(()));

    h.client.clear_rate_limit(&owner, &id);
    assert_eq!(h.client.get_rate_limit(&id), None);
    assert_eq!(rate_usage(&h, id), (0, 0));
    assert_eq!(pay(&h, &agent, id, 5_000), Ok(()));
    assert_eq!(
        h.client.try_clear_rate_limit(&owner, &id),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn rate_limit_charges_each_batch_action() {
    let h = setup();
    at(&h, T0);
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let agent = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    mint(&h, &owner, 10_000);
    h.client.deposit(&id, &owner, &h.token, &10_000);

    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        100,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r2,
        100,
        "",
        "",
    ));

    // A count cap of 1 refuses a two-action batch before anything moves.
    h.client.set_rate_limit(&owner, &id, &0, &1, &WINDOW);
    assert_eq!(
        h.client.try_batch_execute_validated(&agent, &id, &actions),
        Err(Ok(Error::RateLimitExceeded))
    );
    assert_eq!(rate_usage(&h, id), (0, 0));
    assert_eq!(h.client.balance(&id, &h.token), 10_000);

    // A volume cap below the batch total refuses it too.
    h.client.set_rate_limit(&owner, &id, &150, &2, &WINDOW);
    assert_eq!(
        h.client.try_batch_execute_validated(&agent, &id, &actions),
        Err(Ok(Error::RateLimitExceeded))
    );
    assert_eq!(rate_usage(&h, id), (0, 0));

    // With both caps satisfied the batch executes and is charged once.
    h.client.set_rate_limit(&owner, &id, &200, &2, &WINDOW);
    let receipt = h.client.batch_execute_validated(&agent, &id, &actions);
    assert_eq!(receipt.executed, 2);
    assert_eq!(rate_usage(&h, id), (200, 2));
    // The batch's sub-calls actually moved the tokens to each recipient; the
    // wallet's internal balance is bookkeeping the batch path does not touch.
    assert_eq!(token_balance(&h, &r1), 100);
    assert_eq!(token_balance(&h, &r2), 100);
    assert_eq!(h.client.balance(&id, &h.token), 10_000);
}

#[test]
fn rate_limit_storage_stays_constant_size() {
    let h = setup();
    let (id, _owner, agent) = rate_wallet(&h, 100_000, 1_000_000, 0);
    for i in 0..40u64 {
        at(&h, T0 + i * BUCKET);
        assert_eq!(pay(&h, &agent, id, 10), Ok(()));
    }
    // After many spends across many buckets there is still exactly one usage
    // record holding RATE_LIMIT_BUCKETS entries in each dimension.
    let record: crate::RateUsage = h.env.as_contract(&h.contract_id, || {
        h.env
            .storage()
            .persistent()
            .get(&crate::DataKey::RateLimitUsage(id))
            .unwrap()
    });
    assert_eq!(record.volume.len(), crate::RATE_LIMIT_BUCKETS);
    assert_eq!(record.count.len(), crate::RATE_LIMIT_BUCKETS);
    assert_eq!(record.bucket, (T0 + 39 * BUCKET) / BUCKET);
    // The trailing window holds the last four spends only.
    assert_eq!(rate_usage(&h, id), (40, 4));
}

#[test]
fn rate_limit_configuration_reports_standard_events() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    h.client.set_rate_limit(&owner, &id, &1_000, &5, &WINDOW);
    assert_event_data(
        &h.env,
        "WalletRateLimitSet",
        1,
        (id, 1_000i128, 5u32, WINDOW),
    );
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);

    h.client.clear_rate_limit(&owner, &id);
    assert_event_data(&h.env, "WalletRateLimitCleared", 1, (id,));
    assert_event_data(
        &h.env,
        "WalletRateLimitSet",
        1,
        (id, 1_000i128, 5u32, WINDOW),
    );
    assert_no_legacy_wallet_topics(&h.env, &h.contract_id);
}

// ---------------------------------------------------------------------------
// Multi-token balance tracking and allowance checks (Issue #279)
// ---------------------------------------------------------------------------

/// Register a second independent SAC asset on the harness.
fn second_asset(h: &Harness) -> Address {
    let token_admin = Address::generate(&h.env);
    h.env
        .register_stellar_asset_contract_v2(token_admin)
        .address()
}

/// `custody_balance` reads the contract's real SAC balance, not bookkeeping.
#[test]
fn custody_balance_tracks_real_tokens_across_assets() {
    let h = setup();
    let token_b = second_asset(&h);
    let (owner, id) = funded_wallet(&h, 700);

    // Before any funding of asset B the custody read answers 0, never traps.
    assert_eq!(h.client.custody_balance(&token_b), 0);

    mint(&h, &owner, 700); // asset A
    let sac_b = token::StellarAssetClient::new(&h.env, &token_b);
    sac_b.mint(&owner, &300);
    h.client.deposit(&id, &owner, &token_b, &300);

    assert_eq!(h.client.custody_balance(&h.token), 700);
    assert_eq!(h.client.custody_balance(&token_b), 300);
}

/// `custody_balance` on an address that is not a token fails closed with a
/// deterministic code instead of trapping the caller.
#[test]
fn custody_balance_of_a_non_token_address_fails_closed() {
    let h = setup();
    let not_a_token = Address::generate(&h.env);
    assert_eq!(
        h.client.try_custody_balance(&not_a_token),
        Err(Ok(Error::InvalidState))
    );
}

/// Balances stay per (wallet, asset) and internal bookkeeping mirrors real
/// custody for each token.
#[test]
fn multi_token_balances_are_tracked_per_wallet_and_asset() {
    let h = setup();
    let token_b = second_asset(&h);
    let owner_a = Address::generate(&h.env);
    let owner_b = Address::generate(&h.env);
    let id_a = h.client.create_wallet(&owner_a);
    let id_b = h.client.create_wallet(&owner_b);

    mint(&h, &owner_a, 500);
    let sac_b = token::StellarAssetClient::new(&h.env, &token_b);
    sac_b.mint(&owner_b, &900);
    h.client.deposit(&id_a, &owner_a, &h.token, &500);
    h.client.deposit(&id_b, &owner_b, &token_b, &900);

    assert_eq!(h.client.balance(&id_a, &h.token), 500);
    assert_eq!(h.client.balance(&id_a, &token_b), 0);
    assert_eq!(h.client.balance(&id_b, &h.token), 0);
    assert_eq!(h.client.balance(&id_b, &token_b), 900);
    assert_eq!(h.client.custody_balance(&h.token), 500);
    assert_eq!(h.client.custody_balance(&token_b), 900);

    // Spending asset A does not touch asset B or the other wallet.
    let recipient = Address::generate(&h.env);
    h.client
        .transfer(&owner_a, &id_a, &recipient, &h.token, &200);
    assert_eq!(h.client.balance(&id_a, &h.token), 300);
    assert_eq!(h.client.balance(&id_a, &token_b), 0);
    assert_eq!(h.client.balance(&id_b, &token_b), 900);
    assert_eq!(h.client.custody_balance(&token_b), 900);
}

/// An outgoing spend is refused with `InsufficientFunds` when the wallet has
/// no tracked balance for the asset — the uninitialized-pair case.
#[test]
fn transfer_of_an_untracked_asset_fails_with_insufficient_funds() {
    let h = setup();
    let token_b = second_asset(&h);
    let (owner, id) = funded_wallet(&h, 400);
    let recipient = Address::generate(&h.env);

    // The wallet has never seen asset B.
    assert_eq!(h.client.balance(&id, &token_b), 0);
    let res = h.client.try_transfer(&owner, &id, &recipient, &token_b, &1);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
    assert_eq!(token_balance(&h, &recipient), 0);
}

/// The preliminary allowance check runs before the policy and any token
/// call, so a zero-amount spend on an empty wallet reports `InvalidAmount`.
#[test]
fn zero_amount_transfer_on_an_empty_wallet_fails_with_invalid_amount() {
    let h = setup();
    let token_b = second_asset(&h);
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let recipient = Address::generate(&h.env);

    assert_eq!(
        h.client.try_transfer(&owner, &id, &recipient, &token_b, &0),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(h.client.custody_balance(&token_b), 0);
}

/// A tracked ledger that drifted above real custody cannot overdraw: the
/// custody check refuses before the token is called.
#[test]
fn transfer_refused_when_real_custody_is_short_even_if_tracked_is_enough() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 500);
    let recipient = Address::generate(&h.env);

    // Simulate custody drifting out of sync: the ledger says 500 but only 100
    // tokens remain under the contract's control.
    h.env.as_contract(&h.contract_id, || {
        h.env
            .storage()
            .persistent()
            .set(&crate::DataKey::Balance(id, h.token.clone()), &500i128);
        token::TokenClient::new(&h.env, &h.token).transfer(&h.contract_id, &owner, &400);
    });
    assert_eq!(h.client.balance(&id, &h.token), 500);
    assert_eq!(h.client.custody_balance(&h.token), 100);

    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &300);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
    assert_eq!(h.client.balance(&id, &h.token), 500);
    assert_eq!(token_balance(&h, &recipient), 0);

    // An amount within real custody still moves.
    h.client.transfer(&owner, &id, &recipient, &h.token, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

/// Withdrawals carry the same allowance verification as transfers, per asset.
#[test]
fn withdrawal_refused_without_sufficient_multi_token_funds() {
    let h = setup();
    let token_b = second_asset(&h);
    let (owner, id) = funded_wallet(&h, 800);

    // Asset B was never deposited: the tracked read refuses first.
    let res = h.client.try_withdraw(&owner, &id, &token_b, &50);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));

    // Over the tracked balance of asset A: same code, nothing moves.
    let res = h.client.try_withdraw(&owner, &id, &h.token, &801);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
    assert_eq!(h.client.balance(&id, &h.token), 800);
    assert_eq!(h.client.custody_balance(&h.token), 800);

    // Within both balances the withdrawal pays out per asset.
    let sac_b = token::StellarAssetClient::new(&h.env, &token_b);
    sac_b.mint(&owner, &200);
    h.client.deposit(&id, &owner, &token_b, &200);
    h.client.withdraw(&owner, &id, &token_b, &60);
    assert_eq!(token_balance(&h, &owner), 0); // asset A untouched
    assert_eq!(
        token::TokenClient::new(&h.env, &token_b).balance(&owner),
        60
    );
    assert_eq!(h.client.balance(&id, &token_b), 140);
    assert_eq!(h.client.custody_balance(&token_b), 140);
}

/// The error order is deterministic: funds are verified before any balance
/// changes, and a passing spend leaves custody and ledger in agreement.
#[test]
fn allowance_verification_leaves_ledger_and_custody_in_agreement() {
    let h = setup();
    let token_b = second_asset(&h);
    let owner_a = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner_a);

    mint(&h, &owner_a, 1_000);
    let sac_b = token::StellarAssetClient::new(&h.env, &token_b);
    sac_b.mint(&owner_a, &250);
    h.client.deposit(&id, &owner_a, &h.token, &1_000);
    h.client.deposit(&id, &owner_a, &token_b, &250);

    let recipient = Address::generate(&h.env);
    h.client.transfer(&owner_a, &id, &recipient, &h.token, &600);
    h.client.transfer(&owner_a, &id, &recipient, &token_b, &250);

    assert_eq!(h.client.balance(&id, &h.token), 400);
    assert_eq!(h.client.balance(&id, &token_b), 0);
    assert_eq!(h.client.custody_balance(&h.token), 400);
    assert_eq!(h.client.custody_balance(&token_b), 0);
    assert_eq!(token_balance(&h, &recipient), 600);

    // The emptied pair refuses further spends deterministically.
    assert_eq!(
        h.client
            .try_transfer(&owner_a, &id, &recipient, &token_b, &1),
        Err(Ok(Error::InsufficientFunds))
    );
}
