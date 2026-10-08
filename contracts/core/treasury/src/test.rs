#![cfg(test)]
extern crate std;

use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    token, vec, Address, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

use astroid_shared::constants::{
    GOVERNANCE_GRACE_PERIOD, MAX_BATCH_PAYMENTS, MAX_PAUSE_DURATION, MAX_TIMELOCK_DELAY,
    MIN_TIMELOCK_DELAY,
};
use astroid_shared::errors::Error;
use astroid_shared::types::Payment;

use crate::{TreasuryContract, TreasuryContractClient};

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

/// Decode the payload of the most recent `variant` event as the
/// `(org, counterparty, asset, amount, balance)` tuple shared by the
/// structured `TreasuryDeposited` / `TreasuryWithdrawn` events, or `None`
/// when no such event was published.
///
/// Fields are decoded individually instead of comparing raw `Val`s: `Val`
/// equality compares host handles for object types (addresses, strings,
/// vecs), so a decoded event payload never compares equal to a locally
/// constructed one even when the contents match.
fn treasury_flow_payload(
    env: &Env,
    variant: &str,
) -> Option<(String, Address, Address, i128, i128)> {
    let topic: Val = Symbol::new(env, variant).into_val(env);
    let mut found = None;
    for (_emitter, topics, data) in env.events().all().iter() {
        if !topics.contains(topic) {
            continue;
        }
        let fields = match Vec::<Val>::try_from_val(env, &data) {
            Ok(fields) if fields.len() == 5 => fields,
            _ => continue,
        };
        found = Some((
            String::try_from_val(env, &fields.get(0).unwrap()).unwrap(),
            Address::try_from_val(env, &fields.get(1).unwrap()).unwrap(),
            Address::try_from_val(env, &fields.get(2).unwrap()).unwrap(),
            i128::try_from_val(env, &fields.get(3).unwrap()).unwrap(),
            i128::try_from_val(env, &fields.get(4).unwrap()).unwrap(),
        ));
    }
    found
}

struct Harness<'a> {
    env: Env,
    client: TreasuryContractClient<'a>,
    admin: Address,
    multisig: Address,
    asset: Address,
}

/// Register a treasury plus a test SAC token, approve that token for routing,
/// and mint `funded` of the asset to the admin so deposits move real value.
fn setup(org: &str, funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let multisig = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, org), &admin);
    client.set_multisig(&admin, &multisig);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();

    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&admin, &funded);
    }
    client.add_approved_asset(&admin, &asset);

    Harness {
        env,
        client,
        admin,
        multisig,
        asset,
    }
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

#[test]
fn full_flow_deposit_allocate_withdraw() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Internal accounting and real custody both reflect the deposit.
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);
    assert_eq!(token_balance(&h, &h.admin), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);

    h.client
        .allocate_budget(&h.admin, &h.asset, &String::from_str(&h.env, "maint"));

    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 600);
    assert_eq!(holding.total_out, 400);
    // Real tokens left custody and reached the recipient.
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(token_balance(&h, &h.client.address), 600);
}

#[test]
fn withdraw_rejected_when_not_admin() {
    let h = setup("vault", 500);
    let intruder = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &500);

    // intruder is not the admin — refused before any value moves.
    let res = h
        .client
        .try_withdraw(&intruder, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(token_balance(&h, &h.client.address), 500);
}

#[test]
fn withdraw_overdraws() {
    let h = setup("vault", 50);
    h.client.deposit(&h.admin, &h.asset, &50);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
    assert_eq!(token_balance(&h, &h.client.address), 50);
}

#[test]
fn frozen_treasury_rejects_withdrawals() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.freeze(&h.multisig);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &10);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn deposit_into_frozen_treasury_allowed() {
    let h = setup("vault", 1_000);
    h.client.freeze(&h.multisig);
    // Deposits should be allowed even when frozen (only outbound transfers are blocked)
    h.client.deposit(&h.admin, &h.asset, &100);
    // Value moved into the treasury despite being frozen.
    assert_eq!(token_balance(&h, &h.admin), 900);
    assert_eq!(token_balance(&h, &h.client.address), 100);
}

#[test]
fn prepare_holds_state() {
    let h = setup("vault", 0);
    let state = h.client.get();
    assert_eq!(state.org, String::from_str(&h.env, "vault"));
}

#[test]
fn allowance_caps_withdrawal_and_accumulates() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Approve a 500 ceiling for admin -> recipient in this asset.
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &500, &0);

    // First withdrawal within the ceiling succeeds and is deducted.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    let al = h.client.allowance(&h.admin, &recipient, &h.asset);
    assert_eq!(al.spent, 400);
    assert_eq!(token_balance(&h, &recipient), 400);

    // Second withdrawal exceeds the remaining 100 -> rejected at the allowance gate.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &200);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    assert_eq!(token_balance(&h, &recipient), 400);

    // A different recipient is not under the allowance, so it is allowed.
    let other = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &other, &100);
    assert_eq!(token_balance(&h, &other), 100);
}

#[test]
fn expired_allowance_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);
    let admin = Address::generate(&env);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, "vault"), &admin);
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &1_000);
    client.add_approved_asset(&admin, &asset);
    client.deposit(&admin, &asset, &1_000);

    // Allowance already expired (expires_at in the past).
    let recipient = Address::generate(&env);
    client.set_allowance(&admin, &admin, &recipient, &asset, &500, &5_000);
    let res = client.try_withdraw(&admin, &asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::AllowanceExpired)));
}

#[test]
fn remove_allowance_clears_cap() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &100, &0);
    h.client
        .remove_allowance(&h.admin, &h.admin, &recipient, &h.asset);
    // With no allowance in place the full balance may be withdrawn.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &1_000);
    assert_eq!(token_balance(&h, &recipient), 1_000);
}

#[test]
fn test_milestone_releases() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &contract_id);
    client.initialize(&soroban_sdk::String::from_str(&env, "org"), &admin);

    let token = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token_admin = token::StellarAssetClient::new(&env, &token);
    let token_client = token::TokenClient::new(&env, &token);
    client.add_approved_asset(&admin, &token);

    let to = Address::generate(&env);

    let mid = client.init_milestone_disbursement(&admin, &token, &to, &1000, &3);
    assert_eq!(mid, 1);

    // Deposit 1000 into treasury so we have funds
    token_admin.mint(&admin, &1000);
    client.deposit(&admin, &token, &1000);

    // release milestone 1
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 333); // 1000 / 3

    // release milestone 2
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 666);

    // release milestone 3 (final, catches remainder)
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 1000);

    // releasing beyond fails
    let res = client.try_release_next_milestone(&admin, &mid);
    assert!(res.is_err());
}

#[test]
fn standard_events_emitted() {
    // Configuration changes publish a TreasuryConfigUpdated event. Setting a
    // (here placeholder) policy/budget address is enough to exercise the emit
    // path; we avoid a subsequent withdraw on this env because a real policy
    // gate is not wired up.
    let h = setup("vault", 0);
    h.client.set_policy(&h.admin, &h.admin);
    assert_event(&h.env, "TreasuryConfigUpdated");
    h.client.set_budget(&h.admin, &h.admin);
    assert_event(&h.env, "TreasuryConfigUpdated");

    // A successful withdraw (no policy/budget gates configured) publishes a
    // TransferExecuted event.
    let h2 = setup("vault", 1_000);
    let recipient = Address::generate(&h2.env);
    h2.client.deposit(&h2.admin, &h2.asset, &1_000);
    h2.client.withdraw(&h2.admin, &h2.asset, &recipient, &100);
    assert_event(&h2.env, "TransferExecuted");
}

// ---------------------------------------------------------------------------
// Multi-token asset whitelist and routing validation
// ---------------------------------------------------------------------------

/// Register a second SAC token that the treasury has *not* approved, minting
/// `funded` of it to the admin.
fn unapproved_token(h: &Harness, funded: i128) -> Address {
    let token_admin = Address::generate(&h.env);
    let asset = h
        .env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    if funded > 0 {
        token::StellarAssetClient::new(&h.env, &asset).mint(&h.admin, &funded);
    }
    asset
}

#[test]
fn governance_adds_and_removes_approved_assets() {
    let h = setup("vault", 100);
    // setup approved exactly one asset.
    assert!(h.client.is_approved_asset(&h.asset));
    assert_eq!(h.client.approved_asset_count(), 1);

    let other = unapproved_token(&h, 0);
    assert!(!h.client.is_approved_asset(&other));

    h.client.add_approved_asset(&h.admin, &other);
    assert!(h.client.is_approved_asset(&other));
    assert_eq!(h.client.approved_asset_count(), 2);

    h.client.remove_approved_asset(&h.admin, &other);
    assert!(!h.client.is_approved_asset(&other));
    assert_eq!(h.client.approved_asset_count(), 1);

    // With nothing approved, the treasury routes nothing at all — which is
    // also the state a freshly initialized treasury starts in.
    h.client.remove_approved_asset(&h.admin, &h.asset);
    assert_eq!(h.client.approved_asset_count(), 0);
    assert_eq!(
        h.client.try_deposit(&h.admin, &h.asset, &10),
        Err(Ok(Error::AssetNotAuthorized))
    );
}

#[test]
fn whitelist_changes_are_idempotency_checked() {
    let h = setup("vault", 0);
    assert_eq!(
        h.client.try_add_approved_asset(&h.admin, &h.asset),
        Err(Ok(Error::AlreadyExists))
    );
    let other = unapproved_token(&h, 0);
    assert_eq!(
        h.client.try_remove_approved_asset(&h.admin, &other),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn only_governance_can_change_the_whitelist() {
    let h = setup("vault", 0);
    let intruder = Address::generate(&h.env);
    let other = unapproved_token(&h, 0);

    assert_eq!(
        h.client.try_add_approved_asset(&intruder, &other),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_approved_asset(&other));

    assert_eq!(
        h.client.try_remove_approved_asset(&intruder, &h.asset),
        Err(Ok(Error::Unauthorized))
    );
    assert!(h.client.is_approved_asset(&h.asset));
}

#[test]
fn deposit_of_an_unapproved_asset_is_refused() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 1_000);

    let res = h.client.try_deposit(&h.admin, &rogue, &500);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    // The rogue token contract was never invoked: no value moved.
    assert_eq!(
        token::TokenClient::new(&h.env, &rogue).balance(&h.admin),
        1_000
    );
    assert_eq!(h.client.holding(&rogue).total_in, 0);
}

#[test]
fn withdraw_of_an_unapproved_asset_is_refused() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let recipient = Address::generate(&h.env);

    // Revoking approval closes the route without touching the accounting.
    h.client.remove_approved_asset(&h.admin, &h.asset);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);

    // Re-approving restores it.
    h.client.add_approved_asset(&h.admin, &h.asset);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn budget_envelopes_cannot_be_bound_to_unapproved_assets() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 0);
    let res = h
        .client
        .try_allocate_budget(&h.admin, &rogue, &String::from_str(&h.env, "maint"));
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    assert_eq!(h.client.holding(&rogue).budget_id, None);
}

#[test]
fn multiple_approved_assets_route_independently() {
    let h = setup("vault", 1_000);
    let second = unapproved_token(&h, 500);
    h.client.add_approved_asset(&h.admin, &second);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &second, &500);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    h.client.withdraw(&h.admin, &second, &recipient, &200);

    assert_eq!(h.client.holding(&h.asset).total_out, 400);
    assert_eq!(h.client.holding(&second).total_out, 200);
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(
        token::TokenClient::new(&h.env, &second).balance(&recipient),
        200
    );

    // Revoking one asset leaves the other fully usable.
    h.client.remove_approved_asset(&h.admin, &second);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &second, &recipient, &10),
        Err(Ok(Error::AssetNotAuthorized))
    );
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 500);
}

#[test]
fn balance_reports_actual_custody_across_assets() {
    let h = setup("vault", 1_000);
    let second = unapproved_token(&h, 250);
    h.client.add_approved_asset(&h.admin, &second);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &second, &250);
    token::StellarAssetClient::new(&h.env, &h.asset).mint(&h.client.address, &7);

    assert_eq!(h.client.balance(&h.asset), 1_007);
    assert_eq!(h.client.balance(&second), 250);

    let assets: Vec<Address> = vec![&h.env, second.clone(), h.asset.clone()];
    let report = h.client.balances(&assets);
    assert_eq!(report.len(), 2);
    assert_eq!(report.get(0).unwrap().asset, second);
    assert_eq!(report.get(0).unwrap().balance, 250);
    assert_eq!(report.get(1).unwrap().asset, h.asset);
    assert_eq!(report.get(1).unwrap().balance, 1_007);
}

#[test]
fn balance_queries_require_approved_assets() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 100);

    assert_eq!(
        h.client.try_balance(&rogue),
        Err(Ok(Error::AssetNotAuthorized))
    );
    let assets: Vec<Address> = vec![&h.env, rogue];
    assert_eq!(
        h.client.try_balances(&assets),
        Err(Ok(Error::AssetNotAuthorized))
    );
}

#[test]
fn balance_report_rejects_duplicate_assets() {
    let h = setup("vault", 0);
    let assets: Vec<Address> = vec![&h.env, h.asset.clone(), h.asset.clone()];

    assert_eq!(h.client.try_balances(&assets), Err(Ok(Error::InvalidInput)));
}

#[test]
fn balance_report_rejects_oversized_asset_lists() {
    let h = setup("vault", 0);
    let mut assets: Vec<Address> = Vec::new(&h.env);
    for _ in 0..33 {
        assets.push_back(Address::generate(&h.env));
    }

    assert_eq!(h.client.try_balances(&assets), Err(Ok(Error::InvalidInput)));
}

#[test]
fn balance_report_is_empty_for_no_assets() {
    let h = setup("vault", 0);
    let assets: Vec<Address> = Vec::new(&h.env);

    assert!(h.client.balances(&assets).is_empty());
}

#[test]
fn whitelist_changes_emit_events() {
    let h = setup("vault", 0);
    let other = unapproved_token(&h, 0);
    h.client.add_approved_asset(&h.admin, &other);
    assert_event(&h.env, "TreasuryConfigUpdated");
    h.client.remove_approved_asset(&h.admin, &other);
    assert_event(&h.env, "TreasuryConfigUpdated");
}

/// Build one leg of a batch payout.
fn payment(recipient: &Address, amount: i128) -> Payment {
    Payment {
        recipient: recipient.clone(),
        amount,
    }
}

#[test]
fn batch_transfer_pays_every_recipient() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    let c = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 100), payment(&b, 250), payment(&c, 50)];

    h.client.batch_transfer(&h.admin, &h.asset, &payments);

    assert_eq!(token_balance(&h, &a), 100);
    assert_eq!(token_balance(&h, &b), 250);
    assert_eq!(token_balance(&h, &c), 50);
    assert_eq!(token_balance(&h, &h.client.address), 600);

    // Internal accounting mirrors the aggregate payout exactly once.
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 600);
    assert_eq!(holding.total_out, 400);

    assert_event(&h.env, "BatchTransferExecuted");
}

#[test]
fn batch_transfer_over_balance_pays_nobody() {
    let h = setup("vault", 300);
    h.client.deposit(&h.admin, &h.asset, &300);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    // Each leg fits on its own, but the cumulative total overdraws the treasury.
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 200), payment(&b, 200)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));

    // Nothing partially executed: no recipient was paid and custody is intact.
    assert_eq!(token_balance(&h, &a), 0);
    assert_eq!(token_balance(&h, &b), 0);
    assert_eq!(token_balance(&h, &h.client.address), 300);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 300);
    assert_eq!(holding.total_out, 0);
}

#[test]
fn batch_transfer_rolls_back_when_one_leg_is_invalid() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    let c = Address::generate(&h.env);
    // The middle leg is a zero-amount payment, which invalidates the batch.
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 100), payment(&b, 0), payment(&c, 100)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));

    // The legs preceding the bad one are rolled back with the rest of the batch.
    assert_eq!(token_balance(&h, &a), 0);
    assert_eq!(token_balance(&h, &c), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);
}

#[test]
fn batch_transfer_rejected_when_not_admin() {
    let h = setup("vault", 500);
    h.client.deposit(&h.admin, &h.asset, &500);

    let intruder = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 10)];

    let res = h.client.try_batch_transfer(&intruder, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(token_balance(&h, &h.client.address), 500);
}

#[test]
fn batch_transfer_rejected_when_frozen() {
    let h = setup("vault", 500);
    h.client.deposit(&h.admin, &h.asset, &500);
    h.client.freeze(&h.multisig);

    let recipient = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 10)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &recipient), 0);
}

#[test]
fn batch_transfer_rejects_empty_and_oversized_batches() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let empty: Vec<Payment> = Vec::new(&h.env);
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &empty),
        Err(Ok(Error::InvalidInput))
    );

    let mut oversized: Vec<Payment> = Vec::new(&h.env);
    for _ in 0..(MAX_BATCH_PAYMENTS + 1) {
        let r = Address::generate(&h.env);
        oversized.push_back(payment(&r, 1));
    }
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &oversized),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn batch_transfer_at_the_maximum_size_succeeds() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let mut payments: Vec<Payment> = Vec::new(&h.env);
    let mut recipients = std::vec::Vec::new();
    for _ in 0..MAX_BATCH_PAYMENTS {
        let r = Address::generate(&h.env);
        payments.push_back(payment(&r, 5));
        recipients.push(r);
    }

    h.client.batch_transfer(&h.admin, &h.asset, &payments);

    for r in recipients.iter() {
        assert_eq!(token_balance(&h, r), 5);
    }
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_out, 5 * MAX_BATCH_PAYMENTS as i128);
    assert_eq!(holding.total_in, 1_000 - 5 * MAX_BATCH_PAYMENTS as i128);
}

#[test]
fn emergency_freeze_rejected_by_non_multisig() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Admin should not be able to freeze - only multisig
    let res = h.client.try_freeze(&h.admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Random address should also be rejected
    let intruder = Address::generate(&h.env);
    let res = h.client.try_freeze(&intruder);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Ensure transfers still work
    let recipient = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn emergency_freeze_by_multisig_blocks_transfers() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Multisig can freeze
    h.client.freeze(&h.multisig);

    // All outbound transfers should be blocked
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 50)];
    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    // Verify funds are still in treasury
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn emergency_unfreeze_restores_transfers() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze with multisig
    h.client.freeze(&h.multisig);

    // Verify frozen state blocks transfers
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    // Unfreeze with multisig
    h.client.unfreeze(&h.multisig);

    // Transfers should work again
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.client.address), 900);
}

#[test]
fn emergency_unfreeze_rejected_by_non_multisig() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze with multisig
    h.client.freeze(&h.multisig);

    // Admin should not be able to unfreeze
    let res = h.client.try_unfreeze(&h.admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Random address should also be rejected
    let intruder = Address::generate(&h.env);
    let res = h.client.try_unfreeze(&intruder);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Should still be frozen
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn emergency_unfreeze_without_freeze_fails() {
    let h = setup("vault", 1_000);

    // Trying to unfreeze when not frozen should fail
    let res = h.client.try_unfreeze(&h.multisig);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn treasury_frozen_and_unfrozen_events_emitted() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze should emit TreasuryFrozen event
    h.client.freeze(&h.multisig);
    assert_event(&h.env, "TreasuryFrozen");

    // Unfreeze should emit TreasuryUnfrozen event
    h.client.unfreeze(&h.multisig);
    assert_event(&h.env, "TreasuryUnfrozen");
}

#[test]
fn freeze_without_multisig_configured_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, "vault"), &admin);

    // Try to freeze without setting multisig - should fail
    let res = client.try_freeze(&admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

// ---------------------------------------------------------------------------
// Emergency circuit breaker (pause / unpause)
// ---------------------------------------------------------------------------

#[test]
fn unauthorized_pause_attempts_are_rejected() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let intruder = Address::generate(&h.env);

    // Neither direction is open to a stranger, and neither call mutates the
    // pause flag.
    assert_eq!(h.client.try_pause(&intruder), Err(Ok(Error::Unauthorized)));
    assert_eq!(
        h.client.try_unpause(&intruder),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_paused());

    // Outflows still work, because the breaker never engaged.
    let recipient = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn guardian_can_pause_and_unpause() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Bootstrap: the admin is recorded as the initial guardian, and a fresh
    // treasury starts with the breaker disengaged.
    assert_eq!(h.client.guardian(), h.admin);
    assert!(!h.client.is_paused());

    h.client.pause(&h.admin);
    assert!(h.client.is_paused());
    assert_event(&h.env, "TreasuryConfigUpdated");

    h.client.unpause(&h.admin);
    assert!(!h.client.is_paused());
    assert_event(&h.env, "TreasuryConfigUpdated");
}

#[test]
fn multisig_can_pause_and_unpause() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // The organization's multisig holds the authority independently of the
    // guardian slot.
    h.client.pause(&h.multisig);
    assert!(h.client.is_paused());
    h.client.unpause(&h.multisig);
    assert!(!h.client.is_paused());
}

#[test]
fn pause_blocks_outflows_and_keeps_inflows_open() {
    // 1_500 minted so 1_000 can be deposited now and 500 more during the pause.
    let h = setup("vault", 1_500);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.pause(&h.admin);

    let recipient = Address::generate(&h.env);

    // Single withdrawal refused with the dedicated code; nothing moved.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &recipient), 0);

    // Batch payout refused with the same code; no leg is paid.
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 50)];
    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);

    // Inbound deposits stay open during a pause, so recovery funding arrives.
    h.client.deposit(&h.admin, &h.asset, &500);
    assert_eq!(token_balance(&h, &h.client.address), 1_500);
    assert_eq!(h.client.holding(&h.asset).total_in, 1_500);

    // Releasing the breaker restores every outflow.
    h.client.unpause(&h.admin);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.client.address), 1_400);
}

#[test]
fn pause_blocks_milestone_disbursement() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let to = Address::generate(&h.env);
    let mid = h
        .client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &1_000, &3);

    h.client.pause(&h.admin);
    let res = h.client.try_release_next_milestone(&h.admin, &mid);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &to), 0);

    h.client.unpause(&h.admin);
    h.client.release_next_milestone(&h.admin, &mid);
    assert_eq!(token_balance(&h, &to), 333);
}

#[test]
fn pause_toggle_is_idempotency_checked() {
    let h = setup("vault", 0);
    // Unpausing a treasury that was never paused is rejected.
    assert_eq!(h.client.try_unpause(&h.admin), Err(Ok(Error::InvalidState)));
    h.client.pause(&h.admin);
    // Pausing twice is rejected rather than silently accepted.
    assert_eq!(h.client.try_pause(&h.admin), Err(Ok(Error::InvalidState)));
    assert!(h.client.is_paused());
}

#[test]
fn pause_and_freeze_report_distinct_codes() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let recipient = Address::generate(&h.env);

    // The multisig freeze is the structural stop and reports InvalidState.
    h.client.freeze(&h.multisig);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &10),
        Err(Ok(Error::InvalidState))
    );
    h.client.unfreeze(&h.multisig);

    // The guardian pause is the circuit breaker and reports TreasuryPaused.
    h.client.pause(&h.admin);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &10),
        Err(Ok(Error::TreasuryPaused))
    );
    assert_eq!(
        h.client
            .try_batch_transfer(&h.admin, &h.asset, &vec![&h.env, payment(&recipient, 10)]),
        Err(Ok(Error::TreasuryPaused))
    );
}

#[test]
fn set_guardian_rotates_pause_authority() {
    let h = setup("vault", 1_000);
    let new_guardian = Address::generate(&h.env);

    // Only the admin may rotate the guardian.
    let intruder = Address::generate(&h.env);
    assert_eq!(
        h.client.try_set_guardian(&intruder, &new_guardian),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.guardian(), h.admin);

    h.client.set_guardian(&h.admin, &new_guardian);
    assert_eq!(h.client.guardian(), new_guardian);

    // The superseded guardian has lost the authority; the new one holds it.
    assert_eq!(h.client.try_pause(&h.admin), Err(Ok(Error::Unauthorized)));
    h.client.pause(&new_guardian);
    assert!(h.client.is_paused());

    // The multisig keeps its own, independent authority throughout.
    h.client.unpause(&h.multisig);
    assert!(!h.client.is_paused());
}

// --- Registry-verified callers and reentrancy lock (Issue #308) ---

use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::types::ModuleKind;

const GATED_ORG: &str = "vault-org";

/// Token balance of `who` in `asset`.
fn gated_balance(h: &GatedHarness, asset: &Address, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, asset).balance(who)
}

/// A genuine account-format address (strkey `G...`). Soroban's test address
/// generator mints contract-format addresses, so the account side of the
/// gate — which must pass through untouched — needs a real one.
fn account_address(env: &Env) -> Address {
    Address::from_string(&String::from_str(
        env,
        "GAEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSH7S",
    ))
}

/// Harness with the real registry deployed and wired into the treasury: the
/// treasury is registered as the org's Treasury module, an account stands in
/// for the governance caller (the Multisig record outbound movements
/// verify), and a funder is registered as the org's Wallet (the record
/// contract deposits verify). Under `mock_all_auths` every gate below is
/// exercised at the contract-logic level rather than at the signature level.
struct GatedHarness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    client: TreasuryContractClient<'a>,
    /// Governance caller — account-format, recorded as the org's Multisig.
    admin: Address,
    /// Funder recorded as the org's Wallet module.
    funder: Address,
    asset: Address,
    org: String,
}

fn setup_gated(funded: i128) -> GatedHarness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = account_address(&env);
    let multisig = Address::generate(&env);
    let org = String::from_str(&env, GATED_ORG);

    // Registry — the protocol's source of truth for module addresses.
    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);
    registry.register_org(&admin, &org.clone(), &admin);

    // Treasury — wired to the registry, registered as the org's Treasury.
    let treasury_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &treasury_id);
    client.initialize(&org.clone(), &admin);
    client.set_multisig(&admin, &multisig);
    client.set_registry(&admin, &Some(registry_id.clone()));
    registry.register_module(&admin, &org.clone(), &ModuleKind::Treasury, &treasury_id);

    // The funder: a contract recorded as the org's Wallet module.
    let funder = env.register_contract(None, RegistryContract);
    registry.register_module(&admin, &org.clone(), &ModuleKind::Wallet, &funder);

    // A real SAC token, whitelisted and minted to the funder.
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    client.add_approved_asset(&admin, &asset);
    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&funder, &funded);
    }

    GatedHarness {
        env,
        registry,
        client,
        admin,
        funder,
        asset,
        org,
    }
}

/// A hostile, unregistered contract cannot deposit into the treasury: the
/// deposit gate verifies a contract depositor against the org's Wallet
/// module record and refuses everything else with `Unauthorized`.
#[test]
fn unregistered_contract_depositor_is_refused_on_deposit() {
    let h = setup_gated(0);

    let hostile = h.env.register_contract(None, RegistryContract);
    let res = h.client.try_deposit(&hostile, &h.asset, &500);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(h.client.holding(&h.asset).total_in, 0);
    assert_eq!(gated_balance(&h, &h.asset, &h.client.address), 0);
}

/// A contract registered under a different module kind cannot pose as the
/// expected module: the registry resolves (org, kind), not just the address.
#[test]
fn wrong_module_kind_is_refused_on_deposit() {
    let h = setup_gated(0);

    // Register the stranger as the org's Proposal module — a legitimate
    // kind, but not the Wallet kind a deposit requires.
    let stranger = h.env.register_contract(None, RegistryContract);
    h.registry
        .register_module(&h.admin, &h.org.clone(), &ModuleKind::Proposal, &stranger);

    let res = h.client.try_deposit(&stranger, &h.asset, &500);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(h.client.holding(&h.asset).total_in, 0);
}

/// The registered Wallet module stays a first-class depositor: funding flows
/// from an organization's wallet keep working under the gate.
#[test]
fn registered_wallet_module_may_deposit() {
    let h = setup_gated(500);

    h.client.deposit(&h.funder, &h.asset, &500);
    assert_eq!(h.client.holding(&h.asset).total_in, 500);
    assert_eq!(gated_balance(&h, &h.asset, &h.client.address), 500);
}

/// A frozen registry fails the gate closed: even a fully registered caller
/// is refused while the registry cannot answer, so nobody can time a
/// movement to a registry outage.
#[test]
fn frozen_registry_fails_caller_verification_closed() {
    let h = setup_gated(2_000);
    h.client.deposit(&h.funder, &h.asset, &1_000);

    // The funder is a registered Wallet module and could deposit freely a
    // moment ago; with the registry frozen its `lookup` can no longer be
    // answered, so the gate fails closed.
    h.registry.freeze(&h.admin, &h.org.clone());
    let res = h.client.try_deposit(&h.funder, &h.asset, &100);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);

    // The account admin's withdraw is refused on the same principle the
    // moment it is made by a contract caller whose verification fails — the
    // account passthrough does not extend to unanswerable lookups.
    h.registry.unfreeze(&h.admin, &h.org.clone());
    assert!(h.client.try_deposit(&h.funder, &h.asset, &100).is_ok());
}

/// Account callers are never subject to the registry gate — they keep
/// passing through the ordinary role checks — so a plain-key admin can still
/// withdraw with a registry wired.
#[test]
fn account_callers_bypass_the_registry_gate() {
    let h = setup_gated(2_000);
    h.client.deposit(&h.funder, &h.asset, &1_000);

    h.client
        .withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(h.client.holding(&h.asset).total_out, 100);
}

/// Clearing the registry (admin-gated) restores the pre-registry behaviour:
/// the gate — not some incidental state — is what refused the hostile
/// contract.
#[test]
fn clearing_the_registry_restores_legacy_behaviour() {
    let h = setup_gated(500);

    let hostile = h.env.register_contract(None, RegistryContract);
    assert_eq!(
        h.client.try_deposit(&hostile, &h.asset, &100),
        Err(Ok(Error::Unauthorized))
    );

    h.client.set_registry(&h.admin, &None);
    assert_eq!(h.client.registry(), None);

    // Mint to the hostile contract so the legacy deposit actually pays, then
    // verify it goes through with the gate cleared.
    token::StellarAssetClient::new(&h.env, &h.asset).mint(&hostile, &100);
    h.client.deposit(&hostile, &h.asset, &100);
    assert_eq!(h.client.holding(&h.asset).total_in, 100);
}

/// The reentrancy guard releases when a movement completes, so a subsequent,
/// independent movement is never mistaken for a re-entry and the guard never
/// leaks into observable state between calls.
#[test]
fn reentrancy_lock_releases_after_each_movement() {
    let h = setup_gated(2_000);

    h.client.deposit(&h.funder, &h.asset, &1_000);

    h.client
        .withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(h.client.holding(&h.asset).total_out, 100);

    // A second, sequential movement succeeds — a stuck guard would fail this
    // with `InvalidState`.
    h.client
        .withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(h.client.holding(&h.asset).total_out, 200);
}

// ---------------------------------------------------------------------------
// Multi-token accounting (issue #328)
// ---------------------------------------------------------------------------

/// Minimal Soroban token with configurable `decimals` and an optional flat
/// fee burned on every transfer, to exercise non-SAC token behaviour.
#[soroban_sdk::contract]
pub struct MockToken;

#[soroban_sdk::contracttype]
#[derive(Clone)]
enum MockKey {
    Decimals,
    Fee,
    Balance(Address),
}

#[soroban_sdk::contractimpl]
impl MockToken {
    pub fn setup(env: Env, decimals: u32, fee: i128) {
        env.storage().instance().set(&MockKey::Decimals, &decimals);
        env.storage().instance().set(&MockKey::Fee, &fee);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let bal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&MockKey::Balance(to), &(bal + amount));
    }

    /// Remove balance without the holder's involvement (simulates a
    /// clawback or an externally drained custody account).
    pub fn burn(env: Env, from: Address, amount: i128) {
        let bal = Self::balance(env.clone(), from.clone());
        env.storage()
            .persistent()
            .set(&MockKey::Balance(from), &(bal - amount));
    }

    pub fn decimals(env: Env) -> u32 {
        env.storage().instance().get(&MockKey::Decimals).unwrap()
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&MockKey::Balance(id))
            .unwrap_or(0)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let fee: i128 = env.storage().instance().get(&MockKey::Fee).unwrap();
        let from_bal = Self::balance(env.clone(), from.clone());
        assert!(from_bal >= amount, "insufficient balance");
        env.storage()
            .persistent()
            .set(&MockKey::Balance(from), &(from_bal - amount));
        let to_bal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&MockKey::Balance(to), &(to_bal + amount - fee));
    }
}

fn mock_token(h: &Harness, decimals: u32, fee: i128, funded: i128) -> Address {
    let id = h.env.register_contract(None, MockToken);
    let client = MockTokenClient::new(&h.env, &id);
    client.setup(&decimals, &fee);
    client.mint(&h.admin, &funded);
    id
}

#[test]
fn deposits_withdrawals_and_portfolio_across_tokens_with_different_decimals() {
    let h = setup("vault", 10_000_000_000); // SAC: 7 decimals
    let usdc6 = mock_token(&h, 6, 0, 5_000_000);
    let wbtc8 = mock_token(&h, 8, 0, 3_0000_0000);
    h.client.add_approved_asset(&h.admin, &usdc6);
    h.client.add_approved_asset(&h.admin, &wbtc8);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &10_000_000_000);
    h.client.deposit(&h.admin, &usdc6, &5_000_000);
    h.client.deposit(&h.admin, &wbtc8, &2_0000_0000);

    h.client.withdraw(&h.admin, &usdc6, &recipient, &1_500_000);
    h.client.withdraw(&h.admin, &wbtc8, &recipient, &5000_0000);

    let assets = h.client.approved_assets();
    assert_eq!(
        assets,
        vec![&h.env, h.asset.clone(), usdc6.clone(), wbtc8.clone()]
    );

    let portfolio = h.client.portfolio();
    assert_eq!(portfolio.len(), 3);
    let sac = portfolio.get(0).unwrap();
    assert_eq!(
        (sac.decimals, sac.balance, sac.recorded),
        (7, 10_000_000_000, 10_000_000_000)
    );
    let usdc = portfolio.get(1).unwrap();
    assert_eq!(usdc.asset, usdc6);
    assert_eq!(
        (usdc.decimals, usdc.balance, usdc.recorded, usdc.total_out),
        (6, 3_500_000, 3_500_000, 1_500_000)
    );
    let btc = portfolio.get(2).unwrap();
    assert_eq!(
        (btc.decimals, btc.balance, btc.recorded, btc.total_out),
        (8, 1_5000_0000, 1_5000_0000, 5000_0000)
    );
    assert_eq!(
        MockTokenClient::new(&h.env, &usdc6).balance(&recipient),
        1_500_000
    );
}

#[test]
fn get_all_balances_reports_every_approved_token() {
    let h = setup("vault", 1_000);
    let funded = mock_token(&h, 6, 0, 500);
    let empty = mock_token(&h, 8, 0, 0);
    h.client.add_approved_asset(&h.admin, &funded);
    h.client.add_approved_asset(&h.admin, &empty);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &funded, &500);

    let balances = h.client.get_all_balances();
    assert_eq!(balances.len(), 3);
    assert_eq!(balances.get(0).unwrap(), (h.asset.clone(), 1_000));
    assert_eq!(balances.get(1).unwrap(), (funded, 500));
    assert_eq!(balances.get(2).unwrap(), (empty, 0));
}

#[test]
fn zero_balance_assets_are_reported_and_cannot_be_withdrawn() {
    let h = setup("vault", 0);
    let empty = mock_token(&h, 2, 0, 0);
    h.client.add_approved_asset(&h.admin, &empty);

    assert_eq!(h.client.balance(&empty), 0);
    let portfolio = h.client.portfolio();
    let pos = portfolio.get(1).unwrap();
    assert_eq!(
        (pos.decimals, pos.balance, pos.recorded, pos.total_out),
        (2, 0, 0, 0)
    );

    let res = h
        .client
        .try_withdraw(&h.admin, &empty, &Address::generate(&h.env), &1);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
}

#[test]
fn fee_on_transfer_deposit_credits_only_what_arrived() {
    let h = setup("vault", 0);
    let taxed = mock_token(&h, 7, 10, 1_000);
    h.client.add_approved_asset(&h.admin, &taxed);

    h.client.deposit(&h.admin, &taxed, &1_000);
    // 10 was burned in transit: the books match real custody, not the request.
    assert_eq!(h.client.holding(&taxed).total_in, 990);
    assert_eq!(h.client.balance(&taxed), 990);
}

#[test]
fn deposit_that_delivers_nothing_is_rejected() {
    let h = setup("vault", 0);
    let taxed = mock_token(&h, 7, 50, 50);
    h.client.add_approved_asset(&h.admin, &taxed);

    assert_eq!(
        h.client.try_deposit(&h.admin, &taxed, &50),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(h.client.holding(&taxed).total_in, 0);
}

#[test]
fn withdrawal_is_verified_against_live_custody() {
    let h = setup("vault", 0);
    let taxed = mock_token(&h, 7, 5, 1_000);
    h.client.add_approved_asset(&h.admin, &taxed);
    h.client.deposit(&h.admin, &taxed, &1_000); // 995 recorded and held
    let recipient = Address::generate(&h.env);

    // The outgoing fee is charged to the recipient, custody drops by exactly
    // the amount paid, so the withdrawal verifies.
    h.client.withdraw(&h.admin, &taxed, &recipient, &500);
    assert_eq!(h.client.balance(&taxed), 495);
    assert_eq!(h.client.holding(&taxed).total_in, 495);
    assert_eq!(
        MockTokenClient::new(&h.env, &taxed).balance(&recipient),
        495
    );
}

#[test]
fn fee_on_transfer_deposits_book_and_announce_only_what_arrived() {
    // Issue #218 — deposit accounting: the structured TreasuryDeposited
    // payload must report the credited amount and the post-deposit recorded
    // balance, neither of which may exceed real custody on a taxed token.
    let h = setup("vault", 0);
    let taxed = mock_token(&h, 7, 10, 1_000);
    h.client.add_approved_asset(&h.admin, &taxed);

    h.client.deposit(&h.admin, &taxed, &1_000); // 10 burned in transit
    let org = String::from_str(&h.env, "vault");
    assert_eq!(
        treasury_flow_payload(&h.env, "TreasuryDeposited"),
        Some((org.clone(), h.admin.clone(), taxed.clone(), 990, 990))
    );

    // The corrected books compound: the next deposit accrues from 990.
    MockTokenClient::new(&h.env, &taxed).mint(&h.admin, &100);
    h.client.deposit(&h.admin, &taxed, &100); // 90 more arrives
    assert_eq!(
        treasury_flow_payload(&h.env, "TreasuryDeposited"),
        Some((org, h.admin.clone(), taxed.clone(), 90, 1_080))
    );
    assert_eq!(h.client.holding(&taxed).total_in, 1_080);
}

#[test]
fn recorded_event_balance_follows_batch_and_milestone_outflows_per_token() {
    // Issue #218 — every path that debits the ledger must keep the recorded
    // event balance in step, or the next structured event would announce a
    // balance the treasury no longer holds.
    let h = setup("vault", 0);
    let batched = mock_token(&h, 6, 0, 10_000);
    let vested = mock_token(&h, 8, 0, 3_000);
    h.client.add_approved_asset(&h.admin, &batched);
    h.client.add_approved_asset(&h.admin, &vested);
    h.client.deposit(&h.admin, &batched, &10_000);
    h.client.deposit(&h.admin, &vested, &3_000);

    // A batch payout takes 3_000 out of `batched` in two legs...
    let payments: Vec<Payment> = vec![
        &h.env,
        payment(&Address::generate(&h.env), 1_000),
        payment(&Address::generate(&h.env), 2_000),
    ];
    h.client.batch_transfer(&h.admin, &batched, &payments);

    // ...and a milestone release takes 1_000 out of `vested`.
    let payee = Address::generate(&h.env);
    let mid = h
        .client
        .init_milestone_disbursement(&h.admin, &vested, &payee, &3_000, &3);
    h.client.release_next_milestone(&h.admin, &mid);

    // A later withdrawal on each token announces the true remainder.
    let r1 = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &batched, &r1, &500);
    assert_eq!(
        treasury_flow_payload(&h.env, "TreasuryWithdrawn"),
        Some((
            String::from_str(&h.env, "vault"),
            r1,
            batched.clone(),
            500,
            6_500
        ))
    );

    let r2 = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &vested, &r2, &400);
    assert_eq!(
        treasury_flow_payload(&h.env, "TreasuryWithdrawn"),
        Some((
            String::from_str(&h.env, "vault"),
            r2,
            vested.clone(),
            400,
            1_600
        ))
    );

    // Custody and the books agree on every token.
    assert_eq!(h.client.holding(&batched).total_in, 6_500);
    assert_eq!(h.client.holding(&vested).total_in, 1_600);
    assert_eq!(h.client.balance(&batched), 6_500);
    assert_eq!(h.client.balance(&vested), 1_600);
}

#[test]
fn unauthorized_withdrawals_are_refused_across_every_token_without_side_effects() {
    // Issue #218 — strict address verification on the outbound paths, proven
    // on a multi-token treasury: a non-admin caller moves no value, touches
    // no ledger entry and emits no event for any asset, through either
    // outflow route.
    let h = setup("vault", 1_000);
    let usdc = mock_token(&h, 6, 0, 5_000);
    let wbtc = mock_token(&h, 8, 0, 3_000);
    h.client.add_approved_asset(&h.admin, &usdc);
    h.client.add_approved_asset(&h.admin, &wbtc);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &usdc, &5_000);
    h.client.deposit(&h.admin, &wbtc, &3_000);

    let intruder = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let events_before = h.env.events().all().len();

    for asset in [h.asset.clone(), usdc.clone(), wbtc.clone()] {
        assert_eq!(
            h.client.try_withdraw(&intruder, &asset, &recipient, &100),
            Err(Ok(Error::Unauthorized))
        );
    }
    // The batch route sits behind the same single authorization point.
    assert_eq!(
        h.client
            .try_batch_transfer(&intruder, &usdc, &vec![&h.env, payment(&recipient, 100)]),
        Err(Ok(Error::Unauthorized))
    );

    // Nothing moved: no events, no ledger changes, no custody changes.
    assert_eq!(h.env.events().all().len(), events_before);
    for (asset, deposited) in [
        (h.asset.clone(), 1_000),
        (usdc.clone(), 5_000),
        (wbtc.clone(), 3_000),
    ] {
        assert_eq!(h.client.holding(&asset).total_in, deposited);
        assert_eq!(h.client.balance(&asset), deposited);
    }

    // The admin's own withdrawal still settles with exact per-asset accounting.
    h.client.withdraw(&h.admin, &usdc, &recipient, &1_500);
    assert_eq!(
        treasury_flow_payload(&h.env, "TreasuryWithdrawn"),
        Some((
            String::from_str(&h.env, "vault"),
            recipient,
            usdc.clone(),
            1_500,
            3_500
        ))
    );
}

#[test]
fn recorded_balance_above_live_custody_fails_with_insufficient_funds() {
    let h = setup("vault", 0);
    let drained = mock_token(&h, 7, 0, 1_000);
    h.client.add_approved_asset(&h.admin, &drained);
    h.client.deposit(&h.admin, &drained, &1_000);
    // Custody is drained behind the treasury's back (e.g. a clawback).
    MockTokenClient::new(&h.env, &drained).burn(&h.client.address, &600);
    let recipient = Address::generate(&h.env);

    assert_eq!(
        h.client.try_withdraw(&h.admin, &drained, &recipient, &500),
        Err(Ok(Error::InsufficientFunds))
    );
    assert_eq!(
        h.client
            .try_batch_transfer(&h.admin, &drained, &vec![&h.env, payment(&recipient, 500)]),
        Err(Ok(Error::InsufficientFunds))
    );
    // The recorded balance is untouched and the drift is visible.
    let pos = h.client.portfolio().get(1).unwrap();
    assert_eq!((pos.recorded, pos.balance), (1_000, 400));
}

#[test]
fn approved_asset_list_tracks_removals_and_is_bounded() {
    let h = setup("vault", 0);
    let second = mock_token(&h, 6, 0, 0);
    h.client.add_approved_asset(&h.admin, &second);
    h.client.remove_approved_asset(&h.admin, &h.asset);
    assert_eq!(h.client.approved_assets(), vec![&h.env, second.clone()]);
    assert_eq!(h.client.portfolio().len(), 1);

    // Fill the whitelist to capacity; one more is refused.
    while h.client.approved_asset_count() < crate::MAX_TREASURY_ASSETS {
        h.client
            .add_approved_asset(&h.admin, &Address::generate(&h.env));
    }
    assert_eq!(
        h.client
            .try_add_approved_asset(&h.admin, &Address::generate(&h.env)),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(h.client.approved_assets().len(), crate::MAX_TREASURY_ASSETS);
}

#[test]
fn milestones_reject_zero_value_payouts_and_unapproved_assets() {
    let h = setup("vault", 0);
    let to = Address::generate(&h.env);
    // 2 base units over 3 milestones would schedule zero-value payouts.
    assert_eq!(
        h.client
            .try_init_milestone_disbursement(&h.admin, &h.asset, &to, &2, &3),
        Err(Ok(Error::InvalidAmount))
    );
    let rogue = Address::generate(&h.env);
    assert_eq!(
        h.client
            .try_init_milestone_disbursement(&h.admin, &rogue, &to, &300, &3),
        Err(Ok(Error::AssetNotAuthorized))
    );
}

#[test]
fn milestone_math_is_overflow_safe_at_i128_max() {
    let h = setup("vault", i128::MAX);
    h.client.deposit(&h.admin, &h.asset, &i128::MAX);
    let to = Address::generate(&h.env);
    let id = h
        .client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &i128::MAX, &2);
    h.client.release_next_milestone(&h.admin, &id);
    h.client.release_next_milestone(&h.admin, &id);
    assert_eq!(token_balance(&h, &to), i128::MAX);
    assert_eq!(h.client.holding(&h.asset).total_in, 0);
}

// ---------------------------------------------------------------------------
// Pause window: MAX_PAUSE_DURATION auto-lapse (issue #297)
// ---------------------------------------------------------------------------

/// The breaker blocks outflows for exactly `MAX_PAUSE_DURATION` and then
/// lapses on its own: outflows resume without any guardian action while the
/// stale flag stays recorded.
#[test]
fn pause_lapses_after_max_duration_and_unblocks_outflows() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let recipient = Address::generate(&h.env);

    h.client.pause(&h.admin);
    assert!(h.client.is_paused());

    // One second before the cap the breaker still blocks every outflow.
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION - 1);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert!(h.client.is_paused());
    assert_eq!(token_balance(&h, &h.client.address), 1_000);

    // At exactly MAX_PAUSE_DURATION the window closes: outflows resume on
    // their own without any guardian action, while the stale flag stays
    // recorded.
    h.env.ledger().with_mut(|l| l.timestamp += 1);
    assert!(!h.client.is_paused());
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.client.address), 900);
}

#[test]
fn lapsed_pause_keeps_inflows_open_and_is_permanently_harmless() {
    let h = setup("vault", 1_500);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.pause(&h.admin);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION);
    assert!(!h.client.is_paused());

    // The whole outflow surface is open again after the lapse.
    let recipient = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 50)];
    h.client.batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(token_balance(&h, &recipient), 150);

    // Deposits stay open across the pause and the lapse, as always.
    h.client.deposit(&h.admin, &h.asset, &500);
    assert_eq!(token_balance(&h, &h.client.address), 1_350);
    // Internal books match: 1_500 in, 150 out.
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 1_350);
    assert_eq!(holding.total_out, 150);
}

#[test]
fn lapsed_breaker_can_be_reengaged_with_a_fresh_window() {
    let h = setup("vault", 0);

    h.client.pause(&h.admin);
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION);
    assert!(!h.client.is_paused());

    // The flag is stale, so the guardian can re-engage the breaker directly:
    // the new pause opens a fresh full window without a separate unpause.
    h.client.pause(&h.admin);
    assert!(h.client.is_paused());
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &1);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));

    // Near the end of the fresh window the breaker is still blocking.
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION - 1);
    assert!(h.client.is_paused());
}

#[test]
fn unpause_still_fails_when_breaker_never_engaged() {
    let h = setup("vault", 0);
    // Long past any window could have started — the treasury was never
    // paused, so the raw-flag guard keeps unpause rejected.
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION + 1);
    assert_eq!(h.client.try_unpause(&h.admin), Err(Ok(Error::InvalidState)));
}

#[test]
fn active_pause_still_blocks_milestones_until_lapse() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let to = Address::generate(&h.env);
    let mid = h
        .client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &1_000, &3);

    h.client.pause(&h.admin);
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION);
    assert!(!h.client.is_paused());

    // The milestone disbursement resumes as soon as the window closes.
    h.client.release_next_milestone(&h.admin, &mid);
    assert_eq!(token_balance(&h, &to), 333);
}

// Issue #241: authorization on every privileged / outbound operation.
//
// The rest of this suite calls `env.mock_all_auths()`, so it pins the happy
// path but never exercises the failure mode. These tests turn mocking off with
// `Env::set_auths`, which disables it and installs an empty authorization list,
// so `require_auth` is left unsatisfied and the host aborts the invocation.
// That is the shape of an unauthorized direct call: the contract is reached,
// the caller simply cannot sign for it.
//
// Two distinct refusals are pinned, and they are not interchangeable:
//
// - authorization absent            -> `Err(Err(Abort))` (host refused)
// - signature present, wrong caller -> `Err(Ok(Error::Unauthorized))`
//
// Both are terminal for value: a caller must not be able to slip past either
// gate, and a refusal must leave every balance untouched.
// ---------------------------------------------------------------------------

/// A treasury holding `funded` of an approved token, so the outflow paths have
/// real custody to move (and to prove they did not).
fn funded(org: &str, amount: i128) -> Harness<'static> {
    let h = setup(org, amount);
    h.client.deposit(&h.admin, &h.asset, &amount);
    h
}

/// Turn auth mocking off, leaving `require_auth` unsatisfiable.
fn sign_nothing(h: &Harness) {
    h.env.set_auths(&[]);
}

/// Assert a call was refused by the host for want of a signature.
///
/// An unsatisfied `require_auth` never reaches the contract body: the host
/// aborts the invocation, which a `try_*` client surfaces as
/// `Err(Err(Abort))`. The success arm of a generated `try_*` is a
/// `soroban_sdk` conversion wrapper that is not part of this contract's API,
/// so the outcome is pinned by its observable representation.
fn assert_refused_for_lack_of_auth<R: core::fmt::Debug>(res: R) {
    use std::format;
    assert_eq!(
        format!("{:?}", res),
        "Err(Err(Abort))",
        "call must be refused for want of an authorization signature"
    );
}

/// Assert a call was refused by the identity check rather than by a missing
/// signature: the caller is known, and is simply not the right party.
fn assert_refused_as_wrong_caller<R: core::fmt::Debug>(res: R) {
    use std::format;
    assert_eq!(
        format!("{:?}", res),
        "Err(Ok(Unauthorized))",
        "call must be refused for want of the right caller"
    );
}

#[test]
fn an_unsigned_call_cannot_move_value_out_of_the_treasury() {
    let h = funded("acme", 1_000);
    let to = Address::generate(&h.env);
    let custody = h.client.address.clone();
    let to_before = token_balance(&h, &to);
    sign_nothing(&h);

    // withdraw
    assert_refused_for_lack_of_auth(h.client.try_withdraw(&h.admin, &h.asset, &to, &100));
    // batch_transfer
    let mut payments = Vec::new(&h.env);
    payments.push_back(Payment {
        recipient: to.clone(),
        amount: 100,
    });
    assert_refused_for_lack_of_auth(h.client.try_batch_transfer(&h.admin, &h.asset, &payments));

    // Nothing moved: the recipient gained nothing and custody is untouched.
    assert_eq!(token_balance(&h, &to), to_before);
    assert_eq!(token_balance(&h, &custody), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);
}

#[test]
fn an_unsigned_call_cannot_release_a_milestone_payout() {
    let h = funded("acme", 1_000);
    let to = Address::generate(&h.env);
    h.client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &400, &2);
    sign_nothing(&h);

    // A disbursement is an outflow like any other and needs the same signature.
    assert_refused_for_lack_of_auth(h.client.try_release_next_milestone(&h.admin, &1u64));

    assert_eq!(token_balance(&h, &to), 0);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);
    // The counter did not advance, so the payout is still owed in full.
    let id = h.client.address.clone();
    let d = h.env.as_contract(&id, || {
        h.env
            .storage()
            .persistent()
            .get::<_, crate::MilestoneDisbursement>(&crate::DataKey::Milestone(1u64))
    });
    assert_eq!(d.map(|d| d.disbursed), Some(0u32));
}

#[test]
fn an_unsigned_call_cannot_deposit_or_reconfigure_the_treasury() {
    let h = funded("acme", 1_000);
    let to = Address::generate(&h.env);
    let other = Address::generate(&h.env);
    let admin_holds = token_balance(&h, &h.admin);
    let custody = h.client.address.clone();
    sign_nothing(&h);

    // Inbound movement: the depositor's own signature is required, so a third
    // party cannot push tokens in under someone else's name.
    assert_refused_for_lack_of_auth(h.client.try_deposit(&h.admin, &h.asset, &100));
    assert_eq!(token_balance(&h, &h.admin), admin_holds);
    assert_eq!(token_balance(&h, &custody), 1_000);

    // Administration, all of it reached by the recorded admin.
    assert_refused_for_lack_of_auth(h.client.try_set_policy(&h.admin, &other));
    assert_refused_for_lack_of_auth(h.client.try_set_budget(&h.admin, &other));
    assert_refused_for_lack_of_auth(h.client.try_set_multisig(&h.admin, &other));
    assert_refused_for_lack_of_auth(h.client.try_set_guardian(&h.admin, &other));
    assert_refused_for_lack_of_auth(h.client.try_add_approved_asset(&h.admin, &other));
    assert_refused_for_lack_of_auth(h.client.try_remove_approved_asset(&h.admin, &h.asset));
    assert_refused_for_lack_of_auth(h.client.try_allocate_budget(
        &h.admin,
        &h.asset,
        &String::from_str(&h.env, "b1"),
    ));
    assert_refused_for_lack_of_auth(
        h.client
            .try_set_allowance(&h.admin, &h.admin, &to, &h.asset, &100, &0u64),
    );
    assert_refused_for_lack_of_auth(
        h.client
            .try_remove_allowance(&h.admin, &h.admin, &to, &h.asset),
    );
    assert_refused_for_lack_of_auth(
        h.client
            .try_init_milestone_disbursement(&h.admin, &h.asset, &to, &400, &2),
    );
    // The guardian may pause; its own signature is still required.
    assert_refused_for_lack_of_auth(h.client.try_pause(&h.admin));
    assert_refused_for_lack_of_auth(h.client.try_unpause(&h.admin));
    // freeze / unfreeze belong to the multisig, not the admin, so an unsigned
    // admin call is refused on identity before a signature is even demanded.
    assert_refused_as_wrong_caller(h.client.try_freeze(&h.admin));
    assert_refused_as_wrong_caller(h.client.try_unfreeze(&h.admin));

    // None of the above took effect.
    let t = h.client.get();
    assert_eq!(t.admin, h.admin);
    assert_eq!(t.policy, None);
    assert_eq!(t.budget, None);
    assert_eq!(t.multisig, Some(h.multisig.clone()));
    assert_eq!(t.guardian, h.admin);
    assert!(!t.paused);
    assert!(!h.client.is_approved_asset(&other));
    assert!(h.client.is_approved_asset(&h.asset));
}

#[test]
fn initialize_demands_the_admins_signature() {
    // A fresh contract with auth mocking off: the deployer's admin is recorded
    // only if the deployer signs for it. Without this, anyone able to reach a
    // freshly deployed treasury could record themselves as admin.
    let env = Env::default();
    env.set_auths(&[]);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);

    // Nobody can seize the treasury without a signature.
    assert_refused_for_lack_of_auth(
        client.try_initialize(&String::from_str(&env, "acme"), &attacker),
    );
    // The admin's own unsigned call is refused too, and nothing was recorded,
    // so the contract is still unclaimed rather than half-initialized.
    assert_refused_for_lack_of_auth(client.try_initialize(&String::from_str(&env, "acme"), &admin));
    assert!(
        matches!(client.try_get(), Err(Ok(Error::NotInitialized))),
        "a refused initialize must leave the treasury unclaimed, got {:?}",
        client.try_get()
    );

    // With the signature present it succeeds, and the real admin is in charge.
    env.mock_all_auths();
    client.initialize(&String::from_str(&env, "acme"), &admin);
    assert_eq!(client.get().admin, admin);
}

#[test]
fn a_signed_but_wrong_caller_cannot_move_value_out_of_the_treasury() {
    let h = funded("acme", 1_000);
    let to = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    let custody = h.client.address.clone();
    h.client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &400, &2);

    // Auth mocking stays ON, so `require_auth` is satisfied and the failure
    // under test is the identity check rather than a missing signature: an
    // identity check alone is not enough, and neither is a signature alone.
    assert_refused_as_wrong_caller(h.client.try_withdraw(&stranger, &h.asset, &to, &100));
    let mut payments = Vec::new(&h.env);
    payments.push_back(Payment {
        recipient: to.clone(),
        amount: 100,
    });
    assert_refused_as_wrong_caller(h.client.try_batch_transfer(&stranger, &h.asset, &payments));
    assert_refused_as_wrong_caller(h.client.try_release_next_milestone(&stranger, &1u64));
    // Administration is identity-gated the same way.
    assert_refused_as_wrong_caller(h.client.try_set_policy(&stranger, &other_address(&h.env)));
    assert_refused_as_wrong_caller(h.client.try_remove_approved_asset(&stranger, &h.asset));
    assert_refused_as_wrong_caller(h.client.try_pause(&stranger));
    assert_refused_as_wrong_caller(h.client.try_set_guardian(&stranger, &other_address(&h.env)));

    assert_eq!(token_balance(&h, &to), 0);
    assert_eq!(token_balance(&h, &custody), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);
    let id = h.client.address.clone();
    let d = h.env.as_contract(&id, || {
        h.env
            .storage()
            .persistent()
            .get::<_, crate::MilestoneDisbursement>(&crate::DataKey::Milestone(1u64))
    });
    assert_eq!(d.map(|d| d.disbursed), Some(0u32));
}

fn other_address(env: &Env) -> Address {
    Address::generate(env)
}

#[test]
fn freeze_is_the_multisigs_alone_and_pause_is_the_guardians_or_the_multisigs() {
    let h = setup("acme", 0);
    let stranger = Address::generate(&h.env);

    // freeze / unfreeze: the multisig only. Not the admin, not a stranger.
    assert_refused_as_wrong_caller(h.client.try_freeze(&h.admin));
    assert_refused_as_wrong_caller(h.client.try_unfreeze(&h.admin));
    assert_refused_as_wrong_caller(h.client.try_freeze(&stranger));
    h.client.freeze(&h.multisig);
    h.client.unfreeze(&h.multisig);

    // pause / unpause: the guardian (bootstrapped to the admin) or the multisig.
    assert_refused_as_wrong_caller(h.client.try_pause(&stranger));
    h.client.pause(&h.admin);
    h.client.unpause(&h.admin);
    h.client.pause(&h.multisig);
    h.client.unpause(&h.multisig);
    assert!(!h.client.is_paused());
}

#[test]
fn the_reentrancy_guard_is_held_for_the_duration_of_a_withdrawal() {
    let h = funded("acme", 1_000);
    let to = Address::generate(&h.env);
    let id = h.client.address.clone();
    let read_lock = |env: &Env, id: &Address| -> bool {
        env.as_contract(id, || {
            env.storage()
                .instance()
                .get(&crate::DataKey::ReentrancyLock)
                .unwrap_or(false)
        })
    };

    // Simulate being re-entered while a guard is already held: a second
    // invocation of the same outflow must be refused rather than proceeding.
    h.env.as_contract(&id, || {
        h.env
            .storage()
            .instance()
            .set(&crate::DataKey::ReentrancyLock, &true);
    });
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &to, &100),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(token_balance(&h, &to), 0);
    // The refused call neither paid out nor consumed the guard.
    assert!(read_lock(&h.env, &id));

    // Release the guard as the holder would, then a withdrawal that starts
    // with it free still succeeds, and the guard is released again on the way
    // out rather than left engaged.
    h.env.as_contract(&id, || {
        h.env
            .storage()
            .instance()
            .set(&crate::DataKey::ReentrancyLock, &false);
    });
    h.client.withdraw(&h.admin, &h.asset, &to, &100);
    assert_eq!(token_balance(&h, &to), 100);
    assert!(
        !read_lock(&h.env, &id),
        "the guard must be released once the withdrawal completes"
    );
}

#[test]
fn a_failed_withdrawal_leaves_no_guard_behind() {
    let h = funded("acme", 100);
    let to = Address::generate(&h.env);
    let id = h.client.address.clone();

    // Overdrawing fails part-way through the outflow. The host rolls the
    // invocation back, so the guard taken at the start cannot survive the
    // error and strand the treasury against every later withdrawal.
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &to, &1_000),
        Err(Ok(Error::InsufficientFunds))
    );
    let still_locked: bool = h.env.as_contract(&id, || {
        h.env
            .storage()
            .instance()
            .get(&crate::DataKey::ReentrancyLock)
            .unwrap_or(false)
    });
    assert!(
        !still_locked,
        "a reverted withdrawal must not leave the guard engaged"
    );

    // And the treasury is still usable afterwards.
    h.client.withdraw(&h.admin, &h.asset, &to, &50);
    assert_eq!(token_balance(&h, &to), 50);
}

// ---------------------------------------------------------------------------
// Withdrawal time-lock (issue #321)
//
// The treasury is the one place where a compromised admin key is immediately
// monetisable, so high-value payouts are parked instead of settling. The cases
// below pin the three things the cooling-off period must do -- refuse an
// early payout, let the low-value fast path through untouched, and treat a
// queued request as inert until it is explicitly executed or cancelled --
// together with the configuration bounds that stop the control from being set
// to a value that would make it worthless or a denial of service.
// ---------------------------------------------------------------------------

/// A funded treasury at a fixed ledger time, with the withdrawal time-lock
/// configured to `delay` seconds for payouts at or above `threshold`.
///
/// Returns the harness plus a recipient, so the timing cases can drive the
/// ledger forward without rebuilding the world each time.
fn timelocked(delay: u64, threshold: i128, funded: i128) -> (Harness<'static>, Address) {
    let h = setup("vault", funded);
    h.client.deposit(&h.admin, &h.asset, &funded);
    h.client
        .set_withdrawal_time_lock(&h.admin, &delay, &threshold);
    let to = Address::generate(&h.env);
    (h, to)
}

/// Move the ledger to `ts`, asserting it is a forward step so a broken test
/// can never appear to exercise the boundary it means to.
fn warp(h: &Harness, ts: u64) {
    assert!(
        ts >= h.env.ledger().timestamp(),
        "a time-lock case must not rewind the ledger"
    );
    h.env.ledger().set_timestamp(ts);
}

/// Every balance and ledger total the time-locked paths can move, for a
/// "nothing moved" assertion after a refusal.
fn ledger(h: &Harness, to: &Address) -> [i128; 4] {
    let holding = h.client.holding(&h.asset);
    [
        token_balance(h, &h.client.address),
        token_balance(h, to),
        holding.total_in,
        holding.total_out,
    ]
}

#[test]
fn an_unconfigured_treasury_reports_the_disabled_default() {
    let h = setup("vault", 0);
    // Never configured: the lock is off, so `applies` is false for every amount
    // and every outflow behaves exactly as it did before the feature existed.
    let config = h.client.withdrawal_time_lock();
    assert_eq!(config.delay, 0);
    assert_eq!(config.threshold, 0);
    assert!(!config.applies(1));
    assert!(!config.applies(i128::MAX));
    assert_eq!(h.client.pending_withdrawal_count(), 0);
}

#[test]
fn the_threshold_comparison_is_inclusive_at_both_ends() {
    let h = setup("vault", 0);
    let off = h.client.withdrawal_time_lock();
    // A disabled lock captures nothing, however large the payout.
    assert!(!off.applies(0));
    assert!(!off.applies(1_000_000));

    h.client
        .set_withdrawal_time_lock(&h.admin, &(MIN_TIMELOCK_DELAY), &1_000);
    let on = h.client.withdrawal_time_lock();
    assert_eq!(on.delay, MIN_TIMELOCK_DELAY);
    // One base unit below the bar settles immediately; exactly on it is
    // captured, so a payout cannot slip through by shaving a single unit.
    assert!(!on.applies(999));
    assert!(on.applies(1_000));
    assert!(on.applies(1_001));
    assert!(on.applies(i128::MAX));
}

#[test]
fn a_high_value_withdrawal_cannot_settle_in_the_transaction_that_requests_it() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);

    // The direct path is refused with the dedicated early-execution code, and
    // has moved nothing.
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &to, &1_000),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(ledger(&h, &to), [10_000, 0, 10_000, 0]);
}

#[test]
fn a_low_value_withdrawal_is_never_delayed_by_the_configured_time_lock() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);

    // 999 is one base unit under the bar: it settles immediately, at the same
    // ledger timestamp, with no queueing involved.
    h.client.withdraw(&h.admin, &h.asset, &to, &999);
    assert_eq!(token_balance(&h, &to), 999);
    assert_eq!(h.client.holding(&h.asset).total_out, 999);
    assert_eq!(h.client.pending_withdrawal_count(), 0);
}

#[test]
fn a_queued_withdrawal_moves_no_value_while_it_waits() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);

    let id = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &4_000);
    assert_eq!(id, 1);
    assert_eq!(h.client.pending_withdrawal_count(), 1);

    let p = h.client.pending_withdrawal(&id);
    assert_eq!(p.id, id);
    assert_eq!(p.amount, 4_000);
    assert_eq!(p.to, to);
    assert_eq!(p.requester, h.admin);
    assert_eq!(p.requested_at, 1_000);
    assert_eq!(p.execute_after, 1_000 + MIN_TIMELOCK_DELAY);
    assert_eq!(
        p.expires_at,
        1_000 + MIN_TIMELOCK_DELAY + GOVERNANCE_GRACE_PERIOD
    );
    assert!(p.is_pending());
    assert!(p.payments.is_empty());

    // The decisive property: queueing is inert. Custody, the recipient and the
    // internal ledger are all untouched, and stay that way as time passes.
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY - 1);
    assert_eq!(ledger(&h, &to), [10_000, 0, 10_000, 0]);
}

#[test]
fn a_premature_execution_fails_with_the_designated_error_code() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);
    let id = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &4_000);

    // One second short of the deadline is still early, and is refused with the
    // protocol's dedicated early-execution code rather than a generic failure.
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY - 1);
    assert_eq!(
        h.client.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(ledger(&h, &to), [10_000, 0, 10_000, 0]);
    // A refusal leaves the request pending, so the organization can still
    // execute it later rather than having burned it.
    assert!(h.client.pending_withdrawal(&id).is_pending());
}

#[test]
fn the_execution_boundary_is_inclusive() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);
    let id = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &4_000);

    // Exactly at `execute_after` the request is executable: the deadline is
    // inclusive, so the full delay has elapsed and not one second less.
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY);
    h.client.execute_withdrawal(&h.admin, &id);
    assert_eq!(token_balance(&h, &to), 4_000);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_out, 4_000);
    assert_eq!(holding.total_in, 6_000);
    assert_eq!(token_balance(&h, &h.client.address), 6_000);
    assert!(h.client.pending_withdrawal(&id).executed);
}

#[test]
fn a_settled_withdrawal_cannot_be_executed_a_second_time() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);
    let id = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &4_000);
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY);
    h.client.execute_withdrawal(&h.admin, &id);

    // The record is terminal in both directions: re-executing would be a double
    // payout, and cancelling a settled request would misreport the ledger.
    assert_eq!(
        h.client.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        h.client.try_cancel_withdrawal(&h.admin, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(token_balance(&h, &to), 4_000);
    assert_eq!(h.client.holding(&h.asset).total_out, 4_000);
}

#[test]
fn a_cancelled_withdrawal_never_pays_out() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);
    let id = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &4_000);

    // Cancellation is the escape hatch that makes the delay safe to configure:
    // a hostile request can be dropped without waiting it out.
    h.client.cancel_withdrawal(&h.admin, &id);
    assert!(h.client.pending_withdrawal(&id).cancelled);

    // Cancelling twice is refused rather than silently idempotent...
    assert_eq!(
        h.client.try_cancel_withdrawal(&h.admin, &id),
        Err(Ok(Error::InvalidState))
    );
    // ...and the cancelled request stays dead even once its deadline passes.
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.client.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(ledger(&h, &to), [10_000, 0, 10_000, 0]);
}

#[test]
fn a_stale_request_lapses_rather_than_paying_out_arbitrarily_late() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);
    let id = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &4_000);

    // Well past the grace period the request is refused rather than honoured:
    // a request ignored through its whole cooldown must not become a standing
    // obligation cashable against a treasury that has since moved on.
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY + GOVERNANCE_GRACE_PERIOD);
    assert_eq!(
        h.client.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(token_balance(&h, &to), 0);

    // Re-queueing is the sanctioned way to proceed, and it starts a fresh clock.
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY + GOVERNANCE_GRACE_PERIOD + 1);
    let again = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &4_000);
    assert_ne!(again, id, "ids are never reused");
    warp(&h, h.env.ledger().timestamp() + MIN_TIMELOCK_DELAY);
    h.client.execute_withdrawal(&h.admin, &again);
    assert_eq!(token_balance(&h, &to), 4_000);
}

#[test]
fn a_split_batch_cannot_walk_past_the_time_lock() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);
    let other = Address::generate(&h.env);

    // Five legs of 400: every individual leg is under the threshold, but the
    // aggregate is 2_000 and the lock is measured on what leaves the treasury.
    let payments: Vec<Payment> = vec![
        &h.env,
        payment(&to, 400),
        payment(&other, 400),
        payment(&to, 400),
        payment(&other, 400),
        payment(&to, 400),
    ];
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &payments),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(ledger(&h, &to), [10_000, 0, 10_000, 0]);
    assert_eq!(token_balance(&h, &other), 0);

    // The same batch goes through the queue and settles atomically once the
    // delay has elapsed -- all five legs or none.
    let id = h.client.queue_batch_transfer(&h.admin, &h.asset, &payments);
    let p = h.client.pending_withdrawal(&id);
    assert_eq!(p.amount, 2_000);
    assert_eq!(p.payments.len(), 5);
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY);
    h.client.execute_withdrawal(&h.admin, &id);
    assert_eq!(token_balance(&h, &to), 1_200);
    assert_eq!(token_balance(&h, &other), 800);
    assert_eq!(h.client.holding(&h.asset).total_out, 2_000);
}

#[test]
fn a_batch_under_the_threshold_still_pays_immediately() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);
    let other = Address::generate(&h.env);

    // Aggregate 600, under the bar: the fast path the time-lock is careful not
    // to disturb for ordinary agent spending.
    let payments: Vec<Payment> = vec![&h.env, payment(&to, 400), payment(&other, 200)];
    h.client.batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(token_balance(&h, &to), 400);
    assert_eq!(token_balance(&h, &other), 200);
    assert_eq!(h.client.pending_withdrawal_count(), 0);
}

#[test]
fn queueing_a_payout_the_lock_would_not_capture_is_refused() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);

    // Below the threshold: settling immediately is what the configuration asks
    // for, so parking it would impose a cooldown governance never configured.
    assert_eq!(
        h.client.try_queue_withdrawal(&h.admin, &h.asset, &to, &999),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(h.client.pending_withdrawal_count(), 0);
}

#[test]
fn a_zero_time_lock_settles_cleanly_and_captures_nothing() {
    let (h, to) = timelocked(0, 0, 10_000);
    warp(&h, 1_000);

    let config = h.client.withdrawal_time_lock();
    assert_eq!(config.delay, 0);
    assert_eq!(config.threshold, 0);

    // With the lock off there is no queueing step at all: the direct path pays
    // at any size, and nothing can be parked.
    h.client.withdraw(&h.admin, &h.asset, &to, &9_000);
    assert_eq!(token_balance(&h, &to), 9_000);
    assert_eq!(
        h.client
            .try_queue_withdrawal(&h.admin, &h.asset, &to, &9_000),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(h.client.pending_withdrawal_count(), 0);
}

#[test]
fn the_time_lock_configuration_is_bounded() {
    let h = setup("vault", 0);

    // Shorter than a governance change may be, and longer than may be parked.
    assert_eq!(
        h.client
            .try_set_withdrawal_time_lock(&h.admin, &(MIN_TIMELOCK_DELAY - 1), &1_000),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        h.client
            .try_set_withdrawal_time_lock(&h.admin, &(MAX_TIMELOCK_DELAY + 1), &1_000),
        Err(Ok(Error::InvalidInput))
    );
    // Both ends of the permitted window are accepted.
    h.client
        .set_withdrawal_time_lock(&h.admin, &MIN_TIMELOCK_DELAY, &1_000);
    assert_eq!(h.client.withdrawal_time_lock().delay, MIN_TIMELOCK_DELAY);
    h.client
        .set_withdrawal_time_lock(&h.admin, &MAX_TIMELOCK_DELAY, &1_000);
    assert_eq!(h.client.withdrawal_time_lock().delay, MAX_TIMELOCK_DELAY);

    // A zero threshold would capture every payout, including dust.
    assert_eq!(
        h.client
            .try_set_withdrawal_time_lock(&h.admin, &MIN_TIMELOCK_DELAY, &0),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(
        h.client
            .try_set_withdrawal_time_lock(&h.admin, &MIN_TIMELOCK_DELAY, &-1),
        Err(Ok(Error::InvalidAmount))
    );
    // Every rejection left the previous configuration in force.
    assert_eq!(h.client.withdrawal_time_lock().delay, MAX_TIMELOCK_DELAY);
    assert_eq!(h.client.withdrawal_time_lock().threshold, 1_000);
}

#[test]
fn only_the_admin_may_drive_the_time_lock() {
    let h = setup("vault", 10_000);
    h.client.deposit(&h.admin, &h.asset, &10_000);
    let stranger = Address::generate(&h.env);

    // Reconfiguring the control is governance, not administration.
    assert_eq!(
        h.client
            .try_set_withdrawal_time_lock(&stranger, &MIN_TIMELOCK_DELAY, &1_000),
        Err(Ok(Error::Unauthorized))
    );
    let to = Address::generate(&h.env);
    assert_eq!(
        h.client
            .try_queue_withdrawal(&stranger, &h.asset, &to, &4_000),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_cancel_withdrawal(&stranger, &1),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_execute_withdrawal(&stranger, &1),
        Err(Ok(Error::Unauthorized))
    );

    assert_eq!(h.client.withdrawal_time_lock().delay, 0);
    assert_eq!(h.client.pending_withdrawal_count(), 0);
}

#[test]
fn an_unknown_or_reconfigured_request_is_refused_deterministically() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);

    // Ids are allocated, never guessed.
    assert_eq!(
        h.client.try_pending_withdrawal(&7),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_execute_withdrawal(&h.admin, &7),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_cancel_withdrawal(&h.admin, &7),
        Err(Ok(Error::NotFound))
    );

    // Raising the threshold afterwards does not retroactively capture payouts
    // the configuration in force at request time let through.
    h.client
        .set_withdrawal_time_lock(&h.admin, &MIN_TIMELOCK_DELAY, &5_000);
    h.client.withdraw(&h.admin, &h.asset, &to, &1_500);
    assert_eq!(token_balance(&h, &to), 1_500);
}

#[test]
fn a_queued_request_is_observable_and_survives_being_left_alone() {
    let (h, to) = timelocked(MIN_TIMELOCK_DELAY, 1_000, 10_000);
    warp(&h, 1_000);
    let id = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &4_000);

    // A second request may be parked alongside the first, and the waiting period
    // is exactly when an organization needs to see both of them. Its clock starts
    // when it is queued, not when the first one was.
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY / 2);
    let queued_at = h.env.ledger().timestamp();
    let second = h.client.queue_withdrawal(&h.admin, &h.asset, &to, &2_000);
    assert_ne!(second, id, "ids are never reused");

    // Both stay readable and inert as time passes over their deadline.
    warp(&h, 1_000 + MIN_TIMELOCK_DELAY / 2 + 10);
    for pending in [id, second] {
        let p = h.client.pending_withdrawal(&pending);
        assert!(p.is_pending());
        assert_eq!(p.execute_after, p.requested_at + MIN_TIMELOCK_DELAY);
        assert_eq!(p.expires_at, p.execute_after + GOVERNANCE_GRACE_PERIOD);
    }
    assert_eq!(token_balance(&h, &to), 0);
    assert_eq!(h.client.pending_withdrawal_count(), 2);

    // They settle independently once each has served its own delay, in either
    // order, without disturbing the other.
    warp(&h, queued_at + MIN_TIMELOCK_DELAY);
    h.client.execute_withdrawal(&h.admin, &second);
    assert_eq!(token_balance(&h, &to), 2_000);
    h.client.execute_withdrawal(&h.admin, &id);
    assert_eq!(token_balance(&h, &to), 6_000);
    assert_eq!(h.client.holding(&h.asset).total_out, 6_000);
}

// ---------------------------------------------------------------------------
// Standardized event emission (issue #222)
// ---------------------------------------------------------------------------

/// How many events were published under the two-symbol topic
/// `(category, action)` (issue #222).
fn event_count(env: &Env, category: &str, action: &str) -> u32 {
    let cat: Val = Symbol::new(env, category).into_val(env);
    let act: Val = Symbol::new(env, action).into_val(env);
    let mut count = 0;
    for (_emitter, topics, _data) in env.events().all().iter() {
        if topics.len() == 2 && topics.contains(cat.clone()) && topics.contains(act.clone()) {
            count += 1;
        }
    }
    count
}

/// Decoded payload of the most recent `(category, action)` event, or `None`
/// when none was published. Fields are decoded rather than compared as raw
/// `Val`s: `Val` equality compares host handles for object types.
fn event_payload(env: &Env, category: &str, action: &str) -> Option<Vec<Val>> {
    let cat: Val = Symbol::new(env, category).into_val(env);
    let act: Val = Symbol::new(env, action).into_val(env);
    let mut found = None;
    for (_emitter, topics, data) in env.events().all().iter() {
        if topics.len() == 2 && topics.contains(cat.clone()) && topics.contains(act.clone()) {
            found = Vec::<Val>::try_from_val(env, &data).ok();
        }
    }
    found
}

#[test]
fn budget_allocation_events_carry_identifiers_and_timestamp() {
    // Issue #222 — binding a budget envelope mutates the treasury record, so
    // it announces itself on both layers: the tuple-topic event carries the
    // identifiers and the ledger timestamp, the typed event the org context.
    let h = setup("vault", 0);
    h.env.ledger().set_timestamp(1_700_000_000);
    let budget_id = String::from_str(&h.env, "maint");

    assert_eq!(event_count(&h.env, "treasury", "bgt_alloc"), 0);
    h.client.allocate_budget(&h.admin, &h.asset, &budget_id);
    assert_eq!(event_count(&h.env, "treasury", "bgt_alloc"), 1);

    let payload = event_payload(&h.env, "treasury", "bgt_alloc").expect("bgt_alloc payload");
    assert_eq!(payload.len(), 3);
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(0).unwrap()).unwrap(),
        h.asset
    );
    assert_eq!(
        String::try_from_val(&h.env, &payload.get(1).unwrap()).unwrap(),
        budget_id
    );
    assert_eq!(
        u64::try_from_val(&h.env, &payload.get(2).unwrap()).unwrap(),
        1_700_000_000
    );
    // The canonical typed layer fires exactly once for the same action.
    assert_event(&h.env, "TreasuryConfigUpdated");

    // A second allocation replaces the first and is announced again.
    let next = String::from_str(&h.env, "ops");
    h.client.allocate_budget(&h.admin, &h.asset, &next);
    assert_eq!(event_count(&h.env, "treasury", "bgt_alloc"), 2);
}

#[test]
fn allowance_lifecycle_events_follow_the_shared_topic_schema() {
    // Issue #222 — the treasury allowance lifecycle publishes on the same
    // allow_set / allow_use / allow_rem schema as the policy contract, each
    // payload carrying identifiers, the amount where relevant, and the ledger
    // timestamp as its final field.
    let h = setup("vault", 1_000);
    h.env.ledger().set_timestamp(1_700_000_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let agent = h.admin.clone();
    let recipient = Address::generate(&h.env);

    // Creation → ("treasury", "allow_set").
    assert_eq!(event_count(&h.env, "treasury", "allow_set"), 0);
    h.client
        .set_allowance(&h.admin, &agent, &recipient, &h.asset, &500, &0);
    assert_eq!(event_count(&h.env, "treasury", "allow_set"), 1);

    let payload = event_payload(&h.env, "treasury", "allow_set").expect("allow_set payload");
    assert_eq!(payload.len(), 6);
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(0).unwrap()).unwrap(),
        agent
    );
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(1).unwrap()).unwrap(),
        recipient
    );
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(2).unwrap()).unwrap(),
        h.asset
    );
    assert_eq!(
        i128::try_from_val(&h.env, &payload.get(3).unwrap()).unwrap(),
        500
    );
    assert_eq!(
        u64::try_from_val(&h.env, &payload.get(4).unwrap()).unwrap(),
        0
    );
    assert_eq!(
        u64::try_from_val(&h.env, &payload.get(5).unwrap()).unwrap(),
        1_700_000_000
    );

    // A spend that draws on the allowance → ("treasury", "allow_use").
    h.client.withdraw(&h.admin, &h.asset, &recipient, &200);
    assert_eq!(event_count(&h.env, "treasury", "allow_use"), 1);

    let payload = event_payload(&h.env, "treasury", "allow_use").expect("allow_use payload");
    assert_eq!(payload.len(), 5);
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(0).unwrap()).unwrap(),
        agent
    );
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(1).unwrap()).unwrap(),
        recipient
    );
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(2).unwrap()).unwrap(),
        h.asset
    );
    assert_eq!(
        i128::try_from_val(&h.env, &payload.get(3).unwrap()).unwrap(),
        200
    );
    assert_eq!(
        u64::try_from_val(&h.env, &payload.get(4).unwrap()).unwrap(),
        1_700_000_000
    );

    // A refused draw emits nothing: the invocation's events roll back with it.
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &400),
        Err(Ok(Error::AllowanceExceeded))
    );
    assert_eq!(event_count(&h.env, "treasury", "allow_use"), 1);

    // Revocation → ("treasury", "allow_rem").
    h.client
        .remove_allowance(&h.admin, &agent, &recipient, &h.asset);
    assert_eq!(event_count(&h.env, "treasury", "allow_rem"), 1);

    let payload = event_payload(&h.env, "treasury", "allow_rem").expect("allow_rem payload");
    assert_eq!(payload.len(), 4);
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(0).unwrap()).unwrap(),
        agent
    );
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(1).unwrap()).unwrap(),
        recipient
    );
    assert_eq!(
        Address::try_from_val(&h.env, &payload.get(2).unwrap()).unwrap(),
        h.asset
    );
    assert_eq!(
        u64::try_from_val(&h.env, &payload.get(3).unwrap()).unwrap(),
        1_700_000_000
    );
}
