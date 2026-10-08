use astroid_shared::errors::Error;
use astroid_shared::types::AssetAmount;
use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    vec, Address, BytesN, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

use crate::{
    PolicyContract, PolicyContractClient, PolicyDecision, PolicyDenialReason, RuleNode, RuleOp,
    RuleTree, TransactionPayload, MAX_POLICY_RULES,
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

/// Assert that no canonical `ContractEvent` with the given variant was
/// published during the test.
fn assert_no_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(
        !found,
        "expected no ContractEvent::{} to be emitted",
        variant
    );
}

fn setup<'a>(env: &Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "max_txn"),
        &BytesN::from_array(env, &[42; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
        &None,
    );
    client
}

#[test]
fn allows_spend_below_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &999_999,)
        .is_ok());
}

#[test]
fn denies_spend_above_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert!(r.is_err());
}

#[test]
fn allowlist_recipient_enforced() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);
    let asset = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(&env, &id);
    client.initialize();
    client.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &Some(allowed.clone()),
        &None,
        &0,
        &None,
    );

    // Allowed recipient passes
    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &allowed, &1,)
        .is_ok());

    // Other recipient denied
    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &blocked, &1,)
        .is_err());
}

#[test]
fn disable_denies_everything() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    p.set_enabled(&owner, &String::from_str(&env, "max_txn"), &false);
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &Address::generate(&env),
            &1,
        )
        .is_err());
}

#[test]
fn standard_policy_violation_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    // Amount above the configured max triggers a policy denial -> violation event.
    let _ = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert_event(&env, "PolicyViolation");
}

// --- Merchant blacklist tests ---

#[test]
fn merchant_blacklist_blocks_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked_merchant = Address::generate(&env);

    // Add merchant to blacklist
    p.add_merchant_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &blocked_merchant,
    );

    // Transfer to blocked merchant should fail
    let result = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &blocked_merchant,
        &100,
    );
    assert!(result.is_err());

    // Transfer to non-blocked merchant should succeed
    let safe_merchant = Address::generate(&env);
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &safe_merchant,
            &100,
        )
        .is_ok());
}

#[test]
fn merchant_blacklist_removal_allows_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let merchant = Address::generate(&env);

    // Add merchant to blacklist
    p.add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Verify blocked
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &merchant, &100,)
        .is_err());

    // Remove from blacklist
    p.remove_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Now should succeed
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &merchant, &100,)
        .is_ok());
}

#[test]
fn merchant_blacklist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    // Unauthorized user cannot add to blacklist
    let result =
        p.try_add_merchant_blacklist(&unauthorized, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blacklist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    // Add merchant to blacklist
    p.add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Adding again should fail
    let result =
        p.try_add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blacklist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    // Removing non-existent merchant should fail
    let result =
        p.try_remove_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blocked_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked_merchant = Address::generate(&env);

    p.add_merchant_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &blocked_merchant,
    );

    let _ = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &blocked_merchant,
        &100,
    );
    assert_event(&env, "PolicyViolation");
}

// --- Category blacklist tests ---

#[test]
fn category_blacklist_blocks_categories() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Blocked category should fail
    let result = p.try_check_category(
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());

    // Different category should succeed
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "groceries"),
        )
        .is_ok());

    // Empty category should succeed
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, ""),
        )
        .is_ok());
}

#[test]
fn category_blacklist_removal_allows_categories() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Verify blocked
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "gambling"),
        )
        .is_err());

    // Remove from blacklist
    p.remove_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Now should succeed
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "gambling"),
        )
        .is_ok());
}

#[test]
fn category_blacklist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);

    // Unauthorized user cannot add to blacklist
    let result = p.try_add_category_blacklist(
        &unauthorized,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Adding again should fail
    let result = p.try_add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Removing non-existent category should fail
    let result = p.try_remove_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_empty_category_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    // Adding empty category should fail
    let result = p.try_add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, ""),
    );
    assert!(result.is_err());
}

#[test]
fn category_restricted_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    let _ = p.try_check_category(
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert_event(&env, "PolicyViolation");
}

// --- Issue #37: Asset whitelist tests ---

#[test]
fn asset_whitelist_allows_whitelisted_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked = Address::generate(&env);
    let safe = Address::generate(&env);

    // Block the address
    p.add_to_blocklist(&owner, &String::from_str(&env, "max_txn"), &blocked);

    // Transfer to blocked address should fail
    let result = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &blocked, &100);
    assert!(result.is_err());

    // Transfer to non-blocked address should succeed
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &safe, &100,)
        .is_ok());
}

#[test]
fn blocklist_removal_allows_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Whitelist not enabled (default) — any asset should pass
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

#[test]
fn asset_whitelist_add_remove_roundtrip() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    p.set_asset_whitelist_enabled(&owner, &String::from_str(&env, "max_txn"), &true);
    p.add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    // Now remove it
    p.remove_asset_from_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    // validate_asset should fail for a removed asset when whitelist is enabled
    assert!(p
        .try_validate_asset(&String::from_str(&env, "max_txn"), &asset)
        .is_err());
}

#[test]
fn asset_whitelist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);
    let addr = Address::generate(&env);

    let result = p.try_add_to_blocklist(&unauthorized, &String::from_str(&env, "max_txn"), &addr);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    p.add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    let result = p.try_add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    let result =
        p.try_remove_asset_from_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_empty_default_passes_validate() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    // Whitelist disabled by default, validate_asset should pass
    assert!(p
        .try_validate_asset(&String::from_str(&env, "max_txn"), &asset)
        .is_ok());
}

#[test]
fn asset_whitelist_violation_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_asset_whitelist_enabled(&owner, &String::from_str(&env, "max_txn"), &true);

    let _ = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100);
    assert_event(&env, "PolicyViolation");
}

// --- Multi-token allowance tests ---

/// Register a fresh policy with unlimited policy bounds so only the allowance
/// gate is exercised.
fn allowance_setup<'a>(env: &'a Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "mt"),
        &BytesN::from_array(env, &[1; 32]),
        &0,
        &None,
        &None,
        &0,
        &None,
    );
    client
}

#[test]
fn allowance_allows_spend_below_limit() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    let allowed = p.get_allowance(&String::from_str(&env, "mt"), &asset);
    assert_eq!(allowed.limit, 1_000);

    // Within limit headroom: passes check and transfer gate.
    assert_eq!(
        p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &400),
        Ok(Ok(600))
    );
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &400)
        .is_ok());
}

#[test]
fn allowance_exact_boundary_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    // Spend exactly the full limit: allowed (headroom becomes 0).
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1_000)
        .is_ok());
    // update_allowance consumes exactly to the limit.
    assert!(p
        .try_update_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000)
        .is_ok());
}

#[test]
fn allowance_over_limit_rejected_with_exceeded() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);

    let over = p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &1_001);
    assert_eq!(over, Err(Ok(Error::AllowanceExceeded)));
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1_001),
        Err(Ok(Error::AllowanceExceeded))
    );
}

#[test]
fn allowance_cumulative_consumption_blocks_after_limit() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    // Consume 600 via update_allowance.
    assert!(p
        .try_update_allowance(&owner, &String::from_str(&env, "mt"), &asset, &600)
        .is_ok());
    // Only 400 headroom remains.
    assert_eq!(
        p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &400),
        Ok(Ok(0))
    );
    // 401 would exceed the cumulative limit.
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &401),
        Err(Ok(Error::AllowanceExceeded))
    );
    // A fresh 300 transfer still fits.
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &300)
        .is_ok());
}

#[test]
fn multi_token_allowances_are_independent_per_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let xlm = Address::generate(&env);
    let usdc = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &xlm, &100, &0);
    p.set_allowance(&owner, &String::from_str(&env, "mt"), &usdc, &10_000, &0);

    // USDC has room, XLM is capped at 100.
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &usdc, &recip, &5_000)
        .is_ok());
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &xlm, &recip, &101),
        Err(Ok(Error::AllowanceExceeded))
    );
    // An asset with no configured allowance is unrestricted.
    let eth = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &eth, &recip, &1_000_000)
        .is_ok());
}

#[test]
fn allowance_expires_at_past_blocks_spend() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Expires in the past => every spend refused, even below the limit, and the
    // refusal names the lapse rather than passing it off as a rule denial.
    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &500);
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1),
        Err(Ok(Error::AllowanceExpired))
    );
}

#[test]
fn allowance_unauthorized_set_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);

    let r = p.try_set_allowance(&stranger, &String::from_str(&env, "mt"), &asset, &100, &0);
    assert!(r.is_err());
}

#[test]
fn allowance_negative_limit_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);

    let r = p.try_set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &-1, &0);
    assert!(r.is_err());

    // Negative spend is always rejected.
    let c = p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &-5);
    assert!(c.is_err());
}

#[test]
fn allowance_remove_restores_unlimited() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &100, &0);
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &200),
        Err(Ok(Error::AllowanceExceeded))
    );

    p.remove_allowance(&owner, &String::from_str(&env, "mt"), &asset);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &200)
        .is_ok());
}

// --- Composite rule tests ---

fn composite_setup<'a>(env: &'a Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "cr"),
        &BytesN::from_array(env, &[99; 32]),
        &0,
        &None,
        &None,
        &0,
        &None,
    );
    client
}

/// Build a leaf RuleNode (no children).
fn leaf(op: RuleOp, env: &Env) -> RuleNode {
    RuleNode {
        op,
        value_i128: 0,
        value_address: Address::generate(env),
        children_start: 0,
        children_end: 0,
    }
}

/// Build a leaf RuleNode with an i128 value.
fn leaf_amount(op: RuleOp, amount: i128, env: &Env) -> RuleNode {
    RuleNode {
        op,
        value_i128: amount,
        value_address: Address::generate(env),
        children_start: 0,
        children_end: 0,
    }
}

/// Build a leaf RuleNode with an address value.
fn leaf_addr(op: RuleOp, addr: Address, _env: &Env) -> RuleNode {
    RuleNode {
        op,
        value_i128: 0,
        value_address: addr,
        children_start: 0,
        children_end: 0,
    }
}

/// Build a RuleTree with a single leaf node carrying an amount.
fn single_amount_tree(op: RuleOp, amount: i128, env: &Env) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(leaf_amount(op, amount, env));
    tree
}

/// Build a RuleTree with a single leaf node carrying an address.
fn single_addr_tree(op: RuleOp, addr: Address, env: &Env) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(leaf_addr(op, addr, env));
    tree
}

// --- Leaf rule: MaxAmount ---

#[test]
fn composite_max_amount_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 500, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &500)
        .is_ok());
}

#[test]
fn composite_max_amount_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 500, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &501),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- Leaf rule: AllowedRecipient ---

#[test]
fn composite_allowed_recipient_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);

    let tree = single_addr_tree(RuleOp::AllowedRecipient, allowed.clone(), &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &allowed, &100)
        .is_ok());
}

#[test]
fn composite_allowed_recipient_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);

    let tree = single_addr_tree(RuleOp::AllowedRecipient, allowed, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &blocked, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- Leaf rule: AllowedAsset ---

#[test]
fn composite_allowed_asset_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let recip = Address::generate(&env);

    let tree = single_addr_tree(RuleOp::AllowedAsset, asset.clone(), &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100)
        .is_ok());
}

#[test]
fn composite_allowed_asset_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed_asset = Address::generate(&env);
    let other_asset = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let recip = Address::generate(&env);

    let tree = single_addr_tree(RuleOp::AllowedAsset, allowed_asset, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &other_asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- AND combinator ---
// Tree layout for AND(a, b):
//   [0] RuleNode { op: And, children_start: 1, children_end: 2 }
//   [1] RuleNode { op: a }
//   [2] RuleNode { op: b }

#[test]
fn composite_and_all_pass() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 1000, &env));
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, recip.clone(), &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &500)
        .is_ok());
}

#[test]
fn composite_and_one_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 1000, &env));
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, allowed, &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount is fine but recipient is wrong
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &blocked, &500),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn composite_and_empty_children_rejected_at_registration() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    // AND node with children_start == children_end (empty)
    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 1,
    });
    assert_eq!(
        p.try_set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree),
        Err(Ok(Error::InvalidInput))
    );
}

// --- OR combinator ---
// Tree layout for OR(a, b):
//   [0] RuleNode { op: Or, children_start: 1, children_end: 2 }
//   [1] a
//   [2] b

#[test]
fn composite_or_first_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    tree.push_back(leaf_addr(
        RuleOp::AllowedRecipient,
        Address::generate(&env),
        &env,
    ));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount is within limit so first branch passes
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &50)
        .is_ok());
}

#[test]
fn composite_or_second_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, allowed.clone(), &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount exceeds limit but recipient matches
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &allowed, &500)
        .is_ok());
}

#[test]
fn composite_or_all_fail() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    tree.push_back(leaf_addr(
        RuleOp::AllowedRecipient,
        Address::generate(&env),
        &env,
    ));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount exceeds limit AND recipient is wrong
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &blocked, &500),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn composite_or_empty_children_rejected_at_registration() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 1,
    });
    assert_eq!(
        p.try_set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree),
        Err(Ok(Error::InvalidInput))
    );
}

// --- NOT combinator ---
// Tree layout for NOT(MaxAmount(100)):
//   [0] RuleNode { op: Not, children_start: 1, children_end: 2 }
//   [1] RuleNode { op: MaxAmount, value_i128: 100 }

#[test]
fn composite_not_inverts_pass_to_deny() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 2,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount 50 <= 100, inner rule passes => Not inverts => deny
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &50),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn composite_not_inverts_deny_to_pass() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 2,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Amount 150 > 100, inner rule fails => Not inverts => pass
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &150)
        .is_ok());
}

// --- Nested combinations ---
// Tree layout for OR( AND(MaxAmount(500), AllowedRecipient(allowed)), AllowedAsset(asset) ):
//   [0] RuleNode { op: Or, children_start: 1, children_end: 3 }
//   [1] RuleNode { op: And, children_start: 3, children_end: 5 }
//   [2] RuleNode { op: AllowedAsset, value_address: asset }
//   [3] RuleNode { op: MaxAmount, value_i128: 500 }
//   [4] RuleNode { op: AllowedRecipient, value_address: allowed }

#[test]
fn composite_nested_and_or() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    // [0] Root: OR with children 1..3
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    // [1] AND with children 3..5
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 3,
        children_end: 5,
    });
    // [2] AllowedAsset(asset)
    tree.push_back(leaf_addr(RuleOp::AllowedAsset, asset.clone(), &env));
    // [3] MaxAmount(500)
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 500, &env));
    // [4] AllowedRecipient(allowed)
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, allowed.clone(), &env));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Case 1: Wrong recipient but correct asset — OR passes via second branch
    let wrong_recip = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &wrong_recip, &1_000)
        .is_ok());

    // Case 2: Correct recipient and amount within limit — AND branch passes
    // (regardless of asset), so OR passes too.
    let other_asset = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &other_asset, &allowed, &300)
        .is_ok());

    // Case 3: Wrong recipient AND wrong asset — neither OR branch passes => deny
    assert_eq!(
        p.try_check_transfer(
            &String::from_str(&env, "cr"),
            &other_asset,
            &wrong_recip,
            &1_000
        ),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn composite_deeply_nested_not_of_and() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Rule: Not(And(MaxAmount(200), AllowedRecipient(recip)))
    // Denies when BOTH conditions hold; allows when either fails.
    let mut tree = soroban_sdk::Vec::new(&env);
    // [0] NOT with child at index 1
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 2,
    });
    // [1] AND with children 2..4
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 2,
        children_end: 4,
    });
    // [2] MaxAmount(200)
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 200, &env));
    // [3] AllowedRecipient(recip)
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, recip.clone(), &env));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Both hold: amount 100 <= 200 AND recipient matches => And passes => Not denies
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );

    // Amount exceeds: And fails => Not passes
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &300)
        .is_ok());
}

// --- Recursion depth limit ---
// Build a chain of 15 nested Not nodes (exceeds MAX_RULE_DEPTH = 10)
// Layout: [0] Not -> [1] Not -> [2] Not -> ... -> [15] MaxAmount(i128::MAX)

#[test]
fn composite_depth_exceeded() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    for i in 0..15u32 {
        tree.push_back(RuleNode {
            op: RuleOp::Not,
            value_i128: 0,
            value_address: Address::generate(&env),
            children_start: i + 1,
            children_end: i + 2,
        });
    }
    // [15] MaxAmount leaf
    tree.push_back(RuleNode {
        op: RuleOp::MaxAmount,
        value_i128: i128::MAX,
        value_address: Address::generate(&env),
        children_start: 0,
        children_end: 0,
    });

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::InvalidInput))
    );
}

// --- Clear / management ---

#[test]
fn composite_clear_rule_restores_permissive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 10, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Denied by composite rule
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );

    // Clear the rule
    p.clear_composite_rule(&owner, &String::from_str(&env, "cr"));

    // Now passes (no composite rule => permissive)
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100)
        .is_ok());
}

#[test]
fn composite_get_rule_roundtrip() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    // Build a two-node OR tree
    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 500, &env));
    tree.push_back(leaf_addr(
        RuleOp::AllowedRecipient,
        Address::generate(&env),
        &env,
    ));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    let retrieved = p.get_composite_rule(&String::from_str(&env, "cr"));
    assert_eq!(retrieved.len(), tree.len());
}

#[test]
fn composite_get_nonexistent_rule_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    let result = p.try_get_composite_rule(&String::from_str(&env, "cr"));
    assert_eq!(result, Err(Ok(Error::NotFound)));
}

#[test]
fn composite_clear_nonexistent_rule_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    let result = p.try_clear_composite_rule(&owner, &String::from_str(&env, "cr"));
    assert!(result.is_err());
}

#[test]
fn composite_set_rule_unauthorized_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    let tree = single_amount_tree(RuleOp::MaxAmount, 100, &env);
    let result = p.try_set_composite_rule(&unauthorized, &String::from_str(&env, "cr"), &tree);
    assert!(result.is_err());
}

#[test]
fn composite_set_empty_tree_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);

    let tree = soroban_sdk::Vec::new(&env);
    let result = p.try_set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);
    assert!(result.is_err());
}

// --- Rule evaluation event emitted ---

#[test]
fn composite_rule_denied_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 10, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    let _ = p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100);
    assert_event(&env, "PolicyViolation");
}

// --- Evaluate composite rule view function ---

#[test]
fn composite_evaluate_view_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 500, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    let payload = TransactionPayload {
        asset: asset.clone(),
        recipient: recip.clone(),
        amount: 200,
    };
    assert_eq!(
        p.try_evaluate_composite_rule(&String::from_str(&env, "cr"), &payload),
        Ok(Ok(true))
    );
}

#[test]
fn composite_evaluate_view_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let tree = single_amount_tree(RuleOp::MaxAmount, 100, &env);
    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    let payload = TransactionPayload {
        asset: asset.clone(),
        recipient: recip.clone(),
        amount: 200,
    };
    assert_eq!(
        p.try_evaluate_composite_rule(&String::from_str(&env, "cr"), &payload),
        Ok(Ok(false))
    );
}

#[test]
fn composite_evaluate_no_rule_permissive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // No rule set => permissive (true)
    let payload = TransactionPayload {
        asset,
        recipient: recip,
        amount: 999_999,
    };
    assert_eq!(
        p.try_evaluate_composite_rule(&String::from_str(&env, "cr"), &payload),
        Ok(Ok(true))
    );
}

// --- Realistic scenario: max amount OR specific vendor whitelist ---

#[test]
fn composite_realistic_max_amount_or_vendor_whitelist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let vendor_a = Address::generate(&env);
    let vendor_b = Address::generate(&env);
    let random = Address::generate(&env);

    // Rule: OR(MaxAmount(100), AllowedRecipient(vendor_a))
    // i.e. small transfers allowed to anyone, or large transfers only to vendor_a
    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 100, &env));
    tree.push_back(leaf_addr(RuleOp::AllowedRecipient, vendor_a.clone(), &env));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Small transfer to random: passes (MaxAmount branch)
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &random, &50)
        .is_ok());

    // Large transfer to vendor_a: passes (AllowedRecipient branch)
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &vendor_a, &500)
        .is_ok());

    // Large transfer to vendor_b: denied (neither branch)
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &vendor_b, &500),
        Err(Ok(Error::PolicyDenied))
    );

    // Large transfer to random: denied
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &random, &500),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- Realistic scenario: NOT recipient blacklisted AND max amount ---
// Tree layout for AND(NOT(RecipientBlacklisted), MaxAmount(1000)):
//   [0] AND { children_start: 1, children_end: 3 }
//   [1] NOT { children_start: 3, children_end: 4 }
//   [2] MaxAmount(1000)
//   [3] RecipientBlacklisted

#[test]
fn composite_realistic_not_blacklisted_and_max_amount() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let asset = Address::generate(&env);
    let safe = Address::generate(&env);
    let bad = Address::generate(&env);

    let mut tree = soroban_sdk::Vec::new(&env);
    // [0] AND with children 1..3
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    // [1] NOT with child at index 3
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 3,
        children_end: 4,
    });
    // [2] MaxAmount(1000)
    tree.push_back(leaf_amount(RuleOp::MaxAmount, 1000, &env));
    // [3] RecipientBlacklisted
    tree.push_back(leaf(RuleOp::RecipientBlacklisted, &env));

    p.set_composite_rule(&owner, &String::from_str(&env, "cr"), &tree);

    // Safe recipient, amount OK: passes
    assert!(p
        .try_check_transfer(&String::from_str(&env, "cr"), &asset, &safe, &500)
        .is_ok());

    // Blacklisted recipient: denied by blocklist check (before composite rules)
    p.add_to_blocklist(&owner, &String::from_str(&env, "cr"), &bad);
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &bad, &500),
        Err(Ok(Error::PolicyRecipientRestricted))
    );
}

// --- asset deny list ---

#[test]
fn blacklisted_asset_is_denied() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // The transfer passes every scalar gate before the asset is listed.
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());

    p.add_asset_blacklist(&owner, &pid, &asset);
    assert!(p.is_asset_blacklisted(&pid, &asset));
    let r = p.try_check_transfer(&pid, &asset, &recip, &1);
    assert_eq!(r, Err(Ok(Error::PolicyDenied)));
    assert_event(&env, "PolicyViolation");
}

#[test]
fn blacklist_removal_restores_the_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_asset_blacklist(&owner, &pid, &asset);
    p.remove_asset_blacklist(&owner, &pid, &asset);
    assert!(!p.is_asset_blacklisted(&pid, &asset));
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());
}

#[test]
fn blacklist_beats_the_asset_whitelist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Explicitly allow the asset, then deny it: the deny list wins.
    p.set_asset_whitelist_enabled(&owner, &pid, &true);
    p.add_asset_to_whitelist(&owner, &pid, &asset);
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());

    p.add_asset_blacklist(&owner, &pid, &asset);
    let r = p.try_check_transfer(&pid, &asset, &recip, &1);
    assert_eq!(r, Err(Ok(Error::PolicyDenied)));
}

#[test]
fn blacklist_is_scoped_to_its_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let other = String::from_str(&env, "other");
    p.register_policy(
        &owner,
        &other,
        &BytesN::from_array(&env, &[7; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
        &None,
    );
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_asset_blacklist(&owner, &String::from_str(&env, "max_txn"), &asset);
    // The sibling policy is untouched by the other policy's deny list.
    assert!(!p.is_asset_blacklisted(&other, &asset));
    assert!(p.try_check_transfer(&other, &asset, &recip, &1).is_ok());
}

#[test]
fn blacklist_management_rejects_bad_input() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);

    // Removing an asset that was never listed.
    assert_eq!(
        p.try_remove_asset_blacklist(&owner, &pid, &asset),
        Err(Ok(Error::NotFound))
    );
    p.add_asset_blacklist(&owner, &pid, &asset);
    // Listing it twice.
    assert_eq!(
        p.try_add_asset_blacklist(&owner, &pid, &asset),
        Err(Ok(Error::AlreadyExists))
    );
    // Unknown policy.
    assert_eq!(
        p.try_add_asset_blacklist(&owner, &String::from_str(&env, "nope"), &asset),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn only_the_owner_can_manage_the_blacklist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);

    assert_eq!(
        p.try_add_asset_blacklist(&stranger, &pid, &asset),
        Err(Ok(Error::Unauthorized))
    );
    p.add_asset_blacklist(&owner, &pid, &asset);
    assert_eq!(
        p.try_remove_asset_blacklist(&stranger, &pid, &asset),
        Err(Ok(Error::Unauthorized))
    );
}

// --- Multi-asset spending requests (Issue #237) ---

fn entry(asset: &Address, amount: i128) -> AssetAmount {
    AssetAmount {
        asset: asset.clone(),
        amount,
    }
}

fn spent(env: &Env, p: &PolicyContractClient, asset: &Address) -> i128 {
    p.get_allowance(&String::from_str(env, "mt"), asset).spent
}

#[test]
fn multi_asset_amount_at_limit_passes_and_one_over_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let (a, b) = (Address::generate(&env), Address::generate(&env));
    let recip = Address::generate(&env);
    p.set_allowance(&owner, &pid, &a, &1_000, &0);
    p.set_allowance(&owner, &pid, &b, &1_000, &0);

    // limit + 1 is rejected and records nothing.
    assert_eq!(
        p.try_record_multi_asset_spend(&owner, &pid, &recip, &vec![&env, entry(&b, 1_001)]),
        Err(Ok(Error::AllowanceExceeded))
    );
    assert_eq!(spent(&env, &p, &b), 0);

    // Exactly the limit is permitted and consumes the allowance fully.
    p.record_multi_asset_spend(&owner, &pid, &recip, &vec![&env, entry(&a, 1_000)]);
    assert_eq!(spent(&env, &p, &a), 1_000);
    assert_eq!(p.try_check_allowance(&pid, &a, &0), Ok(Ok(0)));
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &vec![&env, entry(&a, 1)]),
        Err(Ok(Error::AllowanceExceeded))
    );
}

#[test]
fn zero_and_negative_amounts_are_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    p.set_allowance(&owner, &pid, &asset, &1_000, &0);

    for bad in [0i128, -1, i128::MIN] {
        assert_eq!(
            p.try_check_multi_asset_transfer(&pid, &recip, &vec![&env, entry(&asset, bad)]),
            Err(Ok(Error::InvalidAmount))
        );
        assert_eq!(
            p.try_record_multi_asset_spend(&owner, &pid, &recip, &vec![&env, entry(&asset, bad)]),
            Err(Ok(Error::InvalidAmount))
        );
        assert_eq!(
            p.try_check_transfer(&pid, &asset, &recip, &bad),
            Err(Ok(Error::InvalidAmount))
        );
        assert_eq!(
            p.try_update_allowance(&owner, &pid, &asset, &bad),
            Err(Ok(Error::InvalidAmount))
        );
    }
    // A negative entry cannot offset a positive one for the same asset.
    assert_eq!(
        p.try_check_multi_asset_transfer(
            &pid,
            &recip,
            &vec![&env, entry(&asset, 1_500), entry(&asset, -600)]
        ),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(spent(&env, &p, &asset), 0);
}

#[test]
fn multi_asset_unlisted_asset_is_rejected_and_nothing_recorded() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let (known, unknown) = (Address::generate(&env), Address::generate(&env));
    let recip = Address::generate(&env);
    p.set_asset_whitelist_enabled(&owner, &pid, &true);
    p.add_asset_to_whitelist(&owner, &pid, &known);
    p.set_allowance(&owner, &pid, &known, &1_000, &0);

    assert_eq!(
        p.try_record_multi_asset_spend(
            &owner,
            &pid,
            &recip,
            &vec![&env, entry(&known, 100), entry(&unknown, 1)]
        ),
        Err(Ok(Error::AssetNotAuthorized))
    );
    assert_eq!(spent(&env, &p, &known), 0);
}

#[test]
fn multi_asset_both_within_limits_records_both() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let (xlm, usdc) = (Address::generate(&env), Address::generate(&env));
    let recip = Address::generate(&env);
    p.set_allowance(&owner, &pid, &xlm, &1_000, &0);
    p.set_allowance(&owner, &pid, &usdc, &500, &0);

    let req = vec![&env, entry(&xlm, 700), entry(&usdc, 500)];
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &req),
        Ok(Ok(()))
    );
    // Checking is read-only.
    assert_eq!(spent(&env, &p, &xlm), 0);
    p.record_multi_asset_spend(&owner, &pid, &recip, &req);
    assert_eq!(spent(&env, &p, &xlm), 700);
    assert_eq!(spent(&env, &p, &usdc), 500);
}

#[test]
fn multi_asset_one_over_limit_rejects_whole_request() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let (xlm, usdc) = (Address::generate(&env), Address::generate(&env));
    let recip = Address::generate(&env);
    p.set_allowance(&owner, &pid, &xlm, &1_000, &0);
    p.set_allowance(&owner, &pid, &usdc, &500, &0);

    // The passing asset comes first in the request and still records nothing.
    for req in [
        vec![&env, entry(&xlm, 700), entry(&usdc, 501)],
        vec![&env, entry(&usdc, 501), entry(&xlm, 700)],
    ] {
        assert_eq!(
            p.try_record_multi_asset_spend(&owner, &pid, &recip, &req),
            Err(Ok(Error::AllowanceExceeded))
        );
        assert_eq!(spent(&env, &p, &xlm), 0);
        assert_eq!(spent(&env, &p, &usdc), 0);
    }
}

#[test]
fn duplicate_entries_are_aggregated_before_checking() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    p.set_allowance(&owner, &pid, &asset, &1_000, &0);

    // 600 + 500 = 1_100 > 1_000, although each entry fits on its own.
    assert_eq!(
        p.try_record_multi_asset_spend(
            &owner,
            &pid,
            &recip,
            &vec![&env, entry(&asset, 600), entry(&asset, 500)]
        ),
        Err(Ok(Error::AllowanceExceeded))
    );
    assert_eq!(spent(&env, &p, &asset), 0);

    // Within the limit the entries are recorded once, as their sum.
    p.record_multi_asset_spend(
        &owner,
        &pid,
        &recip,
        &vec![&env, entry(&asset, 300), entry(&asset, 200)],
    );
    assert_eq!(spent(&env, &p, &asset), 500);
}

#[test]
fn duplicate_entries_cannot_split_past_the_per_transfer_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    // `setup` registers "max_txn" with max_amount = 1_000_000.
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    assert_eq!(
        p.try_check_multi_asset_transfer(
            &pid,
            &recip,
            &vec![&env, entry(&asset, 600_000), entry(&asset, 400_001)]
        ),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        p.try_check_multi_asset_transfer(
            &pid,
            &recip,
            &vec![&env, entry(&asset, 600_000), entry(&asset, 400_000)]
        ),
        Ok(Ok(()))
    );
}

#[test]
fn amounts_near_i128_max_fail_without_panicking() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let (a, b) = (Address::generate(&env), Address::generate(&env));
    let recip = Address::generate(&env);

    // Per-asset totals that do not fit an i128.
    assert_eq!(
        p.try_check_multi_asset_transfer(
            &pid,
            &recip,
            &vec![&env, entry(&a, i128::MAX), entry(&a, 1)]
        ),
        Err(Ok(Error::Overflow))
    );
    // i128::MAX of two *different* assets is fine: amounts are never summed
    // across assets.
    assert_eq!(
        p.try_check_multi_asset_transfer(
            &pid,
            &recip,
            &vec![&env, entry(&a, i128::MAX), entry(&b, i128::MAX)]
        ),
        Ok(Ok(()))
    );

    // Cumulative spend right up to an i128::MAX limit, then one more unit.
    p.set_allowance(&owner, &pid, &a, &i128::MAX, &0);
    p.record_multi_asset_spend(&owner, &pid, &recip, &vec![&env, entry(&a, i128::MAX - 1)]);
    p.update_allowance(&owner, &pid, &a, &1);
    assert_eq!(spent(&env, &p, &a), i128::MAX);
    assert_eq!(
        p.try_update_allowance(&owner, &pid, &a, &1),
        Err(Ok(Error::AllowanceExceeded))
    );
    assert_eq!(
        p.try_check_transfer(&pid, &a, &recip, &i128::MAX),
        Err(Ok(Error::AllowanceExceeded))
    );

    // Lowering a limit below what was spent leaves negative headroom, which
    // rejects every positive amount.
    p.set_allowance(&owner, &pid, &a, &10, &0);
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &vec![&env, entry(&a, 1)]),
        Err(Ok(Error::AllowanceExceeded))
    );
}

#[test]
fn assets_with_different_decimals_keep_independent_limits() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    // 1 XLM (7 decimals) and 5 USDC (6 decimals), in base units.
    let (xlm, usdc) = (Address::generate(&env), Address::generate(&env));
    let recip = Address::generate(&env);
    p.set_allowance(&owner, &pid, &xlm, &10_000_000, &0);
    p.set_allowance(&owner, &pid, &usdc, &5_000_000, &0);

    // 9 USDC exceeds the USDC limit even though it is below the XLM limit.
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &vec![&env, entry(&usdc, 9_000_000)]),
        Err(Ok(Error::AllowanceExceeded))
    );
    // Both limits fully used in one request: the combined 15_000_000 base
    // units are never compared with either limit.
    p.record_multi_asset_spend(
        &owner,
        &pid,
        &recip,
        &vec![&env, entry(&xlm, 10_000_000), entry(&usdc, 5_000_000)],
    );
    assert_eq!(spent(&env, &p, &xlm), 10_000_000);
    assert_eq!(spent(&env, &p, &usdc), 5_000_000);
    for asset in [&xlm, &usdc] {
        assert_eq!(
            p.try_check_multi_asset_transfer(&pid, &recip, &vec![&env, entry(asset, 1)]),
            Err(Ok(Error::AllowanceExceeded))
        );
    }
}

#[test]
fn empty_or_oversized_requests_are_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &Vec::new(&env)),
        Err(Ok(Error::InvalidInput))
    );
    let mut ten = Vec::new(&env);
    for _ in 0..10 {
        ten.push_back(entry(&asset, 1));
    }
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &ten),
        Ok(Ok(()))
    );
    ten.push_back(entry(&asset, 1));
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &ten),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn multi_asset_request_runs_the_policy_gates() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let only = Address::generate(&env);
    let other = Address::generate(&env);
    let recip = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let p = PolicyContractClient::new(&env, &id);
    p.initialize();
    let pid = String::from_str(&env, "single");
    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[3; 32]),
        &0,
        &None,
        &Some(only.clone()),
        &0,
        &None,
    );

    // An asset outside `allowed_asset` sinks the whole request.
    assert_eq!(
        p.try_check_multi_asset_transfer(
            &pid,
            &recip,
            &vec![&env, entry(&only, 1), entry(&other, 1)]
        ),
        Err(Ok(Error::PolicyDenied))
    );
    // Recipient blocklist is evaluated before any asset.
    p.add_to_blocklist(&owner, &pid, &recip);
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &vec![&env, entry(&only, 1)]),
        Err(Ok(Error::PolicyRecipientRestricted))
    );
    // Unknown policy.
    assert_eq!(
        p.try_check_multi_asset_transfer(
            &String::from_str(&env, "nope"),
            &recip,
            &vec![&env, entry(&only, 1)]
        ),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn only_the_owner_can_record_spend() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    p.set_allowance(&owner, &pid, &asset, &1_000, &0);

    // A non-owner cannot burn the owner's allowance through either path.
    assert_eq!(
        p.try_record_multi_asset_spend(&stranger, &pid, &recip, &vec![&env, entry(&asset, 1_000)]),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        p.try_update_allowance(&stranger, &pid, &asset, &1_000),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(spent(&env, &p, &asset), 0);
    assert_eq!(
        p.try_set_recurring_allowance(&stranger, &pid, &asset, &1, &60, &0),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn recording_spend_requires_the_callers_signature() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    // Drop the blanket auth mock: the owner has not signed this call.
    env.set_auths(&[]);
    let r = p.try_record_multi_asset_spend(
        &owner,
        &String::from_str(&env, "mt"),
        &Address::generate(&env),
        &vec![&env, entry(&asset, 1)],
    );
    // A host auth failure, not a contract error code.
    assert!(matches!(r, Err(Err(_))));
}

// --- Rate-limited (recurring) allowances (Issue #237) ---

const START: u64 = 1_000;
const WINDOW: u64 = 100;

/// A policy with a 1_000-per-100s rate limit on `asset`, configured at
/// ledger time `START`.
fn rate_setup<'a>(env: &'a Env, owner: &Address, asset: &Address) -> PolicyContractClient<'a> {
    env.ledger().set_timestamp(START);
    let p = allowance_setup(env, owner);
    p.set_recurring_allowance(
        owner,
        &String::from_str(env, "mt"),
        asset,
        &1_000,
        &WINDOW,
        &0,
    );
    p
}

#[test]
fn rate_limit_first_spend_and_accumulation_within_a_period() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = rate_setup(&env, &owner, &asset);
    let pid = String::from_str(&env, "mt");

    let a = p.get_allowance(&pid, &asset);
    assert_eq!(
        (a.spent, a.window_seconds, a.window_start),
        (0, WINDOW, START)
    );
    // First-ever spend.
    p.update_allowance(&owner, &pid, &asset, &400);
    env.ledger().set_timestamp(START + 50);
    p.update_allowance(&owner, &pid, &asset, &600);
    assert_eq!(spent(&env, &p, &asset), 1_000);
    assert_eq!(
        p.try_update_allowance(&owner, &pid, &asset, &1),
        Err(Ok(Error::AllowanceExceeded))
    );
}

#[test]
fn rate_limit_spend_at_period_end_minus_one_counts_in_current_period() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let p = rate_setup(&env, &owner, &asset);
    let pid = String::from_str(&env, "mt");

    p.update_allowance(&owner, &pid, &asset, &1_000);
    env.ledger().set_timestamp(START + WINDOW - 1);
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recip, &1),
        Err(Ok(Error::AllowanceExceeded))
    );
    let a = p.get_allowance(&pid, &asset);
    assert_eq!((a.spent, a.window_start), (1_000, START));
}

#[test]
fn rate_limit_spend_exactly_at_period_end_opens_a_new_period() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let p = rate_setup(&env, &owner, &asset);
    let pid = String::from_str(&env, "mt");

    p.update_allowance(&owner, &pid, &asset, &1_000);
    env.ledger().set_timestamp(START + WINDOW);
    assert_eq!(p.try_check_allowance(&pid, &asset, &1_000), Ok(Ok(0)));
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1_000).is_ok());
    p.record_multi_asset_spend(&owner, &pid, &recip, &vec![&env, entry(&asset, 250)]);
    let a = p.get_allowance(&pid, &asset);
    assert_eq!((a.spent, a.window_start), (250, START + WINDOW));
}

#[test]
fn rate_limit_resets_after_several_periods_without_carry_over() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = rate_setup(&env, &owner, &asset);
    let pid = String::from_str(&env, "mt");

    p.update_allowance(&owner, &pid, &asset, &1_000);
    // Five whole periods and part of a sixth.
    env.ledger().set_timestamp(START + 5 * WINDOW + 37);
    // The view already reflects the current window, anchored on a boundary.
    let a = p.get_allowance(&pid, &asset);
    assert_eq!((a.spent, a.window_start), (0, START + 5 * WINDOW));
    // Idle periods do not accrue: the limit is still 1_000, not 5_000.
    assert_eq!(
        p.try_update_allowance(&owner, &pid, &asset, &1_001),
        Err(Ok(Error::AllowanceExceeded))
    );
    p.update_allowance(&owner, &pid, &asset, &1_000);
    // The persisted window stays on the boundary schedule (no drift to `now`).
    env.ledger().set_timestamp(START + 6 * WINDOW);
    p.update_allowance(&owner, &pid, &asset, &1);
    let a = p.get_allowance(&pid, &asset);
    assert_eq!((a.spent, a.window_start), (1, START + 6 * WINDOW));
}

#[test]
fn zero_window_allowance_never_resets() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(START);
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    p.set_recurring_allowance(&owner, &pid, &asset, &1_000, &0, &0);

    p.update_allowance(&owner, &pid, &asset, &1_000);
    env.ledger().set_timestamp(u64::MAX);
    assert_eq!(spent(&env, &p, &asset), 1_000);
    assert_eq!(
        p.try_update_allowance(&owner, &pid, &asset, &1),
        Err(Ok(Error::AllowanceExceeded))
    );
}

#[test]
fn ledger_time_before_window_start_keeps_current_usage() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = rate_setup(&env, &owner, &asset);
    let pid = String::from_str(&env, "mt");

    p.update_allowance(&owner, &pid, &asset, &1_000);
    env.ledger().set_timestamp(START - 1);
    let a = p.get_allowance(&pid, &asset);
    assert_eq!((a.spent, a.window_start), (1_000, START));
    assert_eq!(
        p.try_update_allowance(&owner, &pid, &asset, &1),
        Err(Ok(Error::AllowanceExceeded))
    );
}

#[test]
fn rate_limit_window_far_in_the_future_does_not_overflow() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    env.ledger().set_timestamp(START);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    p.set_recurring_allowance(&owner, &pid, &asset, &1_000, &(u64::MAX / 2), &0);

    p.update_allowance(&owner, &pid, &asset, &1_000);
    env.ledger().set_timestamp(u64::MAX);
    // (u64::MAX - START) / (u64::MAX / 2) = 1 whole window elapsed.
    let a = p.get_allowance(&pid, &asset);
    assert_eq!((a.spent, a.window_start), (0, START + u64::MAX / 2));
    p.update_allowance(&owner, &pid, &asset, &1_000);
}

#[test]
fn reconfiguring_the_window_keeps_spend_and_reanchors() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = rate_setup(&env, &owner, &asset);
    let pid = String::from_str(&env, "mt");

    p.update_allowance(&owner, &pid, &asset, &700);
    env.ledger().set_timestamp(START + 50);
    // Changing the window re-anchors it at "now"; the 700 already spent stays.
    p.set_recurring_allowance(&owner, &pid, &asset, &1_000, &200, &0);
    let a = p.get_allowance(&pid, &asset);
    assert_eq!(
        (a.spent, a.window_seconds, a.window_start),
        (700, 200, START + 50)
    );
    env.ledger().set_timestamp(START + 50 + 199);
    assert_eq!(
        p.try_update_allowance(&owner, &pid, &asset, &301),
        Err(Ok(Error::AllowanceExceeded))
    );
    // set_allowance only touches the limit and expiry: the window survives.
    p.set_allowance(&owner, &pid, &asset, &2_000, &0);
    let a = p.get_allowance(&pid, &asset);
    assert_eq!(
        (a.limit, a.window_seconds, a.window_start),
        (2_000, 200, START + 50)
    );
    env.ledger().set_timestamp(START + 50 + 200);
    assert_eq!(spent(&env, &p, &asset), 0);
}

#[test]
fn multi_asset_request_resets_each_asset_on_its_own_schedule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (hourly, cumulative) = (Address::generate(&env), Address::generate(&env));
    let recip = Address::generate(&env);
    let p = rate_setup(&env, &owner, &hourly);
    let pid = String::from_str(&env, "mt");
    p.set_allowance(&owner, &pid, &cumulative, &1_000, &0);

    let both = vec![&env, entry(&hourly, 1_000), entry(&cumulative, 600)];
    p.record_multi_asset_spend(&owner, &pid, &recip, &both);
    env.ledger().set_timestamp(START + WINDOW);
    // The rate-limited asset reset; the cumulative one did not, so the whole
    // request is refused and the reset is not persisted by a failed request.
    assert_eq!(
        p.try_record_multi_asset_spend(&owner, &pid, &recip, &both),
        Err(Ok(Error::AllowanceExceeded))
    );
    assert_eq!(spent(&env, &p, &cumulative), 600);
    p.record_multi_asset_spend(
        &owner,
        &pid,
        &recip,
        &vec![&env, entry(&hourly, 1_000), entry(&cumulative, 400)],
    );
    assert_eq!(spent(&env, &p, &hourly), 1_000);
    assert_eq!(spent(&env, &p, &cumulative), 1_000);
}

#[test]
fn expired_rate_limit_stays_denied_after_a_reset() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(START);
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let pid = String::from_str(&env, "mt");
    p.set_recurring_allowance(&owner, &pid, &asset, &1_000, &WINDOW, &(START + 150));

    env.ledger().set_timestamp(START + 150);
    // A window reset must not resurrect a lapsed envelope: the refusal names
    // the expiry rather than being passed off as a rule denial.
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &vec![&env, entry(&asset, 1)]),
        Err(Ok(Error::AllowanceExpired))
    );
}

// --- Multi-rule composition (rule stack) tests ---
//
// A policy may stack several independent rule trees. All of them must pass for
// `check_transfer` to authorize a transaction: the evaluation short-circuits on
// the first failing rule with `Error::PolicyDenied`.

/// A chain of 15 nested `Not` nodes — structurally valid (so registration
/// accepts it) but deeper than `MAX_RULE_DEPTH`, so evaluating it fails with
/// [`Error::InvalidInput`]. Used to prove the stack short-circuits before it
/// reaches a later, un-evaluable rule.
fn deep_chain_tree(env: &Env) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    for i in 0..15u32 {
        tree.push_back(RuleNode {
            op: RuleOp::Not,
            value_i128: 0,
            value_address: Address::generate(env),
            children_start: i + 1,
            children_end: i + 2,
        });
    }
    tree.push_back(RuleNode {
        op: RuleOp::MaxAmount,
        value_i128: i128::MAX,
        value_address: Address::generate(env),
        children_start: 0,
        children_end: 0,
    });
    tree
}

#[test]
fn multi_rule_recipient_and_amount_both_must_pass() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let vendor = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);

    // Compound policy: allow-listed recipient AND max amount 500.
    assert_eq!(
        p.add_policy_rule(
            &owner,
            &pid,
            &single_addr_tree(RuleOp::AllowedRecipient, vendor.clone(), &env)
        ),
        1
    );
    assert_eq!(
        p.add_policy_rule(
            &owner,
            &pid,
            &single_amount_tree(RuleOp::MaxAmount, 500, &env)
        ),
        2
    );
    assert_eq!(p.get_policy_rules(&pid).len(), 2);

    // Recipient whitelisted and amount within the cap: authorized.
    assert!(p.try_check_transfer(&pid, &asset, &vendor, &500).is_ok());
    assert!(p.try_check_transfer(&pid, &asset, &vendor, &1).is_ok());
}

#[test]
fn multi_rule_whitelisted_recipient_failure_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);

    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, vendor, &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 500, &env),
    );

    // Amount is fine, but the recipient is not on the whitelist: one failing
    // rule is enough to deny the whole evaluation.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &stranger, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn multi_rule_amount_limit_failure_denies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let vendor = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);

    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, vendor.clone(), &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 500, &env),
    );

    // Recipient is whitelisted, but the amount breaches the cap.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &vendor, &501),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn multi_rule_is_conjunctive_across_three_rules() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let vendor = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);

    // recipient + amount + asset: every rule must pass.
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, vendor.clone(), &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 500, &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedAsset, asset.clone(), &env),
    );
    assert_eq!(p.get_policy_rules(&pid).len(), 3);

    assert!(p.try_check_transfer(&pid, &asset, &vendor, &500).is_ok());

    let other_asset = Address::generate(&env);
    assert_eq!(
        p.try_check_transfer(&pid, &other_asset, &vendor, &500),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn multi_rule_empty_stack_is_permissive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // No rules registered: nothing to enforce, every transfer is authorized.
    assert_eq!(p.get_policy_rules(&pid).len(), 0);
    assert!(p
        .try_check_transfer(&pid, &asset, &recip, &1_000_000)
        .is_ok());
    let payload = TransactionPayload {
        asset: asset.clone(),
        recipient: recip,
        amount: 1,
    };
    assert_eq!(p.try_evaluate_policy_rules(&pid, &payload), Ok(Ok(true)));
}

#[test]
fn multi_rule_remove_retires_a_single_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);

    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, vendor.clone(), &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 500, &env),
    );

    // Over the cap while both rules are active.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &vendor, &600),
        Err(Ok(Error::PolicyDenied))
    );

    // Retire the amount rule (index 1); the recipient rule stays in force.
    p.remove_policy_rule(&owner, &pid, &1);
    assert_eq!(p.get_policy_rules(&pid).len(), 1);
    assert!(p.try_check_transfer(&pid, &asset, &vendor, &600).is_ok());
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &stranger, &600),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn multi_rule_remove_bounds_and_missing_stack_fail() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");

    // No stack yet.
    assert_eq!(
        p.try_remove_policy_rule(&owner, &pid, &0),
        Err(Ok(Error::NotFound))
    );

    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 1, &env),
    );
    // Out-of-range index is rejected instead of panicking.
    assert_eq!(
        p.try_remove_policy_rule(&owner, &pid, &5),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        p.try_remove_policy_rule(&owner, &pid, &u32::MAX),
        Err(Ok(Error::InvalidInput))
    );

    p.remove_policy_rule(&owner, &pid, &0);
    // The key is dropped with its last rule.
    assert_eq!(p.get_policy_rules(&pid).len(), 0);
    assert_eq!(
        p.try_remove_policy_rule(&owner, &pid, &0),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        p.try_clear_policy_rules(&owner, &pid),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn multi_rule_only_the_owner_can_manage_the_stack() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");

    let tree = single_amount_tree(RuleOp::MaxAmount, 10, &env);
    assert_eq!(
        p.try_add_policy_rule(&stranger, &pid, &tree),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        p.try_remove_policy_rule(&stranger, &pid, &0),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        p.try_clear_policy_rules(&stranger, &pid),
        Err(Ok(Error::Unauthorized))
    );

    // The owner's own stack is untouched by the rejected attempts.
    p.add_policy_rule(&owner, &pid, &tree);
    assert_eq!(p.get_policy_rules(&pid).len(), 1);
}

#[test]
fn multi_rule_rejects_empty_and_malformed_trees() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");

    // Empty tree.
    let empty = soroban_sdk::Vec::new(&env);
    assert_eq!(
        p.try_add_policy_rule(&owner, &pid, &empty),
        Err(Ok(Error::InvalidInput))
    );

    // AND with an empty child range.
    let mut no_children = soroban_sdk::Vec::new(&env);
    no_children.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 1,
    });
    assert_eq!(
        p.try_add_policy_rule(&owner, &pid, &no_children),
        Err(Ok(Error::InvalidInput))
    );

    // AND whose child range runs past the end of the tree.
    let mut out_of_bounds = soroban_sdk::Vec::new(&env);
    out_of_bounds.push_back(RuleNode {
        op: RuleOp::Or,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 9,
    });
    out_of_bounds.push_back(leaf_amount(RuleOp::MaxAmount, 1, &env));
    assert_eq!(
        p.try_add_policy_rule(&owner, &pid, &out_of_bounds),
        Err(Ok(Error::InvalidInput))
    );

    // NOT with more than one child.
    let mut two_children = soroban_sdk::Vec::new(&env);
    two_children.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    two_children.push_back(leaf_amount(RuleOp::MaxAmount, 1, &env));
    two_children.push_back(leaf_amount(RuleOp::MaxAmount, 2, &env));
    assert_eq!(
        p.try_add_policy_rule(&owner, &pid, &two_children),
        Err(Ok(Error::InvalidInput))
    );

    // Nothing was stored by any of the rejected registrations.
    assert_eq!(p.get_policy_rules(&pid).len(), 0);
}

#[test]
fn multi_rule_stack_is_bounded() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");

    for i in 0..MAX_POLICY_RULES {
        let tree = single_amount_tree(RuleOp::MaxAmount, i as i128, &env);
        assert_eq!(p.add_policy_rule(&owner, &pid, &tree), i + 1);
    }
    assert_eq!(p.get_policy_rules(&pid).len(), MAX_POLICY_RULES);

    // The stack cannot grow past the gas-safety bound.
    let overflow = single_amount_tree(RuleOp::MaxAmount, i128::MAX, &env);
    assert_eq!(
        p.try_add_policy_rule(&owner, &pid, &overflow),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn multi_rule_clear_restores_permissive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 10, &env),
    );
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );

    p.clear_policy_rules(&owner, &pid);
    assert_eq!(p.get_policy_rules(&pid).len(), 0);
    assert!(p.try_check_transfer(&pid, &asset, &recip, &100).is_ok());
}

#[test]
fn multi_rule_denial_emits_policy_violation() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 10, &env),
    );

    let _ = p.try_check_transfer(&pid, &asset, &recip, &100);
    assert_event(&env, "PolicyViolation");
}

#[test]
fn multi_rule_stacks_with_the_single_composite_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);

    // The single composite tree caps the amount at 100 …
    let tree = single_amount_tree(RuleOp::MaxAmount, 100, &env);
    p.set_composite_rule(&owner, &pid, &tree);
    // … while the stack additionally whitelists the vendor.
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, vendor.clone(), &env),
    );

    // Composite tree denies the oversized transfer.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &vendor, &200),
        Err(Ok(Error::PolicyDenied))
    );
    // Stack denies the unlisted recipient.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &stranger, &50),
        Err(Ok(Error::PolicyDenied))
    );
    // Both layers pass for the whitelisted vendor inside the cap.
    assert!(p.try_check_transfer(&pid, &asset, &vendor, &50).is_ok());
}

#[test]
fn multi_rule_short_circuits_on_first_failure() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "cr");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let payload = TransactionPayload {
        asset: asset.clone(),
        recipient: recip.clone(),
        amount: 100,
    };

    // A rule deeper than the recursion guard cannot be evaluated at all.
    let deep = deep_chain_tree(&env);
    let deny = single_amount_tree(RuleOp::MaxAmount, 10, &env);

    // [failing rule, deep rule]: the first rule denies and the loop stops
    // before it ever reaches the un-evaluable second rule.
    p.add_policy_rule(&owner, &pid, &deny);
    p.add_policy_rule(&owner, &pid, &deep);
    assert_eq!(p.try_evaluate_policy_rules(&pid, &payload), Ok(Ok(false)));
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );

    // [deep rule, failing rule]: with the order swapped the depth guard trips
    // first, proving evaluation really does run in stack order.
    p.clear_policy_rules(&owner, &pid);
    p.add_policy_rule(&owner, &pid, &deep);
    p.add_policy_rule(&owner, &pid, &deny);
    assert_eq!(
        p.try_evaluate_policy_rules(&pid, &payload),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recip, &100),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn multi_rule_stack_is_scoped_to_its_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let other = String::from_str(&env, "other");
    p.register_policy(
        &owner,
        &other,
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &None,
        &None,
        &0,
        &None,
    );
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_policy_rule(
        &owner,
        &String::from_str(&env, "cr"),
        &single_amount_tree(RuleOp::MaxAmount, 10, &env),
    );

    // The strict rule is enforced only on its own policy; the sibling stays
    // permissive.
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "cr"), &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(p.get_policy_rules(&other).len(), 0);
    assert!(p.try_check_transfer(&other, &asset, &recip, &100).is_ok());
}

// --- Recipient whitelist (Issue #63) tests ---
//
// A policy owns a dynamic directory of approved destinations. While whitelist
// mode is active only listed recipients may be targeted, an empty directory
// fails closed, and a miss is rejected with `Error::PolicyDenied`.

/// Register a policy with no scalar gates so only the recipient whitelist gate
/// decides the outcome.
fn whitelist_setup<'a>(env: &'a Env, owner: &Address, policy_id: &str) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, policy_id),
        &BytesN::from_array(env, &[5; 32]),
        &0,
        &None,
        &None,
        &0,
        &None,
    );
    client
}

#[test]
fn whitelist_allows_listed_and_blocks_unlisted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl");
    let pid = String::from_str(&env, "wl");
    let asset = Address::generate(&env);
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let stranger = Address::generate(&env);

    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    p.add_recipient_to_whitelist(&owner, &pid, &a);
    p.add_recipient_to_whitelist(&owner, &pid, &b);

    // Listed destinations pass.
    assert!(p.try_check_transfer(&pid, &asset, &a, &1).is_ok());
    assert!(p.try_check_transfer(&pid, &asset, &b, &1).is_ok());
    // An unlisted destination is denied with the policy denial code.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &stranger, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn empty_whitelist_denies_all_recipients() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_empty");
    let pid = String::from_str(&env, "wl_empty");
    let asset = Address::generate(&env);
    let anyone = Address::generate(&env);

    // Mode active with no entries — fail closed, every destination denied.
    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &anyone, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn whitelist_removal_blocks_previously_allowed() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_rem");
    let pid = String::from_str(&env, "wl_rem");
    let asset = Address::generate(&env);
    let a = Address::generate(&env);

    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    p.add_recipient_to_whitelist(&owner, &pid, &a);
    assert!(p.try_check_transfer(&pid, &asset, &a, &1).is_ok());

    p.remove_recipient_from_whitelist(&owner, &pid, &a);
    // The previously approved destination is untrusted again.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &a, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn whitelist_disabled_allows_any_recipient() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_off");
    let pid = String::from_str(&env, "wl_off");
    let asset = Address::generate(&env);
    let anyone = Address::generate(&env);

    // Default state: the gate is not enforced and any destination passes.
    assert!(p.try_check_transfer(&pid, &asset, &anyone, &1).is_ok());
    // Enforcing then relaxing the mode reopens the gate without losing the
    // staged directory.
    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    p.set_recipient_whitelist_enabled(&owner, &pid, &false);
    assert!(p.try_check_transfer(&pid, &asset, &anyone, &1).is_ok());
    assert!(!p.is_recipient_whitelisted(&pid, &anyone));
}

#[test]
fn non_owner_cannot_manage_whitelist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let intruder = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_auth");
    let pid = String::from_str(&env, "wl_auth");
    let target = Address::generate(&env);

    assert_eq!(
        p.try_set_recipient_whitelist_enabled(&intruder, &pid, &true),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        p.try_add_recipient_to_whitelist(&intruder, &pid, &target),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        p.try_remove_recipient_from_whitelist(&intruder, &pid, &target),
        Err(Ok(Error::Unauthorized))
    );
    // The rejected attempts left the directory untouched.
    assert!(p.get_recipient_whitelist(&pid).is_empty());
}

#[test]
fn duplicate_and_missing_recipient_whitelist_ops_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_dup");
    let pid = String::from_str(&env, "wl_dup");
    let target = Address::generate(&env);

    // Listing an address twice is rejected …
    p.add_recipient_to_whitelist(&owner, &pid, &target);
    assert_eq!(
        p.try_add_recipient_to_whitelist(&owner, &pid, &target),
        Err(Ok(Error::AlreadyExists))
    );
    // … and so is removing an address that was never listed.
    let other = Address::generate(&env);
    assert_eq!(
        p.try_remove_recipient_from_whitelist(&owner, &pid, &other),
        Err(Ok(Error::NotFound))
    );
    p.remove_recipient_from_whitelist(&owner, &pid, &target);
    assert_eq!(
        p.try_remove_recipient_from_whitelist(&owner, &pid, &target),
        Err(Ok(Error::NotFound))
    );
    // The last removal also drops the index, so the directory reads empty.
    assert!(p.get_recipient_whitelist(&pid).is_empty());
}

#[test]
fn whitelist_denial_emits_policy_violation() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_evt");
    let pid = String::from_str(&env, "wl_evt");
    let asset = Address::generate(&env);
    let stranger = Address::generate(&env);

    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    let _ = p.try_check_transfer(&pid, &asset, &stranger, &1);
    assert_event(&env, "PolicyViolation");
}

#[test]
fn whitelist_ok_path_records_no_violation_event() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_ok");
    let pid = String::from_str(&env, "wl_ok");
    let asset = Address::generate(&env);
    let listed = Address::generate(&env);

    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    p.add_recipient_to_whitelist(&owner, &pid, &listed);

    // The gate enforces the directory but records nothing while the transfer
    // is authorized.
    assert!(p.try_check_transfer(&pid, &asset, &listed, &1).is_ok());
    assert_no_event(&env, "PolicyViolation");
}

#[test]
fn recipient_whitelist_is_scoped_per_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_a");
    let pid_a = String::from_str(&env, "wl_a");
    let pid_b = String::from_str(&env, "wl_b");
    p.register_policy(
        &owner,
        &pid_b,
        &BytesN::from_array(&env, &[6; 32]),
        &0,
        &None,
        &None,
        &0,
        &None,
    );
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);

    p.set_recipient_whitelist_enabled(&owner, &pid_a, &true);
    p.add_recipient_to_whitelist(&owner, &pid_a, &vendor);

    // The directory belongs to policy A only.
    assert!(p.is_recipient_whitelisted(&pid_a, &vendor));
    assert!(!p.is_recipient_whitelisted(&pid_b, &vendor));
    assert_eq!(p.get_recipient_whitelist(&pid_b).len(), 0);

    // Policy B enforces an empty directory of its own, so the very same
    // destination stays untrusted there.
    p.set_recipient_whitelist_enabled(&owner, &pid_b, &true);
    assert!(p.try_check_transfer(&pid_a, &asset, &vendor, &1).is_ok());
    assert_eq!(
        p.try_check_transfer(&pid_b, &asset, &vendor, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn recipient_whitelist_queries_reflect_edits() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_q");
    let pid = String::from_str(&env, "wl_q");
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    assert!(!p.is_recipient_whitelisted(&pid, &a));
    assert!(p.get_recipient_whitelist(&pid).is_empty());

    p.add_recipient_to_whitelist(&owner, &pid, &a);
    p.add_recipient_to_whitelist(&owner, &pid, &b);
    assert!(p.is_recipient_whitelisted(&pid, &a));
    assert!(p.is_recipient_whitelisted(&pid, &b));

    let listed = p.get_recipient_whitelist(&pid);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed.get(0), Some(a.clone()));
    assert_eq!(listed.get(1), Some(b.clone()));

    p.remove_recipient_from_whitelist(&owner, &pid, &a);
    assert!(!p.is_recipient_whitelisted(&pid, &a));
    let listed = p.get_recipient_whitelist(&pid);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed.get(0), Some(b));
}

#[test]
fn evaluate_recipient_whitelist_entry_point() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_eval");
    let pid = String::from_str(&env, "wl_eval");
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);
    let payload = TransactionPayload {
        asset: asset.clone(),
        recipient: recipient.clone(),
        amount: 1,
    };

    // Mode off: the entry point is permissive.
    assert_eq!(
        p.try_evaluate_recipient_whitelist(&pid, &payload),
        Ok(Ok(()))
    );

    // Mode on with an empty directory: every destination is denied.
    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    assert_eq!(
        p.try_evaluate_recipient_whitelist(&pid, &payload),
        Err(Ok(Error::PolicyDenied))
    );

    // Listing the destination clears the evaluation.
    p.add_recipient_to_whitelist(&owner, &pid, &recipient);
    assert_eq!(
        p.try_evaluate_recipient_whitelist(&pid, &payload),
        Ok(Ok(()))
    );
    assert_event(&env, "PolicyViolation");
}

#[test]
fn blocklisted_recipient_stays_denied_while_whitelisted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_blk");
    let pid = String::from_str(&env, "wl_blk");
    let asset = Address::generate(&env);
    let bad = Address::generate(&env);

    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    p.add_recipient_to_whitelist(&owner, &pid, &bad);
    assert!(p.try_check_transfer(&pid, &asset, &bad, &1).is_ok());

    // The blocklist runs first: listing an address never resurrects a blocked
    // destination.
    p.add_to_blocklist(&owner, &pid, &bad);
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &bad, &1),
        Err(Ok(Error::PolicyRecipientRestricted))
    );
}

#[test]
fn whitelist_and_scalar_gates_are_conjunctive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_mix");
    let pid = String::from_str(&env, "wl_mix");
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);

    // Tighten the scalar cap to 100 alongside the whitelist gate.
    p.rotate_policy(&owner, &pid, &BytesN::from_array(&env, &[5; 32]), &100);
    p.set_recipient_whitelist_enabled(&owner, &pid, &true);
    p.add_recipient_to_whitelist(&owner, &pid, &vendor);

    // Listed and within the cap: authorized.
    assert!(p.try_check_transfer(&pid, &asset, &vendor, &100).is_ok());
    // Listed but over the cap: still denied by the scalar gate.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &vendor, &101),
        Err(Ok(Error::PolicyDenied))
    );
    // Within the cap but unlisted: denied by the whitelist gate.
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &stranger, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn short_form_whitelist_api_manages_entries() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = whitelist_setup(&env, &owner, "wl_short");
    let pid = String::from_str(&env, "wl_short");
    let asset = Address::generate(&env);
    let a = Address::generate(&env);

    // The concise management API drives the same storage as the explicit
    // recipient-named functions.
    p.set_whitelist_enabled(&owner, &pid, &true);
    p.add_whitelist(&owner, &pid, &a);
    assert!(p.is_recipient_whitelisted(&pid, &a));
    assert!(p.try_check_transfer(&pid, &asset, &a, &1).is_ok());

    p.remove_whitelist(&owner, &pid, &a);
    assert!(!p.is_recipient_whitelisted(&pid, &a));
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &a, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

// --- Policy Combination Strategies (All vs Any) ---

#[test]
fn rule_combination_all_requires_all_rules_to_pass() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "all_strategy");
    let recipient = Address::generate(&env);
    let other_recipient = Address::generate(&env);
    let asset = Address::generate(&env);

    // Register policy with All strategy (explicit)
    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[42; 32]),
        &1000,
        &None,
        &None,
        &0,
        &Some(crate::PolicyCombinationStrategy::All),
    );

    // Add two rules: max 500 AND allowed recipient
    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 500, &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, recipient.clone(), &env),
    );

    // Transfer to allowed recipient with amount within limits: both rules pass
    assert!(p.try_check_transfer(&pid, &asset, &recipient, &400).is_ok());

    // Transfer to allowed recipient with amount exceeding rule limit: first rule fails
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recipient, &600),
        Err(Ok(Error::PolicyDenied))
    );

    // Transfer to different recipient with amount within limits: second rule fails
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &other_recipient, &400),
        Err(Ok(Error::PolicyDenied))
    );

    // Transfer to different recipient with amount exceeding limit: both fail
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &other_recipient, &600),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn rule_combination_all_backward_compatible_default() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "default_all");
    let recipient = Address::generate(&env);
    let asset = Address::generate(&env);

    // Register policy without specifying strategy (defaults to All)
    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[42; 32]),
        &1000,
        &None,
        &None,
        &0,
        &None,
    );

    // Add two rules
    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 500, &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, recipient.clone(), &env),
    );

    // Verify both rules are enforced (All strategy behavior)
    assert!(p.try_check_transfer(&pid, &asset, &recipient, &400).is_ok());
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recipient, &600),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn rule_combination_any_requires_at_least_one_rule_to_pass() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "any_strategy");
    let allowed_recipient_1 = Address::generate(&env);
    let allowed_recipient_2 = Address::generate(&env);
    let blocked_recipient = Address::generate(&env);
    let asset = Address::generate(&env);

    // Register policy with Any strategy
    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[42; 32]),
        &1000,
        &None,
        &None,
        &0,
        &Some(crate::PolicyCombinationStrategy::Any),
    );

    // Add two rules: allowed recipient 1 OR allowed recipient 2
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, allowed_recipient_1.clone(), &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, allowed_recipient_2.clone(), &env),
    );

    // Transfer to recipient matching first rule: passes
    assert!(p
        .try_check_transfer(&pid, &asset, &allowed_recipient_1, &100)
        .is_ok());

    // Transfer to recipient matching second rule: passes
    assert!(p
        .try_check_transfer(&pid, &asset, &allowed_recipient_2, &100)
        .is_ok());

    // Transfer to recipient matching neither rule: fails
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &blocked_recipient, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn rule_combination_any_with_no_rules_allows_transfer() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "any_no_rules");
    let recipient = Address::generate(&env);
    let asset = Address::generate(&env);

    // Register policy with Any strategy but NO rules
    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[42; 32]),
        &1000,
        &None,
        &None,
        &0,
        &Some(crate::PolicyCombinationStrategy::Any),
    );

    // Transfer should be allowed (permissive default for Any with no rules)
    assert!(p.try_check_transfer(&pid, &asset, &recipient, &100).is_ok());
}

#[test]
fn rule_combination_any_with_complex_rules() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "any_complex");
    let asset = Address::generate(&env);

    // Create three recipients
    let recipient_1 = Address::generate(&env);
    let recipient_2 = Address::generate(&env);
    let recipient_3 = Address::generate(&env);

    // Register policy with Any strategy
    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[42; 32]),
        &10000,
        &None,
        &None,
        &0,
        &Some(crate::PolicyCombinationStrategy::Any),
    );

    // Add three rules with different recipients
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, recipient_1.clone(), &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, recipient_2.clone(), &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, recipient_3.clone(), &env),
    );

    // Any recipient in the rules should be allowed
    assert!(p
        .try_check_transfer(&pid, &asset, &recipient_1, &100)
        .is_ok());
    assert!(p
        .try_check_transfer(&pid, &asset, &recipient_2, &100)
        .is_ok());
    assert!(p
        .try_check_transfer(&pid, &asset, &recipient_3, &100)
        .is_ok());

    // A recipient not in any rule should be denied
    let unknown = Address::generate(&env);
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &unknown, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn set_rule_combination_strategy_changes_behavior() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "strategy_change");
    let recipient_1 = Address::generate(&env);
    let recipient_2 = Address::generate(&env);
    let asset = Address::generate(&env);

    // Register policy with All strategy
    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[42; 32]),
        &1000,
        &None,
        &None,
        &0,
        &Some(crate::PolicyCombinationStrategy::All),
    );

    // Add two conflicting recipient rules
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, recipient_1.clone(), &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, recipient_2.clone(), &env),
    );

    // With All strategy: recipient_1 fails second rule
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recipient_1, &100),
        Err(Ok(Error::PolicyDenied))
    );

    // Switch to Any strategy
    p.set_rule_combination_strategy(&owner, &pid, &crate::PolicyCombinationStrategy::Any);

    // Now recipient_1 should pass (it matches first rule)
    assert!(p
        .try_check_transfer(&pid, &asset, &recipient_1, &100)
        .is_ok());

    // Switch back to All strategy
    p.set_rule_combination_strategy(&owner, &pid, &crate::PolicyCombinationStrategy::All);

    // recipient_1 should fail again
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recipient_1, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn set_rule_combination_strategy_requires_owner() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "strategy_auth");

    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[42; 32]),
        &1000,
        &None,
        &None,
        &0,
        &Some(crate::PolicyCombinationStrategy::All),
    );

    // Stranger cannot change strategy
    assert_eq!(
        p.try_set_rule_combination_strategy(
            &stranger,
            &pid,
            &crate::PolicyCombinationStrategy::Any
        ),
        Err(Ok(Error::Unauthorized))
    );

    // Owner can change strategy
    assert!(p
        .try_set_rule_combination_strategy(&owner, &pid, &crate::PolicyCombinationStrategy::Any)
        .is_ok());
}

#[test]
fn rule_combination_any_short_circuits_on_first_pass() {
    // Verify that Any strategy stops evaluating once a rule passes (gas efficiency)
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = composite_setup(&env, &owner);
    let pid = String::from_str(&env, "any_short_circuit");
    let allowed_recipient = Address::generate(&env);
    let asset = Address::generate(&env);

    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[42; 32]),
        &1000,
        &None,
        &None,
        &0,
        &Some(crate::PolicyCombinationStrategy::Any),
    );

    // Add three rules; first will pass
    p.add_policy_rule(
        &owner,
        &pid,
        &single_addr_tree(RuleOp::AllowedRecipient, allowed_recipient.clone(), &env),
    );
    // These would fail but shouldn't be evaluated due to short-circuit
    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 1, &env),
    );
    p.add_policy_rule(
        &owner,
        &pid,
        &single_amount_tree(RuleOp::MaxAmount, 0, &env),
    );

    // Even though amount 100 fails rules 2 and 3, rule 1 passes so transfer is allowed
    assert!(p
        .try_check_transfer(&pid, &asset, &allowed_recipient, &100)
        .is_ok());
}

// ---------------------------------------------------------------------------
// Granular policy decisions (Issue #314)
//
// `evaluate_policy` walks the same rules as `check_transfer` but reports which
// one refused the transaction instead of collapsing every refusal onto
// `PolicyDenied`. These tests pin both halves of that contract: the reason each
// rule reports, and the fact that `check_transfer`'s error codes did not move.
// ---------------------------------------------------------------------------

/// The payload `evaluate_policy` takes, built from the arguments
/// `check_transfer` takes.
fn transfer_payload(asset: &Address, recipient: &Address, amount: i128) -> TransactionPayload {
    TransactionPayload {
        asset: asset.clone(),
        recipient: recipient.clone(),
        amount,
    }
}

#[test]
fn evaluate_policy_allows_a_transfer_within_the_single_transaction_ceiling() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    let decision: PolicyDecision = p.evaluate_policy(
        &String::from_str(&env, "max_txn"),
        &transfer_payload(&asset, &recipient, 1_000_000),
    );
    assert!(decision.allowed());
    assert_eq!(decision.reason(), None);
    // The ceiling in force is reported alongside the decision, so a caller that
    // was refused can size a retry without a second read.
    assert_eq!(decision.max_transaction_amount, 1_000_000);
}

#[test]
fn evaluate_policy_names_the_single_transaction_ceiling_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    let decision = p.evaluate_policy(
        &String::from_str(&env, "max_txn"),
        &transfer_payload(&asset, &recipient, 1_000_001),
    );
    assert!(!decision.allowed());
    assert_eq!(
        decision.reason(),
        Some(PolicyDenialReason::AboveMaxTransactionLimit)
    );
    // The collapsed code is unchanged: existing callers still see PolicyDenied.
    assert_eq!(decision.reason().unwrap().to_error(), Error::PolicyDenied);
}

#[test]
fn evaluate_policy_names_the_unapproved_destination_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let stranger = Address::generate(&env);
    let asset = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(&env, &id);
    client.initialize();
    client.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &Some(allowed.clone()),
        &None,
        &0,
        &None,
    );

    let ok = client.evaluate_policy(
        &String::from_str(&env, "vendor_list"),
        &transfer_payload(&asset, &allowed, 10),
    );
    assert!(ok.allowed());
    assert_eq!(ok.reason(), None);

    let denied = client.evaluate_policy(
        &String::from_str(&env, "vendor_list"),
        &transfer_payload(&asset, &stranger, 10),
    );
    assert_eq!(
        denied.reason(),
        Some(PolicyDenialReason::RecipientNotAllowed)
    );
    assert_eq!(denied.reason().unwrap().as_str(), "bad_recipient");
}

#[test]
fn evaluate_policy_names_the_recipient_whitelist_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let approved = Address::generate(&env);
    let untrusted = Address::generate(&env);

    p.add_recipient_to_whitelist(&owner, &policy_id, &approved);
    p.set_recipient_whitelist_enabled(&owner, &policy_id, &true);

    let ok = p.evaluate_policy(&policy_id, &transfer_payload(&asset, &approved, 10));
    assert!(ok.allowed());

    let denied = p.evaluate_policy(&policy_id, &transfer_payload(&asset, &untrusted, 10));
    assert_eq!(
        denied.reason(),
        Some(PolicyDenialReason::RecipientNotWhitelisted)
    );
}

#[test]
fn evaluate_policy_names_the_blacklist_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let blocked = Address::generate(&env);

    p.add_to_blocklist(&owner, &policy_id, &blocked);

    let denied = p.evaluate_policy(&policy_id, &transfer_payload(&asset, &blocked, 10));
    assert_eq!(
        denied.reason(),
        Some(PolicyDenialReason::RecipientBlacklisted)
    );
    assert_eq!(
        denied.reason().unwrap().to_error(),
        Error::PolicyRecipientRestricted
    );
}

#[test]
fn evaluate_policy_names_a_disabled_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    p.set_enabled(&owner, &policy_id, &false);
    let denied = p.evaluate_policy(&policy_id, &transfer_payload(&asset, &recipient, 10));
    assert_eq!(denied.reason(), Some(PolicyDenialReason::Disabled));
}

#[test]
fn evaluate_policy_reserves_errors_for_malformed_input_and_unknown_policies() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    // A policy refusal is a decision, never an `Err`...
    assert!(p
        .try_evaluate_policy(&policy_id, &transfer_payload(&asset, &recipient, 9_999_999))
        .is_ok());
    // ...while a malformed amount and an unknown policy stay errors.
    assert_eq!(
        p.try_evaluate_policy(&policy_id, &transfer_payload(&asset, &recipient, 0)),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(
        p.try_evaluate_policy(
            &String::from_str(&env, "ghost"),
            &transfer_payload(&asset, &recipient, 10)
        ),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn evaluate_policy_agrees_with_check_transfer_on_every_refusal() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    // The dry run reports the reason, and mapping it back onto an error must
    // reproduce exactly what the enforcement path returns.
    let decision = p.evaluate_policy(&policy_id, &transfer_payload(&asset, &recipient, 1_000_001));
    let mapped = decision
        .reason()
        .expect("the ceiling must refuse this")
        .to_error();
    assert_eq!(
        p.try_check_transfer(&policy_id, &asset, &recipient, &1_000_001),
        Err(Ok(mapped))
    );

    // A blacklisted recipient is refused by the same rule on both paths.
    let blocked = Address::generate(&env);
    p.add_to_blocklist(&owner, &policy_id, &blocked);
    let decision = p.evaluate_policy(&policy_id, &transfer_payload(&asset, &blocked, 10));
    let mapped = decision
        .reason()
        .expect("the blocklist must refuse this")
        .to_error();
    assert_eq!(mapped, Error::PolicyRecipientRestricted);
    assert_eq!(
        p.try_check_transfer(&policy_id, &asset, &blocked, &10),
        Err(Ok(mapped))
    );
}

#[test]
fn evaluate_policy_reports_each_rule_exactly_once() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    // A refusal is reported once at the boundary, not once per rule: the
    // dry run publishes exactly the violation the enforcement path publishes
    // (the legacy tuple topic plus the canonical schema), never an extra copy.
    let before = env.events().all().len();
    let decision = p.evaluate_policy(&policy_id, &transfer_payload(&asset, &recipient, 1_000_001));
    assert!(!decision.allowed());
    let published = env.events().all().len() - before;

    let before = env.events().all().len();
    assert_eq!(
        p.try_check_transfer(&policy_id, &asset, &recipient, &1_000_001),
        Err(Ok(Error::PolicyDenied))
    );
    let enforced = env.events().all().len() - before;
    assert_eq!(
        published, enforced,
        "the dry run must report exactly what the write path reports"
    );
}

// ---------------------------------------------------------------------------
// Transfer time windows (operating hours)
// ---------------------------------------------------------------------------

const SECONDS_PER_DAY: u64 = 86_400;

/// Register a policy and confine it to the daily operating window
/// `start → end` (seconds since midnight UTC) repeating every `window_days`
/// seconds. Returns the client and the policy id.
fn time_window_setup<'a>(
    env: &Env,
    owner: &Address,
    policy_id: &str,
    start: u64,
    end: u64,
    window_days: u64,
) -> (PolicyContractClient<'a>, String) {
    let id = env.register_contract(None, PolicyContract);
    let p = PolicyContractClient::new(env, &id);
    p.initialize();
    let pid = String::from_str(env, policy_id);
    p.register_policy(
        owner,
        &pid,
        &BytesN::from_array(env, &[7u8; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
        &None,
    );
    p.set_transfer_window(owner, &pid, &start, &end, &window_days);
    (p, pid)
}

#[test]
fn transfer_allowed_inside_operating_window() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    // 09:00–17:00 UTC, standard day.
    let (p, pid) = time_window_setup(&env, &owner, "hours", 9 * 3600, 17 * 3600, SECONDS_PER_DAY);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Valid ledger timestamps: 10:00 and 16:59 on day 1.
    env.ledger().set_timestamp(86_400 + 10 * 3600);
    assert!(p.try_check_transfer(&pid, &asset, &recip, &100).is_ok());
    env.ledger().set_timestamp(86_400 + 16 * 3600 + 59 * 60);
    assert!(p.try_check_transfer(&pid, &asset, &recip, &100).is_ok());
}

#[test]
fn transfer_denied_outside_operating_window() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (p, pid) = time_window_setup(&env, &owner, "hours", 9 * 3600, 17 * 3600, SECONDS_PER_DAY);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Expired-window ledger timestamps: 06:00 and 23:59 on day 1.
    env.ledger().set_timestamp(6 * 3600);
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );
    env.ledger().set_timestamp(23 * 3600 + 59 * 60);
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recip, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn window_boundaries_are_start_inclusive_and_end_exclusive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (p, pid) = time_window_setup(&env, &owner, "hours", 9 * 3600, 17 * 3600, SECONDS_PER_DAY);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Exactly the start instant is inside; exactly the end instant is outside.
    env.ledger().set_timestamp(9 * 3600);
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());
    env.ledger().set_timestamp(17 * 3600);
    assert_eq!(
        p.try_check_transfer(&pid, &asset, &recip, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn window_denial_emits_policy_violation_event() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (p, pid) = time_window_setup(&env, &owner, "hours", 9 * 3600, 17 * 3600, SECONDS_PER_DAY);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    env.ledger().set_timestamp(2 * 3600);
    let _ = p.try_check_transfer(&pid, &asset, &recip, &1);
    assert_event(&env, "PolicyViolation");
}

#[test]
fn window_wraps_over_midnight() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    // Night window 22:00 → 06:00 crossing the day boundary.
    let (p, pid) = time_window_setup(&env, &owner, "night", 22 * 3600, 6 * 3600, SECONDS_PER_DAY);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    for now in [23u64 * 3600, 86_400, 86_400 + 5 * 3600] {
        env.ledger().set_timestamp(now);
        assert!(
            p.try_check_transfer(&pid, &asset, &recip, &1).is_ok(),
            "transfer at {} must be inside the night window",
            now
        );
    }
    for now in [6u64 * 3600, 12 * 3600, 21 * 3600 + 59 * 60] {
        env.ledger().set_timestamp(now);
        assert_eq!(
            p.try_check_transfer(&pid, &asset, &recip, &1),
            Err(Ok(Error::PolicyDenied)),
            "transfer at {} must be outside the night window",
            now
        );
    }
}

#[test]
fn zero_length_window_fails_closed_and_blocks_everything() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (p, pid) = time_window_setup(&env, &owner, "shut", 9 * 3600, 9 * 3600, SECONDS_PER_DAY);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    for now in [0u64, 9 * 3600, 86_400 + 9 * 3600 + 1, 172_800] {
        env.ledger().set_timestamp(now);
        assert_eq!(
            p.try_check_transfer(&pid, &asset, &recip, &1),
            Err(Ok(Error::PolicyDenied)),
            "zero-length window must deny at {}",
            now
        );
    }
}

#[test]
fn policies_without_a_window_keep_the_permissive_default() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    assert_eq!(p.get_transfer_window(&pid), (0, 0, 0));
    // Every timestamp is fine when no window is configured.
    for now in [0u64, 1, 3_600, 86_399, 500_000] {
        env.ledger().set_timestamp(now);
        assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());
    }
}

#[test]
fn clearing_the_window_restores_full_access() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (p, pid) = time_window_setup(&env, &owner, "hours", 9 * 3600, 17 * 3600, SECONDS_PER_DAY);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    env.ledger().set_timestamp(3 * 3600);
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_err());

    // `window_days == 0` clears the restriction.
    p.set_transfer_window(&owner, &pid, &0, &0, &0);
    assert_eq!(p.get_transfer_window(&pid), (0, 0, 0));
    assert!(p.try_check_transfer(&pid, &asset, &recip, &1).is_ok());
}

#[test]
fn window_rejects_bounds_outside_the_configured_day() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let p = PolicyContractClient::new(&env, &id);
    p.initialize();
    let pid = String::from_str(&env, "hours");
    p.register_policy(
        &owner,
        &pid,
        &BytesN::from_array(&env, &[7u8; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
        &None,
    );

    // A bound at or past the day length can never occur inside that day.
    assert_eq!(
        p.try_set_transfer_window(&owner, &pid, &(SECONDS_PER_DAY + 1), &100, &SECONDS_PER_DAY),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        p.try_set_transfer_window(&owner, &pid, &100, &SECONDS_PER_DAY, &SECONDS_PER_DAY),
        Err(Ok(Error::InvalidInput))
    );
    // A day longer than one calendar month is rejected as a likely unit mix-up.
    assert_eq!(
        p.try_set_transfer_window(&owner, &pid, &100, &200, &(2_592_001)),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn window_config_requires_the_policy_owner() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (p, pid) = time_window_setup(&env, &owner, "hours", 9 * 3600, 17 * 3600, SECONDS_PER_DAY);
    let stranger = Address::generate(&env);

    assert_eq!(
        p.try_set_transfer_window(&stranger, &pid, &0, &100, &SECONDS_PER_DAY),
        Err(Ok(Error::Unauthorized))
    );
    // The configured window is untouched by the rejected call.
    assert_eq!(
        p.get_transfer_window(&pid),
        (9 * 3600, 17 * 3600, SECONDS_PER_DAY)
    );
}

#[test]
fn unknown_policy_reports_no_window() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, PolicyContract);
    let p = PolicyContractClient::new(&env, &id);
    p.initialize();
    assert_eq!(
        p.get_transfer_window(&String::from_str(&env, "ghost")),
        (0, 0, 0)
    );
}

#[test]
fn time_window_gates_multi_asset_spends_too() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (p, pid) = time_window_setup(&env, &owner, "hours", 9 * 3600, 17 * 3600, SECONDS_PER_DAY);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let amounts = vec![
        &env,
        AssetAmount {
            asset: asset.clone(),
            amount: 50,
        },
    ];

    // Outside the window the whole multi-asset request is denied...
    env.ledger().set_timestamp(5 * 3600);
    assert_eq!(
        p.try_check_multi_asset_transfer(&pid, &recip, &amounts),
        Err(Ok(Error::PolicyDenied))
    );

    // ...and inside it the request evaluates normally.
    env.ledger().set_timestamp(12 * 3600);
    assert!(p
        .try_check_multi_asset_transfer(&pid, &recip, &amounts)
        .is_ok());
}

#[test]
fn time_window_is_persisted_on_the_policy_record() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (p, pid) = time_window_setup(&env, &owner, "hours", 22 * 3600, 6 * 3600, SECONDS_PER_DAY);

    assert_eq!(
        p.get_transfer_window(&pid),
        (22 * 3600, 6 * 3600, SECONDS_PER_DAY)
    );
    let policy = p.get(&pid);
    assert_eq!(policy.window_start_time, 22 * 3600);
    assert_eq!(policy.window_end_time, 6 * 3600);
    assert_eq!(policy.window_days, SECONDS_PER_DAY);
    assert!(policy.enabled);
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
fn enable_toggles_emit_standardized_events_with_identifiers_and_timestamp() {
    // Issue #222 — the master enable switch used to mutate storage silently.
    // It now publishes under the standard (policy, action) schema: identifiers
    // first, ledger timestamp last.
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, "max_txn");

    assert_eq!(event_count(&env, "policy", "enabled"), 0);
    p.set_enabled(&owner, &policy_id.clone(), &false);
    assert_eq!(event_count(&env, "policy", "enabled"), 1);

    let payload = event_payload(&env, "policy", "enabled").expect("enabled payload");
    assert_eq!(payload.len(), 3);
    assert_eq!(
        String::try_from_val(&env, &payload.get(0).unwrap()).unwrap(),
        policy_id
    );
    assert!(!bool::try_from_val(&env, &payload.get(1).unwrap()).unwrap());
    assert_eq!(
        u64::try_from_val(&env, &payload.get(2).unwrap()).unwrap(),
        1_700_000_000
    );

    // One event per state change — toggling back is announced again.
    p.set_enabled(&owner, &policy_id.clone(), &true);
    assert_eq!(event_count(&env, "policy", "enabled"), 2);

    // A refused toggle (not the policy's owner) changes nothing and emits
    // nothing: the failed invocation rolls its events back with it.
    let stranger = Address::generate(&env);
    assert_eq!(
        p.try_set_enabled(&stranger, &policy_id, &false),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(event_count(&env, "policy", "enabled"), 2);
}

#[test]
fn asset_whitelist_mode_toggle_emits_its_own_standardized_topic() {
    // Issue #222 — the asset-whitelist switch also mutated storage silently.
    // It gets its own namespaced topic so an indexer can tell the two
    // whitelists apart, on the same (policy_id, enabled, timestamp) schema.
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, "max_txn");

    assert_eq!(event_count(&env, "policy", "awl_mode"), 0);
    p.set_asset_whitelist_enabled(&owner, &policy_id.clone(), &true);
    assert_eq!(event_count(&env, "policy", "awl_mode"), 1);

    let payload = event_payload(&env, "policy", "awl_mode").expect("awl_mode payload");
    assert_eq!(payload.len(), 3);
    assert_eq!(
        String::try_from_val(&env, &payload.get(0).unwrap()).unwrap(),
        policy_id
    );
    assert!(bool::try_from_val(&env, &payload.get(1).unwrap()).unwrap());
    assert_eq!(
        u64::try_from_val(&env, &payload.get(2).unwrap()).unwrap(),
        1_700_000_000
    );

    // The recipient-whitelist toggle keeps its own distinct topic, so the two
    // whitelists stay separable — and each fires exactly once.
    p.set_recipient_whitelist_enabled(&owner, &String::from_str(&env, "max_txn"), &true);
    assert_eq!(event_count(&env, "policy", "wl_mode"), 1);
    assert_eq!(event_count(&env, "policy", "awl_mode"), 1);
}
