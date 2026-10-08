#![cfg(test)]
extern crate std;

use crate::{
    BoundHash, DataKey, RegistryContract, RegistryContractClient, RegistryRole, VersionRecord,
};
use astroid_shared::constants::{MAX_REGISTRY_BATCH, PERSISTENT_BUMP_AMOUNT};
use astroid_shared::errors::Error;
use astroid_shared::types::{ModuleId, ModuleInfo, ModuleKind};
use soroban_sdk::testutils::{storage::Persistent as _, Address as _, AuthorizedFunction, Ledger};
use soroban_sdk::{
    symbol_short, testutils::Events, vec, Address, BytesN, Env, IntoVal, String, Symbol, Val, Vec,
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

fn setup() -> (Env, RegistryContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

#[test]
fn initialize_sets_admin() {
    let (_env, client, admin) = setup();
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn initialize_twice_fails() {
    let (env, client, _admin) = setup();
    let other = Address::generate(&env);
    let res = client.try_initialize(&other);
    assert_eq!(res, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn register_and_lookup_org_and_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    assert_eq!(client.get_org_owner(&org), owner);
    assert!(client.verify_owner(&org, &owner));

    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn duplicate_org_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_register_org(&admin, &org, &owner);
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn non_admin_cannot_register_org() {
    let (env, client, _admin) = setup();
    let intruder = Address::generate(&env);
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    let res = client.try_register_org(&intruder, &org, &owner);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn lookup_missing_module_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_lookup(&org, &ModuleKind::Treasury);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn org_owner_can_transfer_ownership() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    let new_owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    client.set_org_owner(&owner, &org, &new_owner);
    assert_eq!(client.get_org_owner(&org), new_owner);
}

#[test]
fn stranger_cannot_transfer_ownership() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_set_org_owner(&stranger, &org, &stranger);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn version_lookup_upgrade_strategy() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2, &h2);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), v1);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &2), v2);
    // Latest points at the highest registered version.
    assert_eq!(client.get_latest(&ModuleKind::Wallet), v2);
}

#[test]
fn register_version_zero_fails() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let res = client.try_register_version(&admin, &ModuleKind::Wallet, &0, &addr, &h);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

// --- Version registration: auth, hash integrity, immutability (Issue #217) ---

/// Approve `[seed; 32]` for `kind` and return it.
fn approved_hash(
    env: &Env,
    client: &RegistryContractClient,
    admin: &Address,
    kind: ModuleKind,
    seed: u8,
) -> BytesN<32> {
    let h = BytesN::from_array(env, &[seed; 32]);
    client.add_approved_wasm(admin, &kind, &h);
    h
}

#[test]
fn register_version_binds_hash_and_is_retrievable() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Policy, 7);

    client.register_version(&admin, &ModuleKind::Policy, &3, &addr, &h);

    assert_eq!(client.get_version(&ModuleKind::Policy, &3), addr);
    assert_eq!(client.get_version_wasm(&ModuleKind::Policy, &3), h);
    assert_eq!(client.get_latest(&ModuleKind::Policy), addr);
    assert_eq!(client.verify_version(&ModuleKind::Policy, &3, &h), addr);
}

#[test]
fn register_version_demands_the_admin_signature() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);

    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);

    // The admin's signature was required for exactly this invocation.
    let auths = env.auths();
    assert_eq!(auths.len(), 1);
    let (signer, invocation) = &auths[0];
    assert_eq!(signer, &admin);
    match &invocation.function {
        AuthorizedFunction::Contract((contract, function, _args)) => {
            assert_eq!(contract, &client.address);
            assert_eq!(function, &Symbol::new(&env, "register_version"));
        }
        _ => panic!("expected a contract invocation"),
    }
}

#[test]
fn register_version_without_any_signature_is_rejected() {
    let env = Env::default();
    let contract_id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let h = BytesN::from_array(&env, &[1; 32]);
    let addr = Address::generate(&env);

    // Approving and registering both need the admin's auth; with no auth
    // mocked the host refuses before anything is written.
    assert!(client
        .try_add_approved_wasm(&admin, &ModuleKind::Wallet, &h)
        .is_err());
    assert!(client
        .try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h)
        .is_err());
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn non_admin_cannot_register_version() {
    let (env, client, admin, org, owner) = setup_org();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let stranger = Address::generate(&env);
    let upgrader = Address::generate(&env);
    client.grant_role(&owner, &org, &upgrader, &RegistryRole::ModuleUpgrader);

    // Neither a stranger, an org owner, nor an org-scoped ModuleUpgrader may
    // write the global version map: it is protocol-admin only.
    for caller in [&stranger, &owner, &upgrader] {
        assert_eq!(
            client.try_register_version(caller, &ModuleKind::Wallet, &1, &addr, &h),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_latest(&ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn non_admin_cannot_approve_wasm() {
    let (env, client, admin) = setup();
    let stranger = Address::generate(&env);
    let h = BytesN::from_array(&env, &[9; 32]);
    assert_eq!(
        client.try_add_approved_wasm(&stranger, &ModuleKind::Wallet, &h),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!client.is_wasm_approved(&ModuleKind::Wallet, &h));

    client.add_approved_wasm(&admin, &ModuleKind::Wallet, &h);
    assert_eq!(
        client.try_remove_approved_wasm(&stranger, &ModuleKind::Wallet, &h),
        Err(Ok(Error::Unauthorized))
    );
    assert!(client.is_wasm_approved(&ModuleKind::Wallet, &h));
}

#[test]
fn register_version_rejects_unapproved_hash() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let unapproved = BytesN::from_array(&env, &[42; 32]);

    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &unapproved),
        Err(Ok(Error::Unauthorized))
    );
    // A rejected registration writes nothing, including the latest pointer.
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_version_wasm(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_latest(&ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn register_version_rejects_hash_approved_for_another_kind() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let treasury_code = approved_hash(&env, &client, &admin, ModuleKind::Treasury, 5);

    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &treasury_code),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn register_version_rejects_revoked_hash() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.remove_approved_wasm(&admin, &ModuleKind::Wallet, &h);

    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn registered_version_cannot_be_repointed() {
    let (env, client, admin) = setup();
    let original = Address::generate(&env);
    let hijack = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &original, &h1);

    // Even the admin with an approved hash cannot overwrite a published
    // version, so a consumer pinned to v1 keeps getting v1.
    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &hijack, &h2),
        Err(Ok(Error::AlreadyExists))
    );
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), original);
    assert_eq!(client.get_version_wasm(&ModuleKind::Wallet, &1), h1);
}

#[test]
fn same_version_number_is_independent_per_kind() {
    let (env, client, admin) = setup();
    let wallet_v1 = Address::generate(&env);
    let policy_v1 = Address::generate(&env);
    let hw = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let hp = approved_hash(&env, &client, &admin, ModuleKind::Policy, 2);

    client.register_version(&admin, &ModuleKind::Wallet, &1, &wallet_v1, &hw);
    client.register_version(&admin, &ModuleKind::Policy, &1, &policy_v1, &hp);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), wallet_v1);
    assert_eq!(client.get_version(&ModuleKind::Policy, &1), policy_v1);
}

#[test]
fn backfilled_older_version_does_not_move_latest() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let v5 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h5 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 5);

    client.register_version(&admin, &ModuleKind::Wallet, &5, &v5, &h5);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    assert_eq!(client.get_latest(&ModuleKind::Wallet), v5);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), v1);
}

#[test]
fn frozen_registry_blocks_version_registration() {
    let (env, client, admin, org, owner) = setup_org();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.freeze(&owner, &org);

    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h),
        Err(Ok(Error::RegistryFrozen))
    );
    client.unfreeze(&owner, &org);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), addr);
}

#[test]
fn unknown_version_keys_fail_with_not_found() {
    let (env, client, admin) = setup();
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);

    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_version_wasm(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_latest(&ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &1, &h),
        Err(Ok(Error::NotFound))
    );

    // A registered kind still reports NotFound for a version it lacks.
    let addr = Address::generate(&env);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &2),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &2, &h),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn verify_version_rejects_mismatched_hash() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let other = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h1);

    // Approved, but not the code v1 was registered with.
    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &1, &other),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(client.verify_version(&ModuleKind::Wallet, &1, &h1), addr);
}

#[test]
fn verify_version_fails_once_the_bound_hash_is_revoked() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);
    client.remove_approved_wasm(&admin, &ModuleKind::Wallet, &h);

    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &1, &h),
        Err(Ok(Error::Unauthorized))
    );
    // The record itself is untouched; only its verification now fails.
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), addr);
}

#[test]
fn legacy_version_without_bound_hash_never_verifies() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    // A record written before hashes were bound: address only.
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .set(&DataKey::Version(ModuleKind::Wallet, 1), &addr);
    });

    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), addr);
    assert_eq!(
        client.try_get_version_wasm(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &1, &h),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn version_registration_emits_structured_event() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Escrow, 3);

    client.register_version(&admin, &ModuleKind::Escrow, &4, &addr, &h);

    let want_topic: Val = Symbol::new(&env, "RegistryVersionRegistered").into_val(&env);
    let event = env
        .events()
        .all()
        .iter()
        .find(|(_id, topics, _data)| topics.contains(want_topic))
        .expect("RegistryVersionRegistered must be emitted");
    assert_eq!(event.0, client.address);
    let data: (ModuleKind, u32, Address, BytesN<32>) = event.2.into_val(&env);
    assert_eq!(data, (ModuleKind::Escrow, 4, addr.clone(), h));

    // The legacy tuple-topic event is still published for existing consumers.
    let legacy: Vec<Val> = (
        symbol_short!("version"),
        symbol_short!("register"),
        ModuleKind::Escrow,
        4u32,
    )
        .into_val(&env);
    assert!(env
        .events()
        .all()
        .iter()
        .any(|(_id, topics, _data)| topics == legacy));
}

#[test]
fn rejected_registration_emits_no_version_event() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let unapproved = BytesN::from_array(&env, &[1; 32]);
    let _ = client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &unapproved);

    let want_topic: Val = Symbol::new(&env, "RegistryVersionRegistered").into_val(&env);
    assert!(!env
        .events()
        .all()
        .iter()
        .any(|(_id, topics, _data)| topics.contains(want_topic)));
}

#[test]
fn remove_module_works_and_missing_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    client.remove_module(&owner, &org, &ModuleKind::Wallet);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    // Removing again fails.
    assert_eq!(
        client.try_remove_module(&owner, &org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn deprecate_module_blocks_lookup_but_allows_legacy_read() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);

    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    assert!(client.is_module_deprecated(&org, &ModuleKind::Wallet));
    // Routing rejects new interactions targeting the deprecated module.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );
    // ...but the raw address stays readable for legacy migrations.
    assert_eq!(client.get_module_address(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn non_admin_cannot_deprecate_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    // Neither a stranger nor even the org owner may deprecate: admin-only.
    let intruder = Address::generate(&env);
    assert_eq!(
        client.try_deprecate_module(&intruder, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_deprecate_module(&owner, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
}

#[test]
fn deprecate_missing_module_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_deprecate_module(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn reactivate_module_restores_routing() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);

    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );
    client.reactivate_module(&admin, &org, &ModuleKind::Wallet);
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn re_registered_module_clears_deprecation() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    // Re-pointing the module at a new implementation clears the flag so the
    // freshly registered address is routable immediately.
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v2);
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), v2);
}

#[test]
fn removed_deprecated_module_returns_not_found() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    client.remove_module(&owner, &org, &ModuleKind::Wallet);
    // Removing the record also removes its deprecation flag.
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn admin_rotation() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);
    client.set_admin(&admin, &new_admin);
    assert_eq!(client.get_admin(), new_admin);
    // Old admin can no longer act.
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    assert_eq!(
        client.try_register_org(&admin, &org, &owner),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn standard_events_emitted() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    assert_event(&env, "RegistryModuleUpdated");

    let new_owner = Address::generate(&env);
    client.set_org_owner(&owner, &org, &new_owner);
    assert_event(&env, "OrgOwnerChanged");

    client.freeze(&new_owner, &org);
    assert_event(&env, "RegistryFrozen");
}

// ---------------------------------------------------------------------------
// Role-based permission delegation
// ---------------------------------------------------------------------------

/// A registry with one registered organization, returning the org slug and its
/// owner alongside the usual handles.
fn setup_org() -> (
    Env,
    RegistryContractClient<'static>,
    Address,
    String,
    Address,
) {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    (env, client, admin, org, owner)
}

#[test]
fn owner_is_implicitly_owner_role() {
    let (env, client, _admin, org, owner) = setup_org();
    assert_eq!(client.get_role(&org, &owner), Some(RegistryRole::Owner));
    assert!(client.can_manage_module(&org, &owner, &ModuleKind::Policy));
    assert!(client.can_manage_module(&org, &owner, &ModuleKind::Treasury));

    let stranger = Address::generate(&env);
    assert_eq!(client.get_role(&org, &stranger), None);
    assert!(!client.can_manage_module(&org, &stranger, &ModuleKind::Policy));
}

#[test]
fn granted_role_is_readable_and_revocable() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);

    client.grant_role(&owner, &org, &delegate, &RegistryRole::PolicyManager);
    assert_eq!(
        client.get_role(&org, &delegate),
        Some(RegistryRole::PolicyManager)
    );

    // Re-granting replaces rather than stacks.
    client.grant_role(&owner, &org, &delegate, &RegistryRole::TreasuryOperator);
    assert_eq!(
        client.get_role(&org, &delegate),
        Some(RegistryRole::TreasuryOperator)
    );

    client.revoke_role(&owner, &org, &delegate);
    assert_eq!(client.get_role(&org, &delegate), None);

    // Revoking again is an explicit failure, not a silent no-op.
    assert_eq!(
        client.try_revoke_role(&owner, &org, &delegate),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn policy_manager_reaches_only_the_policy_module() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::PolicyManager);

    client.register_module(&delegate, &org, &ModuleKind::Policy, &addr);
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), addr);

    for kind in [ModuleKind::Treasury, ModuleKind::Wallet, ModuleKind::Budget] {
        assert!(!client.can_manage_module(&org, &delegate, &kind));
        assert_eq!(
            client.try_register_module(&delegate, &org, &kind, &addr),
            Err(Ok(Error::Unauthorized))
        );
        assert_eq!(client.try_lookup(&org, &kind), Err(Ok(Error::NotFound)));
    }
}

#[test]
fn treasury_operator_reaches_the_value_custody_modules() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::TreasuryOperator);

    for kind in [ModuleKind::Treasury, ModuleKind::Budget, ModuleKind::Escrow] {
        assert!(client.can_manage_module(&org, &delegate, &kind));
        client.register_module(&delegate, &org, &kind, &addr);
        assert_eq!(client.lookup(&org, &kind), addr);
    }

    // ...but not the policy that governs them.
    assert!(!client.can_manage_module(&org, &delegate, &ModuleKind::Policy));
    assert_eq!(
        client.try_register_module(&delegate, &org, &ModuleKind::Policy, &addr),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn module_upgrader_may_repoint_any_module() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::ModuleUpgrader);

    client.register_module(&delegate, &org, &ModuleKind::Wallet, &v2);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), v2);
    client.register_module(&delegate, &org, &ModuleKind::Policy, &v2);
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), v2);
}

#[test]
fn delegated_owner_reaches_every_module_kind() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::Owner);

    for kind in [
        ModuleKind::Wallet,
        ModuleKind::Treasury,
        ModuleKind::Policy,
        ModuleKind::Escrow,
    ] {
        client.register_module(&delegate, &org, &kind, &addr);
        assert_eq!(client.lookup(&org, &kind), addr);
    }
}

#[test]
fn delegates_may_remove_modules_they_may_register() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Policy, &addr);
    client.register_module(&owner, &org, &ModuleKind::Treasury, &addr);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::PolicyManager);

    client.remove_module(&delegate, &org, &ModuleKind::Policy);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
    // The removal gate matches the registration gate exactly.
    assert_eq!(
        client.try_remove_module(&delegate, &org, &ModuleKind::Treasury),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(client.lookup(&org, &ModuleKind::Treasury), addr);
}

#[test]
fn unauthorized_accounts_are_rejected() {
    let (env, client, _admin, org, _owner) = setup_org();
    let stranger = Address::generate(&env);
    let addr = Address::generate(&env);

    assert_eq!(
        client.try_register_module(&stranger, &org, &ModuleKind::Wallet, &addr),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_remove_module(&stranger, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn delegates_cannot_administer_roles_or_ownership() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let accomplice = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::Owner);

    // Even the broadest delegated role cannot mint further delegations...
    assert_eq!(
        client.try_grant_role(&delegate, &org, &accomplice, &RegistryRole::Owner),
        Err(Ok(Error::Unauthorized))
    );
    // ...revoke its way around the owner...
    assert_eq!(
        client.try_revoke_role(&delegate, &org, &delegate),
        Err(Ok(Error::Unauthorized))
    );
    // ...or escalate into ownership.
    assert_eq!(
        client.try_set_org_owner(&delegate, &org, &delegate),
        Err(Ok(Error::Unauthorized))
    );

    assert_eq!(client.get_role(&org, &accomplice), None);
    assert_eq!(client.get_org_owner(&org), owner);
}

#[test]
fn protocol_admin_may_administer_roles() {
    let (env, client, admin, org, _owner) = setup_org();
    let delegate = Address::generate(&env);

    client.grant_role(&admin, &org, &delegate, &RegistryRole::ModuleUpgrader);
    assert_eq!(
        client.get_role(&org, &delegate),
        Some(RegistryRole::ModuleUpgrader)
    );
    client.revoke_role(&admin, &org, &delegate);
    assert_eq!(client.get_role(&org, &delegate), None);
}

#[test]
fn revoked_delegate_loses_access_immediately() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::PolicyManager);
    client.register_module(&delegate, &org, &ModuleKind::Policy, &addr);

    client.revoke_role(&owner, &org, &delegate);
    assert_eq!(
        client.try_register_module(&delegate, &org, &ModuleKind::Policy, &addr),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn roles_do_not_leak_between_organizations() {
    let (env, client, admin, org_a, owner_a) = setup_org();
    let org_b = String::from_str(&env, "globex");
    let owner_b = Address::generate(&env);
    client.register_org(&admin, &org_b, &owner_b);

    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner_a, &org_a, &delegate, &RegistryRole::PolicyManager);

    client.register_module(&delegate, &org_a, &ModuleKind::Policy, &addr);
    assert_eq!(client.get_role(&org_b, &delegate), None);
    assert_eq!(
        client.try_register_module(&delegate, &org_b, &ModuleKind::Policy, &addr),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn owner_cannot_be_assigned_a_role() {
    let (_env, client, _admin, org, owner) = setup_org();
    // The owner already reaches every kind; recording a narrower role for them
    // would be misleading rather than restrictive.
    assert_eq!(
        client.try_grant_role(&owner, &org, &owner, &RegistryRole::PolicyManager),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(client.get_role(&org, &owner), Some(RegistryRole::Owner));
}

#[test]
fn role_administration_on_an_unknown_org_fails() {
    let (env, client, admin, _org, _owner) = setup_org();
    let ghost = String::from_str(&env, "nowhere");
    let account = Address::generate(&env);

    assert_eq!(
        client.try_grant_role(&admin, &ghost, &account, &RegistryRole::Owner),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_revoke_role(&admin, &ghost, &account),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(client.get_role(&ghost, &account), None);
}

#[test]
fn frozen_registry_blocks_grants_and_delegated_writes() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let other = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::Owner);
    client.freeze(&owner, &org);

    assert_eq!(
        client.try_register_module(&delegate, &org, &ModuleKind::Wallet, &addr),
        Err(Ok(Error::RegistryFrozen))
    );
    assert_eq!(
        client.try_grant_role(&owner, &org, &other, &RegistryRole::Owner),
        Err(Ok(Error::RegistryFrozen))
    );

    // Revocation stays available while frozen so an owner can always withdraw
    // access during an incident.
    client.revoke_role(&owner, &org, &delegate);
    assert_eq!(client.get_role(&org, &delegate), None);
}

// --- registry-gated upgrades ---

/// Two independent registry instances: `registry` plays the protocol registry
/// that authorizes implementations, `member` plays a contract being upgraded
/// (every member contract carries the same three upgrade entrypoints).
struct UpgradeHarness {
    env: Env,
    registry: RegistryContractClient<'static>,
    registry_id: Address,
    member: RegistryContractClient<'static>,
    admin: Address,
}

fn setup_upgrade() -> UpgradeHarness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);

    let member_id = env.register_contract(None, RegistryContract);
    let member = RegistryContractClient::new(&env, &member_id);
    member.initialize(&admin);

    UpgradeHarness {
        env,
        registry,
        registry_id,
        member,
        admin,
    }
}

fn hash(env: &Env, seed: u8) -> soroban_sdk::BytesN<32> {
    soroban_sdk::BytesN::from_array(env, &[seed; 32])
}

#[test]
fn upgrade_authority_is_recorded_and_readable() {
    let h = setup_upgrade();
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    let authority = h.member.get_upgrade_authority();
    assert_eq!(authority.admin, h.admin);
    assert_eq!(authority.registry, h.registry_id);
}

#[test]
fn upgrade_needs_a_configured_authority() {
    let h = setup_upgrade();
    assert_eq!(
        h.member.try_upgrade(&h.admin, &hash(&h.env, 1)),
        Err(Ok(Error::NotInitialized))
    );
}

#[test]
fn upgrade_to_an_unapproved_hash_is_refused() {
    let h = setup_upgrade();
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    // Nothing has been approved for this kind, so the registry says no.
    assert_eq!(
        h.member.try_upgrade(&h.admin, &hash(&h.env, 1)),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn upgrade_requires_the_recorded_admin() {
    let h = setup_upgrade();
    let stranger = Address::generate(&h.env);
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    // Approved in the registry, but the caller is not the upgrade admin.
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Organization, &hash(&h.env, 1));
    assert_eq!(
        h.member.try_upgrade(&stranger, &hash(&h.env, 1)),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn approval_is_scoped_to_the_module_kind() {
    let h = setup_upgrade();
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    // Approved for a different kind than the member reports, so it must not
    // satisfy this member's gate.
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Wallet, &hash(&h.env, 1));
    assert!(h
        .registry
        .is_wasm_approved(&ModuleKind::Wallet, &hash(&h.env, 1)));
    assert!(!h
        .registry
        .is_wasm_approved(&ModuleKind::Organization, &hash(&h.env, 1)));
    assert_eq!(
        h.member.try_upgrade(&h.admin, &hash(&h.env, 1)),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn a_revoked_hash_stops_authorizing_upgrades() {
    let h = setup_upgrade();
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Organization, &hash(&h.env, 1));
    h.registry
        .remove_approved_wasm(&h.admin, &ModuleKind::Organization, &hash(&h.env, 1));
    assert_eq!(
        h.member.try_upgrade(&h.admin, &hash(&h.env, 1)),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn only_the_current_admin_can_rotate_the_authority() {
    let h = setup_upgrade();
    let stranger = Address::generate(&h.env);
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    assert_eq!(
        h.member
            .try_set_upgrade_authority(&stranger, &stranger, &h.registry_id),
        Err(Ok(Error::Unauthorized))
    );
    // The incumbent may hand the role over.
    h.member
        .set_upgrade_authority(&h.admin, &stranger, &h.registry_id);
    assert_eq!(h.member.get_upgrade_authority().admin, stranger);
}

#[test]
fn only_the_registry_admin_can_bootstrap_the_upgrade_authority() {
    let h = setup_upgrade();
    let squatter = Address::generate(&h.env);
    // Before bootstrap, a stranger cannot claim upgrade rights over the
    // registry by getting to `set_upgrade_authority` first.
    assert_eq!(
        h.member
            .try_set_upgrade_authority(&squatter, &squatter, &h.registry_id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.member.try_get_upgrade_authority(),
        Err(Ok(Error::NotInitialized))
    );

    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    assert_eq!(h.member.get_upgrade_authority().admin, h.admin);
}

#[test]
fn uninitialized_registry_cannot_bootstrap_the_upgrade_authority() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &id);
    let anyone = Address::generate(&env);
    assert_eq!(
        client.try_set_upgrade_authority(&anyone, &anyone, &id),
        Err(Ok(Error::Unauthorized))
    );
}

// --- Batch lookup (Issue #228) ---

fn module_id(env: &Env, org: &str, kind: ModuleKind) -> ModuleId {
    ModuleId {
        org: String::from_str(env, org),
        kind,
    }
}

fn live(address: &Address) -> Option<ModuleInfo> {
    Some(ModuleInfo {
        address: address.clone(),
        deprecated: false,
    })
}

/// Register org "acme" with Wallet, Treasury and Policy modules; returns the
/// three module addresses in that order.
fn setup_acme(env: &Env, client: &RegistryContractClient, admin: &Address) -> [Address; 3] {
    let org = String::from_str(env, "acme");
    let owner = Address::generate(env);
    client.register_org(admin, &org, &owner);
    let modules = [
        Address::generate(env),
        Address::generate(env),
        Address::generate(env),
    ];
    let kinds = [ModuleKind::Wallet, ModuleKind::Treasury, ModuleKind::Policy];
    for (kind, address) in kinds.iter().zip(modules.iter()) {
        client.register_module(&owner, &org, kind, address);
    }
    modules
}

#[test]
fn batch_returns_every_registered_module_in_request_order() {
    let (env, client, admin) = setup();
    let [wallet, treasury, policy] = setup_acme(&env, &client, &admin);

    // Deliberately not in registration order.
    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Policy),
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "acme", ModuleKind::Treasury),
    ];
    assert_eq!(
        client.get_modules_batch(&ids),
        vec![&env, live(&policy), live(&wallet), live(&treasury)]
    );
}

#[test]
fn batch_reports_missing_modules_as_none_in_place() {
    let (env, client, admin) = setup();
    let [wallet, _treasury, policy] = setup_acme(&env, &client, &admin);

    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Escrow), // kind never registered
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "ghost", ModuleKind::Wallet), // org never registered
        module_id(&env, "acme", ModuleKind::Policy),
    ];
    assert_eq!(
        client.get_modules_batch(&ids),
        vec![&env, None, live(&wallet), None, live(&policy)]
    );
}

#[test]
fn batch_of_only_missing_modules_is_all_none() {
    let (env, client, _admin) = setup();
    let ids = vec![
        &env,
        module_id(&env, "ghost", ModuleKind::Wallet),
        module_id(&env, "ghost", ModuleKind::Budget),
    ];
    assert_eq!(client.get_modules_batch(&ids), vec![&env, None, None]);
}

#[test]
fn empty_batch_returns_empty_list() {
    let (env, client, _admin) = setup();
    assert_eq!(client.get_modules_batch(&Vec::new(&env)), Vec::new(&env));
}

#[test]
fn batch_at_the_size_limit_succeeds() {
    let (env, client, admin) = setup();
    let [wallet, _treasury, _policy] = setup_acme(&env, &client, &admin);

    let mut ids = Vec::new(&env);
    for _ in 0..MAX_REGISTRY_BATCH {
        ids.push_back(module_id(&env, "acme", ModuleKind::Wallet));
    }
    let result = client.get_modules_batch(&ids);
    assert_eq!(result.len(), MAX_REGISTRY_BATCH);
    assert!(result.iter().all(|m| m == live(&wallet)));
}

#[test]
fn batch_over_the_size_limit_is_rejected() {
    let (env, client, admin) = setup();
    setup_acme(&env, &client, &admin);

    let mut ids = Vec::new(&env);
    for _ in 0..=MAX_REGISTRY_BATCH {
        ids.push_back(module_id(&env, "acme", ModuleKind::Wallet));
    }
    assert_eq!(
        client.try_get_modules_batch(&ids),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn batch_size_is_checked_before_any_storage_read() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    client.register_org(&admin, &org, &Address::generate(&env));
    client.freeze(&admin, &org);

    let mut ids = Vec::new(&env);
    for _ in 0..=MAX_REGISTRY_BATCH {
        ids.push_back(module_id(&env, "acme", ModuleKind::Wallet));
    }
    // The freeze flag is itself a storage read; an oversized batch is refused
    // on its length alone, before the freeze flag is consulted.
    assert_eq!(
        client.try_get_modules_batch(&ids),
        Err(Ok(Error::InvalidInput))
    );
    let one = vec![&env, module_id(&env, "acme", ModuleKind::Wallet)];
    assert_eq!(
        client.try_get_modules_batch(&one),
        Err(Ok(Error::RegistryFrozen))
    );
}

#[test]
fn batch_answers_duplicate_ids_at_every_position() {
    let (env, client, admin) = setup();
    let [wallet, treasury, _policy] = setup_acme(&env, &client, &admin);

    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "acme", ModuleKind::Treasury),
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "ghost", ModuleKind::Wallet),
        module_id(&env, "ghost", ModuleKind::Wallet),
    ];
    assert_eq!(
        client.get_modules_batch(&ids),
        vec![
            &env,
            live(&wallet),
            live(&treasury),
            live(&wallet),
            None,
            None
        ]
    );
}

#[test]
fn batch_agrees_with_the_single_lookups() {
    let (env, client, admin) = setup();
    setup_acme(&env, &client, &admin);
    let org = String::from_str(&env, "acme");
    client.deprecate_module(&admin, &org, &ModuleKind::Treasury);

    let kinds = [
        ModuleKind::Wallet,
        ModuleKind::Treasury, // deprecated
        ModuleKind::Policy,
        ModuleKind::Escrow, // missing
    ];
    let mut ids = Vec::new(&env);
    for kind in kinds {
        ids.push_back(ModuleId {
            org: org.clone(),
            kind,
        });
    }
    let batch = client.get_modules_batch(&ids);
    assert_eq!(batch.len(), ids.len());

    for (id, entry) in ids.iter().zip(batch.iter()) {
        let raw = client.try_get_module_address(&id.org, &id.kind);
        let routed = client.try_lookup(&id.org, &id.kind);
        match entry {
            None => {
                assert_eq!(raw, Err(Ok(Error::NotFound)));
                assert_eq!(routed, Err(Ok(Error::NotFound)));
            }
            Some(info) => {
                assert_eq!(raw, Ok(Ok(info.address.clone())));
                assert_eq!(
                    info.deprecated,
                    client.is_module_deprecated(&id.org, &id.kind)
                );
                if info.deprecated {
                    assert_eq!(routed, Err(Ok(Error::ModuleDeprecated)));
                } else {
                    assert_eq!(routed, Ok(Ok(info.address)));
                }
            }
        }
    }
}

#[test]
fn batch_reports_deprecated_modules_without_failing() {
    let (env, client, admin) = setup();
    let [wallet, treasury, _policy] = setup_acme(&env, &client, &admin);
    let org = String::from_str(&env, "acme");
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "acme", ModuleKind::Treasury),
    ];
    assert_eq!(
        client.get_modules_batch(&ids),
        vec![
            &env,
            Some(ModuleInfo {
                address: wallet,
                deprecated: true,
            }),
            live(&treasury),
        ]
    );
}

#[test]
fn batch_extends_ttl_exactly_like_lookup() {
    let (env, client, admin) = setup();
    setup_acme(&env, &client, &admin);
    let org = String::from_str(&env, "acme");
    client.deprecate_module(&admin, &org, &ModuleKind::Treasury);

    let ttl = |kind: ModuleKind| {
        env.as_contract(&client.address, || {
            env.storage()
                .persistent()
                .get_ttl(&DataKey::Module(org.clone(), kind))
        })
    };
    // Age the records past the bump threshold so a read would extend them.
    env.ledger().with_mut(|l| l.sequence_number += 2 * 17_280);
    let aged = ttl(ModuleKind::Wallet);
    assert!(aged < PERSISTENT_BUMP_AMOUNT);
    assert_eq!(ttl(ModuleKind::Treasury), aged);

    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "acme", ModuleKind::Treasury),
    ];
    client.get_modules_batch(&ids);
    // A live record is extended, as a successful `lookup` extends it; a
    // deprecated one is left alone, as `lookup` (which refuses it) does.
    assert_eq!(ttl(ModuleKind::Wallet), PERSISTENT_BUMP_AMOUNT);
    assert_eq!(ttl(ModuleKind::Treasury), aged);

    // `lookup` on the policy record produces the same extension.
    client.lookup(&org, &ModuleKind::Policy);
    assert_eq!(ttl(ModuleKind::Policy), PERSISTENT_BUMP_AMOUNT);
}

// ---------------------------------------------------------------------------
// Deterministic error codes
//
// Every failure below must surface as a specific `Error` variant, never as a
// generic code and never as a host trap, so an off-chain consumer can branch on
// it. The three groups mirror the classes the protocol promises to keep
// distinct: out-of-bounds / invalid input, unauthorized callers, and frozen
// (lifecycle) refusals.
// ---------------------------------------------------------------------------

/// A registry that was registered but never `initialize`d, so the guards that
/// read instance storage report `NotInitialized` instead of panicking.
fn uninitialized() -> (Env, RegistryContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &contract_id);
    (env, client)
}

#[test]
fn uninitialized_registry_reports_not_initialized() {
    let (env, client) = uninitialized();
    let admin = Address::generate(&env);
    let org = String::from_str(&env, "acme");

    assert_eq!(client.try_get_admin(), Err(Ok(Error::NotInitialized)));
    assert_eq!(
        client.try_register_org(&admin, &org, &Address::generate(&env)),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(
        client.try_deprecate_module(&admin, &org, &ModuleKind::Wallet),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(
        client.try_set_admin(&admin, &Address::generate(&env)),
        Err(Ok(Error::NotInitialized))
    );
}

#[test]
fn out_of_bounds_lookups_report_not_found() {
    let (env, client, _admin) = setup();
    let ghost = String::from_str(&env, "ghost");
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&_admin, &org, &owner);

    // A key that was never written must not read as a default value.
    assert_eq!(client.try_get_org_owner(&ghost), Err(Ok(Error::NotFound)));
    assert_eq!(
        client.try_get_module_address(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_verify_owner(&ghost, &owner),
        Err(Ok(Error::NotFound))
    );
    // No version has been registered, and version 0 can never be registered.
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_latest(&ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn empty_org_slug_is_rejected_as_invalid_input() {
    let (env, client, admin) = setup();
    // An empty string is a valid `String` but not a valid org identifier; it
    // must be refused with `InvalidInput` rather than stored.
    let res = client.try_register_org(
        &admin,
        &String::from_str(&env, ""),
        &Address::generate(&env),
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(
        client.try_get_org_owner(&String::from_str(&env, "")),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn unknown_org_is_not_found_for_every_owner_gated_call() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let ghost = String::from_str(&env, "ghost");
    let new_owner = Address::generate(&env);

    // A real owner naming an organization that does not exist gets `NotFound`,
    // not a permission failure — the two are different diagnoses.
    assert_eq!(
        client.try_set_org_owner(&owner, &ghost, &new_owner),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_register_module(
            &owner,
            &ghost,
            &ModuleKind::Wallet,
            &Address::generate(&env)
        ),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_remove_module(&owner, &ghost, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(client.try_freeze(&owner, &ghost), Err(Ok(Error::NotFound)));
    assert_eq!(
        client.try_unfreeze(&owner, &ghost),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn unauthorized_callers_are_refused_by_the_protocol_admin() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let intruder = Address::generate(&env);
    let intruder_org = String::from_str(&env, "evil");
    client.register_org(&admin, &intruder_org, &intruder);

    // A stranger must never seize the protocol admin, approve Wasm, or record a
    // version, even while holding ownership of an organization of their own.
    assert_eq!(
        client.try_set_admin(&intruder, &intruder),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_add_approved_wasm(&intruder, &ModuleKind::Wallet, &hash(&env, 1)),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_remove_approved_wasm(&intruder, &ModuleKind::Wallet, &hash(&env, 1)),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_register_version(
            &intruder,
            &ModuleKind::Wallet,
            &1,
            &Address::generate(&env),
            &hash(&env, 1)
        ),
        Err(Ok(Error::Unauthorized))
    );
    // The admin is unchanged.
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn freeze_and_unfreeze_require_the_owner_or_admin() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let intruder = Address::generate(&env);

    assert_eq!(
        client.try_freeze(&intruder, &org),
        Err(Ok(Error::Unauthorized))
    );
    client.freeze(&owner, &org);
    assert_eq!(
        client.try_unfreeze(&intruder, &org),
        Err(Ok(Error::Unauthorized))
    );
    // Only the owner or the protocol admin may lift the breaker.
    client.unfreeze(&owner, &org);
    client.freeze(&admin, &org);
    client.unfreeze(&admin, &org);
}

#[test]
fn frozen_registry_refuses_every_organization_scoped_write() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    client.freeze(&owner, &org);

    // Every write that would change routing for this org must report the single
    // dedicated `RegistryFrozen` code — never a generic `Unauthorized`.
    for res in [
        client.try_register_module(&owner, &org, &ModuleKind::Policy, &Address::generate(&env)),
        client.try_remove_module(&owner, &org, &ModuleKind::Wallet),
        client.try_set_org_owner(&owner, &org, &Address::generate(&env)),
        client.try_deprecate_module(&owner, &org, &ModuleKind::Wallet),
        client.try_reactivate_module(&owner, &org, &ModuleKind::Wallet),
        client.try_register_org(&admin, &String::from_str(&env, "other"), &owner),
        client.try_grant_role(
            &owner,
            &org,
            &Address::generate(&env),
            &RegistryRole::PolicyManager,
        ),
    ] {
        assert_eq!(res, Err(Ok(Error::RegistryFrozen)));
    }

    // Routing is frozen too, so a live module reports the same dedicated code
    // rather than being served; the legacy getter stays open for recovery.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::RegistryFrozen))
    );
    assert_eq!(client.get_module_address(&org, &ModuleKind::Wallet), wallet);
    client.unfreeze(&owner, &org);
    client.register_module(&owner, &org, &ModuleKind::Policy, &Address::generate(&env));
}

#[test]
fn deprecated_module_reports_module_deprecated_not_not_found() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    // Deprecation is protocol-admin gated; the org owner is refused.
    assert_eq!(
        client.try_deprecate_module(&owner, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    // The record still exists for the legacy getter, but routing must report the
    // dedicated deprecation code so callers can distinguish it from a missing
    // module.
    assert_eq!(client.get_module_address(&org, &ModuleKind::Wallet), wallet);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );
    // A module that was never registered is `NotFound`, not deprecated.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
    // Reactivating restores routing and clears the code.
    client.reactivate_module(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn unapproved_wasm_cannot_be_removed() {
    let (env, client, admin) = setup();
    // Revoking a hash that was never approved is `NotFound`, not a silent no-op.
    let res = client.try_remove_approved_wasm(&admin, &ModuleKind::Wallet, &hash(&env, 7));
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

// ---------------------------------------------------------------------------
// Upgrade-map storage-read optimization (Issue #319)
//
// Persistent reads dominate gas. `get_versions_batch` must minimize them by
// caching the first read of each distinct (kind, version) — including `None`
// for a missing key — and serving duplicates from an in-memory `Vec` bounded
// by `MAX_REGISTRY_BATCH`. The same read-once, TTL-once semantics as
// `get_version` must hold: a distinct key's TTL is extended once per
// invocation when the record exists and never for a missing key. Overall fee
// and TTL extended only once.

fn versions_batch(
    env: &Env,
    client: &RegistryContractClient,
    ids: &[(ModuleKind, u32)],
) -> Vec<Option<Address>> {
    let mut vids = Vec::new(env);
    for (kind, version) in ids.iter() {
        vids.push_back(crate::VersionId {
            kind: *kind,
            version: *version,
        });
    }
    client.get_versions_batch(&vids)
}

fn version_ttl(env: &Env, client: &RegistryContractClient, kind: ModuleKind, version: u32) -> u32 {
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .get_ttl(&crate::DataKey::VersionRecord(kind, version))
    })
}

#[test]
fn versions_batch_returns_every_registered_version_in_request_order() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2, &h2);

    // Deliberately not in registration order.
    let result = versions_batch(
        &env,
        &client,
        &[(ModuleKind::Wallet, 2), (ModuleKind::Wallet, 1)],
    );
    assert_eq!(result, vec![&env, Some(v2), Some(v1)]);
}

#[test]
fn versions_batch_reports_missing_versions_as_none_in_place() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);

    let result = versions_batch(
        &env,
        &client,
        &[
            (ModuleKind::Wallet, 99), // never registered
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 2), // kind registered, version missing
        ],
    );
    assert_eq!(result, vec![&env, None, Some(v1), None]);
}

#[test]
fn versions_batch_of_only_missing_versions_is_all_none() {
    let (env, client, _admin) = setup();
    let result = versions_batch(
        &env,
        &client,
        &[(ModuleKind::Wallet, 1), (ModuleKind::Wallet, 2)],
    );
    assert_eq!(result, vec![&env, None, None]);
}

#[test]
fn empty_versions_batch_returns_empty_list() {
    let (env, client, _admin) = setup();
    let empty = crate::VersionId {
        kind: ModuleKind::Wallet,
        version: 1,
    };
    // Construct an explicitly empty Vec<VersionId>.
    let ids: Vec<crate::VersionId> = Vec::new(&env);
    assert_eq!(client.get_versions_batch(&ids), Vec::new(&env));
    // Also through helper with no ids.
    assert_eq!(versions_batch(&env, &client, &[]), Vec::new(&env));
    let _ = empty;
}

#[test]
fn versions_batch_at_the_size_limit_succeeds() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);

    let mut ids = Vec::new(&env);
    for _ in 0..MAX_REGISTRY_BATCH {
        ids.push_back(crate::VersionId {
            kind: ModuleKind::Wallet,
            version: 1,
        });
    }
    let result = client.get_versions_batch(&ids);
    assert_eq!(result.len(), MAX_REGISTRY_BATCH);
    assert!(result.iter().all(|a| a == Some(v1.clone())));
}

#[test]
fn versions_batch_over_the_size_limit_is_rejected_before_any_read() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);

    let mut ids = Vec::new(&env);
    for _ in 0..=MAX_REGISTRY_BATCH {
        ids.push_back(crate::VersionId {
            kind: ModuleKind::Wallet,
            version: 1,
        });
    }
    assert_eq!(
        client.try_get_versions_batch(&ids),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn versions_batch_answers_duplicate_ids_at_every_position() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2, &h2);

    // Wallet v1 appears three times, interleaved with v2 and missing keys.
    let result = versions_batch(
        &env,
        &client,
        &[
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 2),
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 99),
            (ModuleKind::Wallet, 99),
            (ModuleKind::Wallet, 1),
        ],
    );
    assert_eq!(
        result,
        vec![
            &env,
            Some(v1.clone()),
            Some(v2.clone()),
            Some(v1.clone()),
            None,
            None,
            Some(v1)
        ]
    );
}

#[test]
fn versions_batch_agrees_with_single_version_lookups() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let vp = Address::generate(&env);
    let hp = approved_hash(&env, &client, &admin, ModuleKind::Policy, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    client.register_version(&admin, &ModuleKind::Policy, &1, &vp, &hp);

    let kinds_versions = [
        (ModuleKind::Wallet, 1), // present
        (ModuleKind::Wallet, 2), // missing
        (ModuleKind::Policy, 1), // present, different kind same version
        (ModuleKind::Policy, 2), // missing
        (ModuleKind::Escrow, 1), // kind never registered
    ];
    let mut vids = Vec::new(&env);
    for (k, v) in kinds_versions.iter() {
        vids.push_back(crate::VersionId {
            kind: *k,
            version: *v,
        });
    }
    let batch = client.get_versions_batch(&vids);
    assert_eq!(batch.len(), vids.len());
    for (vid, entry) in vids.iter().zip(batch.iter()) {
        let single = client.try_get_version(&vid.kind, &vid.version);
        match entry {
            None => assert_eq!(single, Err(Ok(Error::NotFound))),
            Some(addr) => assert_eq!(single, Ok(Ok(addr.clone()))),
        }
    }
}

#[test]
fn versions_batch_deduplicates_reads_and_bumps_once_per_distinct_key() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2, &h2);

    // Age the version records past the bump threshold so a read would extend
    // them only if the TTL bump is actually performed.
    env.ledger().with_mut(|l| l.sequence_number += 2 * 17_280);
    let aged_v1 = version_ttl(&env, &client, ModuleKind::Wallet, 1);
    let aged_v2 = version_ttl(&env, &client, ModuleKind::Wallet, 2);
    assert!(aged_v1 < PERSISTENT_BUMP_AMOUNT);
    assert!(aged_v2 < PERSISTENT_BUMP_AMOUNT);

    // Batch with duplicates: v1 appears three times, v2 once, and a missing
    // key twice. Only the distinct present keys should have their TTL
    // extended, each exactly once.
    let result = versions_batch(
        &env,
        &client,
        &[
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 2),
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 99),
            (ModuleKind::Wallet, 99),
            (ModuleKind::Wallet, 1),
        ],
    );
    assert_eq!(
        result,
        vec![
            &env,
            Some(v1.clone()),
            Some(v2.clone()),
            Some(v1.clone()),
            None,
            None,
            Some(v1.clone())
        ]
    );
    // A present distinct key is extended exactly once, same as a single
    // `get_version` call — not once per duplicate entry.
    assert_eq!(
        version_ttl(&env, &client, ModuleKind::Wallet, 1),
        PERSISTENT_BUMP_AMOUNT
    );
    assert_eq!(
        version_ttl(&env, &client, ModuleKind::Wallet, 2),
        PERSISTENT_BUMP_AMOUNT
    );

    // A missing key has no TTL entry to extend (and the cache never bumps a
    // missing key), so the second batch does not create one.
    env.as_contract(&client.address, || {
        assert!(!env
            .storage()
            .persistent()
            .has(&crate::DataKey::VersionRecord(ModuleKind::Wallet, 99)));
    });

    // Verify `get_version` extends the same way, so the batch matches the
    // single-lookup policy.
    env.ledger().with_mut(|l| l.sequence_number += 2 * 17_280);
    client.get_version(&ModuleKind::Wallet, &1);
    assert_eq!(
        version_ttl(&env, &client, ModuleKind::Wallet, 1),
        PERSISTENT_BUMP_AMOUNT
    );
}

#[test]
fn versions_batch_missing_keys_never_bump_and_are_cached() {
    let (env, client, _admin) = setup();
    // No versions registered; every key is missing.
    let result = versions_batch(
        &env,
        &client,
        &[
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 2),
            (ModuleKind::Wallet, 2),
        ],
    );
    assert_eq!(result, vec![&env, None, None, None, None]);
    // Missing keys have no storage entry, so no TTL exists to extend.
    env.as_contract(&client.address, || {
        for v in [1u32, 2u32] {
            assert!(!env
                .storage()
                .persistent()
                .has(&crate::DataKey::VersionRecord(ModuleKind::Wallet, v)));
        }
    });
}

#[test]
fn versions_batch_same_number_different_kind_is_distinct() {
    let (env, client, admin) = setup();
    let w1 = Address::generate(&env);
    let p1 = Address::generate(&env);
    let hw = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let hp = approved_hash(&env, &client, &admin, ModuleKind::Policy, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &w1, &hw);
    client.register_version(&admin, &ModuleKind::Policy, &1, &p1, &hp);

    // Same version number, different kind — distinct keys, distinct addresses.
    let result = versions_batch(
        &env,
        &client,
        &[
            (ModuleKind::Wallet, 1),
            (ModuleKind::Policy, 1),
            (ModuleKind::Wallet, 1),
            (ModuleKind::Policy, 1),
        ],
    );
    assert_eq!(
        result,
        vec![&env, Some(w1.clone()), Some(p1.clone()), Some(w1), Some(p1)]
    );
}

#[test]
fn versions_batch_initial_deployment_state_is_empty_and_stable() {
    let (env, client, _admin) = setup();
    // Fresh deployment: no versions at all, including version 0 which can
    // never be registered.
    assert_eq!(
        versions_batch(&env, &client, &[(ModuleKind::Wallet, 0)]),
        vec![&env, None]
    );
    assert_eq!(versions_batch(&env, &client, &[]), Vec::new(&env));
    // Still empty after probing.
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn versions_batch_non_existent_version_keys_are_stable() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);

    // A registered kind still reports NotFound for an absent version; the
    // batch mirrors that per entry.
    assert_eq!(
        versions_batch(&env, &client, &[(ModuleKind::Wallet, 2)]),
        vec![&env, None]
    );
    assert_eq!(
        versions_batch(
            &env,
            &client,
            &[(ModuleKind::Wallet, 1), (ModuleKind::Wallet, 2)]
        ),
        vec![&env, Some(v1.clone()), None]
    );
}

#[test]
fn versions_batch_circular_upgrade_paths_do_not_loop() {
    let (env, client, admin) = setup();
    // Simulate Wallet v1 -> v2 -> v3 upgrade chain, then a caller that walks
    // it with duplicates (e.g. verifying v1, v2, v1 again). The batch must
    // answer each position without looping or re-reading.
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    let v3 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    let h3 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 3);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2, &h2);
    client.register_version(&admin, &ModuleKind::Wallet, &3, &v3, &h3);

    // Walk v1 -> v2 -> v3 -> v1 -> v2 (circular walk pattern).
    let result = versions_batch(
        &env,
        &client,
        &[
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 2),
            (ModuleKind::Wallet, 3),
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 2),
        ],
    );
    assert_eq!(
        result,
        vec![
            &env,
            Some(v1.clone()),
            Some(v2.clone()),
            Some(v3.clone()),
            Some(v1),
            Some(v2)
        ]
    );
}

// ---------------------------------------------------------------------------
// Issue #240: consolidated upgrade-map storage layout.
//
// `Version` (address) and `VersionWasm` (hash) were two persistent entries per
// version. They are now one `VersionRecord`. These tests pin the new layout,
// the fallback that keeps pre-consolidation entries readable, and the storage
// access patterns the consolidation was meant to improve.
// ---------------------------------------------------------------------------

/// Whether the contract holds a persistent entry under `key`.
fn has_entry(env: &Env, client: &RegistryContractClient, key: &DataKey) -> bool {
    env.as_contract(&client.address, || env.storage().persistent().has(key))
}

#[test]
fn register_version_stores_one_entry_per_version() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);

    // Exactly one entry, holding the address and the hash together.
    assert!(has_entry(
        &env,
        &client,
        &DataKey::VersionRecord(ModuleKind::Wallet, 1)
    ));
    // The split layout is not written at all: no bare-address entry alongside
    // the record, so a populated upgrade map holds one entry per version
    // instead of two.
    assert!(!has_entry(
        &env,
        &client,
        &DataKey::Version(ModuleKind::Wallet, 1)
    ));
    // And the record is self-contained: both halves answer from it alone.
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), addr);
    assert_eq!(client.get_version_wasm(&ModuleKind::Wallet, &1), h);
}

#[test]
fn register_version_entry_count_does_not_grow_with_versions() {
    // Ten versions cost ten entries. Before the consolidation the same ten
    // versions cost twenty (address + hash each), so the ledger footprint of the
    // upgrade map halves.
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    for v in 1..=10u32 {
        let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, v as u8);
        client.register_version(&admin, &ModuleKind::Wallet, &v, &addr, &h);
    }
    let mut records = 0;
    for v in 1..=10u32 {
        if has_entry(
            &env,
            &client,
            &DataKey::VersionRecord(ModuleKind::Wallet, v),
        ) {
            records += 1;
        }
        // No version fell back to the split layout.
        assert!(!has_entry(
            &env,
            &client,
            &DataKey::Version(ModuleKind::Wallet, v)
        ));
    }
    assert_eq!(records, 10);
}

#[test]
fn a_legacy_entry_still_blocks_re_registration_of_its_pair() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    // Occupy the pair in the pre-consolidation layout.
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .set(&DataKey::Version(ModuleKind::Wallet, 1), &addr);
    });

    // The legacy entry counts as taken, so it cannot be silently republished
    // with different code.
    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h),
        Err(Ok(Error::AlreadyExists))
    );
    // A different pair is still free.
    client.register_version(&admin, &ModuleKind::Wallet, &2, &addr, &h);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &2), addr);
}

#[test]
fn legacy_entries_answer_the_batch_query_too() {
    let (env, client, admin) = setup();
    let legacy_addr = Address::generate(&env);
    let current_addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 7);
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .set(&DataKey::Version(ModuleKind::Wallet, 1), &legacy_addr);
    });
    client.register_version(&admin, &ModuleKind::Wallet, &2, &current_addr, &h);

    // A batch mixes the pre-consolidation entry with a current one.
    let result = versions_batch(
        &env,
        &client,
        &[
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 2),
            (ModuleKind::Wallet, 1),
            (ModuleKind::Wallet, 99),
        ],
    );
    assert_eq!(
        result,
        vec![
            &env,
            Some(legacy_addr.clone()),
            Some(current_addr),
            Some(legacy_addr),
            None
        ]
    );
}

#[test]
fn verify_version_costs_less_than_reading_the_record_twice() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);

    // `verify_version` needs the address and its bound hash, which the
    // consolidated record answers in one read. Reaching the same two facts
    // through the single-purpose getters costs one read each.
    let before = env.budget().cpu_instruction_cost();
    let verified = client.verify_version(&ModuleKind::Wallet, &1, &h);
    let verify_cost = env.budget().cpu_instruction_cost() - before;

    let before = env.budget().cpu_instruction_cost();
    let address = client.get_version(&ModuleKind::Wallet, &1);
    let wasm = client.get_version_wasm(&ModuleKind::Wallet, &1);
    let split_cost = env.budget().cpu_instruction_cost() - before;

    assert_eq!(verified, addr);
    assert_eq!((address, wasm), (addr, h));
    assert!(
        verify_cost < split_cost,
        "consolidated read ({verify_cost}) should beat one read per field ({split_cost})"
    );
}

#[test]
fn versions_batch_cost_scales_with_distinct_keys_not_requested_entries() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    // One registered key, requested many times.
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);

    let mut repeated = Vec::new(&env);
    for _ in 0..MAX_REGISTRY_BATCH {
        repeated.push_back(crate::VersionId {
            kind: ModuleKind::Wallet,
            version: 1,
        });
    }
    let before = env.budget().cpu_instruction_cost();
    let dup = client.get_versions_batch(&repeated);
    let dup_cost = env.budget().cpu_instruction_cost() - before;

    // The same number of entries, but all distinct, so every one is a real
    // ledger read plus TTL extension. A different kind keeps this batch from
    // colliding with the single key above.
    let mut distinct = Vec::new(&env);
    for v in 1..=MAX_REGISTRY_BATCH {
        let hv = approved_hash(&env, &client, &admin, ModuleKind::Policy, v as u8);
        client.register_version(&admin, &ModuleKind::Policy, &v, &addr, &hv);
        distinct.push_back(crate::VersionId {
            kind: ModuleKind::Policy,
            version: v,
        });
    }
    let before = env.budget().cpu_instruction_cost();
    let all = client.get_versions_batch(&distinct);
    let distinct_cost = env.budget().cpu_instruction_cost() - before;

    // Duplicates are answered from the per-invocation cache, so an identical
    // request shape costs markedly less than the one that must touch the ledger
    // once per entry.
    assert!(
        dup_cost < distinct_cost,
        "duplicates {dup_cost} vs distinct {distinct_cost}"
    );

    let mut all_some = Vec::new(&env);
    for _ in 0..MAX_REGISTRY_BATCH {
        all_some.push_back(Some(addr.clone()));
    }
    assert_eq!(dup, all_some);
    assert_eq!(all, all_some);
}

// ---------------------------------------------------------------------------
// Issue #249: upgrade path validation and version compatibility.
//
// The version map publishes immutable `(kind, version)` records; an organization
// reaches one of them by moving a module pointer, which is what
// `upgrade_module` does. These tests pin the whole path: what a valid upgrade
// looks like, every way an invalid target is refused, and the invariant that
// makes the path acyclic — a module's version sequence only ever increases.
// ---------------------------------------------------------------------------

/// A contract address to publish as a version's implementation: the upgrade path
/// refuses to point a module at anything that is not a contract, so a target
/// has to be one.
fn impl_address(env: &Env) -> Address {
    env.register_contract(None, RegistryContract)
}

/// A genuine account-format address (strkey `G...`). Soroban's test address
/// generator mints contract-format addresses, so the account side of the
/// contract-address check needs a real one.
fn account_address(env: &Env) -> Address {
    Address::from_string(&String::from_str(
        env,
        "GAEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSH7S",
    ))
}

/// A registry with `acme` registered, three published `Wallet` versions (v1, v2,
/// v3 — each a contract bound to its own approved hash) and the organization's
/// `Wallet` module sitting on v1, registered by address exactly as every module
/// predating validated upgrades was.
struct PathHarness {
    env: Env,
    client: RegistryContractClient<'static>,
    admin: Address,
    org: String,
    owner: Address,
    /// The three published implementations.
    v1: Address,
    v2: Address,
    v3: Address,
    /// The approved hash each version is bound to.
    h2: BytesN<32>,
    h3: BytesN<32>,
}

fn setup_path() -> PathHarness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let v1 = impl_address(&env);
    let v2 = impl_address(&env);
    let v3 = impl_address(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    let h3 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 3);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2, &h2);
    client.register_version(&admin, &ModuleKind::Wallet, &3, &v3, &h3);

    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);

    PathHarness {
        env,
        client,
        admin,
        org,
        owner,
        v1,
        v2,
        v3,
        h2,
        h3,
    }
}

/// The current version pin for `h`'s wallet module.
fn pin(h: &PathHarness) -> u32 {
    h.client.get_module_version(&h.org, &ModuleKind::Wallet)
}

/// The address `h`'s wallet module currently routes to.
fn pointed_at(h: &PathHarness) -> Address {
    h.client.lookup(&h.org, &ModuleKind::Wallet)
}

#[test]
fn an_upgrade_moves_the_module_onto_a_published_version() {
    let h = setup_path();
    assert_eq!(pointed_at(&h), h.v1);
    // Registered by address and never upgraded: the pin reads as the start of
    // the path, not as a failure.
    assert_eq!(pin(&h), 0);
    // The pre-flight resolves the target without touching anything.
    assert_eq!(
        h.client.validate_upgrade(&h.org, &ModuleKind::Wallet, &2),
        h.v2
    );
    assert_eq!(pin(&h), 0);
    assert_eq!(pointed_at(&h), h.v1);

    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        2
    );

    assert_eq!(pointed_at(&h), h.v2);
    assert_eq!(pin(&h), 2);
    // The version record itself is immutable: an upgrade moves the pointer, it
    // does not republish the version.
    assert_eq!(h.client.get_version(&ModuleKind::Wallet, &2), h.v2);
    assert_eq!(h.client.get_version_wasm(&ModuleKind::Wallet, &2), h.h2);
    // ...and the implementation the module left is still resolvable, so a
    // consumer pinned to v1 keeps getting v1.
    assert_eq!(h.client.get_version(&ModuleKind::Wallet, &1), h.v1);
}

#[test]
fn an_upgrade_path_rolls_forward_one_version_at_a_time() {
    let h = setup_path();
    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        2
    );
    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &3),
        3
    );
    assert_eq!(pointed_at(&h), h.v3);
    assert_eq!(pin(&h), 3);
    // The module now runs exactly the code v3 was published with.
    assert_eq!(h.client.get_version_wasm(&ModuleKind::Wallet, &3), h.h3);
    // Each step changed the contract the module runs: no silent no-op got
    // recorded as progress.
    assert_ne!(h.v1, h.v2);
    assert_ne!(h.v2, h.v3);
}

#[test]
fn the_first_validated_upgrade_may_skip_ahead() {
    let h = setup_path();
    // An unpinned module is at the start of its path, so the newest published
    // version is a legal first step — nothing forces it through every version.
    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &3),
        3
    );
    assert_eq!(pointed_at(&h), h.v3);
    assert_eq!(pin(&h), 3);
}

#[test]
fn an_upgrade_emits_the_structured_and_legacy_events() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);

    let want_topic: Val = Symbol::new(&h.env, "RegistryModuleUpgraded").into_val(&h.env);
    let event = h
        .env
        .events()
        .all()
        .iter()
        .find(|(_id, topics, _data)| topics.contains(want_topic))
        .expect("RegistryModuleUpgraded must be emitted");
    assert_eq!(event.0, h.client.address);
    // `from_version` is 0 for a module that had never been upgraded, so a log
    // reader can tell a first step from a later one.
    let data: (String, ModuleKind, u32, u32, Address, BytesN<32>) = event.2.into_val(&h.env);
    assert_eq!(
        data,
        (
            h.org.clone(),
            ModuleKind::Wallet,
            0,
            2,
            h.v2.clone(),
            h.h2.clone()
        )
    );

    // The legacy tuple-topic event is still published for existing consumers.
    let legacy: Vec<Val> = (symbol_short!("module"), symbol_short!("upgrade")).into_val(&h.env);
    assert!(h
        .env
        .events()
        .all()
        .iter()
        .any(|(_id, topics, _data)| topics == legacy));
}

#[test]
fn a_refused_upgrade_writes_nothing_and_emits_no_event() {
    let h = setup_path();
    // v2's code is no longer approved, so the target fails verification.
    h.client
        .remove_approved_wasm(&h.admin, &ModuleKind::Wallet, &h.h2);

    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::Unauthorized))
    );

    // The pointer and the pin are exactly where they were.
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(pin(&h), 0);
    let want_topic: Val = Symbol::new(&h.env, "RegistryModuleUpgraded").into_val(&h.env);
    assert!(!h
        .env
        .events()
        .all()
        .iter()
        .any(|(_id, topics, _data)| topics.contains(want_topic)));
}

#[test]
fn an_upgrade_to_an_unpublished_version_is_not_found() {
    let h = setup_path();
    // Never registered by anyone.
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &99),
        Err(Ok(Error::NotFound))
    );
    // A gap in the published sequence is still a gap.
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &4),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(pin(&h), 0);
}

#[test]
fn an_upgrade_target_must_belong_to_the_modules_own_kind() {
    let h = setup_path();
    // A perfectly good Policy version is not a Wallet target: the version map is
    // keyed by kind, and a Wallet module may only land on a Wallet version.
    let policy_v9 = impl_address(&h.env);
    let hp = approved_hash(&h.env, &h.client, &h.admin, ModuleKind::Policy, 9);
    h.client
        .register_version(&h.admin, &ModuleKind::Policy, &9, &policy_v9, &hp);

    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &9),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(pin(&h), 0);
}

#[test]
fn version_zero_is_not_an_upgrade_target() {
    let h = setup_path();
    // 0 can never be a registered version, so it is a malformed request rather
    // than a missing one.
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &0),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(pin(&h), 0);
}

#[test]
fn a_version_with_no_bound_hash_is_refused_as_a_target() {
    let h = setup_path();
    // A record published before hashes were bound: there is no code to verify,
    // which is exactly what this path exists to rule out.
    let legacy = impl_address(&h.env);
    env_as_contract(&h, |env| {
        env.storage()
            .persistent()
            .set(&DataKey::Version(ModuleKind::Wallet, 4), &legacy);
    });

    // The version itself still resolves for the legacy read paths...
    assert_eq!(h.client.get_version(&ModuleKind::Wallet, &4), legacy);
    // ...but it cannot become a module's code.
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &4),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        h.client
            .try_validate_upgrade(&h.org, &ModuleKind::Wallet, &4),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(pointed_at(&h), h.v1);
}

/// Run `f` as the registry contract, the way the contract's own code would see
/// its storage. Used to plant records a deployment would already hold.
fn env_as_contract<F: FnOnce(&Env)>(h: &PathHarness, f: F) {
    h.env.as_contract(&h.client.address, || f(&h.env));
}

#[test]
fn a_target_that_is_not_a_contract_is_refused() {
    let h = setup_path();
    // An account address: a version may name one, but routing a module to it
    // would leave the module permanently uncallable.
    let account = account_address(&h.env);
    let h5 = approved_hash(&h.env, &h.client, &h.admin, ModuleKind::Wallet, 5);
    h.client
        .register_version(&h.admin, &ModuleKind::Wallet, &5, &account, &h5);

    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &5),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(pin(&h), 0);
}

#[test]
fn an_upgrade_cannot_repeat_the_version_it_already_runs() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);
    assert_eq!(pin(&h), 2);

    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::CircularUpgrade))
    );
    assert_eq!(pointed_at(&h), h.v2);
    assert_eq!(pin(&h), 2);
}

#[test]
fn an_upgrade_cannot_walk_back_to_an_earlier_version() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &3);
    assert_eq!(pointed_at(&h), h.v3);

    // v2 is published, approved and perfectly valid — it is simply behind the
    // module now, so returning to it would close the loop v1 → v3 → v2 → v3.
    for behind in [1u32, 2] {
        assert_eq!(
            h.client
                .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &behind),
            Err(Ok(Error::CircularUpgrade))
        );
        assert_eq!(
            h.client
                .try_validate_upgrade(&h.org, &ModuleKind::Wallet, &behind),
            Err(Ok(Error::CircularUpgrade))
        );
    }
    assert_eq!(pointed_at(&h), h.v3);
    assert_eq!(pin(&h), 3);
}

#[test]
fn an_upgrade_onto_the_running_contract_is_refused() {
    let h = setup_path();
    // The module is already on v1's implementation, so "upgrading" it to v1
    // changes neither the code nor the routing. It is forward of the (empty)
    // pin, so the address check is what refuses it.
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &1),
        Err(Ok(Error::CircularUpgrade))
    );
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(pin(&h), 0);
}

#[test]
fn an_upgrade_needs_a_module_that_is_already_registered() {
    let h = setup_path();
    // The validated path moves an existing registration; it is not a way to
    // create one, which stays `register_module`'s job.
    let ghost_kind = ModuleKind::Policy;
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ghost_kind, &2),
        Err(Ok(Error::NotFound))
    );

    // A removed module is equally gone, even though its version is still live.
    h.client
        .remove_module(&h.owner, &h.org, &ModuleKind::Wallet);
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn only_a_role_that_reaches_the_kind_may_upgrade_it() {
    let h = setup_path();
    let stranger = Address::generate(&h.env);
    let policy_manager = Address::generate(&h.env);
    let upgrader = Address::generate(&h.env);
    h.client.grant_role(
        &h.owner,
        &h.org,
        &policy_manager,
        &RegistryRole::PolicyManager,
    );
    h.client
        .grant_role(&h.owner, &h.org, &upgrader, &RegistryRole::ModuleUpgrader);

    // A stranger has no role at all...
    assert_eq!(
        h.client
            .try_upgrade_module(&stranger, &h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::Unauthorized))
    );
    // ...and a `PolicyManager` reaches Policy registrations, not the versioned
    // Wallet path, even though an upgrade is exactly the kind of change that
    // role is not scoped to.
    assert_eq!(
        h.client
            .try_upgrade_module(&policy_manager, &h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::Unauthorized))
    );
    // Every refusal left the module alone.
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(pin(&h), 0);

    // A `ModuleUpgrader` may repoint any kind, and the owner may as well.
    assert_eq!(
        h.client
            .upgrade_module(&upgrader, &h.org, &ModuleKind::Wallet, &2),
        2
    );
    assert_eq!(pointed_at(&h), h.v2);
    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &3),
        3
    );
    assert_eq!(pointed_at(&h), h.v3);
}

#[test]
fn an_upgrade_of_an_unknown_organization_is_not_found() {
    let h = setup_path();
    let ghost = String::from_str(&h.env, "ghost");
    // An unknown org has no owner and no modules, so it reports NotFound rather
    // than a permission failure.
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &ghost, &ModuleKind::Wallet, &2),
        Err(Ok(Error::NotFound))
    );
    // Even the protocol admin cannot invent one through this path.
    assert_eq!(
        h.client
            .try_upgrade_module(&h.admin, &ghost, &ModuleKind::Wallet, &2),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn an_empty_organization_slug_is_refused() {
    let h = setup_path();
    let blank = String::from_str(&h.env, "");
    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &blank, &ModuleKind::Wallet, &2),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        h.client
            .try_validate_upgrade(&blank, &ModuleKind::Wallet, &2),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn a_frozen_registry_refuses_upgrades_and_validations() {
    let h = setup_path();
    h.client.freeze(&h.owner, &h.org);

    assert_eq!(
        h.client
            .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::RegistryFrozen))
    );
    // The pre-flight refuses too, so a keeper cannot be told an upgrade is
    // available while the registry would refuse to record it.
    assert_eq!(
        h.client
            .try_validate_upgrade(&h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::RegistryFrozen))
    );
    // The pointer and the pin are untouched. Routing is frozen too, so the
    // recorded address is read through the getter that stays open.
    assert_eq!(
        h.client.get_module_address(&h.org, &ModuleKind::Wallet),
        h.v1
    );
    assert_eq!(pin(&h), 0);

    h.client.unfreeze(&h.owner, &h.org);
    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        2
    );
    assert_eq!(pointed_at(&h), h.v2);
}

#[test]
fn validation_predicts_every_refusal_of_the_write_path() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);

    // With the module on v2, each of these is refused — and the dry run must
    // report the very code the upgrade would have reported, in the same order.
    let cases = [
        (0u32, Error::InvalidInput),
        (99, Error::NotFound),
        (2, Error::CircularUpgrade),
        (1, Error::CircularUpgrade),
    ];
    for (version, expected) in cases {
        assert_eq!(
            h.client
                .try_validate_upgrade(&h.org, &ModuleKind::Wallet, &version),
            Err(Ok(expected)),
            "validate_upgrade({version})"
        );
        assert_eq!(
            h.client
                .try_upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &version),
            Err(Ok(expected)),
            "upgrade_module({version})"
        );
    }
    // None of the attempts moved anything.
    assert_eq!(pointed_at(&h), h.v2);
    assert_eq!(pin(&h), 2);
}

#[test]
fn validation_is_read_only_and_needs_no_signature() {
    // An env with no mocked auth at all: only a read-only call can succeed in
    // it, which is what makes this a test of the auth-free property.
    let env = Env::default();
    let id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let org = String::from_str(&env, "acme");
    let v1 = impl_address(&env);
    let v2 = impl_address(&env);
    let code = BytesN::from_array(&env, &[2; 32]);
    // Write the records a deployed registry would already hold.
    env.as_contract(&id, || {
        env.storage()
            .persistent()
            .set(&DataKey::Org(org.clone()), &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Module(org.clone(), ModuleKind::Wallet), &v1);
        env.storage().persistent().set(
            &DataKey::VersionRecord(ModuleKind::Wallet, 2),
            &VersionRecord {
                address: v2.clone(),
                hash: BoundHash::Bound(code.clone()),
            },
        );
        env.storage()
            .persistent()
            .set(&DataKey::ApprovedWasm(ModuleKind::Wallet, code), &true);
    });

    assert_eq!(client.validate_upgrade(&org, &ModuleKind::Wallet, &2), v2);
    // The write path needs a signature, and gets none.
    assert!(client
        .try_upgrade_module(&admin, &org, &ModuleKind::Wallet, &2)
        .is_err());
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), v1);
    assert_eq!(client.get_module_version(&org, &ModuleKind::Wallet), 0);
}

#[test]
fn an_upgrade_demands_the_callers_signature() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);

    // The owner's signature was required for exactly this invocation.
    let auths = h.env.auths();
    let (signer, invocation) = auths.last().expect("the upgrade must require auth");
    assert_eq!(signer, &h.owner);
    match &invocation.function {
        AuthorizedFunction::Contract((contract, function, _args)) => {
            assert_eq!(contract, &h.client.address);
            assert_eq!(function, &Symbol::new(&h.env, "upgrade_module"));
        }
        _ => panic!("expected a contract invocation"),
    }
}

#[test]
fn an_upgrade_clears_a_deprecation_flag() {
    let h = setup_path();
    h.client
        .deprecate_module(&h.admin, &h.org, &ModuleKind::Wallet);
    assert_eq!(
        h.client.try_lookup(&h.org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );

    // Upgrading is the cure for a deprecated module: the implementation it just
    // left must not keep the new address unroutable.
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);
    assert!(!h.client.is_module_deprecated(&h.org, &ModuleKind::Wallet));
    assert_eq!(pointed_at(&h), h.v2);
}

#[test]
fn pins_are_reported_per_module() {
    let h = setup_path();
    // Unpinned, and distinct from "no such module".
    assert_eq!(pin(&h), 0);
    assert_eq!(
        h.client.try_get_module_version(&h.org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
    let ghost = String::from_str(&h.env, "ghost");
    assert_eq!(
        h.client.try_get_module_version(&ghost, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );

    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);
    assert_eq!(pin(&h), 2);
    // Another kind in the same org is untouched, and so is another org.
    assert_eq!(
        h.client.try_get_module_version(&h.org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn each_organization_keeps_its_own_upgrade_path() {
    let h = setup_path();
    let other = String::from_str(&h.env, "globex");
    let other_owner = Address::generate(&h.env);
    h.client.register_org(&h.admin, &other, &other_owner);
    h.client
        .register_module(&other_owner, &other, &ModuleKind::Wallet, &h.v1);

    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &3);
    assert_eq!(pin(&h), 3);
    // `globex` is still on v1 with an empty path: one organization's upgrade
    // says nothing about another's.
    assert_eq!(h.client.get_module_version(&other, &ModuleKind::Wallet), 0);
    assert_eq!(
        h.client
            .upgrade_module(&other_owner, &other, &ModuleKind::Wallet, &2),
        2
    );
    assert_eq!(h.client.get_module_version(&other, &ModuleKind::Wallet), 2);
    assert_eq!(h.client.lookup(&other, &ModuleKind::Wallet), h.v2);
}

#[test]
fn re_registering_by_address_starts_a_new_upgrade_path() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &3);
    assert_eq!(pin(&h), 3);

    // Pointing the module at a fresh implementation by hand discards the old
    // path: the pin described code this module no longer runs, and keeping it
    // would make the module refuse versions it never actually left behind.
    let fresh = impl_address(&h.env);
    h.client
        .register_module(&h.owner, &h.org, &ModuleKind::Wallet, &fresh);
    assert_eq!(pointed_at(&h), fresh);
    assert_eq!(pin(&h), 0);
    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &1),
        1
    );
    assert_eq!(pointed_at(&h), h.v1);
    assert_eq!(pin(&h), 1);
}

#[test]
fn removing_a_module_forgets_its_upgrade_path() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);
    h.client
        .remove_module(&h.owner, &h.org, &ModuleKind::Wallet);
    // The pin never outlives the record it describes.
    assert_eq!(
        h.client.try_get_module_version(&h.org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );

    let fresh = impl_address(&h.env);
    h.client
        .register_module(&h.owner, &h.org, &ModuleKind::Wallet, &fresh);
    assert_eq!(pin(&h), 0);
    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &1),
        1
    );
    assert_eq!(pointed_at(&h), h.v1);
}

#[test]
fn an_upgrade_extends_the_records_it_writes() {
    let h = setup_path();
    // Age every record the upgrade touches past the bump threshold.
    h.env.ledger().with_mut(|l| l.sequence_number += 2 * 17_280);
    let module_ttl = || {
        h.env.as_contract(&h.client.address, || {
            h.env
                .storage()
                .persistent()
                .get_ttl(&DataKey::Module(h.org.clone(), ModuleKind::Wallet))
        })
    };
    let pin_ttl = || {
        h.env.as_contract(&h.client.address, || {
            h.env
                .storage()
                .persistent()
                .get_ttl(&DataKey::ModuleVersion(h.org.clone(), ModuleKind::Wallet))
        })
    };
    let aged_module = module_ttl();
    assert!(aged_module < PERSISTENT_BUMP_AMOUNT);

    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);

    // The module record and the new pin are both kept alive by the same bump, so
    // they can never expire apart and leave a module that exists but whose
    // ordering guard has silently reset.
    assert_eq!(module_ttl(), PERSISTENT_BUMP_AMOUNT);
    assert_eq!(pin_ttl(), PERSISTENT_BUMP_AMOUNT);
    // The version record the target was resolved from is extended too, as any
    // successful read of it does.
    assert_eq!(
        version_ttl(&h.env, &h.client, ModuleKind::Wallet, 2),
        PERSISTENT_BUMP_AMOUNT
    );
}

#[test]
fn modules_registered_before_this_feature_still_upgrade() {
    // A deployment whose modules were all registered by address: no
    // `ModuleVersion` entry exists anywhere, and none is required for the
    // validated path to work.
    let h = setup_path();
    env_as_contract(&h, |env| {
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::ModuleVersion(h.org.clone(), ModuleKind::Wallet)));
    });
    assert_eq!(pin(&h), 0);
    assert_eq!(
        h.client
            .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        2
    );
    assert_eq!(pin(&h), 2);
    // The pre-existing layouts are untouched: the module still answers the
    // legacy address getter, and no version record moved.
    assert_eq!(
        h.client.get_module_address(&h.org, &ModuleKind::Wallet),
        h.v2
    );
    assert_eq!(h.client.get_version(&ModuleKind::Wallet, &1), h.v1);
    assert_eq!(h.client.get_version(&ModuleKind::Wallet, &2), h.v2);
}

// ---------------------------------------------------------------------------
// Versioned registration (Issue #287)
//
// `register_module` takes an address from the caller, so it can point a module
// at code the registry never published or approved. `register_module_version`
// resolves the address from the immutable version record instead and advances
// the pin with it, so a module can be brought up on a published version without
// an address ever crossing the boundary — and the upgrade path stays monotonic
// even when it is driven through registration rather than `upgrade_module`.
// ---------------------------------------------------------------------------

/// Whether the canonical `ContractEvent` with this variant symbol was published
/// during the test.
fn has_event(env: &Env, variant: &str) -> bool {
    let want: Val = Symbol::new(env, variant).into_val(env);
    env.events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want))
}

/// Register a second organization in `h` and return its slug, so a test can
/// exercise registration on a module that does not exist yet.
fn fresh_org(h: &PathHarness) -> (String, Address) {
    let org = String::from_str(&h.env, "globex");
    let owner = Address::generate(&h.env);
    h.client.register_org(&h.admin, &org, &owner);
    (org, owner)
}

#[test]
fn versioned_registration_creates_a_module_from_a_published_version() {
    let h = setup_path();
    let (org, owner) = fresh_org(&h);

    assert_eq!(
        h.client
            .register_module_version(&owner, &org, &ModuleKind::Wallet, &2),
        2
    );
    // The pointer is the version record's address, and the module starts its
    // upgrade path already pinned to the version it runs.
    assert_eq!(h.client.lookup(&org, &ModuleKind::Wallet), h.v2);
    assert_eq!(h.client.get_module_version(&org, &ModuleKind::Wallet), 2);
    // The version record itself is untouched: registration moves a module, it
    // does not republish a version.
    assert_eq!(h.client.get_version_wasm(&ModuleKind::Wallet, &2), h.h2);

    // A module that did not exist was registered, not upgraded.
    assert_event(&h.env, "RegistryModuleUpdated");
    assert!(!has_event(&h.env, "RegistryModuleUpgraded"));
    // ...and the harness's own module is exactly where it was.
    assert_eq!(pin(&h), 0);
    assert_eq!(pointed_at(&h), h.v1);
}

#[test]
fn versioned_registration_pins_a_module_registered_by_address() {
    let h = setup_path();
    // The module predates validated upgrades: registered by address, no pin.
    assert_eq!(pin(&h), 0);
    assert_eq!(
        h.client
            .register_module_version(&h.owner, &h.org, &ModuleKind::Wallet, &3),
        3
    );
    assert_eq!(pin(&h), 3);
    assert_eq!(pointed_at(&h), h.v3);
    // A move onto an existing registration is reported as an upgrade too, so an
    // indexer sees one history whichever entrypoint drove it.
    assert_event(&h.env, "RegistryModuleUpgraded");
}

#[test]
fn versioned_registration_moves_an_existing_module_forward() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);

    assert_eq!(
        h.client
            .register_module_version(&h.owner, &h.org, &ModuleKind::Wallet, &3),
        3
    );
    assert_eq!(pointed_at(&h), h.v3);
    assert_eq!(pin(&h), 3);

    // The most recent upgrade event: the earlier `upgrade_module` call emitted
    // one too, and this move must be reported as its own step.
    let want_topic: Val = Symbol::new(&h.env, "RegistryModuleUpgraded").into_val(&h.env);
    let event = h
        .env
        .events()
        .all()
        .iter()
        .rfind(|(_id, topics, _data)| topics.contains(want_topic))
        .expect("RegistryModuleUpgraded must be emitted");
    // The move starts from the pin it replaced, not from zero: the upgrade path
    // is continuous across the two entrypoints.
    let data: (String, ModuleKind, u32, u32, Address, BytesN<32>) = event.2.into_val(&h.env);
    assert_eq!(
        data,
        (
            h.org.clone(),
            ModuleKind::Wallet,
            2,
            3,
            h.v3.clone(),
            h.h3.clone()
        )
    );
}

#[test]
fn versioned_registration_refuses_the_version_the_module_already_runs() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);

    // Equal version: the degenerate cycle both validated paths refuse.
    assert_eq!(
        h.client
            .try_register_module_version(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::CircularUpgrade))
    );
    assert_eq!(pointed_at(&h), h.v2);
    assert_eq!(pin(&h), 2);
}

#[test]
fn versioned_registration_cannot_walk_backwards() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &3);

    // Older version: refused, and nothing is written, so the module cannot be
    // rolled back through the registration path.
    let before = h.env.events().all().len();
    assert_eq!(
        h.client
            .try_register_module_version(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::CircularUpgrade))
    );
    assert_eq!(pointed_at(&h), h.v3);
    assert_eq!(pin(&h), 3);
    // A refusal reports nothing: no registration and no upgrade event.
    assert_eq!(h.env.events().all().len(), before);
}

#[test]
fn versioned_registration_validates_the_version_record() {
    let h = setup_path();
    let (org, owner) = fresh_org(&h);

    // Never published for this kind, and version `0` is not a record at all.
    assert_eq!(
        h.client
            .try_register_module_version(&owner, &org, &ModuleKind::Wallet, &99),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client
            .try_register_module_version(&owner, &org, &ModuleKind::Wallet, &0),
        Err(Ok(Error::InvalidInput))
    );
    // Code the admin has revoked is no longer a valid destination.
    h.client
        .remove_approved_wasm(&h.admin, &ModuleKind::Wallet, &h.h2);
    assert_eq!(
        h.client
            .try_register_module_version(&owner, &org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::Unauthorized))
    );
    // Every refusal above wrote nothing: the module does not exist.
    assert_eq!(
        h.client.try_get_module_version(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn versioned_registration_needs_permission_and_a_signature() {
    let h = setup_path();
    let (org, owner) = fresh_org(&h);
    let intruder = Address::generate(&h.env);

    // A stranger reaches neither the organization nor its modules.
    assert_eq!(
        h.client
            .try_register_module_version(&intruder, &org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::Unauthorized))
    );
    // The protocol admin and the recorded owner both do...
    assert_eq!(
        h.client
            .register_module_version(&h.admin, &org, &ModuleKind::Wallet, &2),
        2
    );
    // ...and so does an account the owner has delegated the upgrader role to.
    h.client
        .grant_role(&owner, &org, &intruder, &RegistryRole::ModuleUpgrader);
    assert_eq!(
        h.client
            .register_module_version(&intruder, &org, &ModuleKind::Wallet, &3),
        3
    );

    // The caller's own signature was demanded for exactly that invocation.
    let auths = h.env.auths();
    let (signer, invocation) = auths.last().expect("the registration must require auth");
    assert_eq!(signer, &intruder);
    match &invocation.function {
        AuthorizedFunction::Contract((contract, function, _args)) => {
            assert_eq!(contract, &h.client.address);
            assert_eq!(function, &Symbol::new(&h.env, "register_module_version"));
        }
        _ => panic!("expected a contract invocation"),
    }
}

#[test]
fn versioned_registration_clears_a_deprecation_flag() {
    let h = setup_path();
    h.client
        .upgrade_module(&h.owner, &h.org, &ModuleKind::Wallet, &2);
    h.client
        .deprecate_module(&h.admin, &h.org, &ModuleKind::Wallet);
    assert_eq!(
        h.client.try_lookup(&h.org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );

    h.client
        .register_module_version(&h.owner, &h.org, &ModuleKind::Wallet, &3);
    // The module runs a live, registered implementation again, so routing works.
    assert_eq!(h.client.lookup(&h.org, &ModuleKind::Wallet), h.v3);
    assert!(!h.client.is_module_deprecated(&h.org, &ModuleKind::Wallet));
}

#[test]
fn versioned_registration_agrees_with_the_upgrade_validation() {
    let h = setup_path();
    // The pre-flight and the write path reach the same conclusion, before and
    // after the move.
    assert_eq!(
        h.client.validate_upgrade(&h.org, &ModuleKind::Wallet, &2),
        h.v2
    );
    assert_eq!(
        h.client
            .register_module_version(&h.owner, &h.org, &ModuleKind::Wallet, &2),
        2
    );
    assert_eq!(
        h.client
            .try_validate_upgrade(&h.org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::CircularUpgrade))
    );
}

// ---------------------------------------------------------------------------
// Multi-admin and multisig authorization checks (Issue #224)
// ---------------------------------------------------------------------------

#[test]
fn multi_admin_add_remove_and_get_admins() {
    let (env, client, admin1) = setup();
    let admin2 = Address::generate(&env);
    let admin3 = Address::generate(&env);
    let stranger = Address::generate(&env);

    // Initial admin is present
    let initial_admins = client.get_admins();
    assert_eq!(initial_admins.len(), 1);
    assert!(initial_admins.contains(&admin1));
    assert_eq!(client.get_admin(), admin1);
    assert!(client.is_authorized_admin(&admin1));
    assert!(!client.is_authorized_admin(&stranger));

    // Stranger cannot add an admin
    assert_eq!(
        client.try_add_admin(&stranger, &admin2),
        Err(Ok(Error::Unauthorized))
    );

    // Admin1 adds Admin2
    client.add_admin(&admin1, &admin2);
    let admins = client.get_admins();
    assert_eq!(admins.len(), 2);
    assert!(admins.contains(&admin1));
    assert!(admins.contains(&admin2));
    assert!(client.is_authorized_admin(&admin2));

    // Adding duplicate admin fails
    assert_eq!(
        client.try_add_admin(&admin1, &admin2),
        Err(Ok(Error::AlreadyExists))
    );

    // Admin2 can add Admin3
    client.add_admin(&admin2, &admin3);
    assert_eq!(client.get_admins().len(), 3);

    // Stranger cannot remove an admin
    assert_eq!(
        client.try_remove_admin(&stranger, &admin3),
        Err(Ok(Error::Unauthorized))
    );

    // Removing non-existent admin fails
    assert_eq!(
        client.try_remove_admin(&admin1, &stranger),
        Err(Ok(Error::NotFound))
    );

    // Admin2 removes Admin3
    client.remove_admin(&admin2, &admin3);
    let admins_after_remove = client.get_admins();
    assert_eq!(admins_after_remove.len(), 2);
    assert!(!admins_after_remove.contains(&admin3));
    assert!(!client.is_authorized_admin(&admin3));

    // Removing primary admin rotates primary to the remaining admin
    client.remove_admin(&admin2, &admin1);
    assert_eq!(client.get_admin(), admin2);
    assert_eq!(client.get_admins().len(), 1);
    assert!(!client.is_authorized_admin(&admin1));

    // Cannot remove the last remaining admin
    assert_eq!(
        client.try_remove_admin(&admin2, &admin2),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn multisig_configuration_and_lifecycle() {
    let (env, client, admin) = setup();
    let multisig = Address::generate(&env);
    let stranger = Address::generate(&env);

    assert_eq!(client.get_multisig(), None);
    assert!(!client.is_authorized_admin(&multisig));

    // Stranger cannot configure multisig
    assert_eq!(
        client.try_set_multisig(&stranger, &multisig),
        Err(Ok(Error::Unauthorized))
    );

    // Admin configures multisig
    client.set_multisig(&admin, &multisig);
    assert_eq!(client.get_multisig(), Some(multisig.clone()));
    assert!(client.is_authorized_admin(&multisig));

    // Multisig can administer registry (e.g. add an admin)
    let new_admin = Address::generate(&env);
    client.add_admin(&multisig, &new_admin);
    assert!(client.get_admins().contains(&new_admin));

    // Stranger cannot remove multisig
    assert_eq!(
        client.try_remove_multisig(&stranger),
        Err(Ok(Error::Unauthorized))
    );

    // Admin removes multisig
    client.remove_multisig(&admin);
    assert_eq!(client.get_multisig(), None);
    assert!(!client.is_authorized_admin(&multisig));

    // Removing when absent fails
    assert_eq!(client.try_remove_multisig(&admin), Err(Ok(Error::NotFound)));
}

#[test]
fn multi_admin_and_multisig_wasm_hash_management() {
    let (env, client, admin) = setup();
    let admin2 = Address::generate(&env);
    let multisig = Address::generate(&env);
    let stranger = Address::generate(&env);

    client.add_admin(&admin, &admin2);
    client.set_multisig(&admin, &multisig);

    let h1 = hash(&env, 101);
    let h2 = hash(&env, 102);

    // Unauthorized callers cannot approve Wasm hashes
    assert_eq!(
        client.try_add_approved_wasm(&stranger, &ModuleKind::Wallet, &h1),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!client.is_wasm_approved(&ModuleKind::Wallet, &h1));

    // Secondary admin can approve Wasm hash
    client.add_approved_wasm(&admin2, &ModuleKind::Wallet, &h1);
    assert!(client.is_wasm_approved(&ModuleKind::Wallet, &h1));

    // Multisig can approve Wasm hash
    client.add_approved_wasm(&multisig, &ModuleKind::Organization, &h2);
    assert!(client.is_wasm_approved(&ModuleKind::Organization, &h2));

    // Stranger cannot remove approved Wasm hash
    assert_eq!(
        client.try_remove_approved_wasm(&stranger, &ModuleKind::Wallet, &h1),
        Err(Ok(Error::Unauthorized))
    );

    // Secondary admin can remove approved Wasm hash
    client.remove_approved_wasm(&admin2, &ModuleKind::Wallet, &h1);
    assert!(!client.is_wasm_approved(&ModuleKind::Wallet, &h1));

    // Multisig can remove approved Wasm hash
    client.remove_approved_wasm(&multisig, &ModuleKind::Organization, &h2);
    assert!(!client.is_wasm_approved(&ModuleKind::Organization, &h2));

    // Removed admin loses authorization to manage Wasm hashes
    client.remove_admin(&admin, &admin2);
    assert_eq!(
        client.try_add_approved_wasm(&admin2, &ModuleKind::Wallet, &h1),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn multi_admin_and_multisig_register_version() {
    let (env, client, admin) = setup();
    let admin2 = Address::generate(&env);
    let multisig = Address::generate(&env);
    let stranger = Address::generate(&env);

    client.add_admin(&admin, &admin2);
    client.set_multisig(&admin, &multisig);

    let h1 = hash(&env, 111);
    let h2 = hash(&env, 112);
    client.add_approved_wasm(&admin, &ModuleKind::Wallet, &h1);
    client.add_approved_wasm(&admin, &ModuleKind::Wallet, &h2);

    let v1_addr = Address::generate(&env);
    let v2_addr = Address::generate(&env);

    // Stranger cannot register version
    assert_eq!(
        client.try_register_version(&stranger, &ModuleKind::Wallet, &1, &v1_addr, &h1),
        Err(Ok(Error::Unauthorized))
    );

    // Admin2 registers v1
    client.register_version(&admin2, &ModuleKind::Wallet, &1, &v1_addr, &h1);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), v1_addr);

    // Multisig registers v2
    client.register_version(&multisig, &ModuleKind::Wallet, &2, &v2_addr, &h2);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &2), v2_addr);

    // Removed admin cannot register version
    client.remove_admin(&admin, &admin2);
    let v3_addr = Address::generate(&env);
    let h3 = hash(&env, 113);
    client.add_approved_wasm(&admin, &ModuleKind::Wallet, &h3);
    assert_eq!(
        client.try_register_version(&admin2, &ModuleKind::Wallet, &3, &v3_addr, &h3),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn multi_admin_and_multisig_contract_upgrade_authorization() {
    let h = setup_upgrade();
    let admin2 = Address::generate(&h.env);
    let multisig = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);

    // Bootstrap upgrade authority on member
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);

    // Configure admin2 and multisig on member
    h.member.add_admin(&h.admin, &admin2);
    h.member.set_multisig(&h.admin, &multisig);

    let h1 = hash(&h.env, 201);
    let h2 = hash(&h.env, 202);

    // Stranger attempting upgrade is rejected with Unauthorized at Gate 1
    assert_eq!(
        h.member.try_upgrade(&stranger, &h1),
        Err(Ok(Error::Unauthorized))
    );

    // Admin2 is authorized at Gate 1; if hash is unapproved, rejected with Unauthorized
    assert_eq!(
        h.member.try_upgrade(&admin2, &h1),
        Err(Ok(Error::Unauthorized))
    );

    // Member approves Wasm hash for Organization
    h.member
        .add_approved_wasm(&admin2, &ModuleKind::Organization, &h1);

    // Admin2 passes Gate 1 (auth and approval); fails at Gate 2 (NotFound in version map)
    assert_eq!(h.member.try_upgrade(&admin2, &h1), Err(Ok(Error::NotFound)));

    // Multisig passes Gate 1: if hash unapproved, Unauthorized
    assert_eq!(
        h.member.try_upgrade(&multisig, &h2),
        Err(Ok(Error::Unauthorized))
    );

    // Multisig approves Wasm hash h2
    h.member
        .add_approved_wasm(&multisig, &ModuleKind::Organization, &h2);

    // Multisig passes Gate 1; reaches Gate 2 (NotFound in version map)
    assert_eq!(
        h.member.try_upgrade(&multisig, &h2),
        Err(Ok(Error::NotFound))
    );

    // Removing admin2 revokes their upgrade authorization; fails at Gate 1 even for approved hash
    h.member.remove_admin(&h.admin, &admin2);
    assert_eq!(
        h.member.try_upgrade(&admin2, &h1),
        Err(Ok(Error::Unauthorized))
    );

    // Removing multisig revokes multisig upgrade authorization
    h.member.remove_multisig(&h.admin);
    assert_eq!(
        h.member.try_upgrade(&multisig, &h2),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn multi_admin_and_multisig_module_upgrade_authorization() {
    let (env, client, admin) = setup();
    let admin2 = Address::generate(&env);
    let multisig = Address::generate(&env);
    let stranger = Address::generate(&env);

    client.add_admin(&admin, &admin2);
    client.set_multisig(&admin, &multisig);

    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let mod_v1 = env.register_contract(None, RegistryContract);
    let mod_v2 = env.register_contract(None, RegistryContract);
    let mod_v3 = env.register_contract(None, RegistryContract);
    let h1 = hash(&env, 1);
    let h2 = hash(&env, 2);
    let h3 = hash(&env, 3);

    client.add_approved_wasm(&admin, &ModuleKind::Wallet, &h1);
    client.add_approved_wasm(&admin, &ModuleKind::Wallet, &h2);
    client.add_approved_wasm(&admin, &ModuleKind::Wallet, &h3);

    client.register_version(&admin, &ModuleKind::Wallet, &1, &mod_v1, &h1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &mod_v2, &h2);
    client.register_version(&admin, &ModuleKind::Wallet, &3, &mod_v3, &h3);

    // Register module v1
    client.register_module(&owner, &org, &ModuleKind::Wallet, &mod_v1);

    // Stranger cannot upgrade module
    assert_eq!(
        client.try_upgrade_module(&stranger, &org, &ModuleKind::Wallet, &2),
        Err(Ok(Error::Unauthorized))
    );

    // Admin2 can upgrade module
    assert_eq!(
        client.upgrade_module(&admin2, &org, &ModuleKind::Wallet, &2),
        2
    );
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), mod_v2);

    // Multisig can upgrade module
    assert_eq!(
        client.upgrade_module(&multisig, &org, &ModuleKind::Wallet, &3),
        3
    );
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), mod_v3);
}
