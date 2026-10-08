#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Wallet Contract
//!
//! Programmable, stateful custody wallets for AI agents. The contract is the
//! on-chain custodian: real assets (Stellar Asset Contract tokens) are held at
//! the wallet contract's own address, while per-wallet balances are tracked in
//! internal bookkeeping so an individual wallet can never spend more than it
//! holds.
//!
//! Lifecycle states (PRD Doc 7 §Wallet): `Active`, `Frozen`, `Paused`,
//! `Archived`. Outbound value movement is only permitted from an `Active`
//! wallet; every other state fails safely with a specific error.
//!
//! ## Emergency circuit breaker
//!
//! The per-wallet states above are the owner's tool: they act on one wallet at
//! a time and the owner must be in a position to use them. Compromised agent
//! keys and abnormal on-chain behaviour do not respect that granularity, so the
//! contract also carries a single contract-wide breaker.
//!
//! While tripped, every outbound path — `transfer`, `withdraw` — and the
//! creation of new wallets are refused with [`Error::WalletPaused`]. Everything
//! needed to inspect and recover stays live: all views, `deposit`, and the
//! per-wallet `freeze` / `pause` / `archive` transitions, so an operator can
//! quarantine individual wallets while the breaker holds the line globally.
//!
//! Authority is deliberately asymmetric. A designated guardian can *trip* the
//! breaker, so reacting to an incident is fast and needs only one key. Only the
//! admin can *reset* it — point `admin` at the organization's multisig and
//! resuming operations requires a threshold of signers.
//!
//! Functions: `create_wallet`, `deposit`, `transfer`, `withdraw`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `archive`, `emergency_pause`,
//! `emergency_unpause`, `set_guardian`, `set_policy`, `clear_policy`,
//! `set_policy_bypass`, `batch_execute_validated`, `set_budget`,
//! `set_rate_limit`, `clear_rate_limit`, `custody_balance`.
//!
//! ## Multi-token custody verification
//!
//! The contract custodies any number of Stellar Asset Contract (SAC) assets at
//! once: per-wallet balances are tracked per `(wallet, asset)` pair, so one
//! wallet can hold several tokens without the ledgers touching. Before any
//! outbound movement is approved, two independent checks must pass: the
//! wallet's tracked balance covers the amount ([`Error::InsufficientFunds`]
//! otherwise) and the contract's real on-chain custody — read through the
//! token's SAC `balance` entry point — covers it too. The custody read fails
//! closed ([`Error::InvalidState`] / [`Error::Unauthorized`]) when the asset
//! is not a queryable token, so a mis-typed asset address can never pass for
//! a zero balance. Together the checks turn a token-side refusal that would
//! trap the invocation into a deterministic error code.
//!
//! ## Pre-execution policy hook
//!
//! Per the architecture, the wallet "holds funds and enforces policy before
//! executing transactions". Every outbound movement — `transfer` and
//! `withdraw` — therefore consults the org's Policy contract (wired with
//! [`WalletContract::set_policy`]) *before* any balance is debited or any
//! token moves. The policy is invoked through the generated [`PolicyClient`]
//! with the same canonical `"active"` policy id the treasury uses; a
//! rejection propagates as a deterministic policy error and aborts the
//! invocation, so the wallet is never left debited without the spend having
//! been approved. Individual wallets can be excused from the org-wide gate
//! with [`WalletContract::set_policy_bypass`] (admin only).
//!
//! ## Velocity limits
//!
//! Absolute caps bound how much can be spent, not how fast: a compromised
//! agent key could drain everything a policy allows within seconds. A wallet
//! [`Role::Admin`] can therefore set a per-asset velocity ceiling
//! ([`WalletContract::set_velocity_limit`]): at most `max_amount` may leave the
//! wallet within a rolling window of `window_seconds`. The check runs in the
//! same pre-execution path, right after the policy approves the spend and
//! before any balance is debited, on `transfer`, `withdraw` and every
//! validated batch action; a breach fails with
//! [`Error::VelocityLimitExceeded`] and nothing moves.
//!
//! The window is tracked as [`VELOCITY_BUCKETS`] ledger-time buckets in one
//! fixed-size record per (wallet, asset), overwritten in place. Rejected
//! spends revert with the invocation, so they never consume allowance. The
//! velocity ceiling is independent of the policy bypass: excusing a wallet
//! from the org policy does not lift its own ceiling.
//!
//! ## Sliding-window rate limits
//!
//! Velocity ceilings bound one asset's outflow but say nothing about how many
//! transactions a wallet emits, so a compromised agent can still spray many
//! small spends, or spread value across several assets, without tripping a
//! per-asset ceiling. A wallet [`Role::Admin`] can therefore set a per-wallet
//! rate limit ([`WalletContract::set_rate_limit`]): at most `max_volume` may
//! leave the wallet and at most `max_count` outbound transactions may be issued
//! within a rolling window of `window_seconds`, counted across every asset and
//! across `transfer`, `withdraw` and validated batch actions.
//!
//! The window is tracked as [`RATE_LIMIT_BUCKETS`] ledger-time buckets in one
//! fixed-size record per wallet, overwritten in place, so usage never grows the
//! ledger footprint. A breach fails with [`Error::RateLimitExceeded`] and
//! nothing moves; rejected spends revert with the invocation, so they never
//! consume allowance. Setting `window_seconds == 0` disables the limit, and a
//! `0` cap means "unlimited" for that dimension.
//!
//! Events: `WalletCreated`, `WalletFrozen`, `TransferExecuted`, `WalletPaused`,
//! `WalletUnpaused` (shared schema) plus wallet-scoped state-change events.
//! Access control is role-based (see [`access`]). Every wallet has an owner,
//! who is implicitly [`Role::Admin`], and may delegate a role to any number of
//! other principals so that organization owners, human managers and autonomous
//! agent executors can share a wallet without sharing all of its powers:
//!
//! | Entrypoint                                   | Minimum role |
//! |----------------------------------------------|--------------|
//! | `withdraw`, `pause`, `unpause`, `archive`     | `Admin`      |
//! | `grant_role`, `revoke_role`                   | `Admin`      |
//! | `transfer`                                    | `Agent`      |
//! | `freeze`, `unfreeze`                          | `Agent`, or the contract admin |
//!
//! A caller whose role is below the requirement — including an `Auditor`, who
//! holds no mutating power at all — is rejected with [`Error::Unauthorized`].
//!
//! Functions: `create_wallet`, `deposit`, `transfer`, `withdraw`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `archive`, `grant_role`, `revoke_role`.
//!
//! Events: `WalletCreated`, `WalletFrozen`, `TransferExecuted` (shared schema)
//! plus wallet-scoped state-change and role-administration events.

use crate::access::Role;
use astroid_interfaces::{BudgetClient, PolicyClient, RegistryClient, UpgradeableInterface};
use astroid_shared::constants;
use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::events;
use astroid_shared::math::{checked_add, validate_sufficient_balance, SafeAdd, SafeSub};
use astroid_shared::token::{safe_transfer, token_balance};
pub use astroid_shared::types::WalletData;
use astroid_shared::types::{ModuleId, ModuleKind, ResourceState};
use astroid_shared::validation::{require_non_empty, require_positive_amount};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, String, Symbol, Val,
    Vec,
};

pub mod access;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Emergency/administrative address able to freeze any wallet (instance).
    Admin,
    /// Designated emergency guardian able to trip the breaker (instance).
    Guardian,
    /// Contract-wide emergency pause flag (instance).
    Paused,
    /// Monotonic wallet id counter (instance).
    WalletCount,
    /// Budget contract consulted when consuming batch action value (instance).
    Budget,
    /// Wallet record: id -> WalletData.
    Wallet(u64),
    /// Per-wallet, per-asset balance: (id, asset) -> i128.
    Balance(u64, Address),
    /// Org-wide Policy contract consulted before every outbound movement
    /// (instance).
    Policy,
    /// Per-wallet opt-out from the policy gate: wallet id -> bool (persistent).
    /// Present + `true` means the wallet spends without policy evaluation.
    PolicyBypass(u64),
    /// Velocity ceiling: (wallet id, asset) -> VelocityLimit (persistent).
    VelocityLimit(u64, Address),
    /// Rolling velocity usage: (wallet id, asset) -> VelocityUsage
    /// (persistent). One fixed-size record per limited (wallet, asset), always
    /// overwritten in place, so usage never grows the ledger footprint.
    VelocityUsage(u64, Address),
    /// Rate-limit config: wallet id -> RateLimitConfig (persistent). A missing
    /// entry means rate limiting is off.
    RateLimit(u64),
    /// Rolling rate usage: wallet id -> RateUsage (persistent). One fixed-size
    /// record per limited wallet, always overwritten in place.
    RateLimitUsage(u64),
    /// Registry contract for dynamic policy/budget resolution (instance).
    Registry,
    /// Organization slug for registry lookups (instance).
    Org,
    /// Re-entrancy lock flag (instance).
    ReentrancyLock,
    /// Default budget envelope id for single transfers (instance).
    DefaultBudgetId,
    /// Per-asset budget envelope id: asset -> budget_id (persistent).
    AssetBudgetId(Address),
}

/// Number of equal sub-buckets a velocity window is divided into. Spends are
/// bucketed by ledger time; a bucket's volume counts against the limit until
/// it slides out of the trailing window.
pub const VELOCITY_BUCKETS: u32 = 4;

/// A wallet's velocity ceiling for one asset: at most `max_amount` may leave
/// the wallet within the rolling window of `window_seconds`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VelocityLimit {
    /// Ceiling on outbound volume inside the window, in the asset's smallest
    /// unit. Strictly positive.
    pub max_amount: i128,
    /// Window length in seconds; a positive multiple of [`VELOCITY_BUCKETS`].
    pub window_seconds: u64,
}

/// Outbound volume recorded per bucket for one (wallet, asset).
///
/// `spent[i]` is the volume moved during bucket number `bucket - i`, where a
/// bucket number is `ledger_timestamp / (window_seconds / VELOCITY_BUCKETS)`.
/// `spent` always holds exactly [`VELOCITY_BUCKETS`] entries.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VelocityUsage {
    pub bucket: u64,
    pub spent: soroban_sdk::Vec<i128>,
}

/// Number of equal sub-buckets a rate-limit window is divided into. Outbound
/// activity is bucketed by ledger time; a bucket's volume and transaction count
/// count against the limit until the bucket slides out of the trailing window.
pub const RATE_LIMIT_BUCKETS: u32 = 4;

/// A wallet's rate limit: at most `max_volume` may leave the wallet and at most
/// `max_count` outbound transactions may be issued within the rolling window of
/// `window_seconds`. A `0` cap means "unlimited" for that dimension;
/// `window_seconds == 0` disables the limit entirely.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Ceiling on the total outbound volume inside the window, across every
    /// asset and path. `0` = unlimited.
    pub max_volume: i128,
    /// Ceiling on the number of outbound transactions inside the window. `0` =
    /// unlimited.
    pub max_count: u32,
    /// Window length in seconds; `0` disables the limit. Otherwise a positive
    /// multiple of [`RATE_LIMIT_BUCKETS`].
    pub window_seconds: u64,
}

/// Outbound activity recorded per bucket for one wallet.
///
/// `volume[i]` and `count[i]` describe bucket number `bucket - i`, where a
/// bucket number is `ledger_timestamp / (window_seconds / RATE_LIMIT_BUCKETS)`.
/// Both vectors always hold exactly [`RATE_LIMIT_BUCKETS`] entries.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateUsage {
    pub bucket: u64,
    pub volume: soroban_sdk::Vec<i128>,
    pub count: soroban_sdk::Vec<u32>,
}

/// Public snapshot of a wallet's outbound activity in the active rate-limit
/// window: total volume and transaction count.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitStatus {
    pub volume: i128,
    pub count: u32,
}

/// A single sub-call to be executed as part of a batch. `contract_addr` is the
/// target contract, `fn_name` is the entry-point symbol, and `args` are the
/// serialized arguments. The batch executor invokes each sub-call sequentially;
/// if any fails the entire transaction is atomically reverted by the Soroban
/// runtime.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractCall {
    pub contract_addr: Address,
    pub fn_name: Symbol,
    pub args: soroban_sdk::Vec<Val>,
}

/// One policy- and budget-gated action of a validated batch. Carries the raw
/// [`ContractCall`] to execute plus the metadata the wallet needs to validate
/// the action before any value moves: the policy envelope and asset/recipient
/// the spend is checked against, and the budget envelope it is consumed from.
///
/// An empty `policy_id` skips the policy gate for that action; an empty
/// `budget_id` skips budget consumption — mirrors how the treasury wires each
/// holding to a specific envelope.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchAction {
    /// The external sub-call to execute.
    pub call: ContractCall,
    /// Policy envelope id validated against this action; empty = skip.
    pub policy_id: String,
    /// Budget envelope id consumed by this action; empty = skip.
    pub budget_id: String,
    /// Asset moved by this action, used by the policy check.
    pub asset: Address,
    /// Recipient of this action's value, used by the policy check.
    pub recipient: Address,
    /// Value moved by this action, checked against policy and budget.
    pub amount: i128,
}

/// Aggregated outcome of a validated batch execution.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchReceipt {
    /// Number of sub-calls executed.
    pub executed: u32,
    /// Cumulative value across the batch (checked-sum of all action amounts).
    pub total_amount: i128,
    /// Remaining allocation of the last budget envelope consumed; `0` when the
    /// batch touched no budget.
    pub budget_remaining: i128,
}

/// Per-invocation cache for the velocity ceiling.
///
/// A batch routinely moves value in one asset across many actions. Without this
/// cache every action re-reads that asset's ceiling and re-reads the usage
/// record the previous action had just written, so an `n`-action batch spends
/// `n` times the ledger traffic the window actually needs. Entries are kept in
/// first-touch order, one per distinct asset, so a batch pays a single read of
/// the ceiling and the usage record per asset however many actions reference
/// it, and a single write and pair of TTL bumps on flush.
///
/// Reusing the rolled usage is sound because the ledger clock is fixed for the
/// whole invocation: aging a record to "now" twice within one call yields the
/// same result as aging it once, so only the first action on an asset pays for
/// the roll.
struct VelocityGate {
    wallet_id: u64,
    /// `(asset, ceiling, live usage)`. A `None` ceiling marks an asset with no
    /// limit configured, which costs one read and never grows a usage record.
    entries: soroban_sdk::Vec<(Address, Option<VelocityLimit>, Option<VelocityUsage>)>,
}

impl VelocityGate {
    fn new(env: &Env, wallet_id: u64) -> Self {
        Self {
            wallet_id,
            entries: soroban_sdk::Vec::new(env),
        }
    }

    /// Charge `amount` against `asset`'s ceiling, loading the asset's records on
    /// first touch and reusing them for every later action in this invocation.
    fn enforce(&mut self, env: &Env, asset: &Address, amount: i128) -> Result<(), Error> {
        let index = self.position(env, asset);
        let (_, limit, usage) = self.entries.get(index).unwrap();
        // No ceiling for this asset: there is nothing to charge and nothing to
        // record, exactly as an ungated asset behaves.
        let (Some(limit), Some(mut usage)) = (limit, usage) else {
            return Ok(());
        };
        // A sum that does not even fit in an i128 exceeds every ceiling.
        let within = WalletContract::velocity_total(&usage)?
            .checked_add(amount)
            .map(|after| after <= limit.max_amount)
            .unwrap_or(false);
        ensure!(within, Error::VelocityLimitExceeded);
        let current = usage.spent.get(0).unwrap_or(0).safe_add(amount)?;
        usage.spent.set(0, current);
        self.entries
            .set(index, (asset.clone(), Some(limit), Some(usage)));
        Ok(())
    }

    /// Persist every record this invocation charged, once per asset.
    ///
    /// Writes are deferred to the end of validation so a batch touches each
    /// usage record once. A failure before the flush reverts the invocation and
    /// leaves no usage recorded, which is the same net state as rolling back the
    /// per-action writes.
    fn flush(&self, env: &Env) {
        for (asset, limit, usage) in self.entries.iter() {
            let (Some(_), Some(usage)) = (limit, usage) else {
                continue;
            };
            let usage_key = DataKey::VelocityUsage(self.wallet_id, asset.clone());
            env.storage().persistent().set(&usage_key, &usage);
            // The ceiling is bumped next to its usage so the pair cannot lapse
            // mid-window: an expired ceiling would silently stop applying.
            WalletContract::bump_persistent(env, &usage_key);
            WalletContract::bump_persistent(env, &DataKey::VelocityLimit(self.wallet_id, asset));
        }
    }

    /// Index of `asset`'s entry, loading its records on first touch. The
    /// scanned prefix is bounded by [`constants::MAX_BATCH_CALLS`] because a
    /// batch cannot hold more actions than that, so the lookup stays a
    /// comparison over in-memory handles and costs no ledger access.
    fn position(&mut self, env: &Env, asset: &Address) -> u32 {
        for index in 0..self.entries.len() {
            if self.entries.get(index).unwrap().0 == *asset {
                return index;
            }
        }
        let wallet_id = self.wallet_id;
        let limit: Option<VelocityLimit> = env
            .storage()
            .persistent()
            .get(&DataKey::VelocityLimit(wallet_id, asset.clone()));
        // The usage record is only read for an asset that has a ceiling, so an
        // unlimited asset costs a single read.
        let usage = limit
            .as_ref()
            .map(|limit| WalletContract::rolled_velocity_usage(env, wallet_id, asset, limit));
        self.entries.push_back((asset.clone(), limit, usage));
        self.entries.len() - 1
    }
}

#[contract]
pub struct WalletContract;

#[contractimpl]
impl WalletContract {
    /// Initialize the contract with an emergency admin (may freeze wallets).
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        // The admin is its own guardian until a dedicated one is designated.
        env.storage().instance().set(&DataKey::Guardian, &admin);
        env.storage().instance().set(&DataKey::WalletCount, &0u64);
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Designate the emergency guardian allowed to trip the circuit breaker
    /// (admin only). Set it to a monitoring service or a partner key so an
    /// incident can be contained without waiting on the admin.
    pub fn set_guardian(env: Env, caller: Address, guardian: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Guardian, &guardian);
        Self::bump_instance(&env);
        events::publish(
            &env,
            events::ContractEvent::WalletGuardianChanged { guardian },
        );
        Ok(())
    }

    /// Trip the contract-wide circuit breaker (admin or guardian).
    ///
    /// Freezes every outbound movement and the creation of new wallets at once.
    /// Reads, deposits and the per-wallet recovery transitions stay available.
    pub fn emergency_pause(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_guardian_or_admin(&env, &caller)?;
        if Self::paused(&env) {
            return Err(Error::InvalidState);
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::bump_instance(&env);
        env.events()
            .publish((Symbol::new(&env, "WalletPaused"),), caller);
        Ok(())
    }

    /// Reset the circuit breaker and resume normal operation.
    ///
    /// Admin only: tripping the breaker is a fast, low-privilege reaction, but
    /// releasing it puts funds back in motion and must clear the higher bar.
    pub fn emergency_unpause(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if !Self::paused(&env) {
            return Err(Error::InvalidState);
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::bump_instance(&env);
        env.events()
            .publish((Symbol::new(&env, "WalletUnpaused"),), caller);
        Ok(())
    }

    /// Create a new wallet owned by `owner`. Returns the new wallet id.
    pub fn create_wallet(env: Env, owner: Address) -> Result<u64, Error> {
        Self::when_not_paused(&env)?;
        owner.require_auth();
        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::WalletCount)
            .ok_or(Error::NotInitialized)?;
        count = (count as i128).safe_add(1)? as u64;
        let id = count;
        let data = WalletData {
            owner: owner.clone(),
            state: ResourceState::Active,
        };
        env.storage().persistent().set(&DataKey::Wallet(id), &data);
        Self::bump_wallet(&env, id);
        env.storage().instance().set(&DataKey::WalletCount, &count);
        Self::bump_instance(&env);
        events::publish(
            &env,
            events::ContractEvent::WalletCreated {
                wallet_id: id,
                owner: owner.clone(),
            },
        );
        Ok(id)
    }

    /// Wire the org's Policy contract consulted before every outbound
    /// movement (admin only). Pass an address previously registered to enable
    /// the gate; `clear_policy` removes it. The policy is invoked through the
    /// generated [`PolicyClient`] so a rejection propagates as a deterministic
    /// error and the spend never executes.
    pub fn set_policy(env: Env, caller: Address, policy: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Policy, &policy);
        Self::bump_instance(&env);
        events::publish(
            &env,
            events::ContractEvent::WalletPolicyConfigured { policy },
        );
        Ok(())
    }

    /// Remove the policy gate (admin only). Subsequent spends run ungated.
    pub fn clear_policy(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if !env.storage().instance().has(&DataKey::Policy) {
            return Err(Error::NotFound);
        }
        env.storage().instance().remove(&DataKey::Policy);
        Self::bump_instance(&env);
        events::publish(&env, events::ContractEvent::WalletPolicyCleared);
        Ok(())
    }

    /// Read the wired policy contract, if any.
    pub fn get_policy(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Policy)
    }

    /// Excuse a single wallet from the org-wide policy gate (admin only).
    ///
    /// The gate is org-wide by design; this escape hatch exists for wallets
    /// whose outflows are governed by a stricter contract-level control (a
    /// multisig-guarded payroll wallet, for example). The flag persists so the
    /// opt-out survives TTL expiry of the wallet record.
    pub fn set_policy_bypass(
        env: Env,
        caller: Address,
        wallet_id: u64,
        bypass: bool,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        // Only existing wallets can be configured.
        Self::load_wallet(&env, wallet_id)?;
        let key = DataKey::PolicyBypass(wallet_id);
        if bypass {
            env.storage().persistent().set(&key, &true);
            env.storage().persistent().extend_ttl(
                &key,
                PERSISTENT_LIFETIME_THRESHOLD,
                PERSISTENT_BUMP_AMOUNT,
            );
        } else {
            env.storage().persistent().remove(&key);
        }
        Self::bump_instance(&env);
        events::publish(
            &env,
            events::ContractEvent::WalletPolicyBypassChanged { wallet_id, bypass },
        );
        Ok(())
    }

    /// Whether a wallet is excused from the policy gate.
    pub fn get_policy_bypass(env: Env, wallet_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::PolicyBypass(wallet_id))
            .unwrap_or(false)
    }

    /// Set the velocity ceiling for `asset` on a wallet ([`Role::Admin`]):
    /// at most `max_amount` may leave the wallet within any rolling window of
    /// `window_seconds`, across `transfer`, `withdraw` and validated batch
    /// actions. Agents cannot change it.
    ///
    /// `max_amount` must be positive ([`Error::InvalidAmount`]) and
    /// `window_seconds` a positive multiple of [`VELOCITY_BUCKETS`]
    /// ([`Error::InvalidInput`]). Changing only `max_amount` keeps the volume
    /// already recorded in the window; changing `window_seconds` re-buckets
    /// time, so recorded usage restarts from zero.
    pub fn set_velocity_limit(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
        max_amount: i128,
        window_seconds: u64,
    ) -> Result<(), Error> {
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        ensure!(
            wallet.state != ResourceState::Archived,
            Error::WalletArchived
        );
        require_positive_amount(max_amount)?;
        let buckets = VELOCITY_BUCKETS as u64;
        ensure!(
            window_seconds >= buckets && window_seconds % buckets == 0,
            Error::InvalidInput
        );
        let lkey = DataKey::VelocityLimit(wallet_id, asset.clone());
        let previous: Option<VelocityLimit> = env.storage().persistent().get(&lkey);
        if previous.map(|p| p.window_seconds) != Some(window_seconds) {
            env.storage()
                .persistent()
                .remove(&DataKey::VelocityUsage(wallet_id, asset.clone()));
        }
        let limit = VelocityLimit {
            max_amount,
            window_seconds,
        };
        env.storage().persistent().set(&lkey, &limit);
        Self::bump_persistent(&env, &lkey);
        events::publish(
            &env,
            events::ContractEvent::WalletVelocityLimitSet {
                wallet_id,
                asset,
                max_amount,
                window_seconds,
            },
        );
        Ok(())
    }

    /// Remove a wallet's velocity ceiling for `asset` ([`Role::Admin`]),
    /// deleting its usage record too. [`Error::NotFound`] when none is set.
    pub fn clear_velocity_limit(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
    ) -> Result<(), Error> {
        Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        let lkey = DataKey::VelocityLimit(wallet_id, asset.clone());
        ensure!(env.storage().persistent().has(&lkey), Error::NotFound);
        env.storage().persistent().remove(&lkey);
        env.storage()
            .persistent()
            .remove(&DataKey::VelocityUsage(wallet_id, asset.clone()));
        events::publish(
            &env,
            events::ContractEvent::WalletVelocityLimitCleared { wallet_id, asset },
        );
        Ok(())
    }

    /// Read a wallet's velocity ceiling for `asset`, if any.
    pub fn get_velocity_limit(env: Env, wallet_id: u64, asset: Address) -> Option<VelocityLimit> {
        env.storage()
            .persistent()
            .get(&DataKey::VelocityLimit(wallet_id, asset))
    }

    /// Volume of `asset` that has left the wallet within the current rolling
    /// window, as of the current ledger time (`0` when no ceiling is set).
    pub fn get_velocity_usage(env: Env, wallet_id: u64, asset: Address) -> Result<i128, Error> {
        let limit: VelocityLimit =
            match Self::get_velocity_limit(env.clone(), wallet_id, asset.clone()) {
                Some(limit) => limit,
                None => return Ok(0),
            };
        let usage = Self::rolled_velocity_usage(&env, wallet_id, &asset, &limit);
        Self::velocity_total(&usage)
    }

    /// Set a wallet's sliding-window rate limit ([`Role::Admin`]): at most
    /// `max_volume` may leave the wallet and at most `max_count` outbound
    /// transactions may be issued within any rolling window of
    /// `window_seconds`, counted across every asset and across `transfer`,
    /// `withdraw` and validated batch actions. Agents cannot change it.
    ///
    /// `max_volume` must not be negative ([`Error::InvalidInput`]), and
    /// `window_seconds`, when non-zero, must be a positive multiple of
    /// [`RATE_LIMIT_BUCKETS`] ([`Error::InvalidInput`]). `window_seconds == 0`
    /// disables the limit; a `0` cap means "unlimited" for that dimension.
    /// Changing `window_seconds` re-buckets time, so recorded usage restarts
    /// from zero.
    pub fn set_rate_limit(
        env: Env,
        caller: Address,
        wallet_id: u64,
        max_volume: i128,
        max_count: u32,
        window_seconds: u64,
    ) -> Result<(), Error> {
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        ensure!(
            wallet.state != ResourceState::Archived,
            Error::WalletArchived
        );
        ensure!(max_volume >= 0, Error::InvalidInput);
        let config_key = DataKey::RateLimit(wallet_id);
        let usage_key = DataKey::RateLimitUsage(wallet_id);
        if window_seconds == 0 {
            // Disabling drops both records: an unlimited wallet carries no
            // usage, so a later re-enable starts from a clean window.
            env.storage().persistent().remove(&config_key);
            env.storage().persistent().remove(&usage_key);
        } else {
            let buckets = RATE_LIMIT_BUCKETS as u64;
            ensure!(
                window_seconds >= buckets && window_seconds % buckets == 0,
                Error::InvalidInput
            );
            let previous: Option<RateLimitConfig> = env.storage().persistent().get(&config_key);
            if previous.map(|previous| previous.window_seconds) != Some(window_seconds) {
                env.storage().persistent().remove(&usage_key);
            }
            let config = RateLimitConfig {
                max_volume,
                max_count,
                window_seconds,
            };
            env.storage().persistent().set(&config_key, &config);
            Self::bump_persistent(&env, &config_key);
        }
        events::publish(
            &env,
            events::ContractEvent::WalletRateLimitSet {
                wallet_id,
                max_volume,
                max_count,
                window_seconds,
            },
        );
        Ok(())
    }

    /// Remove a wallet's rate limit ([`Role::Admin`]), deleting its usage record
    /// too. [`Error::NotFound`] when none is set.
    pub fn clear_rate_limit(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        let config_key = DataKey::RateLimit(wallet_id);
        ensure!(env.storage().persistent().has(&config_key), Error::NotFound);
        env.storage().persistent().remove(&config_key);
        env.storage()
            .persistent()
            .remove(&DataKey::RateLimitUsage(wallet_id));
        events::publish(
            &env,
            events::ContractEvent::WalletRateLimitCleared { wallet_id },
        );
        Ok(())
    }

    /// Read a wallet's rate-limit config, if any.
    pub fn get_rate_limit(env: Env, wallet_id: u64) -> Option<RateLimitConfig> {
        env.storage()
            .persistent()
            .get(&DataKey::RateLimit(wallet_id))
    }

    /// Volume and transaction count that have left the wallet within the
    /// current rolling rate-limit window (`(0, 0)` when no limit is set).
    pub fn get_rate_usage(env: Env, wallet_id: u64) -> Result<RateLimitStatus, Error> {
        let config: RateLimitConfig = match env
            .storage()
            .persistent()
            .get(&DataKey::RateLimit(wallet_id))
        {
            Some(config) => config,
            None => {
                return Ok(RateLimitStatus {
                    volume: 0,
                    count: 0,
                })
            }
        };
        if config.window_seconds == 0 {
            return Ok(RateLimitStatus {
                volume: 0,
                count: 0,
            });
        }
        let usage = Self::rolled_rate_usage(&env, wallet_id, &config);
        let (volume, count) = Self::rate_totals(&usage)?;
        Ok(RateLimitStatus { volume, count })
    }

    /// Fund a wallet: pulls `amount` of `asset` from `from` into custody and
    /// credits the wallet's internal balance. Requires `from` authorization.
    pub fn deposit(
        env: Env,
        wallet_id: u64,
        from: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        from.require_auth();
        let wallet = Self::load_wallet(&env, wallet_id)?;
        // Deposits are refused into archived wallets; other states may receive.
        ensure!(
            wallet.state != ResourceState::Archived,
            Error::WalletArchived
        );
        // Move real tokens into the contract's custody, then credit internally.
        token::TokenClient::new(&env, &asset).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
        Self::credit(&env, wallet_id, &asset, amount)?;
        events::publish(
            &env,
            events::ContractEvent::WalletFunded {
                wallet_id,
                from,
                asset,
                amount,
            },
        );
        Ok(())
    }

    /// Pay `amount` of `asset` from a wallet to an arbitrary recipient. This is
    /// the routine operational spend, so [`Role::Agent`] is enough - an
    /// autonomous executor can pay without holding administrative power - and it
    /// is still only permitted while the wallet is `Active`.
    pub fn transfer(
        env: Env,
        caller: Address,
        wallet_id: u64,
        to: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Agent)?;
        Self::require_active_for_transfer(&wallet)?;
        // Pre-execution validation: reject invalid recipients before any policy
        // or balance checks.
        Self::validate_transfer_recipient(&env, &to)?;
        Self::lock(&env)?;
        // Atomic pre-execution: policy → budget → velocity, before any debit.
        // Resolves Policy/Budget via Registry when configured, so upgrades
        // take effect without re-wiring the wallet. Each fallible step
        // unlocks before returning so a failed spend never leaves the
        // contract locked (even if the host commits storage on Err).
        if let Err(e) = Self::pre_execute_checks(&env, wallet_id, &asset, &to, amount, &caller) {
            Self::unlock(&env);
            return Err(e);
        }
        if let Err(e) = Self::enforce_velocity(&env, wallet_id, &asset, amount) {
            Self::unlock(&env);
            return Err(e);
        }
        // Rate limiting counts both value and transactions, across every asset
        // and outbound path, after the per-asset velocity ceiling.
        if let Err(e) = Self::enforce_rate_limit(&env, wallet_id, amount, 1) {
            Self::unlock(&env);
            return Err(e);
        }
        // Preliminary allowance verification before anything is approved: the
        // tracked ledger and the real SAC custody must each cover the amount.
        if let Err(e) = Self::require_custody_funds(&env, wallet_id, &asset, amount) {
            Self::unlock(&env);
            return Err(e);
        }
        if let Err(e) = Self::debit(&env, wallet_id, &asset, amount) {
            Self::unlock(&env);
            return Err(e);
        }
        // Funds were verified above, so the token call cannot refuse for
        // balance reasons; any remaining refusal maps to a deterministic
        // error instead of trapping the invocation.
        if let Err(e) = safe_transfer(&env, &asset, &env.current_contract_address(), &to, amount) {
            Self::unlock(&env);
            return Err(e);
        }
        events::transfer_executed(&env, &env.current_contract_address(), &to, &asset, amount);
        Self::unlock(&env);
        Ok(())
    }

    /// Withdraw `amount` of `asset` from a wallet back to its owner. Funds
    /// leaving the wallet for its owner is an administrative action, so this
    /// requires [`Role::Admin`]; agents are deliberately excluded. Only
    /// permitted while the wallet is `Active`, and the destination is always
    /// the recorded owner regardless of who calls.
    pub fn withdraw(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        Self::require_active_for_transfer(&wallet)?;
        Self::lock(&env)?;
        if let Err(e) =
            Self::pre_execute_checks(&env, wallet_id, &asset, &wallet.owner, amount, &caller)
        {
            Self::unlock(&env);
            return Err(e);
        }
        if let Err(e) = Self::enforce_velocity(&env, wallet_id, &asset, amount) {
            Self::unlock(&env);
            return Err(e);
        }
        // Rate limiting counts both value and transactions, across every asset
        // and outbound path, after the per-asset velocity ceiling.
        if let Err(e) = Self::enforce_rate_limit(&env, wallet_id, amount, 1) {
            Self::unlock(&env);
            return Err(e);
        }
        // Same preliminary allowance verification as `transfer`: tracked
        // balance and real SAC custody both cover the amount before the
        // debit or any token call.
        if let Err(e) = Self::require_custody_funds(&env, wallet_id, &asset, amount) {
            Self::unlock(&env);
            return Err(e);
        }
        if let Err(e) = Self::debit(&env, wallet_id, &asset, amount) {
            Self::unlock(&env);
            return Err(e);
        }
        if let Err(e) = safe_transfer(
            &env,
            &asset,
            &env.current_contract_address(),
            &wallet.owner,
            amount,
        ) {
            Self::unlock(&env);
            return Err(e);
        }
        events::publish(
            &env,
            events::ContractEvent::WalletWithdrawn {
                wallet_id,
                to: wallet.owner,
                asset,
                amount,
            },
        );
        Self::unlock(&env);
        Ok(())
    }

    /// Freeze a wallet. Blocks all outbound movement. Freezing is a safety
    /// action, so [`Role::Agent`] is enough - an agent that detects trouble can
    /// stop the bleeding - as is the contract-level emergency admin.
    pub fn freeze(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role_or_admin(&env, wallet_id, &caller, Role::Agent)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }

        wallet.state = ResourceState::Frozen;
        Self::store_wallet(&env, wallet_id, &wallet);
        events::publish(
            &env,
            events::ContractEvent::WalletStateChanged {
                wallet_id,
                state: symbol_short!("frozen"),
            },
        );
        Ok(())
    }

    /// Unfreeze a wallet back to `Active`. Same gate as `freeze`.
    pub fn unfreeze(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role_or_admin(&env, wallet_id, &caller, Role::Agent)?;
        if wallet.state != ResourceState::Frozen {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Active;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("unfrozen"));
        Ok(())
    }

    /// Pause a wallet ([`Role::Admin`]). Temporarily blocks outbound movement.
    pub fn pause(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state != ResourceState::Active {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Paused;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("paused"));
        Ok(())
    }

    /// Resume a paused wallet ([`Role::Admin`]).
    pub fn unpause(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state != ResourceState::Paused {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Active;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("unpaused"));
        Ok(())
    }

    /// Archive a wallet ([`Role::Admin`]). Terminal state; no further
    /// transactions.
    pub fn archive(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }

        wallet.state = ResourceState::Archived;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("archived"));
        Ok(())
    }

    /// Execute a batch of [`BatchAction`]s atomically, validating every action
    /// against the contract's policy and budget gates before any sub-call
    /// fires. Each action opts into the gates via `policy_id` / `budget_id`: a
    /// non-empty id requires the corresponding contract to be wired up
    /// ([`WalletContract::set_policy`] / [`WalletContract::set_budget`]) or the
    /// batch is refused, while an empty id skips that gate for the action.
    ///
    /// Phase 1 verifies every action and aggregates its value with checked math
    /// in a single pass (one budget consumption per envelope — no speculative
    /// pre-flights), then Phase 2 executes the sub-calls sequentially. Any
    /// failure — a policy denial, a budget overrun, a cumulative overflow, or a
    /// failing sub-call — reverts the entire transaction, so validation and
    /// execution are atomic. On success an aggregated [`BatchReceipt`] is
    /// returned and a [`events::ContractEvent::WalletBatchValidated`] is
    /// published.
    pub fn batch_execute_validated(
        env: Env,
        caller: Address,
        wallet_id: u64,
        actions: soroban_sdk::Vec<BatchAction>,
    ) -> Result<BatchReceipt, Error> {
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Agent)?;
        Self::require_active(&wallet)?;

        if actions.is_empty() {
            return Err(Error::InvalidInput);
        }
        if actions.len() > constants::MAX_BATCH_CALLS {
            return Err(Error::InvalidInput);
        }

        Self::lock(&env)?;
        // Resolve gates once; batch actions may override per-action via ids.
        // Single `get_modules_batch` call keeps gas to one cross-contract
        // invocation regardless of batch size.
        let (reg_policy, reg_budget) = match Self::resolve_gates(&env) {
            Ok(v) => v,
            Err(e) => {
                Self::unlock(&env);
                return Err(e);
            }
        };
        let direct_policy: Option<Address> = env.storage().instance().get(&DataKey::Policy);
        let direct_budget: Option<Address> = env.storage().instance().get(&DataKey::Budget);
        let is_registry = env.storage().instance().has(&DataKey::Registry);

        // Phase 1 — verify every action and aggregate its value with checked
        // math so a cumulative overflow is caught before any value moves.
        let mut total_amount: i128 = 0;
        let mut budget_remaining: i128 = 0;
        // One gate for the whole batch: a batch that moves the same asset
        // repeatedly reads and writes that asset's velocity records once.
        let mut velocity = VelocityGate::new(&env, wallet_id);
        for action in actions.iter() {
            if let Err(e) = require_positive_amount(action.amount) {
                Self::unlock(&env);
                return Err(e);
            }
            total_amount = match checked_add(total_amount, action.amount) {
                Ok(v) => v,
                Err(e) => {
                    Self::unlock(&env);
                    return Err(e);
                }
            };

            if !action.policy_id.is_empty() {
                let policy_addr = if is_registry {
                    match reg_policy.as_ref() {
                        Some(a) => a,
                        None => {
                            Self::unlock(&env);
                            return Err(Error::InvalidInput);
                        }
                    }
                } else {
                    match direct_policy.as_ref() {
                        Some(a) => a,
                        None => {
                            Self::unlock(&env);
                            return Err(Error::InvalidInput);
                        }
                    }
                };
                if let Err(e) = Self::require_policy_check(
                    &env,
                    wallet_id,
                    policy_addr,
                    &action.policy_id,
                    &action.asset,
                    &action.recipient,
                    action.amount,
                ) {
                    Self::unlock(&env);
                    return Err(e);
                }
            }

            // The velocity ceiling is not opt-out per action: an agent cannot
            // route around it by leaving `policy_id` empty. Actions accumulate
            // against the same cached record, so a batch can never split a
            // window's allowance across actions to slip past the ceiling.
            if let Err(e) = velocity.enforce(&env, &action.asset, action.amount) {
                Self::unlock(&env);
                return Err(e);
            }

            if !action.budget_id.is_empty() {
                let budget_addr = if is_registry {
                    match reg_budget.as_ref() {
                        Some(a) => a,
                        None => {
                            Self::unlock(&env);
                            return Err(Error::InvalidInput);
                        }
                    }
                } else {
                    match direct_budget.as_ref() {
                        Some(a) => a,
                        None => {
                            Self::unlock(&env);
                            return Err(Error::InvalidInput);
                        }
                    }
                };
                match BudgetClient::new(&env, budget_addr).try_consume(
                    &caller,
                    &action.budget_id,
                    &action.amount,
                ) {
                    Ok(Ok(rem)) => budget_remaining = rem,
                    Err(Ok(e)) => {
                        Self::unlock(&env);
                        return Err(e.into());
                    }
                    Ok(Err(_)) | Err(Err(_)) => {
                        Self::unlock(&env);
                        return Err(Error::BudgetExceeded);
                    }
                }
            }
        }

        // Charge the whole batch's value and action count to the rate-limit
        // window as one event, before any value moves; a later failure reverts
        // the invocation and the recording with it.
        if let Err(e) = Self::enforce_rate_limit(&env, wallet_id, total_amount, actions.len()) {
            Self::unlock(&env);
            return Err(e);
        }

        // Record the window usage validated above before any value moves; a
        // later failure reverts the invocation and the recording with it.
        velocity.flush(&env);

        // Phase 2 — execute every action sequentially; the runtime rolls the
        // whole batch back if any sub-call fails.
        let mut executed: u32 = 0;
        for action in actions.into_iter() {
            if let Err(e) = Self::execute_call(&env, &action.call) {
                Self::unlock(&env);
                return Err(e);
            }
            executed += 1;
        }

        events::publish(
            &env,
            events::ContractEvent::WalletBatchValidated {
                wallet_id,
                executed,
                total_amount,
                budget_remaining,
            },
        );
        Self::unlock(&env);
        Ok(BatchReceipt {
            executed,
            total_amount,
            budget_remaining,
        })
    }

    /// Wire the budget contract batch actions consume from (contract admin
    /// only). Mirrors [`WalletContract::set_policy`].
    pub fn set_budget(env: Env, caller: Address, budget: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Budget, &budget);
        Self::bump_instance(&env);
        events::publish(
            &env,
            events::ContractEvent::WalletModuleWired {
                module: symbol_short!("budget"),
                address: budget,
            },
        );
        Ok(())
    }

    /// Wire the registry contract for dynamic policy/budget resolution (admin only).
    /// Once set, `transfer`/`withdraw`/`batch_execute_validated` resolve
    /// Policy and Budget addresses via `RegistryClient` rather than the
    /// instance-stored addresses, so upgrades to those modules take effect
    /// without re-wiring the wallet.
    pub fn set_registry(env: Env, caller: Address, registry: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Registry, &registry);
        Self::bump_instance(&env);
        events::publish(
            &env,
            events::ContractEvent::WalletModuleWired {
                module: symbol_short!("registry"),
                address: registry,
            },
        );
        Ok(())
    }

    /// Read the configured registry, if any.
    pub fn get_registry(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Registry)
    }

    /// Set the organization slug used for registry lookups (admin only).
    pub fn set_org(env: Env, caller: Address, org: String) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        require_non_empty(&org)?;
        env.storage().instance().set(&DataKey::Org, &org);
        Self::bump_instance(&env);
        env.events()
            .publish((symbol_short!("wallet"), symbol_short!("org")), org.clone());
        Ok(())
    }

    /// Read the configured org slug, if any.
    pub fn get_org(env: Env) -> Option<String> {
        env.storage().instance().get(&DataKey::Org)
    }

    /// Set the default budget envelope id consumed by single transfers (admin only).
    pub fn set_default_budget_id(
        env: Env,
        caller: Address,
        budget_id: String,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        require_non_empty(&budget_id)?;
        env.storage()
            .instance()
            .set(&DataKey::DefaultBudgetId, &budget_id);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Read the default budget id, if any.
    pub fn get_default_budget_id(env: Env) -> Option<String> {
        env.storage().instance().get(&DataKey::DefaultBudgetId)
    }

    /// Clear the default budget id (admin only).
    pub fn clear_default_budget_id(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if !env.storage().instance().has(&DataKey::DefaultBudgetId) {
            return Err(Error::NotFound);
        }
        env.storage().instance().remove(&DataKey::DefaultBudgetId);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Set a per-asset budget envelope id (admin only). Takes precedence over the default.
    pub fn set_asset_budget_id(
        env: Env,
        caller: Address,
        asset: Address,
        budget_id: String,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        require_non_empty(&budget_id)?;
        let key = DataKey::AssetBudgetId(asset.clone());
        env.storage().persistent().set(&key, &budget_id);
        Self::bump_persistent(&env, &key);
        events::publish(
            &env,
            events::ContractEvent::WalletAssetBudgetSet { asset, budget_id },
        );
        Ok(())
    }

    /// Read the per-asset budget id, if any.
    pub fn get_asset_budget_id(env: Env, asset: Address) -> Option<String> {
        env.storage()
            .persistent()
            .get(&DataKey::AssetBudgetId(asset))
    }

    /// Clear a per-asset budget id (admin only).
    pub fn clear_asset_budget_id(env: Env, caller: Address, asset: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let key = DataKey::AssetBudgetId(asset.clone());
        ensure!(env.storage().persistent().has(&key), Error::NotFound);
        env.storage().persistent().remove(&key);
        Ok(())
    }

    /// Invoke a single batch call so a callee failure surfaces as its own
    /// contract error, reverting the whole batch atomically; system-level
    /// failures are reported as [`Error::BatchCallFailed`].
    fn execute_call(env: &Env, call: &ContractCall) -> Result<(), Error> {
        match env.try_invoke_contract::<Val, Error>(
            &call.contract_addr,
            &call.fn_name,
            call.args.clone(),
        ) {
            Ok(_) => Ok(()),
            // A raw `Val` always decodes, so this arm is unreachable in
            // practice; kept for exhaustiveness.
            Err(Ok(e)) => Err(e),
            // System-level failure (panic / abort / unknown error code).
            Err(Err(_)) => Err(Error::BatchCallFailed),
        }
    }

    /// Delegate `role` on a wallet to `account`, replacing any role it already
    /// held. Requires [`Role::Admin`], so the owner (implicitly `Admin`) or an
    /// admin it has already delegated to may administer roles.
    ///
    /// Granting to the owner is refused: the owner is implicitly `Admin`, so the
    /// grant would either be redundant or an attempted demotion that the guards
    /// would ignore anyway. Refusing it keeps the stored roles honest.
    pub fn grant_role(
        env: Env,
        caller: Address,
        wallet_id: u64,
        account: Address,
        role: Role,
    ) -> Result<(), Error> {
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }
        if account == wallet.owner {
            return Err(Error::InvalidInput);
        }
        access::set_role(&env, wallet_id, &account, role);
        events::publish(
            &env,
            events::ContractEvent::WalletRoleChanged {
                wallet_id,
                account,
                role: Some(role.as_symbol()),
                action: symbol_short!("granted"),
            },
        );
        Ok(())
    }

    /// Revoke whatever role `account` holds on a wallet. Requires
    /// [`Role::Admin`]. Fails with [`Error::NotFound`] when the account holds no
    /// granted role, so a revocation is never silently a no-op.
    ///
    /// Permitted on an archived wallet so role records can still be cleaned up.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        wallet_id: u64,
        account: Address,
    ) -> Result<(), Error> {
        Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        access::clear_role(&env, wallet_id, &account)?;
        events::publish(
            &env,
            events::ContractEvent::WalletRoleChanged {
                wallet_id,
                account,
                role: None,
                action: symbol_short!("revoked"),
            },
        );
        Ok(())
    }

    // --- views ---

    /// Read the role `account` effectively holds on a wallet, or `None` if it
    /// holds none. The wallet owner always resolves to [`Role::Admin`].
    pub fn get_role(env: Env, wallet_id: u64, account: Address) -> Result<Option<Role>, Error> {
        let wallet = Self::load_wallet(&env, wallet_id)?;
        Ok(access::effective_role(
            &env,
            wallet_id,
            &wallet.owner,
            &account,
        ))
    }

    /// Whether `account` holds at least `role` on a wallet - the same question
    /// the entrypoint guards ask, exposed for off-chain callers.
    pub fn has_role(env: Env, wallet_id: u64, account: Address, role: Role) -> Result<bool, Error> {
        let wallet = Self::load_wallet(&env, wallet_id)?;
        Ok(access::require_role(&env, wallet_id, &wallet.owner, &account, role).is_ok())
    }

    /// Read a wallet's owner + state.
    pub fn get_wallet(env: Env, wallet_id: u64) -> Result<WalletData, Error> {
        Self::load_wallet(&env, wallet_id)
    }

    /// Read a wallet's internal balance for an asset (0 if none recorded).
    /// Stays available while the breaker is tripped.
    pub fn balance(env: Env, wallet_id: u64, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(wallet_id, asset))
            .unwrap_or(0)
    }

    /// Read the contract's real on-chain custody of `asset` — the SAC balance
    /// held at the contract's own address that backs every wallet's internal
    /// bookkeeping. The read goes through the token's SAC interface and fails
    /// closed with a deterministic error when the asset cannot be queried.
    pub fn custody_balance(env: Env, asset: Address) -> Result<i128, Error> {
        token_balance(&env, &asset, &env.current_contract_address())
    }

    /// Whether the contract-wide circuit breaker is currently tripped.
    pub fn is_paused(env: Env) -> bool {
        Self::paused(&env)
    }

    /// The address currently designated as emergency guardian.
    pub fn get_guardian(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Guardian)
            .ok_or(Error::NotInitialized)
    }

    // --- internal helpers ---

    /// Map policy denials and cross-contract invocation failures to one stable
    /// wallet-facing error. Only a successful policy response authorizes spend.
    ///
    /// Records a [`events::ContractEvent::WalletPolicyChecked`] on the passing
    /// path. No event is published for a denial: the invocation is about to
    /// revert, which discards anything already published, and the policy module
    /// emits its own [`events::ContractEvent::PolicyViolation`] for the reason
    /// - duplicating it here would double-count every refusal.
    fn require_policy_check(
        env: &Env,
        wallet_id: u64,
        policy_addr: &Address,
        policy_id: &String,
        asset: &Address,
        recipient: &Address,
        amount: i128,
    ) -> Result<(), Error> {
        match PolicyClient::new(env, policy_addr)
            .try_check_transfer(policy_id, asset, recipient, &amount)
        {
            Ok(Ok(())) => {
                events::publish(
                    env,
                    events::ContractEvent::WalletPolicyChecked {
                        wallet_id,
                        asset: asset.clone(),
                        amount,
                    },
                );
                Ok(())
            }
            Ok(Err(_)) | Err(_) => Err(Error::PolicyDenied),
        }
    }

    /// Re-entrancy guard: refuse if a wallet entrypoint is already on the stack.
    fn lock(env: &Env) -> Result<(), Error> {
        let locked: bool = env
            .storage()
            .instance()
            .get(&DataKey::ReentrancyLock)
            .unwrap_or(false);
        ensure!(!locked, Error::InvalidState);
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &true);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    fn unlock(env: &Env) {
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &false);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    /// Resolve Policy and Budget addresses, preferring the Registry when
    /// `Registry` + `Org` are configured. Uses a single `get_modules_batch`
    /// call to fetch both in one cross-contract invocation for gas savings.
    fn resolve_gates(env: &Env) -> Result<(Option<Address>, Option<Address>), Error> {
        let reg: Option<Address> = env.storage().instance().get(&DataKey::Registry);
        let org: Option<String> = env.storage().instance().get(&DataKey::Org);
        if let (Some(reg), Some(org)) = (reg, org) {
            let mut ids = Vec::new(env);
            ids.push_back(ModuleId {
                org: org.clone(),
                kind: ModuleKind::Policy,
            });
            ids.push_back(ModuleId {
                org: org.clone(),
                kind: ModuleKind::Budget,
            });
            match RegistryClient::new(env, &reg).try_get_modules_batch(&ids) {
                Ok(Ok(modules)) => {
                    let policy = modules.get(0).unwrap().and_then(|info| {
                        if info.deprecated {
                            None
                        } else {
                            Some(info.address)
                        }
                    });
                    let budget = modules.get(1).unwrap().and_then(|info| {
                        if info.deprecated {
                            None
                        } else {
                            Some(info.address)
                        }
                    });
                    return Ok((policy, budget));
                }
                Err(Ok(e)) => return Err(e),
                Ok(Err(_)) | Err(Err(_)) => return Err(Error::InvalidState),
            }
        }
        let policy: Option<Address> = env.storage().instance().get(&DataKey::Policy);
        let budget: Option<Address> = env.storage().instance().get(&DataKey::Budget);
        Ok((policy, budget))
    }

    /// Budget envelope for `asset`: per-asset id takes precedence over the
    /// default, minimizing reads when no budget is configured.
    fn budget_id_for(env: &Env, asset: &Address) -> Option<String> {
        if let Some(id) = env
            .storage()
            .persistent()
            .get::<DataKey, String>(&DataKey::AssetBudgetId(asset.clone()))
        {
            return Some(id);
        }
        env.storage().instance().get(&DataKey::DefaultBudgetId)
    }

    /// Consume `amount` from `budget_id` at `budget_addr`, mapping
    /// `BudgetError` to the wallet's `Error` table so callers get a precise
    /// code (e.g. `BudgetExceeded`, `BudgetExpired`).
    fn consume_budget(
        env: &Env,
        budget_addr: &Address,
        budget_id: &String,
        caller: &Address,
        amount: i128,
    ) -> Result<(), Error> {
        match BudgetClient::new(env, budget_addr).try_consume(caller, budget_id, &amount) {
            Ok(Ok(_)) => Ok(()),
            Err(Ok(e)) => Err(e.into()),
            Ok(Err(_)) | Err(Err(_)) => Err(Error::BudgetExceeded),
        }
    }

    /// Atomic pre-execution hook: policy → budget → velocity, before any
    /// debit. If registry is configured, addresses are resolved dynamically;
    /// otherwise falls back to instance-wired addresses. A bypassed wallet
    /// skips the policy gate but never the budget or velocity gates.
    fn pre_execute_checks(
        env: &Env,
        wallet_id: u64,
        asset: &Address,
        recipient: &Address,
        amount: i128,
        caller: &Address,
    ) -> Result<(), Error> {
        let (policy_addr, budget_addr) = Self::resolve_gates(env)?;
        // Policy gate (skipped when wallet is bypassed).
        if let Some(policy_addr) = policy_addr.as_ref() {
            if !Self::get_policy_bypass(env.clone(), wallet_id) {
                Self::require_policy_check(
                    env,
                    wallet_id,
                    policy_addr,
                    &String::from_str(env, "active"),
                    asset,
                    recipient,
                    amount,
                )?;
            }
        }
        // Budget gate (per-asset or default envelope).
        if let Some(budget_addr) = budget_addr.as_ref() {
            if let Some(budget_id) = Self::budget_id_for(env, asset) {
                Self::consume_budget(env, budget_addr, &budget_id, caller, amount)?;
            }
        }
        Ok(())
    }

    /// Velocity hook, applied to every outbound movement after the policy
    /// check. With no ceiling configured for `(wallet_id, asset)` it is a
    /// no-op. Otherwise it rejects with [`Error::VelocityLimitExceeded`] when
    /// the trailing-window volume plus `amount` would exceed the ceiling, and
    /// records `amount` in the current bucket when it fits.
    ///
    /// The window is `VELOCITY_BUCKETS` epoch-aligned buckets of
    /// `window_seconds / VELOCITY_BUCKETS` each: the current bucket plus the
    /// three before it. A spend therefore counts for between 3/4 and all of a
    /// window after it happens, and any span shorter than 3/4 of a window can
    /// never carry more than `max_amount` out of the wallet.
    ///
    /// A single movement is a one-asset [`VelocityGate`], which keeps the rule
    /// in exactly one place; batches share a gate across all their actions.
    fn enforce_velocity(
        env: &Env,
        wallet_id: u64,
        asset: &Address,
        amount: i128,
    ) -> Result<(), Error> {
        let mut velocity = VelocityGate::new(env, wallet_id);
        velocity.enforce(env, asset, amount)?;
        velocity.flush(env);
        Ok(())
    }

    /// Load the usage record aged to the current ledger time: buckets that
    /// slid out of the window are dropped and bucket 0 is the current one.
    /// If the ledger clock reads earlier than the recorded bucket, nothing is
    /// aged out, so a clock anomaly can never free allowance.
    fn rolled_velocity_usage(
        env: &Env,
        wallet_id: u64,
        asset: &Address,
        limit: &VelocityLimit,
    ) -> VelocityUsage {
        let bucket_seconds = limit.window_seconds / VELOCITY_BUCKETS as u64;
        let now_bucket = env.ledger().timestamp() / bucket_seconds;
        let stored: Option<VelocityUsage> = env
            .storage()
            .persistent()
            .get(&DataKey::VelocityUsage(wallet_id, asset.clone()));
        let mut spent = soroban_sdk::Vec::new(env);
        for _ in 0..VELOCITY_BUCKETS {
            spent.push_back(0i128);
        }
        let bucket = match stored {
            None => now_bucket,
            Some(usage) => {
                let bucket = now_bucket.max(usage.bucket);
                let shift = bucket - usage.bucket;
                for i in 0..VELOCITY_BUCKETS {
                    let target = i as u64 + shift;
                    if target < VELOCITY_BUCKETS as u64 {
                        spent.set(target as u32, usage.spent.get(i).unwrap_or(0));
                    }
                }
                bucket
            }
        };
        VelocityUsage { bucket, spent }
    }

    fn velocity_total(usage: &VelocityUsage) -> Result<i128, Error> {
        let mut total: i128 = 0;
        for amount in usage.spent.iter() {
            total = total.safe_add(amount)?;
        }
        Ok(total)
    }

    /// Rate-limit hook, applied to every outbound movement after the velocity
    /// check. With no limit configured for `wallet_id` it is a no-op. Otherwise
    /// it rejects with [`Error::RateLimitExceeded`] when the trailing window's
    /// volume plus `amount`, or its transaction count plus `count`, would
    /// exceed the configured caps, and records the charge in the current bucket
    /// when it fits.
    fn enforce_rate_limit(
        env: &Env,
        wallet_id: u64,
        amount: i128,
        count: u32,
    ) -> Result<(), Error> {
        let config: RateLimitConfig = match env
            .storage()
            .persistent()
            .get(&DataKey::RateLimit(wallet_id))
        {
            Some(config) => config,
            None => return Ok(()),
        };
        if config.window_seconds == 0 {
            return Ok(());
        }
        let key = DataKey::RateLimitUsage(wallet_id);
        let mut usage = Self::rolled_rate_usage(env, wallet_id, &config);
        let (total_volume, total_count) = Self::rate_totals(&usage)?;

        let new_count = total_count.checked_add(count).ok_or(Error::Overflow)?;
        if config.max_count != 0 && new_count > config.max_count {
            return Err(Error::RateLimitExceeded);
        }
        let new_volume = total_volume.safe_add(amount)?;
        if config.max_volume != 0 && new_volume > config.max_volume {
            return Err(Error::RateLimitExceeded);
        }

        let bucket_volume = usage.volume.get(0).unwrap_or(0).safe_add(amount)?;
        let bucket_count = usage
            .count
            .get(0)
            .unwrap_or(0)
            .checked_add(count)
            .ok_or(Error::Overflow)?;
        usage.volume.set(0, bucket_volume);
        usage.count.set(0, bucket_count);
        env.storage().persistent().set(&key, &usage);
        Self::bump_persistent(env, &key);
        Ok(())
    }

    /// Load the rate usage record aged to the current ledger time: buckets that
    /// slid out of the window are dropped and bucket 0 is the current one. If
    /// the ledger clock reads earlier than the recorded bucket, nothing is aged
    /// out, so a clock anomaly can never free allowance.
    fn rolled_rate_usage(env: &Env, wallet_id: u64, config: &RateLimitConfig) -> RateUsage {
        let bucket_seconds = config.window_seconds / RATE_LIMIT_BUCKETS as u64;
        let now_bucket = env.ledger().timestamp() / bucket_seconds;
        let stored: Option<RateUsage> = env
            .storage()
            .persistent()
            .get(&DataKey::RateLimitUsage(wallet_id));
        let mut volume = soroban_sdk::Vec::new(env);
        let mut count = soroban_sdk::Vec::new(env);
        for _ in 0..RATE_LIMIT_BUCKETS {
            volume.push_back(0i128);
            count.push_back(0u32);
        }
        let bucket = match stored {
            None => now_bucket,
            Some(usage) => {
                let bucket = now_bucket.max(usage.bucket);
                let shift = bucket - usage.bucket;
                for i in 0..RATE_LIMIT_BUCKETS {
                    let target = i as u64 + shift;
                    if target < RATE_LIMIT_BUCKETS as u64 {
                        volume.set(target as u32, usage.volume.get(i).unwrap_or(0));
                        count.set(target as u32, usage.count.get(i).unwrap_or(0));
                    }
                }
                bucket
            }
        };
        RateUsage {
            bucket,
            volume,
            count,
        }
    }

    /// Sum the per-bucket volume and transaction count of a rolled usage record.
    fn rate_totals(usage: &RateUsage) -> Result<(i128, u32), Error> {
        let mut total_volume: i128 = 0;
        let mut total_count: u32 = 0;
        for amount in usage.volume.iter() {
            total_volume = total_volume.safe_add(amount)?;
        }
        for count in usage.count.iter() {
            total_count = total_count.checked_add(count).ok_or(Error::Overflow)?;
        }
        Ok((total_volume, total_count))
    }

    fn bump_persistent(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(
            key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn load_wallet(env: &Env, id: u64) -> Result<WalletData, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Wallet(id))
            .ok_or(Error::NotFound)
    }

    fn store_wallet(env: &Env, id: u64, data: &WalletData) {
        env.storage().persistent().set(&DataKey::Wallet(id), data);
        Self::bump_wallet(env, id);
    }

    /// Authenticate `caller`, then require it to hold at least `required` on the
    /// wallet. The wallet is loaded first so an unknown id reports
    /// [`Error::NotFound`] rather than an authorization failure.
    fn require_wallet_role(
        env: &Env,
        id: u64,
        caller: &Address,
        required: Role,
    ) -> Result<WalletData, Error> {
        caller.require_auth();
        let wallet = Self::load_wallet(env, id)?;
        access::require_role(env, id, &wallet.owner, caller, required)?;

        Ok(wallet)
    }

    /// As [`Self::require_wallet_role`], but the contract-level emergency admin
    /// also passes regardless of any per-wallet role.
    fn require_wallet_role_or_admin(
        env: &Env,
        id: u64,
        caller: &Address,
        required: Role,
    ) -> Result<WalletData, Error> {
        caller.require_auth();
        let wallet = Self::load_wallet(env, id)?;
        let admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        if admin.map(|a| &a == caller).unwrap_or(false) {
            return Ok(wallet);
        }
        access::require_role(env, id, &wallet.owner, caller, required)?;

        Ok(wallet)
    }

    fn paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// The circuit breaker guard applied to every value-moving entrypoint.
    fn when_not_paused(env: &Env) -> Result<(), Error> {
        if Self::paused(env) {
            return Err(Error::WalletPaused);
        }
        Ok(())
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if &admin != caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn require_guardian_or_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        let guardian: Option<Address> = env.storage().instance().get(&DataKey::Guardian);
        let allowed = &admin == caller || guardian.map(|g| &g == caller).unwrap_or(false);
        if !allowed {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn require_active(wallet: &WalletData) -> Result<(), Error> {
        ensure!(wallet.state != ResourceState::Frozen, Error::WalletFrozen);
        ensure!(wallet.state != ResourceState::Paused, Error::WalletPaused);
        ensure!(
            wallet.state != ResourceState::Archived,
            Error::WalletArchived
        );
        Ok(())
    }

    /// Like `require_active` but returns wallet-state-specific errors for
    /// non-Active states to give transfer-specific error codes.
    fn require_active_for_transfer(wallet: &WalletData) -> Result<(), Error> {
        match wallet.state {
            ResourceState::Frozen => Err(Error::WalletFrozen),
            ResourceState::Paused => Err(Error::WalletPaused),
            ResourceState::Archived => Err(Error::WalletArchived),
            ResourceState::Active => Ok(()),
        }
    }

    /// Validate that the transfer recipient is a valid address (not zero address
    /// and not the contract itself).
    fn validate_transfer_recipient(env: &Env, recipient: &Address) -> Result<(), Error> {
        // Reject zero address (all zeros)
        let zero_addr = Address::from_string(&String::from_str(
            env,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        ));
        if recipient == &zero_addr {
            return Err(Error::InvalidInput);
        }
        // Reject self-transfer to the wallet contract
        if recipient == &env.current_contract_address() {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    fn credit(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::Balance(id, asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.safe_add(amount)?;
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(
            &key,
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    fn debit(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::Balance(id, asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if current < amount {
            return Err(Error::InsufficientFunds);
        }
        let updated = current.safe_sub(amount)?;

        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(
            &key,
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Preliminary allowance check for every outbound movement: both the
    /// wallet's tracked balance for `asset` and the contract's real SAC
    /// custody must cover `amount` before the spend is approved.
    ///
    /// The tracked read comes first so an uninitialized (never-funded)
    /// `(wallet, asset)` pair answers [`Error::InsufficientFunds`] exactly
    /// like a short balance, and the custody read second so a ledger that
    /// drifted above the tokens actually on hand cannot overdraw custody —
    /// a condition the later token call would otherwise surface as a raw
    /// host trap instead of a code. A zero or negative amount is refused
    /// with [`Error::InvalidAmount`]. Pure verification: no state changes.
    fn require_custody_funds(
        env: &Env,
        wallet_id: u64,
        asset: &Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        let tracked: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(wallet_id, asset.clone()))
            .unwrap_or(0);
        validate_sufficient_balance(tracked, amount)?;
        let custody = Self::sac_balance(env, asset)?;
        validate_sufficient_balance(custody, amount)
    }

    /// Query the contract's own SAC balance of `asset` without trapping; a
    /// token that cannot be queried fails closed with a deterministic code.
    fn sac_balance(env: &Env, asset: &Address) -> Result<i128, Error> {
        token_balance(env, asset, &env.current_contract_address())
    }

    fn emit_state(env: &Env, id: u64, action: soroban_sdk::Symbol) {
        env.events()
            .publish((symbol_short!("wallet"), action.clone()), id);
        events::publish(
            env,
            events::ContractEvent::WalletStateChanged {
                wallet_id: id,
                state: action,
            },
        );
    }

    fn bump_wallet(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Wallet(id),
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for WalletContract {
    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    fn get_upgrade_authority(
        env: Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for `ModuleKind::Wallet` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Wallet,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
