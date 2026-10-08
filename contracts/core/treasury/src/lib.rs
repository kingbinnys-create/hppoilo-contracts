#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Treasury Contract
//!
//! Custodies organizational funds and enforces governance on every outbound
//! movement (PRD Doc 7 §Treasury). Every `withdraw` / `transfer` resolves the
//! organization's Policy and Budget contracts and calls them BEFORE debiting
//! the ledger, so a spend must satisfy:
//!
//! ```text
//! admin auth → policy.check_transfer → budget.consume → assets move
//! ```
//!
//! Cross-contract calls go through the typed clients generated from
//! [`astroid_interfaces`], keeping the graph acyclic: `Treasury → {Policy, Budget}`.
//!
//! ## Asset whitelist
//!
//! Policy and budget gates constrain *how much* may move and *to whom*, but
//! neither says anything about *which token contract* is being invoked. An
//! agent that can name an arbitrary `Address` as the asset can point the
//! treasury at a hostile Stellar asset contract, whose `transfer` is arbitrary
//! code running with the treasury as the authorizer.
//!
//! Every routing decision is therefore checked against a persistent whitelist
//! of approved token contracts before any value moves:
//!
//! ```text
//! asset whitelisted → admin auth → policy.check_transfer → budget.consume → assets move
//! ```
//!
//! The whitelist is governance-managed (`add_approved_asset` /
//! `remove_approved_asset`, both admin-gated — point `admin` at the
//! organization's multisig to require a threshold of signers) and unapproved
//! assets are refused deterministically with [`Error::AssetNotAuthorized`] on
//! both inflows and outflows.
//!
//! [`TreasuryContract::batch_transfer`] applies the same gate chain to a whole
//! vector of payouts in a single, atomic invocation: the cumulative amount is
//! accumulated with checked math and validated against the treasury balance
//! before any value moves, so autonomous agents can pay many contributors for
//! the fee of one transaction. If any leg fails, the host reverts the entire
//! invocation and no recipient is paid.
//!
//! ## Emergency circuit breaker (pause)
//!
//! Alongside the multisig-only `freeze`, the treasury carries a dedicated
//! `paused: bool` flag and an authorized `guardian: Address` in its instance
//! storage. `pause` / `unpause` may only be called by that guardian or by the
//! organization's multisig, and they flip nothing but the flag - structural
//! ownership and configuration stay untouched:
//!
//! ```text
//! paused ── withdraw / batch_transfer / release_next_milestone ──▶ Error::TreasuryPaused
//! paused ── deposit ─────────────────────────────────────────────▶ still accepted
//! ```
//!
//! Inbound deposits are deliberately left open while the breaker is engaged,
//! so an organization can keep receiving recovery funding during an incident;
//! only value leaving the treasury is refused, with the dedicated
//! [`Error::TreasuryPaused`] code so off-chain monitors can distinguish "we
//! paused on purpose" from a generic state failure.
//!
//! ## Withdrawal time-lock (Issue #321)
//!
//! Every gate above constrains *how much* may move and *to whom*, but none of
//! them introduces a delay. That leaves the treasury's sharpest edge
//! unaddressed: a single compromised admin key is immediately monetisable,
//! because whoever holds it can move the entire balance in one signed
//! transaction, and no governance threshold, policy or budget can interpose if
//! that key is alone on the multisig.
//!
//! [`WithdrawalTimeLock`] closes that window. High-value payouts are parked
//! instead of settling, and the funds stay in custody and in the ledger while
//! the organization has a chance to notice and react:
//!
//! ```text
//! withdraw / batch_transfer, amount >= threshold ──▶ Error::TimelockNotExpired
//! queue_withdrawal ──▶ pending, no value moved ──▶ cancel_withdrawal
//!                                             └──▶ execute_withdrawal (after the delay)
//! ```
//!
//! Three properties are deliberate:
//!
//! * **The batch path is measured on its aggregate.** A lock that only guarded
//!   `withdraw` would be advisory: the same movement split across a batch of
//!   small legs, or issued as several sub-threshold withdrawals, would walk
//!   straight past it. The threshold therefore applies to what leaves the
//!   treasury, not to how it was packaged.
//! * **The low-value fast path is untouched.** A treasury that never configures
//!   a time-lock resolves to the disabled default, and payouts below the
//!   configured threshold keep settling immediately — so ordinary agent
//!   spending is not made to wait a day for a governance control aimed at
//!   draining the whole balance.
//! * **Timing is read from the ledger, never the wall clock.** Every comparison
//!   uses `env.ledger().timestamp()`, which the network controls, so no caller
//!   can influence when a cooldown elapses. The `execute_after` boundary is
//!   inclusive, and a request left unexecuted past its grace period
//!   ([`GOVERNANCE_GRACE_PERIOD`]) lapses rather than becoming a standing
//!   obligation the organization can no longer cancel in time.
//!
//! Queueing moves nothing, which is what makes the waiting period meaningful:
//! the request is visible and cancellable while it is still inert.
//!
//! ## Registry-verified callers (Issue #308)
//!
//! The treasury's movement endpoints (`deposit`, `withdraw`,
//! `batch_transfer`, `release_next_milestone`) are reachable by any Soroban
//! contract that can submit an invocation, so a hostile contract could try to
//! move value while impersonating a module. The organization closes that hole
//! by wiring its registry address with [`TreasuryContract::set_registry`] and
//! registering the expected module addresses there. When a movement arrives
//! *from a contract address*, the treasury resolves `(org, kind)` in the
//! registry and refuses any caller other than the recorded module with the
//! dedicated [`Error::Unauthorized`] code. `withdraw` /
//! `batch_transfer` / `release_next_milestone` verify their contract caller
//! against the org's [`ModuleKind::Multisig`] record (the governance contract
//! the admin operates through), `deposit` verifies a contract depositor
//! against [`ModuleKind::Wallet`] — an organization's funding wallets stay
//! first-class depositors — while ordinary (account) callers keep passing
//! straight through to the pre-existing role checks. Unregistered module
//! kinds fail closed. Setting a registry is optional for backward
//! compatibility; once it is set, contract callers can never bypass it.
//!
//! ## Authorization
//!
//! Every function that can move value or rewire the treasury is gated on a
//! `require_auth`, and the gate is a single shared helper per role so the set
//! of authorized entry points can be audited in one place rather than
//! re-derived per function:
//!
//! - [`Self::require_admin`] — the recorded `admin`, for `initialize`-time
//!   configuration, allowances, budgets, the asset whitelist, and all three
//!   outbound paths (`withdraw`, `batch_transfer`, `release_next_milestone`).
//! - [`Self::require_multisig`] — the organization multisig, for the frozen
//!   circuit breaker alone.
//! - [`Self::require_guardian`] — the guardian (or the multisig), for the
//!   `paused` breaker alone.
//! - `from.require_auth()` — the depositor, on the one inbound path.
//!
//! An emergency role is never also an admin: neither the multisig nor the
//! guardian can pay out, approve an asset, or rewire the treasury, and an
//! allowance never confers authority — it only lowers a ceiling for a caller
//! that is already authorized.
//!
//! A role check is never sufficient on its own. Each helper compares the caller
//! against storage and *then* demands the caller's signature, so knowing an
//! address is not enough to act as it, and a signature is not a substitute for
//! being the right party. `initialize` demands the admin's signature for the
//! same reason: it is the moment the admin is chosen, so before it the contract
//! has no recorded owner to check against and the signature is the only thing
//! standing between a fresh deployment and a claim by whoever calls first.
//!
//! Outflows additionally hold a reentrancy guard for the duration of the
//! transfer. The guard is taken before any state is advanced and released on
//! the way out; if the invocation reverts first the host rolls the write back,
//! so a failed spend can never leave the treasury locked against later ones.
//!
//! ## Multi-token accounting
//!
//! The treasury custodies any number of approved Soroban token contracts side
//! by side (up to [`MAX_TREASURY_ASSETS`]). Each asset keeps its own
//! [`Holding`] record and the approved set is enumerable, so
//! [`TreasuryContract::portfolio`] reports every asset's live custody balance,
//! recorded balance and `decimals` in one call. Amounts are always in the
//! token's own base units; the treasury never normalizes across decimals.
//!
//! Token contracts are not trusted to move exactly what they are asked to:
//!
//! - `deposit` credits the amount that *actually arrived* (the custody balance
//!   delta), so a fee-on-transfer token cannot inflate the books, and a
//!   transfer that delivers nothing is rejected with [`Error::InvalidAmount`].
//! - Every outflow checks the live custody balance first
//!   ([`Error::InsufficientFunds`] instead of a token-level panic) and then
//!   verifies the balance fell by exactly the amount paid, reverting with
//!   [`Error::InvalidState`] otherwise.
//!
//! All token math goes through the shared checked helpers.
//!
//! Functions: `initialize`, `set_policy`, `set_budget`, `set_multisig`,
//! `set_registry`, `set_guardian`, `add_approved_asset`,
//! `remove_approved_asset`, `freeze`, `unfreeze`, `pause`, `unpause`,
//! `deposit`, `withdraw`, `batch_transfer`, `allocate_budget`,
//! `set_allowance`, `remove_allowance`, `allowance`,
//! `init_milestone_disbursement`, `release_next_milestone`, `get`, `holding`,
//! `is_paused`, `guardian`, `registry`, `is_approved_asset`,
//! `approved_asset_count`, `approved_assets`, `portfolio`.
//!
//! Withdrawal time-lock (Issue #321): `set_withdrawal_time_lock`,
//! `withdrawal_time_lock`, `queue_withdrawal`, `queue_batch_transfer`,
//! `execute_withdrawal`, `cancel_withdrawal`, `pending_withdrawal`,
//! `pending_withdrawal_count`.

use astroid_interfaces::{PolicyClient, RegistryClient, TreasuryInterface, UpgradeableInterface};
use astroid_shared::constants::{
    GOVERNANCE_GRACE_PERIOD, INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_BATCH_PAYMENTS,
    MAX_PAUSE_DURATION, MAX_TIMELOCK_DELAY, MIN_TIMELOCK_DELAY, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::events;
use astroid_shared::math::{checked_add, checked_add_u64, checked_div, checked_mul, checked_sub};
use astroid_shared::types::{ModuleKind, Payment, ResourceState};
use astroid_shared::validation::{
    require_non_empty, require_positive_amount, require_time_reached,
};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, String, Symbol, Vec,
};

/// Maximum number of token contracts a treasury may have approved at once.
/// Bounds every per-asset iteration (e.g. [`TreasuryContract::portfolio`]).
pub const MAX_TREASURY_ASSETS: u32 = 32;
const MAX_BALANCE_ASSETS: u32 = MAX_TREASURY_ASSETS;

/// Stored treasury record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Treasury {
    pub org: String,
    pub admin: Address,
    /// Organization's multisig contract — authorized for emergency freeze/unfreeze.
    pub multisig: Option<Address>,
    /// Organization's Policy contract — consulted on every spend.
    pub policy: Option<Address>,
    /// Organization's Budget contract root.
    pub budget: Option<Address>,
    /// Lifecycle state shared with wallets.
    pub state: ResourceState,
    /// Protocol registry consulted to verify contract callers (Issue #308).
    /// `None` keeps the pre-registry behaviour; once set, movement calls made
    /// *by contract addresses* must resolve to the expected module record or
    /// refused with [`Error::Unauthorized`] (the canonical enum is at its 50-variant cap).
    pub registry: Option<Address>,
    /// Emergency circuit-breaker guardian: may engage or release the pause
    /// alongside the multisig. Bootstrapped to `admin` at `initialize` and
    /// rotated through [`TreasuryContract::set_guardian`].
    pub guardian: Address,
    /// Whether the emergency circuit breaker is currently engaged. While
    /// `true`, every outbound disbursement or transfer is refused with
    /// [`Error::TreasuryPaused`]; inbound deposits stay open so recovery
    /// funding can still arrive.
    pub paused: bool,
    /// Ledger timestamp at which the breaker was engaged, or `0` while
    /// disengaged. Every pause lapses automatically after
    /// [`MAX_PAUSE_DURATION`]; see [`TreasuryContract::pause`].
    pub paused_at: u64,
}

/// Per-asset accounting within the treasury.

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneDisbursement {
    pub total_amount: i128,
    pub milestones: u32,
    pub disbursed: u32,
    pub amount_per_milestone: i128,
    pub asset: Address,
    pub to: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Holding {
    pub asset: Address,
    /// Cumulative amount deposited for this asset.
    pub total_in: i128,
    /// Cumulative amount withdrawn for this asset.
    pub total_out: i128,
    /// Budget envelope backing this asset, if any.
    pub budget_id: Option<String>,
}

// The per-asset balance record the `balances` view answers with lives in
// `astroid-shared` (Issue #293): it describes a custody balance rather than
// anything treasury-specific, so it is defined once for the whole workspace and
// re-exported here so `astroid_treasury::AssetBalance` keeps resolving.
pub use astroid_shared::types::AssetBalance;

/// One approved asset's position, as reported by
/// [`TreasuryContract::portfolio`]. All amounts are in the token's base units.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetPosition {
    pub asset: Address,
    /// The token contract's own `decimals()`.
    pub decimals: u32,
    /// Live balance held by the treasury contract on the token ledger.
    pub balance: i128,
    /// Balance according to the treasury's internal accounting.
    pub recorded: i128,
    /// Cumulative amount paid out of the treasury in this asset.
    pub total_out: i128,
}

/// Composite key identifying a withdrawal allowance scoped to a specific agent
/// (the caller that may spend), recipient and asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowanceId {
    pub agent: Address,
    pub recipient: Address,
    pub asset: Address,
}

/// Active withdrawal allowance restricting agent-driven expenditures against a
/// specific recipient/asset to a pre-approved `limit` over a time window.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Allowance {
    pub agent: Address,
    pub recipient: Address,
    pub asset: Address,
    /// Maximum cumulative amount that may be withdrawn under this allowance.
    pub limit: i128,
    /// Amount already consumed against the allowance.
    pub spent: i128,
    /// Unix timestamp after which the allowance can no longer be used (0 = never).
    pub expires_at: u64,
}

/// Cooling-off configuration for high-value withdrawals (Issue #321).
///
/// A treasury is the one contract where a single compromised admin key is
/// immediately monetisable: whoever holds it can move the whole balance in one
/// signed transaction. The time-lock inserts a mandatory waiting period in
/// front of exactly those movements, long enough for the organization to
/// notice and react.
///
/// The configuration is deliberately two-dimensional:
///
/// ```text
/// delay == 0                     → time-lock disabled, every outflow immediate
/// delay  > 0, amount <  threshold → low-value fast path, immediate
/// delay  > 0, amount >= threshold → must be queued, then executed after `delay`
/// ```
///
/// Splitting the payout into sub-threshold withdrawals would otherwise make
/// the time-lock trivially bypassable, which is why the batch path is measured
/// on the **aggregate** payout total rather than per leg (see
/// [`TreasuryContract::batch_transfer`]).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalTimeLock {
    /// Cooling-off period in seconds applied to time-locked withdrawals.
    /// `0` disables the time-lock entirely; any enabled delay must lie within
    /// `[MIN_TIMELOCK_DELAY, MAX_TIMELOCK_DELAY]`, so the treasury can neither
    /// be configured with a meaningless delay nor parked behind an effectively
    /// infinite one.
    pub delay: u64,
    /// Minimum payout (in the asset's base units) at or above which a withdrawal
    /// becomes time-locked. Always `0` while the time-lock is disabled.
    pub threshold: i128,
}

impl WithdrawalTimeLock {
    /// The default: no cooling-off period, every outflow immediate. A treasury
    /// that has never configured a time-lock therefore behaves exactly as it did
    /// before one existed.
    pub fn disabled() -> Self {
        Self {
            delay: 0,
            threshold: 0,
        }
    }

    /// Whether a payout of `amount` must be time-locked. A disabled lock never
    /// captures anything, and the comparison is inclusive so a payout landing
    /// exactly on the threshold is captured rather than allowed through by a
    /// single base unit.
    pub fn applies(&self, amount: i128) -> bool {
        self.delay > 0 && amount >= self.threshold
    }
}

/// A withdrawal parked in its cooling-off period, waiting to be executed or
/// cancelled (Issue #321).
///
/// Queueing a withdrawal moves **no value**: the amount stays in custody and in
/// the internal ledger until [`TreasuryContract::execute_withdrawal`] pays it
/// out. That is the whole point of the cooling-off period — a queued request is
/// visible, cancellable and inert.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingWithdrawal {
    /// Monotonic identifier, assigned at queue time.
    pub id: u64,
    /// The admin that queued the request, recorded for auditing.
    pub requester: Address,
    /// Token contract the withdrawal settles in.
    pub asset: Address,
    /// Single-recipient target. Unused when `payments` carries the batch legs.
    pub to: Address,
    /// Aggregate payout, in the asset's base units. Always equals the sum of
    /// `payments` for a batch request.
    pub amount: i128,
    /// Batch legs for a queued [`TreasuryContract::queue_batch_transfer`];
    /// empty for a plain queued [`TreasuryContract::queue_withdrawal`].
    pub payments: Vec<Payment>,
    /// Ledger timestamp at which the request was queued.
    pub requested_at: u64,
    /// Ledger timestamp from which the payout becomes executable. Execution
    /// strictly at this instant is allowed; one second earlier is refused with
    /// [`Error::TimelockNotExpired`].
    pub execute_after: u64,
    /// Ledger timestamp at which an unexecuted request lapses. A stale request
    /// must be re-queued under fresh scrutiny rather than lying dormant
    /// indefinitely and becoming executable at an arbitrary future point.
    pub expires_at: u64,
    /// Whether the request was terminated by [`TreasuryContract::cancel_withdrawal`].
    pub cancelled: bool,
    /// Whether the payout has already settled. A request may settle at most once.
    pub executed: bool,
}

impl PendingWithdrawal {
    /// Whether the request is still awaiting a decision: neither cancelled nor
    /// already paid out.
    pub fn is_pending(&self) -> bool {
        !self.cancelled && !self.executed
    }
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Treasury,
    Holding(Address),
    /// Whitelist membership: token contract address -> approved (persistent).
    ApprovedAsset(Address),
    /// Number of currently approved assets (instance).
    ApprovedAssetCount,
    /// Enumerable list of currently approved assets (instance).
    ApprovedAssetList,
    /// Recorded per-asset custody balance backing the structured deposit and
    /// withdrawal events (persistent).
    AssetBalance(Address),
    ReentrancyLock,
    /// Emergency circuit breaker freeze flag (persistent).
    Frozen,
    Milestone(u64),
    MilestoneCount,
    Allowance(AllowanceId),
    /// Cooling-off configuration for high-value withdrawals (instance).
    WithdrawalTimeLock,
    /// A queued withdrawal waiting out its cooling-off period (persistent).
    PendingWithdrawal(u64),
    /// Id allocator for `PendingWithdrawal` (instance).
    PendingWithdrawalCount,
}

#[contract]
pub struct TreasuryContract;

#[contractimpl]
impl TreasuryContract {
    /// Create a treasury for `org`, gated on the admin's signature.
    ///
    /// The circuit breaker starts disengaged (`paused == false`), no registry
    /// gate is configured (wire one later with [`Self::set_registry`]) and the
    /// deployer admin is recorded as the initial guardian, so a freshly
    /// created treasury always has at least one account that can pause it;
    /// rotate the guardian afterwards with [`Self::set_guardian`].
    pub fn initialize(env: Env, org: String, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Treasury) {
            return Err(Error::AlreadyInitialized);
        }
        // Initialization decides who owns the treasury and who may later move
        // every asset it custodies, so the admin's signature is what makes the
        // function safe to expose at all: without it, anyone who can reach a
        // freshly deployed contract could record themselves as admin and lock
        // the deployer out. Demanded before anything is written, and after the
        // re-initialization guard so a second attempt still reports
        // `AlreadyInitialized` rather than an auth failure.
        admin.require_auth();
        require_non_empty(&org)?;
        env.storage().instance().set(
            &DataKey::Treasury,
            &Treasury {
                org: org.clone(),
                admin: admin.clone(),
                multisig: None,
                policy: None,
                budget: None,
                registry: None,
                state: ResourceState::Active,
                guardian: admin.clone(),
                paused: false,
                paused_at: 0,
            },
        );
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        events::treasury_created(&env, &org, &admin);
        Ok(())
    }

    /// Wire the protocol registry used to verify contract callers (Issue
    /// #308). Admin-gated; point it at the organization's own registry
    /// deployment and register the expected module addresses there. Clearing
    /// it (`None`) restores the pre-registry behaviour where any contract may
    /// call the movement endpoints, so treat it as a governance decision.
    pub fn set_registry(env: Env, caller: Address, registry: Option<Address>) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.registry = registry;
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("registry"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("registry")), ());
        Ok(())
    }

    /// Wire the policy-enforcement contract consulted before every spend.
    pub fn set_policy(env: Env, caller: Address, policy: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.policy = Some(policy);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("policy"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("policy")), ());
        Ok(())
    }

    /// Wire the budget-tracking contract backing this treasury.
    pub fn set_budget(env: Env, caller: Address, budget: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.budget = Some(budget);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("budget"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("budget")), ());
        Ok(())
    }

    /// Approve a token contract for use by this treasury (governance-gated).
    ///
    /// Only whitelisted assets may be deposited, withdrawn or bound to a budget
    /// envelope, so this is the single point at which an organization decides
    /// which token contracts its funds are ever routed through.
    pub fn add_approved_asset(env: Env, caller: Address, asset: Address) -> Result<(), Error> {
        let t = Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedAsset(asset.clone());
        if env.storage().persistent().get(&key).unwrap_or(false) {
            return Err(Error::AlreadyExists);
        }
        let mut list = Self::approved_list(&env);
        if list.len() >= MAX_TREASURY_ASSETS {
            return Err(Error::InvalidInput);
        }
        list.push_back(asset.clone());
        Self::store_approved_list(&env, &list);
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        let count = checked_add(Self::approved_count(&env) as i128, 1)? as u32;
        Self::store_approved_count(&env, count);
        Self::emit_asset_change(&env, &t, &asset, symbol_short!("asset_add"));
        Ok(())
    }

    /// Revoke a token contract's approval (governance-gated).
    ///
    /// Existing internal accounting for the asset is deliberately left intact
    /// so a revoked holding stays inspectable; what stops is any further
    /// routing through it.
    pub fn remove_approved_asset(env: Env, caller: Address, asset: Address) -> Result<(), Error> {
        let t = Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedAsset(asset.clone());
        if !env.storage().persistent().get(&key).unwrap_or(false) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        let mut list = Self::approved_list(&env);
        if let Some(i) = list.first_index_of(&asset) {
            list.remove(i);
            Self::store_approved_list(&env, &list);
        }
        let count = Self::approved_count(&env).saturating_sub(1);
        Self::store_approved_count(&env, count);
        Self::emit_asset_change(&env, &t, &asset, symbol_short!("asset_rm"));
        Ok(())
    }

    /// Wire the multisig contract authorized for emergency freeze/unfreeze.
    pub fn set_multisig(env: Env, caller: Address, multisig: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.multisig = Some(multisig);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("multisig"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("multisig")), ());
        Ok(())
    }

    /// Emergency freeze — only the registry-verified multisig can freeze.
    /// Sets a dedicated frozen flag in persistent storage that blocks all outbound transfers.
    pub fn freeze(env: Env, caller: Address) -> Result<(), Error> {
        let t = Self::require_multisig(&env, &caller)?;
        env.storage().persistent().set(&DataKey::Frozen, &true);
        Self::bump_frozen(&env);
        events::publish(
            &env,
            events::ContractEvent::TreasuryFrozen { org: t.org.clone() },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("frozen")), ());
        Ok(())
    }

    /// Emergency unfreeze — only the registry-verified multisig can unfreeze.
    /// Clears the frozen flag to restore outbound transfers.
    pub fn unfreeze(env: Env, caller: Address) -> Result<(), Error> {
        let t = Self::require_multisig(&env, &caller)?;
        let frozen: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Frozen)
            .unwrap_or(false);
        if !frozen {
            return Err(Error::InvalidState);
        }
        env.storage().persistent().set(&DataKey::Frozen, &false);
        Self::bump_frozen(&env);
        events::publish(
            &env,
            events::ContractEvent::TreasuryUnfrozen { org: t.org.clone() },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("unfrozen")), ());
        Ok(())
    }

    /// Rotate the emergency circuit-breaker guardian (admin-gated).
    ///
    /// The guardian is a dedicated key whose only powers are
    /// [`Self::pause`] / [`Self::unpause`]; pointing it at a hot
    /// monitoring key (or at another multisig) lets an organization decouple
    /// "who can stop the treasury" from "who can spend from it".
    pub fn set_guardian(env: Env, caller: Address, guardian: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.guardian = guardian;
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("guardian"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("guardian")), ());
        Ok(())
    }

    /// Engage the emergency circuit breaker.
    ///
    /// Restricted to the recorded guardian or the organization's multisig
    /// (both checked against instance storage, then authorized with
    /// `require_auth`). While engaged, every outbound value movement
    /// ([`Self::withdraw`], [`Self::batch_transfer`],
    /// [`Self::release_next_milestone`]) short-circuits with
    /// [`Error::TreasuryPaused`]; inbound deposits stay open so recovery
    /// funding can still arrive. Unlike [`Self::freeze`] this does not change
    /// any structural ownership or configuration - only the pause flag moves.
    ///
    /// The breaker is temporary by construction: it engages with the ledger
    /// timestamp stamped into [`Treasury::paused_at`] and lapses automatically
    /// once [`MAX_PAUSE_DURATION`] has elapsed, after which outflows resume on
    /// their own while the stale flag stays recorded until it is cleared. An
    /// indefinite stop must go through the multisig-only [`Self::freeze`].
    pub fn pause(env: Env, caller: Address) -> Result<(), Error> {
        let mut t = Self::require_guardian(&env, &caller)?;
        // Re-engaging over a breaker that has merely lapsed is fine; only a
        // pause still inside its window is rejected as a double-toggle.
        if Self::pause_is_active(&t, &env) {
            return Err(Error::InvalidState);
        }
        t.paused = true;
        t.paused_at = env.ledger().timestamp();
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("pause"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("paused")), ());
        Ok(())
    }

    /// Release the emergency circuit breaker and restore outbound transfers.
    ///
    /// Same guardian/multisig gate as [`Self::pause`], and symmetric: an
    /// attempt to unpause a treasury that is not paused fails with
    /// [`Error::InvalidState`] rather than silently doing nothing. Clearing
    /// the breaker also resets [`Treasury::paused_at`], so the next
    /// [`Self::pause`] gets a fresh [`MAX_PAUSE_DURATION`] window.
    ///
    /// Releasing a breaker whose window has already lapsed also succeeds: the
    /// stale flag and [`Treasury::paused_at`] are cleared so the breaker can
    /// be re-engaged cleanly later.
    pub fn unpause(env: Env, caller: Address) -> Result<(), Error> {
        let mut t = Self::require_guardian(&env, &caller)?;
        if !t.paused {
            return Err(Error::InvalidState);
        }
        t.paused = false;
        t.paused_at = 0;
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("unpause"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("unpaused")), ());
        Ok(())
    }

    /// Deposit assets into the treasury (any funder may authorize). Moves real
    /// tokens from `from` into the treasury's custody, then credits the
    /// internal per-asset accounting with the amount that actually arrived.
    ///
    /// The custody balance is measured before and after the transfer, so a
    /// token that delivers less than `amount` (e.g. fee-on-transfer) is only
    /// credited what it delivered; one that delivers nothing, or claims to
    /// deliver more than was sent, is rejected.
    ///
    /// A contract depositor is verified against the registry's `Wallet` record
    /// for the treasury's organization (an organization's funding wallets stay
    /// first-class depositors); account depositors are unrestricted (Issue
    /// #308). The reentrancy lock spans the token transfer.
    pub fn deposit(env: Env, from: Address, asset: Address, amount: i128) -> Result<(), Error> {
        require_positive_amount(amount)?;
        from.require_auth();
        let t = Self::load(&env)?;
        Self::require_active(&t)?;
        // Inbound routing is validated too: an unapproved token contract is
        // never invoked, not even to pull funds in.
        Self::require_approved_asset(&env, &asset)?;
        // Issue #308 — verify where the deposit is coming from before the
        // ledger is touched, then hold the reentrancy lock across the
        // external token call.
        Self::require_verified_caller(&env, &t, &from, ModuleKind::Wallet)?;
        Self::lock(&env)?;
        // Pull tokens into the contract's own custody and measure the delta.
        let token_client = token::TokenClient::new(&env, &asset);
        let custody = env.current_contract_address();
        let before = token_client.balance(&custody);
        token_client.transfer(&from, &custody, &amount);
        let received = checked_sub(token_client.balance(&custody), before)?;
        if received <= 0 {
            return Err(Error::InvalidAmount);
        }
        if received > amount {
            return Err(Error::InvalidState);
        }
        let mut h = Self::load_holding(&env, &asset);
        h.total_in = checked_add(h.total_in, received)?;
        Self::store_holding(&env, &asset, &h);
        // The recorded balance mirrors the ledger itself rather than being
        // credited with the *requested* amount: on a fee-on-transfer token the
        // two differ, and only what actually arrived may be booked (Issue
        // #218). Syncing from the holding keeps the two inseparable on every
        // path that mutates either.
        let balance = h.total_in;
        Self::store_asset_balance(&env, &asset, balance);
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("deposited")),
            (asset.clone(), received),
        );
        events::publish(
            &env,
            events::ContractEvent::TreasuryDeposited {
                org: t.org.clone(),
                from: from.clone(),
                asset: asset.clone(),
                // The value actually credited to the treasury, matching the
                // tuple-topic event above — never the requested figure.
                amount: received,
                balance,
            },
        );
        Self::unlock(&env);
        Ok(())
    }

    /// Attach a budget envelope to an asset (admin).
    pub fn allocate_budget(
        env: Env,
        admin: Address,
        asset: Address,
        budget_id: String,
    ) -> Result<(), Error> {
        let t = Self::require_admin(&env, &admin)?;
        require_non_empty(&budget_id)?;
        Self::require_approved_asset(&env, &asset)?;
        let mut h = Self::load_holding(&env, &asset);
        h.budget_id = Some(budget_id.clone());
        Self::store_holding(&env, &asset, &h);
        // Issue #222 — binding an envelope mutates the treasury record, so it
        // announces itself on both layers like every other config change: the
        // canonical typed event plus a tuple-topic event carrying the
        // identifiers and the ledger timestamp.
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("bgt_alloc")),
            (asset.clone(), budget_id.clone(), env.ledger().timestamp()),
        );
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("bgt_alloc"),
            },
        );
        Ok(())
    }

    /// Create or update a withdrawal allowance capping how much `agent` may send
    /// to `recipient` in `asset`. `limit` is the cumulative ceiling; `expires_at`
    /// is an optional unix expiry (0 = no expiry). Admin only.
    pub fn set_allowance(
        env: Env,
        admin: Address,
        agent: Address,
        recipient: Address,
        asset: Address,
        limit: i128,
        expires_at: u64,
    ) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &admin)?;
        require_positive_amount(limit)?;
        if agent == recipient {
            return Err(Error::InvalidInput);
        }
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        let allowance = Allowance {
            agent: id.agent.clone(),
            recipient: id.recipient.clone(),
            asset: id.asset.clone(),
            limit,
            spent: 0,
            expires_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Allowance(id.clone()), &allowance);
        // Issue #222 — shared topic helpers keep the treasury on the same
        // `allow_set` / `allow_use` / `allow_rem` schema the policy contract
        // already publishes under.
        events::allowance_set(&env, &id.agent, &id.recipient, &id.asset, limit, expires_at);
        Ok(())
    }

    /// Remove an active withdrawal allowance (admin only).
    pub fn remove_allowance(
        env: Env,
        admin: Address,
        agent: Address,
        recipient: Address,
        asset: Address,
    ) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &admin)?;
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Allowance(id.clone()))
        {
            return Err(Error::NotFound);
        }
        env.storage()
            .persistent()
            .remove(&DataKey::Allowance(id.clone()));
        events::allowance_removed(&env, &id.agent, &id.recipient, &id.asset);
        Ok(())
    }

    /// Read the current state of a withdrawal allowance.
    pub fn allowance(
        env: Env,
        agent: Address,
        recipient: Address,
        asset: Address,
    ) -> Result<Allowance, Error> {
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(id))
            .ok_or(Error::NotFound)
    }

    /// Withdraw assets to a recipient. Only the admin may call, and the spend
    /// must clear policy and budget gates before the ledger is debited.
    ///
    /// While the circuit breaker is engaged this short-circuits with
    /// [`Error::TreasuryPaused`] before any other gate is consulted.
    ///
    /// When a time-lock is configured and `amount` reaches its threshold, this
    /// call is refused with [`Error::TimelockNotExpired`] and settles nothing:
    /// the payout must first be parked by
    /// [`TreasuryContract::queue_withdrawal`] and then paid out by
    /// [`TreasuryContract::execute_withdrawal`] once the cooling-off period has
    /// elapsed. Amounts below the threshold keep settling immediately.
    pub fn withdraw(
        env: Env,
        caller: Address,
        asset: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::require_not_paused(&env)?;
        Self::check_frozen(&env)?;
        // Single audited authorization point for every outbound movement: the
        // caller must be the recorded admin and must sign for it.
        let t = Self::require_admin(&env, &caller)?;
        Self::require_active(&t)?;

        // 1. Routing validation — refuse to invoke a token contract the
        //    organization has not approved, before any gate is consulted.
        Self::require_approved_asset(&env, &asset)?;

        // 2. Issue #308 — a contract caller must be the registry-recorded
        //    Multisig (governance) module for this organization; account
        //    callers pass through to the admin check above.
        Self::require_verified_caller(&env, &t, &caller, ModuleKind::Multisig)?;

        // 3. Issue #321 — refuse to settle a high-value payout in the same
        //    transaction that requests it. Everything below this point moves
        //    value, so the check sits ahead of the reentrancy lock and ahead of
        //    every external call.
        Self::require_not_time_locked(&env, amount)?;

        Self::settle_withdrawal(&env, &t, &caller, &asset, &to, amount)
    }

    /// The value-moving half of [`Self::withdraw`]: policy, budget, allowance,
    /// ledger debit and the token transfer itself, under the reentrancy lock.
    ///
    /// Split out so that [`Self::execute_withdrawal`] can settle a queued
    /// payout through exactly the same audited path — the only thing that
    /// differs is that the caller's own request went through a cooling-off
    /// period first.
    fn settle_withdrawal(
        env: &Env,
        t: &Treasury,
        caller: &Address,
        asset: &Address,
        to: &Address,
        amount: i128,
    ) -> Result<(), Error> {
        // Issue #308 — engage the reentrancy lock before the first
        // external call (policy and budget are cross-contract invocations
        // too) and hold it to the end of the movement.
        Self::lock(env)?;

        // Policy verification — the policy contract evaluates the spend.
        if let Some(policy_addr) = &t.policy {
            PolicyClient::new(env, policy_addr).check_transfer(
                &String::from_str(env, "active"),
                asset,
                to,
                &amount,
            );
        }

        // Budget consumption — aborts if the envelope lacks headroom.
        let mut holding = Self::load_holding(env, asset);
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(env, budget_addr)
                .consume(caller, budget_id, &amount);
        }

        // Withdrawal allowance enforcement — restrict agent-driven spends
        // to pre-approved periodic ceilings per (agent, recipient, asset).
        let allowance_id = AllowanceId {
            agent: caller.clone(),
            recipient: to.clone(),
            asset: asset.clone(),
        };
        if let Some(mut al) = env
            .storage()
            .persistent()
            .get::<DataKey, Allowance>(&DataKey::Allowance(allowance_id.clone()))
        {
            if al.expires_at != 0 && env.ledger().timestamp() >= al.expires_at {
                Self::unlock(env);
                return Err(Error::AllowanceExpired);
            }
            let remaining = checked_sub(al.limit, al.spent)?;
            if amount > remaining {
                Self::unlock(env);
                return Err(Error::AllowanceExceeded);
            }
            al.spent = checked_add(al.spent, amount)?;
            env.storage()
                .persistent()
                .set(&DataKey::Allowance(allowance_id), &al);
            // Issue #222 — consuming an allowance is a state change worth
            // indexing: who spent, to whom, in what asset, how much, and when.
            events::allowance_consumed(env, caller, to, asset, amount);
        }

        // Debit the internal ledger, then move real tokens out of custody.
        if holding.total_in < amount {
            Self::unlock(env);
            return Err(Error::InsufficientFunds);
        }
        holding.total_in = checked_sub(holding.total_in, amount)?;
        holding.total_out = checked_add(holding.total_out, amount)?;
        Self::store_holding(env, asset, &holding);
        // Mirror the debited ledger exactly (see `Self::deposit`): the recorded
        // balance is the holding itself, so it cannot drift from the books
        // regardless of which outflow path settles (Issue #218).
        let balance = holding.total_in;
        Self::store_asset_balance(env, asset, balance);
        events::transfer_executed(env, &t.admin, to, asset, amount);
        Self::transfer_out(env, asset, to, amount)?;
        events::transfer_executed(env, &t.admin, to, asset, amount);
        events::publish(
            env,
            events::ContractEvent::TransferExecuted {
                from: t.admin.clone(),
                to: to.clone(),
                asset: asset.clone(),
                amount,
            },
        );
        events::publish(
            env,
            events::ContractEvent::TreasuryWithdrawn {
                org: t.org.clone(),
                to: to.clone(),
                asset: asset.clone(),
                amount,
                balance,
            },
        );
        Self::unlock(env);
        Ok(())
    }

    /// Disburse `payments` of a single `asset` to many recipients in one atomic
    /// transaction. Only the admin may call, and the batch clears exactly the
    /// same gates as [`TreasuryContract::withdraw`] — policy per leg, budget for
    /// the aggregate — before the ledger is debited.
    ///
    /// The payout total is accumulated with the shared checked-math helpers and
    /// verified against the treasury's recorded balance up front, so an
    /// over-drawing batch is rejected before any token moves. Beyond that,
    /// atomicity is guaranteed by the host: returning an error (or a failing
    /// sub-call, such as a policy denial or a token transfer) rolls back every
    /// storage write and every transfer made earlier in the invocation, so a
    /// batch either pays every recipient or none of them.
    ///
    /// Like every other outflow it is refused with [`Error::TreasuryPaused`]
    /// while the emergency circuit breaker is engaged - a batch payout is a
    /// disbursement like any other.
    ///
    /// The time-lock (Issue #321) is measured on the **aggregate** payout, not
    /// per leg: measuring per leg would let a caller walk straight past the
    /// cooling-off period by splitting one large movement into many small ones,
    /// which would leave the direct [`Self::withdraw`] path as the only
    /// time-locked route and render it advisory. A batch whose total reaches
    /// the threshold is refused with [`Error::TimelockNotExpired`] and must be
    /// parked with [`Self::queue_batch_transfer`] instead.
    pub fn batch_transfer(
        env: Env,
        caller: Address,
        asset: Address,
        payments: Vec<Payment>,
    ) -> Result<(), Error> {
        if payments.is_empty() || payments.len() > MAX_BATCH_PAYMENTS {
            return Err(Error::InvalidInput);
        }
        Self::require_not_paused(&env)?;
        Self::check_frozen(&env)?;
        // Same single audited authorization point as `withdraw`: admin identity
        // plus the caller's own signature.
        let t = Self::require_admin(&env, &caller)?;
        Self::require_active(&t)?;

        // 1. Validate every leg and accumulate the payout with checked math, so
        //    a malformed or overflowing batch is rejected before anything moves.
        let mut total: i128 = 0;
        for payment in payments.iter() {
            require_positive_amount(payment.amount)?;
            total = checked_add(total, payment.amount)?;
        }

        // 2. Cumulative balance check against the recorded holding.
        let holding = Self::load_holding(&env, &asset);
        if holding.total_in < total {
            return Err(Error::InsufficientFunds);
        }

        // 3. Issue #308 — a contract caller must be the registry-recorded
        //    Multisig (governance) module for this organization; account
        //    callers pass through to the admin check above.
        Self::require_verified_caller(&env, &t, &caller, ModuleKind::Multisig)?;
        // 4. Issue #321 — the aggregate payout, not the individual legs, decides
        //    whether the cooling-off period applies.
        Self::require_not_time_locked(&env, total)?;

        Self::settle_batch(&env, &t, &caller, &asset, payments)
    }

    /// The value-moving half of [`Self::batch_transfer`]: per-leg policy, the
    /// aggregate budget debit, the ledger debit and the transfer loop, all
    /// under the reentrancy lock.
    ///
    /// Shared with [`Self::execute_withdrawal`] so a queued batch settles
    /// through exactly the same audited path an immediate one does.
    fn settle_batch(
        env: &Env,
        t: &Treasury,
        caller: &Address,
        asset: &Address,
        payments: Vec<Payment>,
    ) -> Result<(), Error> {
        // Re-accumulate the total from the legs themselves rather than trusting
        // a stored figure, so the amount budget is debited is always exactly the
        // amount actually paid out.
        let mut total: i128 = 0;
        for payment in payments.iter() {
            total = checked_add(total, payment.amount)?;
        }

        // Issue #308 — engage the reentrancy lock before the first external
        // call and hold it across the whole transfer loop.
        Self::lock(env)?;

        // Policy verification — each leg is evaluated on its own, because
        // per-recipient and per-amount gates are what the policy encodes.
        if let Some(policy_addr) = &t.policy {
            let policy = PolicyClient::new(env, policy_addr);
            let policy_id = String::from_str(env, "active");
            for payment in payments.iter() {
                policy.check_transfer(&policy_id, asset, &payment.recipient, &payment.amount);
            }
        }

        // Budget consumption — one debit for the aggregate rather than one
        // cross-contract call per recipient.
        let mut holding = Self::load_holding(env, asset);
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(env, budget_addr)
                .consume(caller, budget_id, &total);
        }

        // Debit the internal ledger once, then move real tokens per recipient.
        holding.total_in = checked_sub(holding.total_in, total)?;
        holding.total_out = checked_add(holding.total_out, total)?;
        Self::store_holding(env, asset, &holding);
        // Keep the recorded event balance in lockstep with the ledger this
        // batch just debited (Issue #218): a later deposit/withdrawal event
        // must not announce a balance this payout already paid out.
        Self::store_asset_balance(env, asset, holding.total_in);

        let token_client = token::TokenClient::new(env, asset);
        let custody = env.current_contract_address();
        let before = token_client.balance(&custody);
        if before < total {
            return Err(Error::InsufficientFunds);
        }
        for payment in payments.iter() {
            token_client.transfer(&custody, &payment.recipient, &payment.amount);
        }
        // The token must have debited exactly the batch total from custody.
        if checked_sub(before, token_client.balance(&custody))? != total {
            return Err(Error::InvalidState);
        }

        // A single summary event keeps the log concise; the per-recipient moves
        // are already observable as the asset contract's own transfer events.
        events::publish(
            env,
            events::ContractEvent::BatchTransferExecuted {
                from: t.admin.clone(),
                asset: asset.clone(),
                count: payments.len(),
                total,
            },
        );
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("batchpay")),
            (asset.clone(), payments.len(), total),
        );

        Self::unlock(env);
        Ok(())
    }

    // --- withdrawal time-lock (Issue #321) ---

    /// Configure the cooling-off period applied to high-value withdrawals.
    ///
    /// ```text
    /// delay == 0  → time-lock disabled, every outflow settles immediately
    /// delay  > 0  → payouts of `threshold` or more must be queued first
    /// ```
    ///
    /// An enabled `delay` must lie within
    /// `[MIN_TIMELOCK_DELAY, MAX_TIMELOCK_DELAY]` — the same bounds governance
    /// changes are held to — so the treasury cannot be configured with a delay
    /// short enough to be worthless, nor parked behind one long enough to be a
    /// denial of service. `threshold` must be positive whenever the lock is
    /// enabled; a zero threshold would capture every payout, including dust.
    ///
    /// Configuring the lock does not disturb anything already queued: requests
    /// parked under an earlier configuration keep their own recorded
    /// `execute_after`.
    pub fn set_withdrawal_time_lock(
        env: Env,
        caller: Address,
        delay: u64,
        threshold: i128,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let config = if delay == 0 {
            // Disabling is the zero-configuration case: nothing is captured and
            // the threshold is normalised to `0` so the stored record is not
            // self-contradictory.
            WithdrawalTimeLock::disabled()
        } else {
            if !(MIN_TIMELOCK_DELAY..=MAX_TIMELOCK_DELAY).contains(&delay) {
                return Err(Error::InvalidInput);
            }
            require_positive_amount(threshold)?;
            WithdrawalTimeLock { delay, threshold }
        };
        env.storage()
            .instance()
            .set(&DataKey::WithdrawalTimeLock, &config);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("timelock")),
            (config.delay, config.threshold),
        );
        Ok(())
    }

    /// The cooling-off configuration currently in force.
    ///
    /// A treasury that never configured one reports the disabled default rather
    /// than failing, so off-chain monitors can probe it before `initialize` just
    /// as they can with [`Self::registry`].
    pub fn withdrawal_time_lock(env: Env) -> WithdrawalTimeLock {
        Self::load_time_lock(&env)
    }

    /// Park a high-value withdrawal in its cooling-off period and return its id.
    ///
    /// Every gate a direct [`Self::withdraw`] clears is cleared here too — the
    /// request is authorized and validated exactly as a payout would be — but
    /// **no value moves**: the amount stays in custody and in the internal
    /// ledger until [`Self::execute_withdrawal`] settles it. That is what makes
    /// the waiting period meaningful, and it is why a queued request is visible,
    /// cancellable and inert rather than a delayed payment already in flight.
    ///
    /// Refused with [`Error::InvalidInput`] when the configured time-lock does
    /// not actually capture `amount`: queueing a payout the lock would have let
    /// through anyway would manufacture a cooldown that governance never asked
    /// for, and silently capturing low-value dust would strand it.
    pub fn queue_withdrawal(
        env: Env,
        caller: Address,
        asset: Address,
        to: Address,
        amount: i128,
    ) -> Result<u64, Error> {
        require_positive_amount(amount)?;
        Self::require_not_paused(&env)?;
        Self::check_frozen(&env)?;
        let t = Self::require_admin(&env, &caller)?;
        Self::require_active(&t)?;
        // Routing and caller verification are settled at request time, so a
        // request that could never have been paid is never parked.
        Self::require_approved_asset(&env, &asset)?;
        Self::require_verified_caller(&env, &t, &caller, ModuleKind::Multisig)?;
        Self::require_time_lock_applies(&env, amount)?;

        Self::open_pending(&env, &caller, asset, to, amount, Vec::new(&env))
    }

    /// Park a whole batch payout in its cooling-off period and return its id.
    ///
    /// The batch counterpart of [`Self::queue_withdrawal`], and for the same
    /// reason: the time-lock measures the **aggregate** payout, so a batch that
    /// reaches the threshold has to go through the same waiting period as an
    /// equivalent single withdrawal rather than remaining an unmonitored way
    /// around it.
    pub fn queue_batch_transfer(
        env: Env,
        caller: Address,
        asset: Address,
        payments: Vec<Payment>,
    ) -> Result<u64, Error> {
        if payments.is_empty() || payments.len() > MAX_BATCH_PAYMENTS {
            return Err(Error::InvalidInput);
        }
        Self::require_not_paused(&env)?;
        Self::check_frozen(&env)?;
        let t = Self::require_admin(&env, &caller)?;
        Self::require_active(&t)?;

        let mut total: i128 = 0;
        for payment in payments.iter() {
            require_positive_amount(payment.amount)?;
            total = checked_add(total, payment.amount)?;
        }
        Self::require_verified_caller(&env, &t, &caller, ModuleKind::Multisig)?;
        Self::require_time_lock_applies(&env, total)?;

        // `to` is not meaningful for a multi-recipient payout; the legs in
        // `payments` are the record. The first leg's recipient is carried so the
        // stored record is never self-contradictory for a reader that only
        // looks at the scalar fields.
        let to = payments.first().unwrap().recipient.clone();
        Self::open_pending(&env, &caller, asset, to, total, payments)
    }

    /// Settle a queued withdrawal once its cooling-off period has elapsed.
    ///
    /// The gating is strictly deterministic against the ledger timestamp, never
    /// wall-clock time:
    ///
    /// ```text
    /// cancelled or already executed → Error::InvalidState
    /// timestamp >= expires_at       → Error::ProposalExpired
    /// timestamp <  execute_after    → Error::TimelockNotExpired
    /// otherwise                     → the payout settles
    /// ```
    ///
    /// The boundary itself is inclusive: executing at exactly `execute_after`
    /// succeeds, one second earlier is refused. Executing past `expires_at` is
    /// refused rather than honoured, so a request that was ignored through its
    /// whole cooldown cannot be cashed in months later against a treasury whose
    /// balances have since changed entirely.
    pub fn execute_withdrawal(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        Self::require_not_paused(&env)?;
        Self::check_frozen(&env)?;
        let t = Self::require_admin(&env, &caller)?;
        Self::require_active(&t)?;

        let key = DataKey::PendingWithdrawal(id);
        let mut p: PendingWithdrawal = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        // Terminal states are closed to both directions: a cancelled request is
        // never paid, and a settled one is never paid twice.
        if !p.is_pending() {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() >= p.expires_at {
            return Err(Error::ProposalExpired);
        }
        // The cooling-off period itself. `require_time_reached` reports the
        // dedicated early-execution code shared with multisig governance changes
        // and escrow releases, so a monitor can recognise "not yet" across every
        // time-locked flow in the protocol.
        require_time_reached(&env, p.execute_after)?;

        // Re-check routing and caller at settlement time, not only at request
        // time: the asset may have been de-whitelisted, or the caller may have
        // stopped being the recorded module, during the waiting period.
        Self::require_approved_asset(&env, &p.asset)?;
        Self::require_verified_caller(&env, &t, &caller, ModuleKind::Multisig)?;

        // Record the settlement before the payout. If the payout aborts, the
        // host reverts this write along with everything else, so the record
        // cannot end up marking a payout that never happened; setting it first
        // is what makes a second, concurrent execution impossible.
        p.executed = true;
        env.storage().persistent().set(&key, &p);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

        if p.payments.is_empty() {
            Self::settle_withdrawal(&env, &t, &caller, &p.asset, &p.to, p.amount)?;
        } else {
            Self::settle_batch(&env, &t, &caller, &p.asset, p.payments.clone())?;
        }

        env.events().publish(
            (symbol_short!("timelock"), symbol_short!("executed")),
            (id, p.amount),
        );
        Ok(())
    }

    /// Terminate a queued withdrawal, leaving the funds in the treasury.
    ///
    /// The escape hatch that makes the cooling-off period safe to configure: if
    /// a request turns out to be hostile or simply stale, governance can drop
    /// it without waiting out the delay and without the payout ever having
    /// touched custody. A cancelled request is terminal — it can neither be
    /// executed afterwards nor cancelled twice.
    pub fn cancel_withdrawal(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &caller)?;
        let key = DataKey::PendingWithdrawal(id);
        let mut p: PendingWithdrawal = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        if !p.is_pending() {
            return Err(Error::InvalidState);
        }
        p.cancelled = true;
        env.storage().persistent().set(&key, &p);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.events()
            .publish((symbol_short!("timelock"), symbol_short!("canceled")), id);
        Ok(())
    }

    /// A queued withdrawal by id. [`Error::NotFound`] for an id that was never
    /// issued.
    pub fn pending_withdrawal(env: Env, id: u64) -> Result<PendingWithdrawal, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingWithdrawal(id))
            .ok_or(Error::NotFound)
    }

    /// How many withdrawals have ever been queued. Ids are issued from this
    /// counter and never reused, so a cancelled or expired id is never handed
    /// out again for a different request.
    pub fn pending_withdrawal_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::PendingWithdrawalCount)
            .unwrap_or(0)
    }

    // --- views ---

    /// The address currently authorized to pause / unpause this treasury
    /// (alongside the multisig).
    pub fn guardian(env: Env) -> Result<Address, Error> {
        Ok(Self::load(&env)?.guardian)
    }

    /// The registry used to verify contract callers, if one is wired.
    ///
    /// An uninitialized treasury reports no registry rather than failing, so
    /// off-chain callers can probe it before `initialize`.
    pub fn registry(env: Env) -> Option<Address> {
        Self::load(&env).ok().and_then(|t| t.registry)
    }

    /// Initialize a milestone-based disbursement.
    pub fn init_milestone_disbursement(
        env: Env,
        caller: Address,
        asset: Address,
        to: Address,
        total_amount: i128,
        milestones: u32,
    ) -> Result<u64, Error> {
        let _t = Self::require_admin(&env, &caller)?;
        require_positive_amount(total_amount)?;
        Self::require_approved_asset(&env, &asset)?;
        if milestones == 0 {
            return Err(Error::InvalidInput);
        }

        let amount_per_milestone = checked_div(total_amount, milestones as i128)?;
        // Fewer base units than milestones would schedule zero-value payouts.
        if amount_per_milestone == 0 {
            return Err(Error::InvalidAmount);
        }

        let count_key = DataKey::MilestoneCount;
        let count: u64 = env.storage().instance().get(&count_key).unwrap_or(0);
        let count = count.checked_add(1).ok_or(Error::Overflow)?;

        let disbursement = MilestoneDisbursement {
            total_amount,
            milestones,
            disbursed: 0,
            amount_per_milestone,
            asset,
            to,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Milestone(count), &disbursement);
        env.storage().persistent().extend_ttl(
            &DataKey::Milestone(count),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.storage().instance().set(&count_key, &count);
        env.events().publish(
            (symbol_short!("milestone"), symbol_short!("init")),
            (count, total_amount, milestones),
        );
        Ok(count)
    }

    /// Release the next milestone payout.
    ///
    /// An outflow like any other: refused with [`Error::TreasuryPaused`] while
    /// the emergency circuit breaker is engaged, and a contract caller must be
    /// the registry-recorded Treasury module (Issue #308). The reentrancy lock
    /// is held across the budget debit and the token transfer.
    pub fn release_next_milestone(
        env: Env,
        caller: Address,
        milestone_id: u64,
    ) -> Result<(), Error> {
        Self::require_not_paused(&env)?;
        let t = Self::require_admin(&env, &caller)?;
        // Issue #308 — verify the caller before the ledger is touched.
        Self::require_verified_caller(&env, &t, &caller, ModuleKind::Multisig)?;
        // Take the same reentrancy guard the other two outflows take, before
        // the disbursement counter is advanced and the payout is made.
        Self::lock(&env)?;
        let key = DataKey::Milestone(milestone_id);
        let mut d: MilestoneDisbursement = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;

        if d.disbursed >= d.milestones {
            return Err(Error::InvalidState);
        }

        Self::require_approved_asset(&env, &d.asset)?;

        let mut amount = d.amount_per_milestone;
        let last = d.milestones - 1; // milestones > 0, checked at init
        if d.disbursed == last {
            // The final payout absorbs the rounding remainder.
            let disbursed_so_far = checked_mul(d.amount_per_milestone, last as i128)?;
            amount = checked_sub(d.total_amount, disbursed_so_far)?;
        }

        d.disbursed = d.disbursed.checked_add(1).ok_or(Error::Overflow)?;
        env.storage().persistent().set(&key, &d);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

        // Execute withdrawal logic
        let mut holding = Self::load_holding(&env, &d.asset);
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(&env, budget_addr)
                .consume(&caller, budget_id, &amount);
        }

        if holding.total_in < amount {
            return Err(Error::InsufficientFunds);
        }
        holding.total_in = checked_sub(holding.total_in, amount)?;
        holding.total_out = checked_add(holding.total_out, amount)?;
        Self::store_holding(&env, &d.asset, &holding);
        // Same recorded-balance sync as every other outflow (Issue #218).
        Self::store_asset_balance(&env, &d.asset, holding.total_in);

        Self::transfer_out(&env, &d.asset, &d.to, amount)?;
        env.events().publish(
            (symbol_short!("milestone"), symbol_short!("disbursed")),
            (milestone_id, d.disbursed, amount),
        );
        Self::unlock(&env);
        Ok(())
    }

    /// The full treasury record. [`Error::NotInitialized`] before
    /// [`Self::initialize`].
    pub fn get(env: Env) -> Result<Treasury, Error> {
        Self::load(&env)
    }

    pub fn holding(env: Env, asset: Address) -> Holding {
        Self::load_holding(&env, &asset)
    }

    pub fn balances(env: Env, assets: Vec<Address>) -> Result<Vec<AssetBalance>, Error> {
        if assets.len() > MAX_BALANCE_ASSETS {
            return Err(Error::InvalidInput);
        }
        for i in 0..assets.len() {
            let asset = assets.get_unchecked(i);
            for j in (i + 1)..assets.len() {
                if assets.get_unchecked(j) == asset {
                    return Err(Error::InvalidInput);
                }
            }
        }

        let mut report = Vec::new(&env);
        for asset in assets.iter() {
            let balance = Self::read_token_balance(&env, &asset)?;
            report.push_back(AssetBalance { asset, balance });
        }
        Ok(report)
    }

    /// Live balances for every approved token, bounded by `MAX_TREASURY_ASSETS`.
    pub fn get_all_balances(env: Env) -> Result<Vec<(Address, i128)>, Error> {
        let mut report = Vec::new(&env);
        for asset in Self::approved_list(&env).iter() {
            report.push_back((asset.clone(), Self::read_token_balance(&env, &asset)?));
        }
        Ok(report)
    }

    /// Number of token contracts currently on the whitelist.
    pub fn approved_asset_count(env: Env) -> u32 {
        Self::approved_count(&env)
    }

    /// Every token contract currently on the whitelist, in approval order.
    pub fn approved_assets(env: Env) -> Vec<Address> {
        Self::approved_list(&env)
    }

    /// Position of every approved asset: live custody balance, recorded
    /// balance, cumulative outflow and the token's `decimals`. Bounded by
    /// [`MAX_TREASURY_ASSETS`]. Assets never deposited report zero balances.
    pub fn portfolio(env: Env) -> Vec<AssetPosition> {
        let custody = env.current_contract_address();
        let mut report = Vec::new(&env);
        for asset in Self::approved_list(&env).iter() {
            let token_client = token::TokenClient::new(&env, &asset);
            let holding = Self::load_holding(&env, &asset);
            report.push_back(AssetPosition {
                decimals: token_client.decimals(),
                balance: token_client.balance(&custody),
                recorded: holding.total_in,
                total_out: holding.total_out,
                asset,
            });
        }
        report
    }

    // --- internals ---

    /// Read the treasury record.
    ///
    /// Returns [`Error::NotInitialized`] when [`Self::initialize`] has not run,
    /// so every entry point reports a deterministic code instead of trapping
    /// the whole invocation with an opaque host error.
    fn load(env: &Env) -> Result<Treasury, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Treasury)
            .ok_or(Error::NotInitialized)
    }

    fn store(env: &Env, t: &Treasury) {
        env.storage().instance().set(&DataKey::Treasury, t);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<Treasury, Error> {
        let t = Self::load(env)?;
        if t.admin != *caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        Ok(t)
    }

    fn is_asset_approved(env: &Env, asset: &Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ApprovedAsset(asset.clone()))
            .unwrap_or(false)
    }

    fn read_token_balance(env: &Env, asset: &Address) -> Result<i128, Error> {
        if !Self::is_asset_approved(env, asset) {
            return Err(Error::AssetNotAuthorized);
        }
        Ok(token::TokenClient::new(env, asset).balance(&env.current_contract_address()))
    }

    /// Reject any routing through a token contract that governance has not
    /// approved. The whitelist starts empty, so a freshly initialized treasury
    /// moves nothing until an asset is explicitly approved.
    fn require_approved_asset(env: &Env, asset: &Address) -> Result<(), Error> {
        if !Self::is_asset_approved(env, asset) {
            return Err(Error::AssetNotAuthorized);
        }
        env.storage().persistent().extend_ttl(
            &DataKey::ApprovedAsset(asset.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Pay `amount` of `asset` out of custody to `to`, checking the live
    /// custody balance first and verifying afterwards that it fell by exactly
    /// `amount`.
    fn transfer_out(env: &Env, asset: &Address, to: &Address, amount: i128) -> Result<(), Error> {
        let token_client = token::TokenClient::new(env, asset);
        let custody = env.current_contract_address();
        let before = token_client.balance(&custody);
        if before < amount {
            return Err(Error::InsufficientFunds);
        }
        token_client.transfer(&custody, to, &amount);
        if checked_sub(before, token_client.balance(&custody))? != amount {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn approved_list(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::ApprovedAssetList)
            .unwrap_or_else(|| Vec::new(env))
    }

    fn store_approved_list(env: &Env, list: &Vec<Address>) {
        env.storage()
            .instance()
            .set(&DataKey::ApprovedAssetList, list);
    }

    fn approved_count(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ApprovedAssetCount)
            .unwrap_or(0)
    }

    /// Persist the per-asset balance used by the structured deposit and
    /// withdrawal events so the resulting balance never has to be recomputed
    /// from the flow totals at emission time.
    ///
    /// Callers always pass the updated [`Holding::total_in`], keeping this
    /// record an exact mirror of the internal ledger on every value path
    /// (Issue #218).
    fn store_asset_balance(env: &Env, asset: &Address, balance: i128) {
        let key = DataKey::AssetBalance(asset.clone());
        env.storage().persistent().set(&key, &balance);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn store_approved_count(env: &Env, count: u32) {
        env.storage()
            .instance()
            .set(&DataKey::ApprovedAssetCount, &count);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    /// Publish a whitelist change under both the contract-local tuple topic and
    /// the canonical cross-cutting schema.
    fn emit_asset_change(env: &Env, t: &Treasury, asset: &Address, action: Symbol) {
        env.events()
            .publish((symbol_short!("treasury"), action.clone()), asset.clone());
        events::publish(
            env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action,
            },
        );
    }

    fn require_multisig(env: &Env, caller: &Address) -> Result<Treasury, Error> {
        let t = Self::load(env)?;
        match &t.multisig {
            Some(multisig) if multisig == caller => {
                caller.require_auth();
                Ok(t)
            }
            _ => Err(Error::Unauthorized),
        }
    }

    /// Authorize a circuit-breaker operation: the caller must be either the
    /// recorded guardian or the organization's multisig, verified against
    /// instance storage before `require_auth` is demanded.
    fn require_guardian(env: &Env, caller: &Address) -> Result<Treasury, Error> {
        let t = Self::load(env)?;
        let is_multisig = matches!(&t.multisig, Some(multisig) if multisig == caller);
        if t.guardian != *caller && !is_multisig {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        Ok(t)
    }

    /// Whether an engaged breaker is still inside its [`MAX_PAUSE_DURATION`]
    /// window. A lapsed pause stops blocking outflows but keeps its stale
    /// flag stored until [`Self::unpause`] clears it or [`Self::pause`]
    /// re-engages over it.
    fn pause_is_active(t: &Treasury, env: &Env) -> bool {
        t.paused && env.ledger().timestamp() < t.paused_at.saturating_add(MAX_PAUSE_DURATION)
    }

    /// Short-circuit an outbound value movement while the emergency circuit
    /// breaker is engaged, with the dedicated [`Error::TreasuryPaused`] code.
    ///
    /// Reads the flag from instance storage on every call rather than caching
    /// it, and is never called on inbound paths: deposits must keep working
    /// during a pause so recovery funding can arrive.
    ///
    /// The breaker also lapses here: once [`MAX_PAUSE_DURATION`] has passed
    /// since [`Treasury::paused_at`], a still-set flag no longer blocks
    /// outflows. This bounds the blast radius of the breaker without trusting
    /// any external keeper to release it — if the guardian disappears mid
    /// incident, the treasury unblocks itself after the cap. A pause that
    /// must outlive the cap is the multisig-only [`Self::freeze`].
    fn require_not_paused(env: &Env) -> Result<(), Error> {
        if Self::pause_is_active(&Self::load(env)?, env) {
            return Err(Error::TreasuryPaused);
        }
        Ok(())
    }

    fn check_frozen(env: &Env) -> Result<(), Error> {
        let frozen: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Frozen)
            .unwrap_or(false);
        if frozen {
            return Err(Error::InvalidState);
        }
        // Deliberately does not touch `DataKey::ReentrancyLock`: freezing is a
        // state predicate, and clearing the guard here would let a caller that
        // had already taken it release it mid-operation.
        Ok(())
    }

    fn bump_frozen(env: &Env) {
        env.storage().persistent().extend_ttl(
            &DataKey::Frozen,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn require_active(t: &Treasury) -> Result<(), Error> {
        match t.state {
            ResourceState::Active => Ok(()),
            _ => Err(Error::InvalidState),
        }
    }

    /// Engage the reentrancy lock over the value paths (Issue #308).
    ///
    /// The flag lives in instance storage, so the host rolls it back if the
    /// invocation aborts — a failed movement can never leave the treasury
    /// wedged shut. A re-entered call observes the lock engaged and fails with
    /// [`Error::InvalidState`] before touching the ledger.
    fn lock(env: &Env) -> Result<(), Error> {
        if env
            .storage()
            .instance()
            .get(&DataKey::ReentrancyLock)
            .unwrap_or(false)
        {
            return Err(Error::InvalidState);
        }
        // Hold the guard for the remainder of the invocation. It is released by
        // `unlock` on the way out; if the invocation instead returns an error
        // before reaching that point, the host rolls the write back, so the
        // guard can never be left engaged.
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &true);
        Ok(())
    }

    /// Release the reentrancy guard at the end of a movement.
    fn unlock(env: &Env) {
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &false);
    }

    // --- withdrawal time-lock internals (Issue #321) ---

    /// The cooling-off configuration in force, or the disabled default when the
    /// treasury has never set one.
    ///
    /// Defaulting rather than failing is what makes the feature strictly
    /// additive: an unconfigured treasury resolves to `delay == 0`, and
    /// `WithdrawalTimeLock::applies` is then false for every amount, so every
    /// pre-existing outflow path behaves exactly as it did before.
    fn load_time_lock(env: &Env) -> WithdrawalTimeLock {
        env.storage()
            .instance()
            .get(&DataKey::WithdrawalTimeLock)
            .unwrap_or_else(WithdrawalTimeLock::disabled)
    }

    /// Refuse an immediate payout of `amount` when the time-lock captures it.
    ///
    /// Called on both value paths *before* the reentrancy lock is taken and
    /// before any external call, so a time-locked payout is rejected having
    /// moved nothing and consumed nothing.
    ///
    /// [`Error::TimelockNotExpired`] is the deliberate code here: it is the
    /// protocol's dedicated early-execution code, already reported by multisig
    /// governance changes and escrow releases, so an operator sees one
    /// consistent "this action is still inside its cooling-off period" signal
    /// regardless of which module refused.
    fn require_not_time_locked(env: &Env, amount: i128) -> Result<(), Error> {
        if Self::load_time_lock(env).applies(amount) {
            return Err(Error::TimelockNotExpired);
        }
        Ok(())
    }

    /// Refuse to park a payout the configured time-lock would not have
    /// captured, so queueing cannot be used to impose a cooldown governance
    /// never configured.
    fn require_time_lock_applies(env: &Env, amount: i128) -> Result<(), Error> {
        if Self::load_time_lock(env).applies(amount) {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// Record a queued withdrawal and return its id.
    ///
    /// Both timestamps are computed with the shared checked `u64` addition from
    /// the ledger clock, so a configuration near `u64::MAX` surfaces as
    /// [`Error::Overflow`] rather than wrapping into an `execute_after` already
    /// in the past — which would turn a maximum cooldown into none at all.
    ///
    /// `expires_at` gives the request the same grace-period treatment
    /// governance changes get: once a matured request is left unexecuted for
    /// [`GOVERNANCE_GRACE_PERIOD`] it lapses and must be re-queued under fresh
    /// scrutiny, instead of becoming a standing obligation the organization can
    /// no longer cancel in time.
    fn open_pending(
        env: &Env,
        requester: &Address,
        asset: Address,
        to: Address,
        amount: i128,
        payments: Vec<Payment>,
    ) -> Result<u64, Error> {
        let config = Self::load_time_lock(env);
        let now = env.ledger().timestamp();
        let execute_after = checked_add_u64(now, config.delay)?;
        let expires_at = checked_add_u64(execute_after, GOVERNANCE_GRACE_PERIOD)?;

        let count_key = DataKey::PendingWithdrawalCount;
        let id: u64 = env.storage().instance().get(&count_key).unwrap_or(0);
        let id = id.checked_add(1).ok_or(Error::Overflow)?;

        let pending = PendingWithdrawal {
            id,
            requester: requester.clone(),
            asset,
            to,
            amount,
            payments,
            requested_at: now,
            execute_after,
            expires_at,
            cancelled: false,
            executed: false,
        };

        let key = DataKey::PendingWithdrawal(id);
        env.storage().persistent().set(&key, &pending);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.storage().instance().set(&count_key, &id);

        // Announced separately from the payout it describes: a queued request
        // is observable while it is still inert, which is the whole window an
        // organization has to notice a hostile request and cancel it.
        env.events().publish(
            (symbol_short!("timelock"), symbol_short!("queued")),
            (id, amount, execute_after),
        );
        Ok(id)
    }

    /// Registry verification for cross-contract callers (Issue #308).
    ///
    /// Three-tier gate, reading the org's registry through the typed
    /// [`RegistryClient`] when one is wired:
    ///
    /// 1. **Account callers pass through.** Only contract addresses are
    ///    subject to the registry — an account (or other non-contract)
    ///    `caller` is verified by the role checks that follow instead.
    /// 2. **The caller must be the recorded module.** `RegistryClient::lookup`
    ///    resolves `(org, expected_kind)` and only the returned address
    ///    passes: outbound movements verify their contract caller against the
    ///    org's [`ModuleKind::Multisig`] record (the governance contract the
    ///    admin operates through), deposits verify a contract depositor
    ///    against [`ModuleKind::Wallet`]. An unregistered kind, or a contract
    ///    registered under a different kind, is refused.
    /// 3. **Fail closed.** Registry errors (frozen, deprecated module, host
    ///    failure) are not differenced: if the treasury cannot establish
    ///    that the caller is the module, the caller is refused.
    ///
    /// The refusal uses [`Error::Unauthorized`]: the canonical enum is at its
    /// XDR 50-variant cap, so a dedicated code cannot be added (see the note
    /// on `shared/src/errors.rs`).
    fn require_verified_caller(
        env: &Env,
        t: &Treasury,
        caller: &Address,
        expected_kind: ModuleKind,
    ) -> Result<(), Error> {
        if !Self::is_contract_address(caller) {
            return Ok(());
        }
        let registry = match &t.registry {
            Some(addr) => RegistryClient::new(env, addr),
            None => return Ok(()),
        };
        let verified = match registry.try_lookup(&t.org.clone(), &expected_kind) {
            Ok(Ok(recorded)) => recorded == *caller,
            Ok(Err(_)) | Err(_) => false,
        };
        if verified {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Whether `address` is a contract principal (as opposed to an account).
    ///
    /// SDK 21 does not expose [`Address::is_contract`], so this inspects the
    /// first byte of the address's canonical strkey encoding: `G` is the
    /// ed25519-account type byte and `C` the contract type byte. Strkeys are
    /// always 56 characters, so anything else is treated as not-a-contract
    /// and stays subject to the ordinary role checks.
    fn is_contract_address(address: &Address) -> bool {
        let strkey = address.to_string();
        let mut buf = [0u8; 56];
        if strkey.len() as usize != buf.len() {
            return false;
        }
        strkey.copy_into_slice(&mut buf);
        buf[0] == b'C'
    }

    fn load_holding(env: &Env, asset: &Address) -> Holding {
        env.storage()
            .persistent()
            .get(&DataKey::Holding(asset.clone()))
            .unwrap_or(Holding {
                asset: asset.clone(),
                total_in: 0,
                total_out: 0,
                budget_id: None,
            })
    }

    fn store_holding(env: &Env, asset: &Address, h: &Holding) {
        env.storage()
            .persistent()
            .set(&DataKey::Holding(asset.clone()), h);
        env.storage().persistent().extend_ttl(
            &DataKey::Holding(asset.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

// ---------------------------------------------------------------------------
// Shared read surface, exposed through `TreasuryInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl TreasuryInterface for TreasuryContract {
    fn balance(env: Env, asset: Address) -> Result<i128, Error> {
        Self::read_token_balance(&env, &asset)
    }

    /// Whether `asset` is currently approved for routing.
    fn is_approved_asset(env: Env, asset: Address) -> bool {
        Self::is_asset_approved(&env, &asset)
    }

    /// Whether the emergency circuit breaker is currently engaged — that is,
    /// a pause is stored *and* still inside its [`MAX_PAUSE_DURATION`] window.
    /// A breaker left past its window reads `false` here even before the
    /// stale flag is cleared, matching when outflows actually resume.
    fn is_paused(env: Env) -> bool {
        Self::load(&env)
            .map(|t| Self::pause_is_active(&t, &env))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for TreasuryContract {
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
    /// `wasm_hash` must be approved for `ModuleKind::Treasury` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Treasury,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
