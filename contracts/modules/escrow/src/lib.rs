#![no_std]
//! # Astroid Escrow Contract
//!
//! Temporary custody: `Sender → Escrow → (conditions) → Recipient`.
//! Escrows are used for milestone payments, freelancer work, agent-to-agent
//! settlements, and time-locked / gradual linear release schedules (PRD Doc 7 §Escrow).
//!
//! A single escrow agreement may hold several distinct Stellar asset tokens at
//! once (e.g. a milestone payout mixing USDC and XLM) — `Escrow::assets` is a
//! list of `(asset, amount)` pairs rather than a single token/amount.
//!
//! On `create` the sender's funds are pulled into the contract's own custody and
//! only leave through one of three settlement paths:
//!
//! ```text
//! Funded ──(arbiter, before deadline+grace)─────▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(signature override, before deadline)▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(cancel, before deadline)────────────▶ Refunded ─▶ sender    ─▶ Closed
//! Funded ──(after deadline+grace, no release)───▶ reclaim  ─▶ sender    ─▶ Closed
//!    └────(after deadline+grace, marker)────────▶ Expired ──(refund)──▶ Refunded
//! ```
//!
//! `Expired` is a permissionless status marker (a keeper/UI may set it once the
//! deadline passes); funds stay in custody until `refund` returns them to the
//! sender, so no escrow can be `Closed` with money still locked.
//!
//! ## Bounded refund window
//!
//! `grace_period` says when the sender's reclaim paths *open*; `refund_window`
//! optionally says when they *close*. An escrow created through
//! [`EscrowContract::create_with_refund_window`] may only be reclaimed during
//! `[deadline + grace_period, deadline + grace_period + refund_window)`, after
//! which `refund`, `refund_timelock` and `reclaim` all fail with
//! [`Error::EscrowExpired`]. `refund_window == 0` — what plain
//! [`EscrowContract::create`] stores — leaves the window open forever and
//! preserves the previous behaviour exactly.
//!
//! The window is measured from the moment refunds open rather than from the
//! deadline, so it can never close before it opens.
//! [`EscrowContract::refund_window_closes_at`] and
//! [`EscrowContract::is_refundable`] expose the rule so clients need not
//! recompute it off-chain.
//!
//! ## Signature-based release override
//!
//! Besides the single named `arbiter`, an escrow may name a set of
//! pre-configured ed25519 public keys (`override_signers`) and a threshold
//! (`override_threshold`). Anyone may call [`EscrowContract::override_release`]
//! with a `(nonce, signatures)` pair; the escrow releases early once enough of
//! the supplied signatures verify against the escrow's pre-configured keys.
//! This is independent of Soroban account auth — the cryptographic signatures
//! themselves are the authorization, which lets off-chain systems (or keys not
//! registered as Soroban accounts) approve a release.
//!
//! Every signature must cover a deterministic payload — the contract address,
//! the network id, the escrow id and the caller-supplied `nonce` — hashed with
//! SHA-256. The escrow tracks the last-used nonce and only accepts a strictly
//! greater one, which makes a captured signature unusable a second time
//! (replay protection).
//!
//! ## Milestone-based progressive release
//!
//! An escrow may optionally be funded via [`EscrowContract::deposit_with_milestones`]
//! with a list of basis-point-weighted milestones. Instead of a single arbiter
//! release, the arbiter approves each milestone individually via
//! [`EscrowContract::release_milestone`], disbursing funds proportionally. The
//! final milestone pays the dust-free remainder so the full amount is disbursed.
//! Plain `release` is blocked on milestone escrows to enforce phased settlement.
//!
//! ## Multi-party release conditions
//!
//! A settlement sometimes needs more than one pair of hands before the recipient
//! is paid — a buyer agent, a seller agent and an independent validator oracle
//! all signing off on the same delivery. An escrow created with
//! [`EscrowContract::create_with_release_condition`] carries a
//! [`ReleaseCondition`]: a bounded allow-list of `participants` and an
//! `approval_threshold`. Each participant signs off on its own Soroban account
//! via [`EscrowContract::approve_release`], and the arbiter's
//! [`EscrowContract::release`] (or the signature override) only pays out once the
//! threshold is met.
//!
//! Three properties matter:
//!
//! - **Additive, not substitutive.** The condition never replaces the arbiter or
//!   the override signatures; a caller must clear both gates. It is a
//!   precondition on every path that moves value *to the recipient* on an
//!   escrow that carries a condition — `release`, `override_release`, `claim` and
//!   `withdraw`. Milestone escrows are created by a different entrypoint that
//!   never records a condition, so `release_milestone` needs no gate.
//! - **Sender exits stay open.** `cancel`, `refund`, `refund_timelock` and
//!   `reclaim` are deliberately ungated, so a timed-out multi-party escrow always
//!   resolves back to the funder. A condition can delay a payout but can never
//!   lock up the depositor's money.
//! - **Distinct parties only.** Approvals are recorded one key per participant,
//!   so a party approving twice fails with [`Error::AlreadySigned`] and cannot
//!   inflate the count towards the threshold.
//!
//! The condition lives under its own storage key rather than inside [`Escrow`],
//! so single-party escrows pay nothing for it and previously stored escrows keep
//! deserializing after an upgrade.
//!
//! ## Time-lock release schedules
//!
//! Escrows support configurable time-locks and gradual release schedules:
//! - Bullet / Cliff time-locks (`ReleaseType::Cliff`): 100% unlocked at maturity.
//! - Linear release schedules (`ReleaseType::Linear`): Continuous linear vesting
//!   from start_time to end_time with optional cliff_time.
//! - Partial and multiple gradual withdrawals by the beneficiary.
//! - Deterministic errors while locked: the beneficiary-facing `withdraw` /
//!   `claim` paths report `Error::TimeLockActive` before maturity or cliff,
//!   while release attempts (the arbiter's `release` and the signature-based
//!   `override_release`) report the distinct `Error::EscrowLocked`
//!   (alias of `Error::TimelockNotExpired`, wire name `TIMELOCK_NOT_EXPIRED`) —
//!   the escrow's release condition is not yet
//!   satisfied at the current ledger timestamp (Issue #315, #332).
//!
//! The time lock is enforced on every value-leaving path, including the
//! arbiter's `release`: a scheduled escrow cannot be released ahead of its
//! vesting schedule no matter how much settlement time remains (see
//! [`EscrowContract::release`]). The lock also covers cancellation: `cancel`
//! is refused with [`Error::TimeLockActive`] on a scheduled escrow that has
//! already vested anything, so the schedule cannot be routed around by
//! refunding early (Issue #307). The [`EscrowContract::is_unlocked`] view
//! exposes schedule maturity to off-chain clients.

//! ## Token whitelist
//!
//! Anyone may create an escrow, so without a gate the contract would let a
//! caller lock an arbitrary token contract into custody — spam-token escrows
//! that pad a record the caller controls, at the protocol's expense. Every
//! token therefore has to be approved by the contract admin recorded at
//! [`EscrowContract::initialize`]:
//!
//! ```text
//! unapproved token ──▶ create / create_timelock / create_scheduled /
//!                       initialize_timelock / fund / deposit_with_milestones
//!                   ──▶ Error::AssetNotAuthorized
//! approved token   ──▶ escrow created, funds move into custody
//! ```
//!
//! The check is the same [`Error::AssetNotAuthorized`] code the treasury
//! whitelist, the budget asset registry and the policy asset whitelist report,
//! so one handler covers a "this token is not usable here" refusal across every
//! Astroid contract. Approval is a persistent flag per token address, so a
//! deposit check costs one read no matter how large the whitelist is.
//!
//! Revoking a token stops it being escrowed *going forward* only: escrows that
//! already hold it stay releasable and refundable, so revoking can never strand
//! funds. An escrow that was initialized but not yet funded is re-checked at
//! [`EscrowContract::fund`] time, so a token revoked in between is refused there
//! too. Escrows capped per agreement by [`MAX_ESCROW_ASSETS`]; the whitelist
//! itself by [`MAX_ESCROW_TOKENS`].

pub mod storage;

pub use storage::{
    bump_escrow, bump_milestones, get_count, has_release_approval, increment_count, load_escrow,
    load_release_condition, mark_release_approval, store_escrow, store_release_condition, DataKey,
    Escrow, EscrowState, Milestone, MilestoneSet, MilestoneSpec, MilestoneStatus, ReleaseCondition,
    ReleaseSchedule, ReleaseType,
};

use astroid_interfaces::{EscrowInterface, UpgradeableInterface};
use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_ESCROW_ASSETS, MAX_SIGNERS,
    PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::{Error, MilestoneError};
use astroid_shared::events::{self, ContractEvent};
use astroid_shared::math::{checked_add, checked_div, checked_mul, checked_sub};
use astroid_shared::types::AssetAmount;
use astroid_shared::validation::require_positive_amount;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, vec, Address, Bytes, BytesN, Env,
    String, Symbol, Vec,
};

/// Upper bound on the number of distinct token contracts the admin may
/// whitelist. Each approval costs a persistent entry plus a slot in the
/// enumerable list, so the list is capped rather than left unbounded.
pub const MAX_ESCROW_TOKENS: u32 = 32;

/// Calculate vested amount according to a ReleaseSchedule at a given ledger timestamp.
pub fn calculate_vested_amount(
    amount: i128,
    schedule: &ReleaseSchedule,
    current_time: u64,
) -> Result<i128, Error> {
    match schedule.release_type {
        ReleaseType::None => Ok(0),
        ReleaseType::Cliff => {
            if schedule.end_time < schedule.start_time
                || schedule.cliff_time < schedule.start_time
                || schedule.cliff_time > schedule.end_time
            {
                return Err(Error::InvalidInput);
            }
            if current_time < schedule.cliff_time || current_time < schedule.start_time {
                return Ok(0);
            }
            if current_time >= schedule.end_time {
                Ok(amount)
            } else {
                Ok(0)
            }
        }
        ReleaseType::Linear => {
            if schedule.end_time <= schedule.start_time
                || schedule.cliff_time < schedule.start_time
                || schedule.cliff_time > schedule.end_time
            {
                return Err(Error::InvalidInput);
            }
            if current_time < schedule.cliff_time || current_time < schedule.start_time {
                return Ok(0);
            }
            if current_time >= schedule.end_time {
                return Ok(amount);
            }
            let total_duration = (schedule.end_time - schedule.start_time) as i128;
            if total_duration == 0 {
                return Ok(amount);
            }
            let elapsed = (current_time - schedule.start_time) as i128;
            let vested = checked_div(checked_mul(amount, elapsed)?, total_duration)?;
            Ok(vested)
        }
    }
}

/// Calculate currently claimable (vested minus already released) amount for an escrow.
pub fn calculate_claimable_amount(escrow: &Escrow, current_time: u64) -> Result<i128, Error> {
    if matches!(
        escrow.schedule.release_type,
        ReleaseType::Cliff | ReleaseType::Linear
    ) {
        let vested = calculate_vested_amount(escrow.funded_amount, &escrow.schedule, current_time)?;
        let claimable = checked_sub(vested, escrow.released_amount)?;
        if claimable < 0 {
            return Ok(0);
        }
        Ok(claimable)
    } else {
        Ok(0)
    }
}

/// One signer's ed25519 signature over an [`EscrowContract::override_release`]
/// payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverrideSignature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

/// Creation arguments for an escrow that additionally requires multi-party
/// sign-off before any funds reach the recipient.
///
/// Grouped into a single struct (like [`MilestoneSpec`]) because the plain
/// creation entrypoints already carry eleven arguments; adding two more inline
/// would make the ABI unreadable.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseConditionConfig {
    pub sender: Address,
    pub recipient: Address,
    pub arbiter: Address,
    pub assets: Vec<AssetAmount>,
    pub deadline: u64,
    pub grace_period: u64,
    pub refund_window: u64,
    pub memo: String,
    /// Pre-configured ed25519 keys for the signature-override release path; an
    /// empty set with a `0` threshold disables it.
    pub override_signers: Vec<BytesN<32>>,
    pub override_threshold: u32,
    /// Counterparties allowed to approve a release. An empty set disables the
    /// condition, which then requires a `0` `approval_threshold`.
    pub participants: Vec<Address>,
    /// How many distinct participants must approve before funds may move to
    /// the recipient.
    pub approval_threshold: u32,
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    /// Initialize the contract, recording `admin` as the only address allowed
    /// to manage the token whitelist.
    ///
    /// The whitelist starts empty, which approves nothing: until an admin calls
    /// [`Self::approve_token`], every token-bearing entrypoint refuses its
    /// deposit with [`Error::AssetNotAuthorized`]. That is deliberate — an
    /// escrow that accepts any token is trivially spammable, since anyone may
    /// park a worthless token contract to pad a record they control.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Count) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Count, &0u64);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    /// Approve a token contract so it may be escrowed (admin only).
    ///
    /// Approval is the gate that keeps arbitrary token contracts out of
    /// custody. Re-approving an already-approved token is refused with
    /// [`Error::AlreadyExists`] rather than silently absorbed, so a
    /// re-run governance script cannot mistake a no-op for a change.
    pub fn approve_token(env: Env, caller: Address, token: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if Self::is_token_approved_internal(&env, &token) {
            return Err(Error::AlreadyExists);
        }
        let mut list = Self::approved_token_list(&env);
        if list.len() >= MAX_ESCROW_TOKENS {
            return Err(Error::InvalidInput);
        }
        list.push_back(token.clone());
        Self::store_approved_token_list(&env, &list);

        let key = DataKey::ApprovedToken(token.clone());
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        Self::emit_token_change(&env, &token, symbol_short!("tok_add"));
        Ok(())
    }

    /// Revoke a token contract's approval (admin only).
    ///
    /// This only stops the token being escrowed *going forward*. Escrows that
    /// already hold it stay releasable and refundable, so a revocation can
    /// never strand funds in custody; the sender can still `reclaim` or
    /// `refund`, and the arbiter can still `release`. Escrows that were
    /// initialized but never funded are refused at `fund` instead.
    ///
    /// Revoking a token that is not approved is refused with
    /// [`Error::NotFound`], so a revocation is never silently a no-op.
    pub fn revoke_token(env: Env, caller: Address, token: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if !Self::is_token_approved_internal(&env, &token) {
            return Err(Error::NotFound);
        }
        env.storage()
            .persistent()
            .remove(&DataKey::ApprovedToken(token.clone()));
        let mut list = Self::approved_token_list(&env);
        if let Some(i) = list.first_index_of(&token) {
            list.remove(i);
            Self::store_approved_token_list(&env, &list);
        }
        Self::emit_token_change(&env, &token, symbol_short!("tok_rm"));
        Ok(())
    }

    /// The address recorded at `initialize` that manages the whitelist.
    pub fn admin(env: Env) -> Result<Address, Error> {
        Self::load_admin(&env)
    }

    /// Whether `token` may currently be escrowed.
    pub fn is_token_approved(env: Env, token: Address) -> bool {
        Self::is_token_approved_internal(&env, &token)
    }

    /// Every approved token contract, in approval order.
    pub fn approved_tokens(env: Env) -> Vec<Address> {
        Self::approved_token_list(&env)
    }

    /// Create + fund an escrow in one call. `sender` locks every listed asset
    /// amount until `deadline` and names a `recipient` and an `arbiter`. The
    /// real tokens are moved into the contract's custody here — the escrow
    /// always reflects funds actually held.
    ///
    /// `release_signers`/`release_threshold` optionally configure the manual
    /// signature-override mechanism (see module docs); pass an empty
    /// `release_signers` and a `0` threshold to disable it for this escrow.
    /// `grace_period` extends the settlement window past the deadline: the
    /// arbiter may still release during the grace, but the sender may only
    /// reclaim the funds once the grace has fully elapsed without fulfillment.
    /// Either party (sender or arbiter) may cancel before the deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        deadline: u64,
        grace_period: u64,
        memo: String,
        release_signers: Vec<BytesN<32>>,
        release_threshold: u32,
    ) -> Result<u64, Error> {
        Self::create_with_refund_window(
            env,
            sender,
            recipient,
            arbiter,
            assets,
            deadline,
            grace_period,
            0,
            memo,
            release_signers,
            release_threshold,
        )
    }

    /// Create + fund an escrow with a bounded refund window. Identical to
    /// [`Self::create`] except that the sender may only reclaim the funds during
    /// `[deadline + grace_period, deadline + grace_period + refund_window)`;
    /// passing `0` leaves the window open forever.
    ///
    /// Refunds do not open until the grace period has elapsed, so the window is
    /// measured from the moment they open rather than from the deadline — a
    /// window can therefore never close before it opens.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_refund_window(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        deadline: u64,
        grace_period: u64,
        refund_window: u64,
        memo: String,
        release_signers: Vec<BytesN<32>>,
        release_threshold: u32,
    ) -> Result<u64, Error> {
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        Self::validate_assets(&env, &assets)?;
        Self::validate_override_config(&release_signers, release_threshold)?;

        let id = increment_count(&env)?;

        let mut funded_amount: i128 = 0;
        for a in assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
            funded_amount = checked_add(funded_amount, a.amount)?;
        }

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: assets.clone(),
            state: EscrowState::Funded,
            deadline,
            grace_period,
            refund_window,
            funded_amount,
            memo,
            schedule: ReleaseSchedule::none(),
            released_amount: 0,
            override_signers: release_signers,
            override_threshold: release_threshold,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender.clone(), recipient.clone(), assets.clone()),
        );
        events::publish(
            &env,
            ContractEvent::EscrowCreated {
                escrow_id: id,
                sender,
                recipient,
                assets,
                deadline,
            },
        );
        Ok(id)
    }

    /// Create + fund an escrow that may only pay out once `approval_threshold`
    /// distinct `participants` have signed off via [`Self::approve_release`].
    ///
    /// Every other creation parameter behaves exactly as in
    /// [`Self::create_with_refund_window`], which this delegates to, so an empty
    /// `participants` list simply yields a plain escrow (and then demands a `0`
    /// threshold).
    ///
    /// The condition is deliberately *additive* to the existing authorizations:
    /// the arbiter still has to call `release` (or enough `override_signers` still
    /// have to sign) **and** the participants have to approve. It is not an
    /// alternative route to the funds. Sender-side exits (`cancel`, `refund`,
    /// `refund_timelock`, `reclaim`) are untouched, so a condition can never
    /// strand or lock up the funder's own money.
    pub fn create_with_release_condition(
        env: Env,
        config: ReleaseConditionConfig,
    ) -> Result<u64, Error> {
        // Validate the condition before pulling any tokens, so a bad
        // participant set can never move funds.
        Self::validate_release_condition(&config.participants, config.approval_threshold)?;
        let id = Self::create_with_refund_window(
            env.clone(),
            config.sender,
            config.recipient,
            config.arbiter,
            config.assets,
            config.deadline,
            config.grace_period,
            config.refund_window,
            config.memo,
            config.override_signers,
            config.override_threshold,
        )?;
        if !config.participants.is_empty() {
            store_release_condition(
                &env,
                id,
                &ReleaseCondition {
                    participants: config.participants,
                    threshold: config.approval_threshold,
                    approvals: 0,
                },
            );
        }
        Ok(id)
    }

    /// Sign off on releasing escrow `id` to its recipient, as one of the
    /// escrow's `participants`. Returns the number of distinct approvals
    /// recorded so far.
    ///
    /// The caller authorizes with its own Soroban account signature
    /// (`require_auth`), so an approval can only ever be recorded by the
    /// participant itself — no relayer may vote on its behalf. Participants are
    /// recorded as a set: a repeat approval from the same party fails with
    /// [`Error::AlreadySigned`] and never inflates the count.
    pub fn approve_release(env: Env, caller: Address, id: u64) -> Result<u32, Error> {
        caller.require_auth();
        let escrow = load_escrow(&env, id)?;
        // Approvals are only meaningful while the funds are still in escrow;
        // once the escrow has been released, refunded or closed there is
        // nothing left to sign off on.
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        let mut condition = load_release_condition(&env, id).ok_or(Error::NotFound)?;
        if !condition.participants.contains(&caller) {
            return Err(Error::NotASigner);
        }
        if has_release_approval(&env, id, &caller) {
            return Err(Error::AlreadySigned);
        }
        mark_release_approval(&env, id, &caller);
        condition.approvals = checked_add(condition.approvals as i128, 1)? as u32;
        store_release_condition(&env, id, &condition);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("approval")),
            (id, caller, condition.approvals, condition.threshold),
        );
        Ok(condition.approvals)
    }

    /// Read the multi-party release condition attached to `id`, or
    /// [`Error::NotFound`] when the escrow carries none.
    pub fn get_release_condition(env: Env, id: u64) -> Result<ReleaseCondition, Error> {
        load_release_condition(&env, id).ok_or(Error::NotFound)
    }

    /// The participants that have approved release of `id`, in the order they
    /// were declared. Bounded by the participant cap, so a client gets the
    /// whole sign-off picture in one call.
    pub fn release_approvals(env: Env, id: u64) -> Result<Vec<Address>, Error> {
        let condition = load_release_condition(&env, id).ok_or(Error::NotFound)?;
        let mut approved: Vec<Address> = Vec::new(&env);
        for participant in condition.participants.iter() {
            if has_release_approval(&env, id, &participant) {
                approved.push_back(participant);
            }
        }
        Ok(approved)
    }

    /// Create a funded time-locked escrow with bullet cliff release at `unlock_time`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_timelock(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        unlock_time: u64,
        memo: String,
    ) -> Result<u64, Error> {
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        let now = env.ledger().timestamp();
        if unlock_time <= now {
            return Err(Error::InvalidInput);
        }
        Self::validate_assets(&env, &assets)?;

        let id = increment_count(&env)?;

        let mut funded_amount: i128 = 0;
        for a in assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
            funded_amount = checked_add(funded_amount, a.amount)?;
        }

        let schedule = ReleaseSchedule {
            release_type: ReleaseType::Cliff,
            start_time: now,
            cliff_time: unlock_time,
            end_time: unlock_time,
        };

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: assets.clone(),
            state: EscrowState::Funded,
            deadline: unlock_time,
            grace_period: 0,
            refund_window: 0,
            funded_amount,
            memo,
            schedule,
            released_amount: 0,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender.clone(), recipient.clone(), assets.clone()),
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (
                id,
                sender.clone(),
                recipient.clone(),
                assets.clone(),
                unlock_time,
            ),
        );
        events::publish(
            &env,
            ContractEvent::EscrowCreated {
                escrow_id: id,
                sender,
                recipient,
                assets,
                deadline: unlock_time,
            },
        );
        Ok(id)
    }

    /// Create a funded escrow with configurable release schedule (Cliff or Linear).
    #[allow(clippy::too_many_arguments)]
    pub fn create_scheduled(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        schedule: ReleaseSchedule,
        deadline: u64,
        memo: String,
    ) -> Result<u64, Error> {
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        Self::validate_assets(&env, &assets)?;
        if schedule.start_time > schedule.cliff_time
            || schedule.cliff_time > schedule.end_time
            || schedule.end_time <= schedule.start_time
        {
            return Err(Error::InvalidInput);
        }
        if schedule.end_time <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        let effective_deadline = if deadline == 0 {
            schedule.end_time
        } else {
            deadline
        };
        if effective_deadline < schedule.end_time {
            return Err(Error::InvalidInput);
        }

        let id = increment_count(&env)?;

        let mut funded_amount: i128 = 0;
        for a in assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
            funded_amount = checked_add(funded_amount, a.amount)?;
        }

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: assets.clone(),
            state: EscrowState::Funded,
            deadline: effective_deadline,
            grace_period: 0,
            refund_window: 0,
            funded_amount,
            memo,
            schedule: schedule.clone(),
            released_amount: 0,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender.clone(), recipient.clone(), assets.clone()),
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("sched")),
            (
                id,
                sender.clone(),
                recipient.clone(),
                assets.clone(),
                funded_amount,
                schedule.start_time,
                schedule.end_time,
            ),
        );
        events::publish(
            &env,
            ContractEvent::EscrowCreated {
                escrow_id: id,
                sender,
                recipient,
                assets,
                deadline: effective_deadline,
            },
        );
        Ok(id)
    }

    /// Initialize an escrow with time-lock (unfunded version). Manual
    /// signature override is not available on this path (empty signer set).
    /// `grace_period` extends the settlement window past `unlock_time`.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize_timelock(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        unlock_time: u64,
        grace_period: u64,
        memo: String,
    ) -> Result<u64, Error> {
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        let now = env.ledger().timestamp();
        if unlock_time <= now {
            return Err(Error::InvalidInput);
        }
        Self::validate_assets(&env, &assets)?;

        let id = increment_count(&env)?;

        let schedule = ReleaseSchedule {
            release_type: ReleaseType::Cliff,
            start_time: now,
            cliff_time: unlock_time,
            end_time: unlock_time,
        };

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: assets.clone(),
            state: EscrowState::Created,
            deadline: unlock_time,
            grace_period,
            refund_window: 0,
            funded_amount: 0,
            memo,
            schedule,
            released_amount: 0,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (
                id,
                sender.clone(),
                recipient.clone(),
                assets.clone(),
                unlock_time,
            ),
        );
        events::publish(
            &env,
            ContractEvent::EscrowCreated {
                escrow_id: id,
                sender,
                recipient,
                assets,
                deadline: unlock_time,
            },
        );
        Ok(id)
    }

    /// Fund an initialized escrow.
    pub fn fund(env: Env, sender: Address, id: u64) -> Result<(), Error> {
        sender.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.sender != sender {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Created) {
            return Err(Error::InvalidState);
        }
        // Re-check the whitelist rather than trusting the check made when the
        // escrow was initialized: an admin may have revoked one of these tokens
        // in between, and funding is the moment value actually enters custody.
        Self::require_tokens_approved(&env, &escrow.assets)?;

        let mut total: i128 = 0;
        for a in escrow.assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
            total = checked_add(total, a.amount)?;
        }

        escrow.funded_amount = total;
        escrow.state = EscrowState::Funded;
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (
                id,
                escrow.sender.clone(),
                escrow.recipient.clone(),
                escrow.assets.clone(),
            ),
        );
        events::publish(
            &env,
            ContractEvent::EscrowCreated {
                escrow_id: id,
                sender: escrow.sender.clone(),
                recipient: escrow.recipient.clone(),
                assets: escrow.assets.clone(),
                deadline: escrow.deadline,
            },
        );
        Ok(())
    }

    /// Beneficiary partial or full withdrawal according to release schedule.
    pub fn withdraw(env: Env, caller: Address, id: u64, amount: i128) -> Result<i128, Error> {
        caller.require_auth();
        require_positive_amount(amount)?;
        let mut escrow = load_escrow(&env, id)?;
        Self::reject_milestone_settlement(&env, id)?;
        if escrow.recipient != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        let claimable = calculate_claimable_amount(&escrow, now)?;
        if claimable <= 0 {
            return Err(Error::TimeLockActive);
        }
        if amount > claimable {
            return Err(Error::InsufficientFunds);
        }
        // Last gate before the payout: a multi-party escrow may only settle once
        // enough distinct participants have approved.
        Self::require_release_approvals(&env, id)?;

        escrow.released_amount = checked_add(escrow.released_amount, amount)?;
        if escrow.released_amount == escrow.funded_amount {
            escrow.state = EscrowState::Released;
        }
        store_escrow(&env, id, &escrow);

        for a in escrow.assets.iter() {
            let send_amount = checked_div(checked_mul(a.amount, amount)?, escrow.funded_amount)?;
            if send_amount > 0 {
                token::TokenClient::new(&env, &a.asset).transfer(
                    &env.current_contract_address(),
                    &escrow.recipient,
                    &send_amount,
                );
                events::transfer_executed(
                    &env,
                    &escrow.sender,
                    &escrow.recipient,
                    &a.asset,
                    send_amount,
                );
            }
        }
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("withdraw")),
            (id, caller, amount, escrow.released_amount),
        );
        Ok(escrow.released_amount)
    }

    /// Claim all currently available funds from time-locked or scheduled escrow.
    pub fn claim(env: Env, caller: Address, id: u64) -> Result<i128, Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        Self::reject_milestone_settlement(&env, id)?;
        if escrow.recipient != caller {
            return Err(Error::Unauthorized);
        }
        // Settle the state first so a final escrow always reports `InvalidState`
        // rather than a stale condition complaint.
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Created) {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();

        if matches!(escrow.state, EscrowState::Funded) {
            let claimable = if matches!(
                escrow.schedule.release_type,
                ReleaseType::Cliff | ReleaseType::Linear
            ) {
                calculate_claimable_amount(&escrow, now)?
            } else {
                if now < Self::grace_end(&escrow)? {
                    return Err(Error::TimeLockActive);
                }
                checked_sub(escrow.funded_amount, escrow.released_amount)?
            };

            if claimable <= 0 {
                return Err(Error::TimeLockActive);
            }
            // Last gate before the payout: a multi-party escrow may only settle
            // once enough distinct participants have approved.
            Self::require_release_approvals(&env, id)?;

            escrow.released_amount = checked_add(escrow.released_amount, claimable)?;
            if escrow.released_amount == escrow.funded_amount {
                escrow.state = EscrowState::Released;
            }
            store_escrow(&env, id, &escrow);

            for a in escrow.assets.iter() {
                let send_amount =
                    checked_div(checked_mul(a.amount, claimable)?, escrow.funded_amount)?;
                if send_amount > 0 {
                    token::TokenClient::new(&env, &a.asset).transfer(
                        &env.current_contract_address(),
                        &escrow.recipient,
                        &send_amount,
                    );
                    events::transfer_executed(
                        &env,
                        &escrow.sender,
                        &escrow.recipient,
                        &a.asset,
                        send_amount,
                    );
                }
            }
            env.events().publish(
                (symbol_short!("escrow"), symbol_short!("claimed")),
                (id, caller, claimable),
            );
            Ok(claimable)
        } else if matches!(escrow.state, EscrowState::Created) {
            if now < Self::grace_end(&escrow)? {
                return Err(Error::TimeLockActive);
            }
            Self::require_release_approvals(&env, id)?;
            escrow.state = EscrowState::Released;
            store_escrow(&env, id, &escrow);
            let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
            Self::transfer_all(&env, &escrow, &escrow.recipient, remaining)?;
            for a in escrow.assets.iter() {
                events::transfer_executed(
                    &env,
                    &escrow.sender,
                    &escrow.recipient,
                    &a.asset,
                    a.amount,
                );
            }
            env.events().publish(
                (symbol_short!("escrow"), symbol_short!("claimed")),
                (id, caller, escrow.funded_amount),
            );
            Ok(escrow.funded_amount)
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Release the escrowed assets to the recipient. Only the arbiter may call,
    /// and only before the deadline — afterward the sender reclaims via `refund`.
    ///
    /// Time-locked escrows additionally gate on the release schedule: a `Cliff`
    /// schedule refuses any release before its `cliff_time`, and a `Linear`
    /// schedule refuses a release before the cliff or beyond the amount vested
    /// at the current ledger timestamp. Both early-release cases report the
    /// [`Error::EscrowLocked`] alias (wire code `TIMELOCK_NOT_EXPIRED`),
    /// separating "the escrow's own release clock has not matured" from the
    /// beneficiary-facing [`Error::TimeLockActive`] reported by `withdraw` /
    /// `claim`.
    ///
    /// `release_amount` is the amount to release this call. Partial releases are
    /// supported: the cumulative `released_amount` is tracked on the escrow and
    /// must not exceed `funded_amount`. A full release transitions the escrow to
    /// `Released`; a partial release keeps the escrow in `Funded` so that more
    /// can be released later or the remaining balance can be revoked.
    pub fn release(env: Env, arbiter: Address, id: u64, release_amount: i128) -> Result<(), Error> {
        arbiter.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.arbiter != arbiter {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.storage().persistent().has(&DataKey::Milestones(id)) {
            return Err(Error::InvalidState);
        }
        // Issue #238 / #315 / #332 / #307 — time-lock verification. A schedule-backed escrow
        // can only be released once its own release schedule has matured,
        // regardless of how much time is left on the settlement deadline:
        //
        // - `Cliff` schedules unlock everything at `cliff_time` (=
        //   `end_time`), so a release before maturity is premature by
        //   definition.
        // - `Linear` schedules vest continuously between `start_time` and
        //   `end_time`; nothing has vested before `cliff_time` and any
        //   release may not exceed the amount vested at the current ledger
        //   timestamp.
        //
        // Deterministic error: [`Error::EscrowLocked`] while the lock holds —
        // release requests fail while the ledger timestamp is below the
        // configured release time and succeed once it has passed. Both checks
        // read the ledger clock via `env.ledger().timestamp()`.
        let now = env.ledger().timestamp();
        if matches!(escrow.schedule.release_type, ReleaseType::Cliff) {
            if now < escrow.schedule.cliff_time {
                return Err(Error::EscrowLocked);
            }
        } else if matches!(escrow.schedule.release_type, ReleaseType::Linear) {
            if now < escrow.schedule.cliff_time {
                return Err(Error::EscrowLocked);
            }
            // Issue #307 — a release settles the escrow in full, so nothing
            // unvested may ever move through it: the outstanding balance must
            // have vested at the current ledger timestamp. While part of the
            // schedule is still locked, the beneficiary's `withdraw` / `claim`
            // paths are the only way to reach the vested portion.
            let vested = calculate_vested_amount(escrow.funded_amount, &escrow.schedule, now)?;
            if release_amount > vested {
                return Err(Error::EscrowLocked);
            }
            // Issue #307 — a release settles the escrow in full, so nothing
            // unvested may ever move through it: the outstanding balance must
            // have vested at the current ledger timestamp, even when the
            // requested amount alone is within the vested portion. While part
            // of the schedule is still locked, the beneficiary's `withdraw` /
            // `claim` paths are the only way to reach the vested funds.
            let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
            if remaining > vested {
                return Err(Error::EscrowLocked);
            }
        }
        if now >= Self::grace_end(&escrow)? {
            // Issue #292 — harden the release/refund handoff: a keeper that
            // never ran `expire` leaves the escrow sitting in `Funded` even
            // though its settlement window has closed. Verify the deadline
            // condition on *this* attempt instead of trusting the marker: the
            // expired-but-unmarked record still refuses the release with
            // [`Error::EscrowExpired`], and the permissionless `expire` /
            // `refund` / `reclaim` paths resolve the funds back to the sender.
            // We do NOT persist an `Expired` transition here: returning `Err`
            // rolls back every storage write, so the marker can only be set
            // through the `expire` entrypoint — keeping release and refund
            // mutually exclusive.
            return Err(Error::EscrowExpired);
        }
        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        if release_amount > remaining {
            return Err(Error::InvalidAmount);
        }
        // Last gate before the payout: a multi-party escrow may only settle once
        // enough distinct participants have approved. Escrows without a
        // condition are unaffected.
        Self::require_release_approvals(&env, id)?;

        // Issue #307 — the release settles the escrow in full: the entire
        // remaining custody balance moves to the recipient and the escrow
        // becomes `Released`. The time-lock gates above are what keep unvested
        // funds from riding along on a partially-vested `Linear` schedule.
        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.released_amount = escrow.funded_amount;
        escrow.state = EscrowState::Released;
        store_escrow(&env, id, &escrow);
        // Move the real tokens out of custody to the recipient.
        Self::transfer_all(&env, &escrow, &escrow.recipient, remaining)?;
        for a in escrow.assets.iter() {
            events::transfer_executed(&env, &escrow.sender, &escrow.recipient, &a.asset, a.amount);
        }
        events::publish(
            &env,
            ContractEvent::EscrowReleased {
                escrow_id: id,
                recipient: escrow.recipient.clone(),
                assets: escrow.assets.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("released")),
            (id, arbiter, release_amount),
        );
        Ok(())
    }

    /// Release the escrowed assets to the recipient via the manual signature
    /// override instead of the named arbiter. Requires at least
    /// `override_threshold` distinct, valid ed25519 signatures from the
    /// escrow's pre-configured `override_signers`, each covering a
    /// deterministic payload built from the contract address, network id,
    /// escrow id and `nonce`. `nonce` must be strictly greater than the last
    /// nonce this escrow consumed, which makes a captured signature set
    /// unusable a second time.
    ///
    /// Permissionless by design: the cryptographic signatures are the
    /// authorization, so any relayer may submit them.
    ///
    /// Signatures authorize *who* may release; they do not override *when*.
    /// A schedule-backed escrow refuses an early override release with the
    /// same [`Error::EscrowLocked`] code the arbiter path uses (Issue #315, #332),
    /// so the signature path cannot route around a time lock.
    pub fn override_release(
        env: Env,
        id: u64,
        nonce: u64,
        signatures: Vec<OverrideSignature>,
    ) -> Result<(), Error> {
        let mut escrow = load_escrow(&env, id)?;
        Self::reject_milestone_settlement(&env, id)?;
        if escrow.override_signers.is_empty() || escrow.override_threshold == 0 {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() >= escrow.deadline {
            return Err(Error::EscrowExpired);
        }
        // Issue #315 / #332 — the signature override must respect the escrow's own
        // release clock: a `Cliff` schedule refuses any release before its
        // `cliff_time`, and a `Linear` schedule refuses a release before the
        // cliff or beyond the vested amount at the current ledger timestamp.
        // Deterministic error: [`Error::EscrowLocked`].
        let now = env.ledger().timestamp();
        if matches!(escrow.schedule.release_type, ReleaseType::Cliff) {
            if now < escrow.schedule.cliff_time {
                return Err(Error::EscrowLocked);
            }
        } else if matches!(escrow.schedule.release_type, ReleaseType::Linear) {
            if now < escrow.schedule.cliff_time {
                return Err(Error::EscrowLocked);
            }
            let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
            let vested = calculate_vested_amount(escrow.funded_amount, &escrow.schedule, now)?;
            if remaining > vested {
                return Err(Error::EscrowLocked);
            }
        }
        if nonce <= escrow.override_nonce {
            return Err(Error::InvalidNonce);
        }
        if signatures.len() < escrow.override_threshold {
            return Err(Error::ThresholdNotMet);
        }

        let payload = Self::override_payload(&env, id, nonce);
        let digest: Bytes = env.crypto().sha256(&payload).into();

        // Every signer must be a distinct, pre-configured key, and every
        // signature must verify against the deterministic payload. Any single
        // invalid signature (unknown key, reused key, bad signature) fails the
        // whole call — signatures are never "partially" honored.
        let mut seen: Vec<BytesN<32>> = Vec::new(&env);
        for sig in signatures.iter() {
            if !escrow.override_signers.contains(&sig.public_key) {
                return Err(Error::NotASigner);
            }
            if seen.contains(&sig.public_key) {
                return Err(Error::AlreadySigned);
            }
            // Panics (aborting the whole invocation) if the signature is invalid.
            env.crypto()
                .ed25519_verify(&sig.public_key, &digest, &sig.signature);
            seen.push_back(sig.public_key.clone());
        }
        if seen.len() < escrow.override_threshold {
            return Err(Error::ThresholdNotMet);
        }
        // The signature override is an alternative *arbiter*, not an alternative
        // to the multi-party condition: on an escrow configured with participants
        // the sign-off must be recorded in addition to the signatures.
        Self::require_release_approvals(&env, id)?;

        escrow.override_nonce = nonce;
        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.state = EscrowState::Released;
        store_escrow(&env, id, &escrow);
        Self::transfer_all(&env, &escrow, &escrow.recipient, remaining)?;
        for a in escrow.assets.iter() {
            events::transfer_executed(&env, &escrow.sender, &escrow.recipient, &a.asset, a.amount);
        }
        events::publish(
            &env,
            ContractEvent::EscrowReleased {
                escrow_id: id,
                recipient: escrow.recipient.clone(),
                assets: escrow.assets.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("override")),
            (id, nonce),
        );
        Ok(())
    }

    /// Mark a timed-out escrow `Expired` once its deadline has passed.
    pub fn expire(env: Env, id: u64) -> Result<(), Error> {
        let mut escrow = load_escrow(&env, id)?;
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < Self::grace_end(&escrow)? {
            // The grace window is still open — the arbiter may still release, so the
            // escrow cannot be marked expired yet.
            return Err(Error::InvalidState);
        }
        escrow.state = EscrowState::Expired;
        store_escrow(&env, id, &escrow);
        env.events()
            .publish((symbol_short!("escrow"), symbol_short!("expired")), id);
        Ok(())
    }

    /// Refund remaining funds back to the sender once the escrow has timed out.
    ///
    /// Only the stored `sender` may refund. Timing uses the ledger clock:
    /// before `deadline` the call fails with [`Error::TimeLockActive`], during
    /// `[deadline, deadline + grace_period)` with [`Error::GraceActive`]; from
    /// `deadline + grace_period` onward (inclusive) the refund is permitted —
    /// the same instant at which `release` starts failing with
    /// [`Error::EscrowExpired`], so the two paths never overlap.
    pub fn refund(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        Self::reject_milestone_settlement(&env, id)?;
        if escrow.sender != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Expired) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            // Before the fulfillment deadline the escrow is still live.
            return Err(Error::TimeLockActive);
        }
        if env.ledger().timestamp() < Self::grace_end(&escrow)? {
            // During the grace window the counterparty may still fulfill, so funds
            // may not yet be reclaimed via refund. Use `reclaim` after grace expiry.
            return Err(Error::GraceActive);
        }
        Self::require_refund_window_open(&env, &escrow)?;

        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);

        if remaining > 0 {
            for a in escrow.assets.iter() {
                let return_amount =
                    checked_div(checked_mul(a.amount, remaining)?, escrow.funded_amount)?;
                if return_amount > 0 {
                    token::TokenClient::new(&env, &a.asset).transfer(
                        &env.current_contract_address(),
                        &escrow.sender,
                        &return_amount,
                    );
                }
            }
        }
        events::publish(
            &env,
            ContractEvent::EscrowRefunded {
                escrow_id: id,
                sender: escrow.sender.clone(),
                assets: escrow.assets.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("refunded")),
            (id, caller),
        );
        Ok(())
    }

    /// Refund time-locked escrow after unlock_time / deadline has elapsed.
    pub fn refund_timelock(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        Self::reject_milestone_settlement(&env, id)?;
        if escrow.sender != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(
            escrow.state,
            EscrowState::Created | EscrowState::Funded | EscrowState::Expired
        ) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < Self::grace_end(&escrow)? {
            return Err(Error::TimeLockActive);
        }
        Self::require_refund_window_open(&env, &escrow)?;

        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);

        if remaining > 0 {
            for a in escrow.assets.iter() {
                let return_amount =
                    checked_div(checked_mul(a.amount, remaining)?, escrow.funded_amount)?;
                if return_amount > 0 {
                    token::TokenClient::new(&env, &a.asset).transfer(
                        &env.current_contract_address(),
                        &escrow.sender,
                        &return_amount,
                    );
                }
            }
        }
        events::publish(
            &env,
            ContractEvent::EscrowRefunded {
                escrow_id: id,
                sender: escrow.sender.clone(),
                assets: escrow.assets.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ref_tl")),
            (id, caller),
        );
        Ok(())
    }

    /// Close a settled escrow (terminal).
    /// Cancel an escrow before its fulfillment `deadline` and return any held
    /// funds to the sender. Either the `sender` or the `arbiter` may cancel, but
    /// only while the escrow is still `Funded`/`Created` and before the deadline
    /// has been reached — this is the pre-fulfillment dispute exit.
    pub fn cancel(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        // A milestone escrow has to settle its remaining balance through the
        // milestone-aware path, which refunds only the un-disbursed remainder
        // and freezes the outstanding milestones. Routing `cancel` here keeps
        // the familiar entrypoint usable without risking a whole-balance
        // transfer after a partial payout.
        if env.storage().persistent().has(&DataKey::Milestones(id)) {
            Self::cancel_milestones_inner(&env, &caller, id)?;
            return Ok(());
        }
        let mut escrow = load_escrow(&env, id)?;
        if escrow.sender != caller && escrow.arbiter != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Created) {
            return Err(Error::InvalidState);
        }
        // Cancellation is only permitted before the fulfillment deadline.
        if env.ledger().timestamp() >= escrow.deadline {
            return Err(Error::InvalidState);
        }
        // Issue #307 — a scheduled escrow may not be cancelled past its own
        // vesting progress either: once any value has vested (or matured), a
        // refund-to-sender would bypass the time lock. Deterministic error:
        // [`Error::TimeLockActive`]. Schedule-less escrows keep the previous
        // behaviour and may be cancelled freely before the deadline.
        if !matches!(escrow.schedule.release_type, ReleaseType::None) {
            let vested = calculate_vested_amount(
                escrow.funded_amount,
                &escrow.schedule,
                env.ledger().timestamp(),
            )?;
            if vested > 0 {
                return Err(Error::TimeLockActive);
            }
        }

        // Refund only what has not already been paid out. A partial release is
        // impossible on the generic paths (they settle the whole balance), but
        // computing the remainder here keeps `cancel` honest if that changes.
        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        if remaining > 0 {
            for a in escrow.assets.iter() {
                let return_amount =
                    checked_div(checked_mul(a.amount, remaining)?, escrow.funded_amount)?;
                if return_amount > 0 {
                    token::TokenClient::new(&env, &a.asset).transfer(
                        &env.current_contract_address(),
                        &escrow.sender,
                        &return_amount,
                    );
                    events::transfer_executed(
                        &env,
                        &escrow.sender,
                        &escrow.sender,
                        &a.asset,
                        return_amount,
                    );
                }
            }
        }
        events::publish(
            &env,
            ContractEvent::EscrowRefunded {
                escrow_id: id,
                sender: escrow.sender.clone(),
                assets: escrow.assets.clone(),
            },
        );
        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("cancelled")),
            (id, caller),
        );
        Ok(())
    }

    /// Reclaim the escrowed funds to the sender after the grace period has fully
    /// elapsed without counterparty fulfillment. Only the `sender` may reclaim,
    /// and only once `now >= deadline + grace_period`. This is the post-dispute
    /// safe-settlement path that guarantees funds cannot be stranded or
    /// double-spent while a dispute is unresolved.
    pub fn reclaim(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        Self::reject_milestone_settlement(&env, id)?;
        // Only the sender may reclaim post-grace.
        if escrow.sender != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Expired) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            // Before the fulfillment deadline the escrow is still live.
            return Err(Error::TimeLockActive);
        }
        // The grace window must have fully elapsed without fulfillment.
        let grace_end = Self::grace_end(&escrow)?;
        if env.ledger().timestamp() < grace_end {
            return Err(Error::GraceActive);
        }
        Self::require_refund_window_open(&env, &escrow)?;

        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);
        Self::transfer_all(&env, &escrow, &escrow.sender, remaining)?;
        for a in escrow.assets.iter() {
            events::transfer_executed(&env, &escrow.sender, &escrow.sender, &a.asset, a.amount);
        }
        events::publish(
            &env,
            ContractEvent::EscrowRefunded {
                escrow_id: id,
                sender: escrow.sender.clone(),
                assets: escrow.assets.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("reclaimed")),
            (id, caller),
        );
        Ok(())
    }

    pub fn close(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if !matches!(escrow.state, EscrowState::Released | EscrowState::Refunded) {
            return Err(Error::InvalidState);
        }
        if caller != escrow.sender && caller != escrow.recipient && caller != escrow.arbiter {
            return Err(Error::Unauthorized);
        }
        escrow.state = EscrowState::Closed;
        store_escrow(&env, id, &escrow);
        Ok(())
    }

    /// Fund an escrow with a milestone-based progressive release schedule.
    /// `milestones` is an ordered list of basis-point-weighted milestones whose
    /// weights must sum to exactly 10_000 (100%). The arbiter approves each
    /// milestone individually via [`EscrowContract::release_milestone`]; plain
    /// `release` is blocked on milestone escrows to enforce phased settlement.
    #[allow(clippy::too_many_arguments)]
    pub fn deposit_with_milestones(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        asset: Address,
        amount: i128,
        deadline: u64,
        memo: String,
        milestones: Vec<MilestoneSpec>,
    ) -> Result<u64, Error> {
        sender.require_auth();
        require_positive_amount(amount)?;
        Self::require_token_approved(&env, &asset)?;
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        if milestones.is_empty() {
            return Err(Error::InvalidInput);
        }

        let mut total_bps: u32 = 0;
        for spec in milestones.iter() {
            total_bps = total_bps
                .checked_add(spec.release_bps)
                .ok_or(Error::Overflow)?;
        }
        if total_bps != 10_000 {
            return Err(Error::InvalidInput);
        }

        let id = increment_count(&env)?;

        token::TokenClient::new(&env, &asset).transfer(
            &sender,
            &env.current_contract_address(),
            &amount,
        );

        let mut items: Vec<Milestone> = Vec::new(&env);
        for (i, spec) in milestones.iter().enumerate() {
            items.push_back(Milestone {
                index: i as u32,
                description: spec.description.clone(),
                release_bps: spec.release_bps,
                status: MilestoneStatus::Pending,
            });
        }
        let set = MilestoneSet {
            milestones: items,
            released_amount: 0,
            cancelled: false,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Milestones(id), &set);
        bump_milestones(&env, id);

        let asset_amounts = vec![
            &env,
            AssetAmount {
                asset: asset.clone(),
                amount,
            },
        ];

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: asset_amounts,
            state: EscrowState::Funded,
            deadline,
            grace_period: 0,
            refund_window: 0,
            funded_amount: amount,
            memo,
            schedule: ReleaseSchedule::none(),
            released_amount: 0,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("milestone")),
            (id, sender, recipient, asset, amount),
        );
        Ok(id)
    }

    /// Approve and release a single milestone's proportional payout.
    ///
    /// Only the escrow's `arbiter` may approve. A milestone starts `Pending`;
    /// approval moves it to `Completed` and pays its share of the escrow to the
    /// recipient. The final milestone approved pays the dust-free remainder, so
    /// the full funded amount is always disbursed even when the basis-point
    /// weights do not divide evenly.
    ///
    /// Deterministic refusals (`MilestoneError`, which carries the canonical
    /// wire codes for the generic failures):
    /// - a non-arbiter caller gets [`MilestoneError::Unauthorized`];
    /// - an unknown index, a missing schedule, or a disputed milestone gets
    ///   [`MilestoneError::InvalidMilestone`];
    /// - a milestone that was already approved gets
    ///   [`MilestoneError::MilestoneAlreadyCompleted`];
    /// - an escrow that is no longer `Funded` gets
    ///   [`MilestoneError::InvalidState`].
    pub fn release_milestone(
        env: Env,
        caller: Address,
        id: u64,
        index: u32,
    ) -> Result<(), MilestoneError> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.arbiter != caller {
            return Err(MilestoneError::Unauthorized);
        }

        let mut set: MilestoneSet = env
            .storage()
            .persistent()
            .get(&DataKey::Milestones(id))
            .ok_or(MilestoneError::NotFound)?;
        if set.cancelled {
            return Err(MilestoneError::InvalidState);
        }

        let mut found_idx: u32 = 0;
        let mut target: Option<Milestone> = None;
        for (i, m) in set.milestones.iter().enumerate() {
            if m.index == index {
                found_idx = i as u32;
                target = Some(m.clone());
            }
        }
        // An index that is not on the schedule is an invalid milestone.
        let milestone = target.ok_or(MilestoneError::InvalidMilestone)?;
        match milestone.status {
            MilestoneStatus::Completed => return Err(MilestoneError::MilestoneAlreadyCompleted),
            // A disputed milestone cannot be approved until it is resolved.
            MilestoneStatus::Disputed => return Err(MilestoneError::InvalidMilestone),
            MilestoneStatus::Pending => {}
        }
        // Only a live escrow can disburse a milestone payout.
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(MilestoneError::InvalidState);
        }

        let total_amount = Self::total_amount(&escrow.assets);
        let mut unreleased: u32 = 0;
        for m in set.milestones.iter() {
            if m.status != MilestoneStatus::Completed {
                unreleased = unreleased.saturating_add(1);
            }
        }
        // Checked arithmetic: `gross` is a floored proportional payout, and the
        // last outstanding milestone receives the remainder, so rounding dust
        // is never stranded in the contract.
        let gross = checked_div(
            checked_mul(total_amount, milestone.release_bps as i128)?,
            10_000,
        )?;
        let remaining = checked_sub(total_amount, set.released_amount)?;
        let payout = if unreleased == 1 { remaining } else { gross };
        // A phased payout is still a payout, so this path deliberately has no
        // multi-party gate: the two creation entrypoints are mutually exclusive
        // (`deposit_with_milestones` never records a release condition, and
        // `create_with_release_condition` never installs milestones), so
        // `load_release_condition` is always empty here. If milestone creation
        // ever grows condition support, add `Self::require_release_approvals`
        // and a dedicated `MilestoneError` code in the same change.

        let primary_asset = escrow.assets.get_unchecked(0).asset.clone();
        token::TokenClient::new(&env, &primary_asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &payout,
        );
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            &primary_asset,
            payout,
        );

        set.released_amount = checked_add(set.released_amount, payout)?;
        let updated = Milestone {
            index: milestone.index,
            description: milestone.description,
            release_bps: milestone.release_bps,
            status: MilestoneStatus::Completed,
        };
        set.milestones.set(found_idx, updated);
        env.storage()
            .persistent()
            .set(&DataKey::Milestones(id), &set);
        bump_milestones(&env, id);

        let all_released = set
            .milestones
            .iter()
            .all(|m| m.status == MilestoneStatus::Completed);
        if all_released {
            escrow.released_amount = set.released_amount;
            escrow.state = EscrowState::Released;
            store_escrow(&env, id, &escrow);
        }

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ms_rel")),
            (id, caller, index, payout),
        );
        Ok(())
    }

    /// Flag a single, still-pending milestone as disputed (arbiter only).
    ///
    /// A disputed milestone is frozen: it cannot be approved (releasing its
    /// share) until the arbiter resolves it back to `Pending`, so a contested
    /// deliverable can never be paid out accidentally. Disputing an already
    /// completed milestone is refused with
    /// [`MilestoneError::MilestoneAlreadyCompleted`]; disputing an unknown
    /// index, a milestone that is already disputed, or one on a cancelled
    /// schedule is refused with [`MilestoneError::InvalidMilestone`].
    pub fn dispute_milestone(
        env: Env,
        caller: Address,
        id: u64,
        index: u32,
    ) -> Result<(), MilestoneError> {
        caller.require_auth();
        let escrow = load_escrow(&env, id)?;
        if escrow.arbiter != caller {
            return Err(MilestoneError::Unauthorized);
        }
        let mut set: MilestoneSet = env
            .storage()
            .persistent()
            .get(&DataKey::Milestones(id))
            .ok_or(MilestoneError::NotFound)?;
        if set.cancelled {
            return Err(MilestoneError::InvalidState);
        }

        let mut found_idx: u32 = 0;
        let mut target: Option<Milestone> = None;
        for (i, m) in set.milestones.iter().enumerate() {
            if m.index == index {
                found_idx = i as u32;
                target = Some(m.clone());
            }
        }
        let milestone = target.ok_or(MilestoneError::InvalidMilestone)?;
        match milestone.status {
            MilestoneStatus::Completed => return Err(MilestoneError::MilestoneAlreadyCompleted),
            MilestoneStatus::Disputed => return Err(MilestoneError::InvalidMilestone),
            MilestoneStatus::Pending => {}
        }
        // Only a live escrow can change a milestone's status.
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(MilestoneError::InvalidState);
        }
        set.milestones.set(
            found_idx,
            Milestone {
                index: milestone.index,
                description: milestone.description,
                release_bps: milestone.release_bps,
                status: MilestoneStatus::Disputed,
            },
        );
        env.storage()
            .persistent()
            .set(&DataKey::Milestones(id), &set);
        bump_milestones(&env, id);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ms_disp")),
            (id, caller, index),
        );
        Ok(())
    }

    /// Resolve a disputed milestone back to `Pending` (arbiter only) so it can
    /// be approved again. Resolving a milestone that is not disputed — either
    /// still `Pending` or already `Completed` — is a deterministic refusal
    /// ([`MilestoneError::InvalidMilestone`] /
    /// [`MilestoneError::MilestoneAlreadyCompleted`]).
    pub fn resolve_milestone(
        env: Env,
        caller: Address,
        id: u64,
        index: u32,
    ) -> Result<(), MilestoneError> {
        caller.require_auth();
        let escrow = load_escrow(&env, id)?;
        if escrow.arbiter != caller {
            return Err(MilestoneError::Unauthorized);
        }
        let mut set: MilestoneSet = env
            .storage()
            .persistent()
            .get(&DataKey::Milestones(id))
            .ok_or(MilestoneError::NotFound)?;
        if set.cancelled {
            return Err(MilestoneError::InvalidState);
        }

        let mut found_idx: u32 = 0;
        let mut target: Option<Milestone> = None;
        for (i, m) in set.milestones.iter().enumerate() {
            if m.index == index {
                found_idx = i as u32;
                target = Some(m.clone());
            }
        }
        let milestone = target.ok_or(MilestoneError::InvalidMilestone)?;
        match milestone.status {
            MilestoneStatus::Completed => return Err(MilestoneError::MilestoneAlreadyCompleted),
            MilestoneStatus::Pending => return Err(MilestoneError::InvalidMilestone),
            MilestoneStatus::Disputed => {}
        }
        // Only a live escrow can change a milestone's status.
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(MilestoneError::InvalidState);
        }
        set.milestones.set(
            found_idx,
            Milestone {
                index: milestone.index,
                description: milestone.description,
                release_bps: milestone.release_bps,
                status: MilestoneStatus::Pending,
            },
        );
        env.storage()
            .persistent()
            .set(&DataKey::Milestones(id), &set);
        bump_milestones(&env, id);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ms_res")),
            (id, caller, index),
        );
        Ok(())
    }

    /// Cancel the remaining unreleased milestones and refund that portion to
    /// the sender.
    ///
    /// This is the milestone-aware exit: milestones already approved keep their
    /// payouts, while every still-`Pending` or `Disputed` milestone is frozen
    /// and the funds it would have unlocked are returned to the sender. Either
    /// party (sender or arbiter) may call it while the escrow is `Funded` (or
    /// `Expired`), mirroring [`Self::cancel`]. The generic whole-balance
    /// settlement paths are refused for milestone escrows so a partial payout
    /// can never be double-spent.
    ///
    /// Returns the amount refunded this call.
    pub fn cancel_remaining_milestones(env: Env, caller: Address, id: u64) -> Result<i128, Error> {
        caller.require_auth();
        Self::cancel_milestones_inner(&env, &caller, id)
    }

    /// Shared implementation behind [`Self::cancel_remaining_milestones`] and
    /// the milestone branch of [`Self::cancel`]. The caller's authorization is
    /// established once by the entrypoint; this helper only does the state
    /// transition and the refund, so a routed `cancel` never requires the same
    /// address to authorize twice.
    fn cancel_milestones_inner(env: &Env, caller: &Address, id: u64) -> Result<i128, Error> {
        let mut escrow = load_escrow(env, id)?;
        if escrow.sender != *caller && escrow.arbiter != *caller {
            return Err(Error::Unauthorized);
        }

        let mut set: MilestoneSet = env
            .storage()
            .persistent()
            .get(&DataKey::Milestones(id))
            .ok_or(Error::NotFound)?;
        // Check the idempotency guard before the state guard so a second
        // cancellation reports the precise reason rather than a generic state
        // refusal.
        if set.cancelled {
            return Err(Error::AlreadyExists);
        }
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Expired) {
            return Err(Error::InvalidState);
        }

        // Only the un-disbursed remainder is refundable; payouts already made
        // to the recipient are final.
        let remaining = checked_sub(escrow.funded_amount, set.released_amount)?;
        set.cancelled = true;
        let mut updated: Vec<Milestone> = Vec::new(env);
        for m in set.milestones.iter() {
            let mut m = m.clone();
            if m.status == MilestoneStatus::Pending {
                m.status = MilestoneStatus::Disputed;
            }
            updated.push_back(m);
        }
        set.milestones = updated;
        env.storage()
            .persistent()
            .set(&DataKey::Milestones(id), &set);
        bump_milestones(env, id);

        if remaining > 0 {
            for a in escrow.assets.iter() {
                let return_amount =
                    checked_div(checked_mul(a.amount, remaining)?, escrow.funded_amount)?;
                if return_amount > 0 {
                    token::TokenClient::new(env, &a.asset).transfer(
                        &env.current_contract_address(),
                        &escrow.sender,
                        &return_amount,
                    );
                    events::transfer_executed(
                        env,
                        &escrow.sender,
                        &escrow.sender,
                        &a.asset,
                        return_amount,
                    );
                }
            }
        }
        escrow.state = EscrowState::Refunded;
        store_escrow(env, id, &escrow);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ms_can")),
            (id, caller.clone(), remaining),
        );
        Ok(remaining)
    }

    /// Read the milestone state for an escrow.
    pub fn milestones(env: Env, id: u64) -> Result<MilestoneSet, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Milestones(id))
            .ok_or(Error::NotFound)
    }

    // --- views ---

    pub fn get(env: Env, id: u64) -> Result<Escrow, Error> {
        load_escrow(&env, id)
    }

    pub fn get_schedule(env: Env, id: u64) -> Result<ReleaseSchedule, Error> {
        let escrow = load_escrow(&env, id)?;
        Ok(escrow.schedule)
    }

    /// Move `remaining` out of the contract's custody to `to`, pro-rata
    /// across the listed assets. Callers compute `remaining` as funded minus
    /// already released *before* mutating the escrow record, so a settlement
    /// that follows partial `withdraw` / `claim` payouts moves exactly what
    /// is still held instead of over-drawing custody (Issue #307).
    fn transfer_all(
        env: &Env,
        escrow: &Escrow,
        to: &Address,
        remaining: i128,
    ) -> Result<(), Error> {
        if remaining == 0 {
            return Ok(());
        }
        for a in escrow.assets.iter() {
            let send_amount = checked_div(checked_mul(a.amount, remaining)?, escrow.funded_amount)?;
            if send_amount > 0 {
                token::TokenClient::new(env, &a.asset).transfer(
                    &env.current_contract_address(),
                    to,
                    &send_amount,
                );
            }
        }
        Ok(())
    }

    /// Sum the amounts across every listed asset (single-asset milestone
    /// escrows simply return that asset's amount).
    fn total_amount(assets: &Vec<AssetAmount>) -> i128 {
        let mut total: i128 = 0;
        for a in assets.iter() {
            total += a.amount;
        }
        total
    }

    /// Refuse a generic whole-balance settlement path on a milestone escrow.
    ///
    /// Milestone escrows settle only through [`Self::release_milestone`]
    /// (per-milestone payout) and [`Self::cancel_remaining_milestones`] (refund
    /// of the unreleased remainder). Every generic path transfers whole asset
    /// amounts, which would double-pay milestones already released, so all of
    /// them are refused with [`Error::InvalidState`].
    fn reject_milestone_settlement(env: &Env, id: u64) -> Result<(), Error> {
        if env.storage().persistent().has(&DataKey::Milestones(id)) {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    /// Timestamp the refund window closes at (`0` = never). Refunds open at
    /// `deadline + grace_period`, so the window is measured from there.
    /// `saturating_add` keeps an absurd `refund_window` from wrapping around
    /// into an already-closed window.
    fn closes_at(escrow: &Escrow) -> u64 {
        if escrow.refund_window == 0 {
            return 0;
        }
        escrow
            .deadline
            .saturating_add(escrow.grace_period)
            .saturating_add(escrow.refund_window)
    }

    /// The instant the grace period ends, i.e. when the escrow becomes
    /// fulfillable / refundable.
    ///
    /// `grace_period` is caller-supplied and unbounded, so the sum is computed
    /// through the checked helper: with `overflow-checks` on even in release, a
    /// raw `deadline + grace_period` would abort the invocation (and silently
    /// wrap in Wasm) instead of reporting [`Error::Overflow`].
    fn grace_end(escrow: &Escrow) -> Result<u64, Error> {
        Ok(checked_add(escrow.deadline as i128, escrow.grace_period as i128)? as u64)
    }

    /// Refuse a reclaim once a bounded refund window has elapsed, so an
    /// un-refunded, timed-out escrow can be treated as final. An unbounded
    /// window (`refund_window == 0`) never closes.
    fn require_refund_window_open(env: &Env, escrow: &Escrow) -> Result<(), Error> {
        let closes_at = Self::closes_at(escrow);
        if closes_at != 0 && env.ledger().timestamp() >= closes_at {
            return Err(Error::EscrowExpired);
        }
        Ok(())
    }

    /// Validate a multi-asset list: non-empty, within the size cap, every
    /// amount strictly positive, no asset listed more than once, and every
    /// asset approved for escrow.
    ///
    /// The whitelist check lives here, ahead of the shape checks, so that every
    /// creation path — [`Self::create`], [`Self::create_timelock`],
    /// [`Self::create_scheduled`] and [`Self::initialize_timelock`] — is gated
    /// by construction rather than by remembering to call the check. A token
    /// that is not approved is refused before the list is even inspected,
    /// because the question of whether the caller may use that token at all
    /// precedes the question of whether the amounts are well formed.
    fn validate_assets(env: &Env, assets: &Vec<AssetAmount>) -> Result<(), Error> {
        Self::require_tokens_approved(env, assets)?;
        if assets.is_empty() || assets.len() > MAX_ESCROW_ASSETS {
            return Err(Error::InvalidInput);
        }
        for i in 0..assets.len() {
            let a = assets.get_unchecked(i);
            require_positive_amount(a.amount)?;
            for j in (i + 1)..assets.len() {
                if assets.get_unchecked(j).asset == a.asset {
                    return Err(Error::InvalidInput);
                }
            }
        }
        Ok(())
    }

    /// Refuse any listed token the admin has not approved. An empty whitelist
    /// approves nothing, so a freshly initialized contract escrows no token
    /// until an admin acts.
    fn require_tokens_approved(env: &Env, assets: &Vec<AssetAmount>) -> Result<(), Error> {
        for a in assets.iter() {
            Self::require_token_approved(env, &a.asset)?;
        }
        Ok(())
    }

    /// Refuse a single token that is not approved for escrow.
    fn require_token_approved(env: &Env, token: &Address) -> Result<(), Error> {
        if Self::is_token_approved_internal(env, token) {
            Ok(())
        } else {
            Err(Error::AssetNotAuthorized)
        }
    }

    fn is_token_approved_internal(env: &Env, token: &Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ApprovedToken(token.clone()))
            .unwrap_or(false)
    }

    fn approved_token_list(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::ApprovedTokenList)
            .unwrap_or_else(|| Vec::new(env))
    }

    fn store_approved_token_list(env: &Env, list: &Vec<Address>) {
        env.storage()
            .instance()
            .set(&DataKey::ApprovedTokenList, list);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    fn load_admin(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Gate a whitelist change on the recorded admin's signature. The identity
    /// check precedes `require_auth` so a call from a non-admin is refused
    /// without recording an authorization it could never use.
    fn require_admin(env: &Env, caller: &Address) -> Result<Address, Error> {
        let admin = Self::load_admin(env)?;
        if admin != *caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        Ok(admin)
    }

    fn emit_token_change(env: &Env, token: &Address, action: Symbol) {
        env.events()
            .publish((symbol_short!("escrow"), action), token.clone());
    }

    /// Validate a participant set and its threshold, mirroring
    /// [`Self::validate_override_config`]: either both empty/zero (no condition
    /// recorded), or a non-empty, size-capped, duplicate-free participant set with
    /// a threshold in `[1, participants.len()]`.
    fn validate_release_condition(
        participants: &Vec<Address>,
        threshold: u32,
    ) -> Result<(), Error> {
        if participants.is_empty() {
            if threshold != 0 {
                return Err(Error::InvalidThreshold);
            }
            return Ok(());
        }
        if participants.len() > MAX_SIGNERS {
            return Err(Error::TooManySigners);
        }
        if threshold == 0 || threshold > participants.len() {
            return Err(Error::InvalidThreshold);
        }
        for i in 0..participants.len() {
            let p = participants.get_unchecked(i);
            for j in (i + 1)..participants.len() {
                if participants.get_unchecked(j) == p {
                    return Err(Error::InvalidInput);
                }
            }
        }
        Ok(())
    }

    /// Refuse recipient settlement until the escrow's configured number of
    /// distinct participants has authorized the release. Escrows without a
    /// condition carry no such key, so they settle exactly as before.
    ///
    /// Every caller invokes this as its *last* check, immediately before the
    /// first state mutation or token transfer. The condition can therefore only
    /// ever prevent a payout that would otherwise have gone through — it never
    /// masks a more specific pre-existing error (an expired deadline, a time
    /// lock, a double release), and a failing call touches no extra storage.
    fn require_release_approvals(env: &Env, id: u64) -> Result<(), Error> {
        if let Some(condition) = load_release_condition(env, id) {
            if condition.approvals < condition.threshold {
                return Err(Error::ThresholdNotMet);
            }
        }
        Ok(())
    }

    /// Validate an override signer set + threshold: either both empty/zero
    /// (override disabled), or a non-empty, size-capped, duplicate-free signer
    /// set with a threshold in `[1, signers.len()]`.
    fn validate_override_config(signers: &Vec<BytesN<32>>, threshold: u32) -> Result<(), Error> {
        if signers.is_empty() {
            if threshold != 0 {
                return Err(Error::InvalidThreshold);
            }
            return Ok(());
        }
        if signers.len() > MAX_SIGNERS {
            return Err(Error::TooManySigners);
        }
        if threshold == 0 || threshold > signers.len() {
            return Err(Error::InvalidThreshold);
        }
        for i in 0..signers.len() {
            let s = signers.get_unchecked(i);
            for j in (i + 1)..signers.len() {
                if signers.get_unchecked(j) == s {
                    return Err(Error::InvalidInput);
                }
            }
        }
        Ok(())
    }

    /// Build the deterministic payload signed by override signers: the
    /// contract address, the network id (derived from the network
    /// passphrase), the escrow id and the nonce. Binding the contract address
    /// and network id prevents a signature from one deployment/network being
    /// replayed on another; binding the escrow id prevents cross-escrow
    /// replay; the strictly-increasing nonce prevents same-escrow replay.
    pub(crate) fn override_payload(env: &Env, id: u64, nonce: u64) -> Bytes {
        let mut payload = env.current_contract_address().to_xdr(env);
        payload.append(&Bytes::from_array(
            env,
            &env.ledger().network_id().to_array(),
        ));
        payload.append(&Bytes::from_array(env, &id.to_be_bytes()));
        payload.append(&Bytes::from_array(env, &nonce.to_be_bytes()));
        payload
    }
}

// ---------------------------------------------------------------------------
// Escrow lifecycle reads, exposed through the shared `EscrowInterface`
// (Issue #293).
//
// These views are the escrow crate's part of the workspace-wide read surface:
// they answer with primitives only, so a wallet, a budget or an off-chain
// monitor can drive them through the one generated `EscrowClient` without
// depending on this crate's record types.
// ---------------------------------------------------------------------------
#[contractimpl]
impl EscrowInterface for EscrowContract {
    /// Number of escrows created so far, i.e. the id the next `create` takes.
    fn escrow_count(env: Env) -> u64 {
        get_count(&env)
    }

    /// Timestamp at which the escrow's refund window closes, or `0` when the
    /// window has no upper bound. Lets clients show a countdown without
    /// recomputing the window rule off-chain.
    fn refund_window_closes_at(env: Env, id: u64) -> Result<u64, Error> {
        Ok(Self::closes_at(&load_escrow(&env, id)?))
    }

    /// Whether the funds may be reclaimed for `id` at the current ledger time —
    /// the escrow still holds them, the grace period has elapsed, and the refund
    /// window has not closed.
    fn is_refundable(env: Env, id: u64) -> Result<bool, Error> {
        let escrow = load_escrow(&env, id)?;
        if !matches!(
            escrow.state,
            EscrowState::Created | EscrowState::Funded | EscrowState::Expired
        ) {
            return Ok(false);
        }
        let now = env.ledger().timestamp();
        if now < Self::grace_end(&escrow)? {
            return Ok(false);
        }
        Ok(Self::require_refund_window_open(&env, &escrow).is_ok())
    }

    /// Amount claimable right now under the escrow's release schedule.
    fn get_claimable_amount(env: Env, id: u64) -> Result<i128, Error> {
        let escrow = load_escrow(&env, id)?;
        calculate_claimable_amount(&escrow, env.ledger().timestamp())
    }

    /// Amount vested so far under the escrow's release schedule.
    fn get_vested_amount(env: Env, id: u64) -> Result<i128, Error> {
        let escrow = load_escrow(&env, id)?;
        calculate_vested_amount(
            escrow.funded_amount,
            &escrow.schedule,
            env.ledger().timestamp(),
        )
    }

    /// Whether the escrow's release schedule has matured at the current ledger
    /// timestamp: `true` for schedule-less escrows once they exist, `true` for
    /// a `Cliff` schedule at/after `cliff_time`, and `true` for a `Linear`
    /// schedule once anything has vested. Clients use this to show an unlock
    /// countdown without recomputing the schedule off-chain.
    fn is_unlocked(env: Env, id: u64) -> Result<bool, Error> {
        let escrow = load_escrow(&env, id)?;
        Ok(matches!(escrow.schedule.release_type, ReleaseType::None)
            || calculate_vested_amount(
                escrow.funded_amount,
                &escrow.schedule,
                env.ledger().timestamp(),
            )? > 0)
    }
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for EscrowContract {
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
    /// `wasm_hash` must be approved for `ModuleKind::Escrow` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Escrow,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
