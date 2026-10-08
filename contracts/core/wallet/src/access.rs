//! Role-based access control for wallet actions.
//!
//! Wallet actions used to be gated on a single "is the caller the owner?"
//! check, which cannot express the operational hierarchies Astroid runs on: an
//! organization owner, the human managers acting on its behalf, the autonomous
//! agents executing routine spends, and read-only auditors are all distinct
//! principals with distinct powers over the same wallet.
//!
//! This module stores an explicit role per `(wallet, account)` pair and exposes
//! the guards the contract entrypoints use. Roles are **totally ordered by
//! privilege** ([`Role::rank`]), so a guard asks for the *minimum* role an
//! action needs and any strictly more privileged role also satisfies it:
//!
//! ```text
//! Admin (2)  ─ full control: withdrawals, lifecycle, role administration
//! Agent (1)  ─ routine operational spends (transfers), subject to wallet state
//! Auditor(0) ─ read-only; never satisfies a guard on a mutating entrypoint
//! ```
//!
//! The wallet's `owner` is implicitly [`Role::Admin`] and cannot be demoted, so
//! a wallet can never be locked out of its own administration by a bad grant.

use astroid_shared::constants::{PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD};
use astroid_shared::errors::Error;
use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol};

/// A principal's role on a specific wallet.
///
/// Discriminants are part of the public ABI and MUST NOT be reordered or
/// reused once released.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Read-only observer. Satisfies no guard on a mutating entrypoint.
    Auditor = 0,
    /// Autonomous executor. May move value out of an active wallet, but may
    /// not withdraw to the owner, change lifecycle state or administer roles.
    Agent = 1,
    /// Full control, equivalent to the wallet owner.
    Admin = 2,
}

impl Role {
    /// Privilege rank. A granted role satisfies a required role when its rank
    /// is greater than or equal to the required rank.
    pub fn rank(self) -> u32 {
        match self {
            Role::Auditor => 0,
            Role::Agent => 1,
            Role::Admin => 2,
        }
    }

    /// Whether holding `self` is enough to perform an action requiring
    /// `required`.
    pub fn satisfies(self, required: Role) -> bool {
        self.rank() >= required.rank()
    }

    /// Stable short symbol for this role, used in event payloads so an indexer
    /// reads a name rather than a bare discriminant. Kept in lockstep with the
    /// discriminants above.
    pub fn as_symbol(self) -> Symbol {
        match self {
            Role::Auditor => symbol_short!("auditor"),
            Role::Agent => symbol_short!("agent"),
            Role::Admin => symbol_short!("admin"),
        }
    }
}

/// Storage keys owned by this module. Kept separate from the contract's own
/// `DataKey` so role records can never collide with wallet or balance entries.
#[contracttype]
#[derive(Clone)]
enum AccessKey {
    /// Granted role: (wallet id, account) -> Role.
    Role(u64, Address),
}

/// Read the role explicitly granted to `account` on a wallet, if any. The
/// wallet owner is deliberately not synthesized here — see [`effective_role`].
pub fn granted_role(env: &Env, wallet_id: u64, account: &Address) -> Option<Role> {
    env.storage()
        .persistent()
        .get(&AccessKey::Role(wallet_id, account.clone()))
}

/// Resolve the role `account` effectively holds on a wallet, treating the
/// wallet `owner` as an implicit [`Role::Admin`].
pub fn effective_role(
    env: &Env,
    wallet_id: u64,
    owner: &Address,
    account: &Address,
) -> Option<Role> {
    if owner == account {
        return Some(Role::Admin);
    }
    granted_role(env, wallet_id, account)
}

/// Guard: require that `caller` holds at least `required` on the wallet.
///
/// Returns [`Error::Unauthorized`] when the caller holds no role at all or a
/// role below `required`. Callers are expected to have already authenticated
/// the address (`require_auth`); this guard answers authorization only.
pub fn require_role(
    env: &Env,
    wallet_id: u64,
    owner: &Address,
    caller: &Address,
    required: Role,
) -> Result<(), Error> {
    match effective_role(env, wallet_id, owner, caller) {
        Some(role) if role.satisfies(required) => Ok(()),
        _ => Err(Error::Unauthorized),
    }
}

/// Record a role grant, replacing any role the account already held.
pub fn set_role(env: &Env, wallet_id: u64, account: &Address, role: Role) {
    let key = AccessKey::Role(wallet_id, account.clone());
    env.storage().persistent().set(&key, &role);
    env.storage().persistent().extend_ttl(
        &key,
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}

/// Remove a role grant. Returns [`Error::NotFound`] when nothing was granted,
/// so revoking is not silently a no-op.
pub fn clear_role(env: &Env, wallet_id: u64, account: &Address) -> Result<(), Error> {
    let key = AccessKey::Role(wallet_id, account.clone());
    if !env.storage().persistent().has(&key) {
        return Err(Error::NotFound);
    }
    env.storage().persistent().remove(&key);
    Ok(())
}
