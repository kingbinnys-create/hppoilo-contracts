use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use astroid_shared::types::AssetAmount;
use soroban_sdk::{contracttype, Address, BytesN, Env, String, Vec};

/// Release type for time-locked escrow schedules.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseType {
    /// Standard escrow without automated schedule.
    None = 0,
    /// 100% unlocked at cliff_time / end_time (bullet release).
    Cliff = 1,
    /// Linearly unlocked between start_time and end_time (with optional cliff).
    Linear = 2,
}

/// Release schedule configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSchedule {
    pub release_type: ReleaseType,
    pub start_time: u64,
    pub cliff_time: u64,
    pub end_time: u64,
}

impl ReleaseSchedule {
    pub fn none() -> Self {
        Self {
            release_type: ReleaseType::None,
            start_time: 0,
            cliff_time: 0,
            end_time: 0,
        }
    }
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EscrowState {
    Created = 0,
    Funded = 1,
    Released = 2,
    Refunded = 3,
    Expired = 4,
    Closed = 5,
}

/// Lifecycle status of a single milestone within a milestone-based escrow.
///
/// A milestone starts `Pending`; the arbiter moves it to `Completed` by
/// approving it (which disburses its share), or to `Disputed` if the
/// deliverable is contested. A `Disputed` milestone cannot be approved until
/// the arbiter resolves it back to `Pending`; a `Completed` milestone is
/// terminal.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MilestoneStatus {
    /// Awaiting reviewer approval; the milestone's share is still in custody.
    Pending = 0,
    /// Approved by the arbiter and paid out; terminal.
    Completed = 1,
    /// Contested, so it can no longer be approved until resolved.
    Disputed = 2,
}

/// A single milestone within a milestone-based escrow. `release_bps` is the
/// proportion of the total escrow amount (in basis points, 10_000 = 100%) that
/// is disbursed to the recipient when this milestone is approved.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Milestone {
    pub index: u32,
    pub description: String,
    pub release_bps: u32,
    pub status: MilestoneStatus,
}

/// Input describing a milestone when the escrow is created.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneSpec {
    pub description: String,
    pub release_bps: u32,
}

/// Aggregate milestone state for an escrow: the ordered milestones, how much
/// of the escrow has been disbursed so far, and whether the sender cancelled
/// the remaining unreleased milestones.
///
/// `released_amount` is the cumulative payout. Once every milestone is
/// completed it equals the funded amount — the final approval pays the
/// dust-free remainder so checked per-milestone division can never leak funds.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneSet {
    pub milestones: Vec<Milestone>,
    pub released_amount: i128,
    pub cancelled: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escrow {
    pub sender: Address,
    pub recipient: Address,
    pub arbiter: Address,
    pub assets: Vec<AssetAmount>,
    pub state: EscrowState,
    pub deadline: u64,
    /// Extra time after `deadline` during which the arbiter may still release
    /// and before the sender may reclaim. 0 means no grace beyond the deadline.
    pub grace_period: u64,
    /// How long the sender may reclaim the funds once refunds open at
    /// `deadline + grace_period`. `0` leaves the window open forever; a bounded
    /// window lets settlement logic treat an un-refunded, timed-out escrow as
    /// final.
    pub refund_window: u64,
    pub funded_amount: i128,
    pub memo: String,
    pub schedule: ReleaseSchedule,
    pub released_amount: i128,
    pub override_signers: Vec<BytesN<32>>,
    pub override_threshold: u32,
    pub override_nonce: u64,
}

/// Multi-party release condition attached to an escrow: the parties that may
/// sign off on paying the recipient, how many of them must do so, and how many
/// have.
///
/// Stored under its own key rather than inside [`Escrow`] so that escrows
/// without a condition neither pay for the extra fields on every read/write
/// nor break deserialization of escrows written by an earlier deployment.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseCondition {
    /// Allow-list of counterparties permitted to approve a release.
    pub participants: Vec<Address>,
    /// How many distinct participants must approve before funds may move to
    /// the recipient. Always in `[1, participants.len()]` for a stored
    /// condition.
    pub threshold: u32,
    /// Running count of distinct participants that have approved so far.
    pub approvals: u32,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Count,
    Escrow(u64),
    Milestones(u64),
    /// The address allowed to manage the token whitelist, recorded at
    /// `initialize` (instance). The escrow has no per-org roles, so token
    /// governance sits with this single address.
    Admin,
    /// Token whitelist membership: token contract address -> approved
    /// (persistent). Keeping the flag on its own key makes a deposit check a
    /// single read regardless of how many tokens are approved.
    ApprovedToken(Address),
    /// Enumerable list of approved tokens, in approval order (instance).
    ApprovedTokenList,
    /// Multi-party release condition attached to an escrow: the parties that
    /// may sign off on paying the recipient and how many must do so.
    ReleaseCondition(u64),
    /// One key per approving participant, so recording an approval writes a
    /// single entry instead of rewriting the whole condition.
    ReleaseApproval(u64, Address),
}

pub fn get_count(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::Count).unwrap_or(0)
}

pub fn increment_count(env: &Env) -> Result<u64, Error> {
    let count = get_count(env);
    let next = checked_add(count as i128, 1)? as u64;
    env.storage().instance().set(&DataKey::Count, &next);
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    Ok(next)
}

pub fn load_escrow(env: &Env, id: u64) -> Result<Escrow, Error> {
    env.storage()
        .persistent()
        .get(&DataKey::Escrow(id))
        .ok_or(Error::NotFound)
}

pub fn store_escrow(env: &Env, id: u64, escrow: &Escrow) {
    env.storage().persistent().set(&DataKey::Escrow(id), escrow);
    bump_escrow(env, id);
}

pub fn bump_escrow(env: &Env, id: u64) {
    env.storage().persistent().extend_ttl(
        &DataKey::Escrow(id),
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}

/// Extend the TTL of an escrow's milestone schedule. Called after every write
/// to `DataKey::Milestones(id)` so a long-running phased agreement does not see
/// its schedule archived between approvals (which would strand the remaining
/// funds).
pub fn bump_milestones(env: &Env, id: u64) {
    env.storage().persistent().extend_ttl(
        &DataKey::Milestones(id),
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}

pub fn load_release_condition(env: &Env, id: u64) -> Option<ReleaseCondition> {
    env.storage()
        .persistent()
        .get(&DataKey::ReleaseCondition(id))
}

pub fn store_release_condition(env: &Env, id: u64, condition: &ReleaseCondition) {
    let key = DataKey::ReleaseCondition(id);
    env.storage().persistent().set(&key, condition);
    env.storage().persistent().extend_ttl(
        &key,
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}

/// Whether `who` has already approved release of escrow `id`. False for
/// escrows that carry no release condition.
pub fn has_release_approval(env: &Env, id: u64, who: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::ReleaseApproval(id, who.clone()))
        .unwrap_or(false)
}

/// Record `who`'s approval of release of escrow `id`.
pub fn mark_release_approval(env: &Env, id: u64, who: &Address) {
    let key = DataKey::ReleaseApproval(id, who.clone());
    env.storage().persistent().set(&key, &true);
    env.storage().persistent().extend_ttl(
        &key,
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}
