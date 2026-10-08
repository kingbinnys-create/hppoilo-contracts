//! Storage keys and data structures for the multisig contract.
//!
//! Everything that is written to (or read from) contract storage lives here so
//! the on-chain layout has a single home: the instance/persistent [`DataKey`]
//! variants and the `#[contracttype]` records that are stored under them,
//! including the weighted signer set ([`SignerWeight`]) and the pending
//! governance/threshold state. The contract logic in `lib.rs` re-exports these
//! items, so their public paths are unchanged.

use soroban_sdk::{contracttype, Address, Bytes, Symbol, Val, Vec};

#[contracttype]
#[derive(Clone)]
pub(crate) enum DataKey {
    /// Config: current weighted signer set (instance).
    Signers,
    /// Config: current approval weight threshold (instance).
    Threshold,
    /// State: global emergency lock flag (instance).
    EmergencyLock,
    /// State: monotonic proposal id counter (instance).
    ProposalCount,
    /// State: proposal record by id (persistent).
    Proposal(u64),
    /// Relationship: whether a signer approved a proposal (persistent).
    Approval(u64, Address),
    /// State: last used batch nonce (instance); batches must use a greater one.
    LastBatchNonce,
    /// Config: timelock delay applied to governance changes (instance, seconds).
    TimelockDelay,
    /// State: monotonic governance-change id counter (instance).
    ChangeCount,
    /// State: pending governance change by id (persistent).
    Change(u64),
    /// Pending threshold change awaiting finalization.
    PendingThreshold,
}

/// A registered signer and its positive voting weight.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerWeight {
    pub address: Address,
    pub weight: u32,
}

/// A pending threshold change that must wait a delay before finalization.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingThresholdChange {
    pub new_threshold: u32,
    /// Ledger sequence when the change was submitted.
    pub effective_from: u32,
}

/// Internal multisig proposal. `action`/`payload` describe the intended change
/// or call; the multisig only records weighted approvals and marks it executed
/// once the accumulated weight meets the threshold. Actual value movement is
/// delegated to the calling context (e.g. the Treasury) which checks
/// `is_executed`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsProposal {
    pub proposer: Address,
    /// A short action tag, e.g. `payment`, `config`.
    pub action: Symbol,
    /// Opaque payload (e.g. serialized transfer intent / hash).
    pub payload: Bytes,
    /// Accumulated approval weight (sum of approver weights).
    pub approval_weight: u32,
    pub executed: bool,
    /// Earliest timestamp at which execution is allowed (time lock; 0 = none).
    pub unlock_at: u64,
}

/// A governance modification awaiting the timelock. Each variant carries the
/// exact post-state it will apply, so what was proposed is what executes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GovernanceChange {
    /// Set the approval weight threshold to the given value.
    Threshold(u32),
    /// Set an existing signer's voting weight.
    SignerWeight(Address, u32),
    /// Admit a new signer with the given positive weight.
    AddSigner(Address, u32),
    /// Drop an existing signer.
    RemoveSigner(Address),
    /// Change the timelock delay applied to future governance proposals.
    TimelockDelay(u64),
}

/// A proposed governance change parked behind the timelock.
///
/// `eta` is fixed at proposal time and is the earliest timestamp at which
/// [`crate::MultiSigContract::execute_threshold_change`] will apply the change;
/// `expires_at` bounds how long the matured change stays executable.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingChange {
    /// Signer that raised the change.
    pub proposer: Address,
    /// The modification that will be applied on execution.
    pub change: GovernanceChange,
    /// Ledger timestamp at which the change was proposed.
    pub proposed_at: u64,
    /// Earliest timestamp at which execution is permitted.
    pub eta: u64,
    /// Timestamp at (and after) which the change can no longer be executed.
    pub expires_at: u64,
    pub executed: bool,
    pub cancelled: bool,
}

/// A single discrete contract call inside a batch. `args` are raw Soroban
/// values, so any contract function can be targeted.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchCall {
    /// Contract to invoke.
    pub contract: Address,
    /// Function to invoke on the target contract.
    pub func: Symbol,
    /// Arguments passed to the target function.
    pub args: Vec<Val>,
}
