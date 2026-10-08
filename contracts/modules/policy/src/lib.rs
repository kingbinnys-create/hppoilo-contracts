#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Policy Contract
//!
//! Verifies that a proposed transfer complies with the ACTIVE policy
//! configuration (PRD Doc 7 §Policy). The Astroid backend owns the human-facing
//! policy graph; this contract stores only a cryptographic hash of the active
//! configuration and a small set of scalar gates so on-chain verification is
//! cheap, fast and tamper-evident (PRD "Policy Hash Verification" enhancement).
//!
//! ```text
//! off-chain policy.json → hash → store on-chain
//! transaction → recompute hash of ACTIVE config → compare → allow / deny
//! ```
//!
//! This contract answers: "may `amount` of `asset` flow to `recipient`
//! right now?" with a deterministic [`Error`] when it may not.
//!
//! Functions: `initialize`, `register_policy`, `rotate_policy`, `set_allowance`,
//! `set_recurring_allowance`, `get_allowance`, `check_allowance`,
//! `update_allowance`, `set_transfer_window`, `get_transfer_window`,
//! `check_transfer`, `check_multi_asset_transfer`,
//! `record_multi_asset_spend`.
//!
//! ## Multi-token allowances
//!
//! A policy can attach a per-asset spending allowance to any policy. Each
//! Stellar asset type (native XLM or a Soroban SAC token) is tracked under its
//! own `(policy_id, asset)` key, so evaluation is safe against overflow and
//! cheap (single persistent read/write).
//!
//! ## Recurring (rate-limited) allowances
//!
//! An allowance configured with `window_seconds > 0` (see
//! `set_recurring_allowance`) is a rate limit: at most `limit` may be spent
//! per fixed window of `window_seconds`. Windows are anchored at
//! `window_start` (the ledger time the window was configured) and the period
//! containing `now` is
//!
//! ```text
//! k      = (now - window_start) / window_seconds      (integer division)
//! period = [window_start + k*window_seconds, window_start + (k+1)*window_seconds)
//! ```
//!
//! so a request at exactly `window_start + window_seconds` belongs to the
//! NEW period. Transitions are settled lazily on every read and spend: when
//! `k >= 1`, `spent` resets to zero and `window_start` re-anchors to the
//! boundary (not to `now`), so windows never drift and an allowance left idle
//! for many periods settles every missed reset at once. Time always comes
//! from `env.ledger().timestamp()`; no caller-supplied time is accepted.
//! `window_seconds == 0` keeps the allowance cumulative (one-shot).
//!
//! ## Multi-asset spending requests
//!
//! `check_multi_asset_transfer` and `record_multi_asset_spend` evaluate one
//! request that moves several assets to a single recipient. Entries for the
//! same asset are summed (checked) before any gate runs, so an over-limit
//! spend cannot be split into several under-limit entries. Each asset is then
//! evaluated against its own gates and allowance only; raw amounts of
//! different assets are never compared or summed, since their decimals
//! differ. Evaluation is all-or-nothing: every asset is validated before any
//! spend is recorded.
//!
//! ## Transfer time windows
//!
//! Autonomous agents are only meant to operate during approved hours, so a
//! policy can be narrowed to a daily operating window in ledger time. The
//! window is configured by the policy owner with `set_transfer_window` as a
//! time-of-day `start_time` and `end_time` (both seconds since midnight UTC)
//! plus the length of the day they repeat over (`window_days`). Both bounds
//! default to `0`, which leaves the gate off and every policy created before
//! this feature keeps its behaviour.
//!
//! `check_transfer` reads the current time from `env.ledger().timestamp()` —
//! no caller-supplied time is ever trusted — and denies a transaction with
//! [`Error::PolicyDenied`] (and an `outside_window` violation event) when the
//! time of day falls outside `[start_time, end_time)`. The bounds are inclusive
//! at the start and exclusive at the end, so a midnight-crossing window such as
//! `22:00 → 06:00` wraps over the day boundary and an `end_time` exactly equal
//! to `start_time` degenerates to "no time is allowed" rather than "all day".
//!
//! ## Asset deny list
//!
//! Agents source their token lists off-chain, so a policy also owns an on-chain
//! asset deny list keyed by `(policy_id, asset)` and managed by the policy owner
//! through `add_asset_blacklist` / `remove_asset_blacklist`. `check_transfer`
//! probes it once and denies a listed asset with [`Error::PolicyDenied`] and an
//! `asset_blacklisted` violation reason. The deny list is evaluated after the
//! allow gates and wins over them, so blacklisting an allow-listed or
//! whitelisted asset takes effect immediately.
//!
//! A dedicated `AssetBlacklisted` error code would read better here, but
//! [`Error`] already carries the 50 cases a Soroban error enum may declare, so
//! the deny list reuses [`Error::PolicyDenied`] and is distinguished by its
//! violation event reason.
//!
//! ## Multi-rule composition
//!
//! On top of the single composite tree set through `set_composite_rule`, a
//! policy can stack up to [`MAX_POLICY_RULES`] independent rule trees with
//! `add_policy_rule`. The stack is evaluated on every `check_transfer` and the
//! rules are combined conjunctively: **all** registered rules must pass. The
//! iteration short-circuits — the first rule that evaluates to `false` aborts
//! the loop immediately (gas-efficient) and the transfer is denied with
//! [`Error::PolicyDenied`]. `remove_policy_rule` / `clear_policy_rules` shrink
//! the stack again, so the governance team can retire a rule without touching
//! the remaining ones.
//!
//! ## Recipient whitelisting
//!
//! A policy can additionally own an on-chain *recipient whitelist* — the
//! organization's approved destination directory. Entries are stored per rule
//! set under `(policy_id, recipient)` and managed dynamically with
//! `add_recipient_to_whitelist` / `remove_recipient_from_whitelist`, while the
//! mode itself is a per-policy toggle (`set_recipient_whitelist_enabled`) so a
//! directory can be staged before it is enforced.
//!
//! While the mode is active every destination must be listed: an **empty**
//! whitelist denies every recipient (fail closed by default) and a miss is
//! rejected with [`Error::PolicyDenied`] plus a `not_whitelisted` violation
//! event. With the mode off the gate is a no-op, so existing policies keep
//! their behaviour until governance opts in.

use astroid_interfaces::{PolicyInterface, UpgradeableInterface};
use astroid_shared::constants::SECONDS_PER_MONTH;
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::math::{checked_add, checked_sub};
use astroid_shared::types::AssetAmount;
use astroid_shared::validation::{
    require_non_empty, require_non_negative_amount, require_positive_amount,
};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, Map, String, Vec,
};

/// Maximum recursion depth for composite rule evaluation to prevent stack
/// overflows and excessive gas consumption on-chain.
const MAX_RULE_DEPTH: u32 = 10;

/// Maximum number of entries in one multi-asset spending request. Every
/// distinct asset costs a few storage reads, so this bounds the worst-case
/// cost of a single evaluation.
const MAX_SPEND_ENTRIES: u32 = 10;

/// Maximum number of independent rule trees a policy may stack. Bounds the
/// cost of the all-rules-must-pass evaluation loop so a policy owner cannot
/// register an unbounded amount of work for every transfer check.
const MAX_POLICY_RULES: u32 = 16;

/// A transaction payload submitted for policy evaluation.
///
/// This struct carries the essential fields of a proposed transfer so the
/// composite rule engine can assess it against the full policy tree.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPayload {
    /// The Stellar asset contract address being transferred.
    pub asset: Address,
    /// The intended recipient of the transfer.
    pub recipient: Address,
    /// The amount being transferred (in base units).
    pub amount: i128,
}

/// The operation performed by a rule node.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RuleOp {
    /// Leaf: transfer amount must be at most `value_i128`.
    MaxAmount = 0,
    /// Leaf: recipient must equal `value_address`.
    AllowedRecipient = 1,
    /// Leaf: asset must equal `value_address`.
    AllowedAsset = 2,
    /// Leaf: recipient must be on the on-chain blacklist.
    RecipientBlacklisted = 3,
    /// Leaf: recipient must be on the merchant blacklist.
    MerchantBlacklisted = 4,
    /// Branch: **all** children must evaluate to `true`.
    And = 5,
    /// Branch: **at least one** child must evaluate to `true`.
    Or = 6,
    /// Branch: negates the single child rule.
    Not = 7,
}

/// A single node in a flattened composite rule tree.
///
/// Branch nodes (`And`, `Or`, `Not`) reference their children by index range
/// into the enclosing [`RuleTree`] vector. Leaf nodes use
/// `children_start == children_end == 0`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleNode {
    /// The operation this node performs.
    pub op: RuleOp,
    /// Payload for leaf nodes that carry an amount threshold.
    pub value_i128: i128,
    /// Payload for leaf nodes that carry an address.
    pub value_address: Address,
    /// Index of the first child in the tree vector (`0` = no children).
    pub children_start: u32,
    /// One past the last child index (`0` = no children).
    pub children_end: u32,
}

/// A flattened composite policy rule tree.
///
/// The root node is always at index **0**.  Children of a branch node at index
/// `i` occupy the contiguous range `[children_start, children_end)` in the
/// same vector.
///
/// **Gas safety:** Evaluation is depth-limited to [`MAX_RULE_DEPTH`].
pub type RuleTree = soroban_sdk::Vec<RuleNode>;

/// A stack of independently registered rule trees for one policy. Every entry
/// is an independent [`RuleTree`] and **all** of them must pass for a
/// transaction to be authorized.
pub type RuleStack = soroban_sdk::Vec<RuleTree>;

/// Reject a malformed [`RuleTree`] at write time.
///
/// The tree must contain a root node at index 0 and every branch node's child
/// range must resolve inside the tree (`children_start < children_end <= len`,
/// exactly one child for `Not`). Validating on registration keeps the
/// evaluation loop's iteration bounds safe: `evaluate_node` then only has to
/// walk ranges that are known to resolve.
fn validate_rule_tree(tree: &RuleTree) -> Result<(), Error> {
    if tree.is_empty() {
        return Err(Error::InvalidInput);
    }
    let len = tree.len();
    for i in 0..len {
        let node = tree.get(i).ok_or(Error::InvalidInput)?;
        // `checked_sub` keeps the range arithmetic panic-free: a crafted
        // `children_start > children_end` must yield `InvalidInput`, never an
        // overflow abort.
        let bad_children = match node.op {
            RuleOp::And | RuleOp::Or => {
                node.children_start >= node.children_end || node.children_end > len
            }
            RuleOp::Not => {
                node.children_end.checked_sub(node.children_start) != Some(1)
                    || node.children_end > len
            }
            // Leaves carry a payload instead of children.
            _ => false,
        };
        if bad_children {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

/// Cache blacklist membership for the recipient while evaluating a policy's
/// composite rule and rule stack.
#[derive(Default)]
struct RuleEvaluationContext {
    recipient_blacklisted: Option<bool>,
    merchant_blacklisted: Option<bool>,
}

impl RuleEvaluationContext {
    fn recipient_blacklisted(&mut self, env: &Env, recipient: &Address) -> bool {
        if let Some(is_blacklisted) = self.recipient_blacklisted {
            return is_blacklisted;
        }
        let is_blacklisted = env
            .storage()
            .persistent()
            .has(&DataKey::Blacklist(recipient.clone()));
        self.recipient_blacklisted = Some(is_blacklisted);
        is_blacklisted
    }

    fn merchant_blacklisted(&mut self, env: &Env, recipient: &Address) -> bool {
        if let Some(is_blacklisted) = self.merchant_blacklisted {
            return is_blacklisted;
        }
        let is_blacklisted = env
            .storage()
            .persistent()
            .has(&DataKey::MerchantBlacklist(recipient.clone()));
        self.merchant_blacklisted = Some(is_blacklisted);
        is_blacklisted
    }
}

/// Evaluate a node in a [`RuleTree`] against `payload`.
///
/// `depth` is decremented on every recursive call; returns
/// `Err(Error::InvalidInput)` when exhausted (stack/gas protection).
fn evaluate_node(
    env: &Env,
    tree: &RuleTree,
    node_idx: u32,
    payload: &TransactionPayload,
    depth: u32,
    context: &mut RuleEvaluationContext,
) -> Result<bool, Error> {
    if depth == 0 {
        return Err(Error::InvalidInput);
    }
    let remaining = depth - 1;
    let node = tree.get(node_idx).ok_or(Error::InvalidInput)?;
    match node.op {
        RuleOp::MaxAmount => Ok(payload.amount <= node.value_i128),
        RuleOp::AllowedRecipient => Ok(payload.recipient == node.value_address),
        RuleOp::AllowedAsset => Ok(payload.asset == node.value_address),
        RuleOp::RecipientBlacklisted => Ok(context.recipient_blacklisted(env, &payload.recipient)),
        RuleOp::MerchantBlacklisted => Ok(context.merchant_blacklisted(env, &payload.recipient)),
        RuleOp::And => {
            if node.children_start == node.children_end {
                return Err(Error::InvalidInput);
            }
            for i in node.children_start..node.children_end {
                if !evaluate_node(env, tree, i, payload, remaining, context)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        RuleOp::Or => {
            if node.children_start == node.children_end {
                return Err(Error::InvalidInput);
            }
            for i in node.children_start..node.children_end {
                if evaluate_node(env, tree, i, payload, remaining, context)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        RuleOp::Not => {
            // `checked_sub` keeps the range arithmetic panic-free: a crafted
            // `children_start == u32::MAX` must yield `InvalidInput`, never an
            // overflow abort. Exactly one child is required.
            if node.children_end.checked_sub(node.children_start) != Some(1) {
                return Err(Error::InvalidInput);
            }
            let result =
                evaluate_node(env, tree, node.children_start, payload, remaining, context)?;
            Ok(!result)
        }
    }
}

/// Strategy for combining multiple policy rules in the policy rules stack.
///
/// When a policy has multiple registered rules (via `add_policy_rule`), this
/// enum determines how they are combined during evaluation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PolicyCombinationStrategy {
    /// All rules must pass for the policy to allow the transfer.
    /// This is the default and most restrictive strategy.
    All = 0,
    /// At least one rule must pass for the policy to allow the transfer.
    /// If no rules are registered, the policy allows the transfer by default.
    Any = 1,
}

impl PolicyCombinationStrategy {
    /// Returns the default combination strategy (All).
    pub fn default_strategy() -> Self {
        PolicyCombinationStrategy::All
    }
}

/// Why one policy rule refused a transaction (Issue #314).
///
/// Every refusal used to collapse onto a single `PolicyDenied`: a caller that
/// wanted to react differently to "over the single-transaction ceiling" than to
/// "destination is not on the approved list" had to decode the contract's
/// violation event to tell them apart. The rule walk now returns this reason
/// directly through [`PolicyContract::evaluate_policy`], and
/// [`PolicyContract::check_transfer`] maps it onto the exact error code it has
/// always returned, so the wire behaviour of existing callers is unchanged.
///
/// Discriminants are part of the public ABI and MUST NOT be reordered or reused
/// once released.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PolicyDenialReason {
    /// The policy is switched off; every spend is refused.
    Disabled = 0,
    /// The policy's expiry has passed.
    Expired = 1,
    /// The recipient is on the protocol blocklist.
    RecipientBlacklisted = 2,
    /// The recipient is on the merchant blocklist.
    MerchantBlacklisted = 3,
    /// The policy enforces its approved destination directory and the recipient
    /// is not in it.
    RecipientNotWhitelisted = 4,
    /// The amount exceeds the policy's single-transaction ceiling
    /// (`Policy::max_amount`).
    AboveMaxTransactionLimit = 5,
    /// The policy pins a single allowed recipient and this is not it.
    RecipientNotAllowed = 6,
    /// The policy pins a single allowed asset and this is not it.
    AssetNotAllowed = 7,
    /// The asset is on the policy's asset deny list.
    AssetBlacklisted = 8,
    /// The policy enforces its asset allow-list and the asset is not in it.
    AssetNotWhitelisted = 9,
    /// The spend would breach the per-`(policy, asset)` allowance.
    AllowanceExceeded = 10,
    /// The per-`(policy, asset)` allowance has lapsed.
    AllowanceExpired = 11,
    /// The policy's composite rule tree evaluated to `false`.
    CompositeRuleDenied = 12,
    /// The policy's registered rule stack evaluated to `false`.
    RuleStackDenied = 13,
    /// The current ledger time falls outside the policy's configured transfer
    /// window (`Policy::is_within_transfer_window`, Issue #405).
    OutsideTransferWindow = 14,
}

impl PolicyDenialReason {
    /// The error `check_transfer` reports for this refusal. Each mapping
    /// preserves the code that gate returned before the rule walk was made
    /// granular, so an existing caller sees no change.
    pub fn to_error(self) -> Error {
        match self {
            PolicyDenialReason::Disabled
            | PolicyDenialReason::Expired
            | PolicyDenialReason::RecipientNotWhitelisted
            | PolicyDenialReason::AboveMaxTransactionLimit
            | PolicyDenialReason::RecipientNotAllowed
            | PolicyDenialReason::AssetNotAllowed
            | PolicyDenialReason::AssetBlacklisted
            | PolicyDenialReason::CompositeRuleDenied
            | PolicyDenialReason::RuleStackDenied
            | PolicyDenialReason::OutsideTransferWindow => Error::PolicyDenied,
            PolicyDenialReason::RecipientBlacklisted => Error::PolicyRecipientRestricted,
            PolicyDenialReason::MerchantBlacklisted => Error::PolicyMerchantBlocked,
            PolicyDenialReason::AssetNotWhitelisted => Error::AssetNotAuthorized,
            PolicyDenialReason::AllowanceExceeded => Error::AllowanceExceeded,
            PolicyDenialReason::AllowanceExpired => Error::AllowanceExpired,
        }
    }

    /// The stable short symbol carried by the `PolicyViolation` event for this
    /// refusal. Off-chain consumers key on these strings, so they are frozen
    /// alongside the numeric discriminants.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyDenialReason::Disabled => "disabled",
            PolicyDenialReason::Expired => "expired",
            PolicyDenialReason::RecipientBlacklisted => "blacklisted",
            PolicyDenialReason::MerchantBlacklisted => "merchant_blocked",
            PolicyDenialReason::RecipientNotWhitelisted => "not_whitelisted",
            PolicyDenialReason::AboveMaxTransactionLimit => "above_max",
            PolicyDenialReason::RecipientNotAllowed => "bad_recipient",
            PolicyDenialReason::AssetNotAllowed => "bad_asset",
            PolicyDenialReason::AssetBlacklisted => "asset_blacklisted",
            PolicyDenialReason::AssetNotWhitelisted => "asset_not_whitelisted",
            PolicyDenialReason::AllowanceExceeded => "allowance_exceeded",
            PolicyDenialReason::AllowanceExpired => "allowance_expired",
            PolicyDenialReason::CompositeRuleDenied => "rule_denied",
            PolicyDenialReason::RuleStackDenied => "rules_denied",
            PolicyDenialReason::OutsideTransferWindow => "outside_window",
        }
    }

    /// Whether the gate that produced this reason already published its own
    /// violation event. The allowance gate reports its refusal itself (so
    /// `check_allowance` and `update_allowance`, which persist the outcome,
    /// keep their event), so the rule walk must not publish it a second time.
    fn is_self_reported(self) -> bool {
        matches!(
            self,
            PolicyDenialReason::AllowanceExceeded | PolicyDenialReason::AllowanceExpired
        )
    }
}

/// The verdict of one policy evaluation (Issue #314).
///
/// Modelled as a sum type rather than an `Option<PolicyDenialReason>` because a
/// `#[contracttype]` cannot encode `Option` of a custom contracttype enum: the
/// SDK's `Option` conversion needs an infallible `From<&T> for ScVal`, which a
/// derived enum does not provide (the registry's `BoundHash` exists for exactly
/// the same reason). The two states are exhaustive and the discriminant of the
/// `Denied` case carries which rule refused.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyVerdict {
    /// Every rule passed.
    Allowed,
    /// One rule refused the transfer; the payload names which.
    Denied(PolicyDenialReason),
}

/// The outcome of evaluating one transaction against a policy (Issue #314).
///
/// `verdict` is the decision; it is [`PolicyVerdict::Denied`] exactly when a rule
/// refused the transfer, and the payload then names the first rule that did.
/// `max_transaction_amount` echoes the single-transaction ceiling in force
/// (`0` = no ceiling) so a caller that was refused for
/// [`PolicyDenialReason::AboveMaxTransactionLimit`] can size a retry without a
/// second read.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub verdict: PolicyVerdict,
    pub max_transaction_amount: i128,
}

impl PolicyDecision {
    /// A passing decision under a ceiling of `max_transaction_amount`.
    fn allow(max_transaction_amount: i128) -> Self {
        PolicyDecision {
            verdict: PolicyVerdict::Allowed,
            max_transaction_amount,
        }
    }

    /// A refusal naming the rule that produced it.
    fn deny(reason: PolicyDenialReason, max_transaction_amount: i128) -> Self {
        PolicyDecision {
            verdict: PolicyVerdict::Denied(reason),
            max_transaction_amount,
        }
    }

    /// Whether the transaction was permitted.
    pub fn allowed(&self) -> bool {
        matches!(self.verdict, PolicyVerdict::Allowed)
    }

    /// The rule that refused the transaction, or `None` when it was permitted.
    pub fn reason(&self) -> Option<PolicyDenialReason> {
        match self.verdict {
            PolicyVerdict::Allowed => None,
            PolicyVerdict::Denied(reason) => Some(reason),
        }
    }
}

/// On-chain representation of a registered policy.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Admin that controls this policy (typically the treasury/admin wallet).
    pub owner: Address,
    /// SHA-256 hash of the human-readable policy JSON managed off-chain.
    pub config_hash: BytesN<32>,
    /// Scalar gates baked in for cheap on-chain checks (so we don't need JSON).
    pub max_amount: i128,
    /// Allow-listed recipient (zero-length means "any" is allowed).
    pub allowed_recipient: Option<Address>,
    /// Asset contract address the spend must be in (None = any asset).
    pub allowed_asset: Option<Address>,
    /// Unix timestamp the policy is active until (0 = no expiry).
    pub expires_at: u64,
    /// Whether the policy is currently enabled.
    pub enabled: bool,
    /// Strategy for combining multiple policy rules (All by default).
    pub rule_combination_strategy: PolicyCombinationStrategy,
    /// Time of day (seconds since midnight UTC) the operating window opens.
    /// `0` together with `window_end_time == 0` disables the gate.
    pub window_start_time: u64,
    /// Time of day (seconds since midnight UTC) the operating window closes
    /// (exclusive). Equal to `window_start_time` when the gate is disabled.
    pub window_end_time: u64,
    /// Length of the repeating window day in seconds (86_400 for a standard
    /// day). `0` means the time window is not enforced.
    pub window_days: u64,
}

impl Policy {
    /// Whether a transfer at ledger time `now` falls inside this policy's
    /// operating window.
    ///
    /// The gate is off when `window_days == 0` (always inside). Otherwise the
    /// time of day is `now % window_days` and the window is the half-open
    /// range `[window_start_time, window_end_time)`; a window whose start is
    /// not before its end wraps over the day boundary, so `22:00 → 06:00`
    /// admits the night hours. An `end_time` equal to `start_time` admits no
    /// time at all (fail closed). Callers supply `now` only for testability;
    /// production code passes `env.ledger().timestamp()`.
    fn is_within_transfer_window(&self, now: u64) -> bool {
        if self.window_days == 0 {
            return true;
        }
        let time_of_day = now % self.window_days;
        if self.window_start_time < self.window_end_time {
            time_of_day >= self.window_start_time && time_of_day < self.window_end_time
        } else if self.window_start_time == self.window_end_time {
            // Degenerate zero-length window: fail closed — no time is allowed,
            // mirroring the empty-recipient-whitelist behaviour.
            false
        } else {
            // Wrapping window across the day boundary (e.g. `22:00 → 06:00`).
            time_of_day >= self.window_start_time || time_of_day < self.window_end_time
        }
    }
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Policy(String),
    Count,
    Blacklist(Address),
    MerchantBlacklist(Address),
    CategoryBlacklist(String),
    /// Per-policy asset whitelist: (policy_id, asset) -> true.
    AssetWhitelist(String, Address),
    /// Per-policy asset deny list: (policy_id, asset) -> (). Keyed by policy so
    /// each policy governs only its own assets.
    AssetBlacklist(String, Address),
    /// Whether an org uses a permissive (all-assets-allowed) or restrictive
    /// (whitelist-enforced) asset mode. Stored per policy_id.
    AssetWhitelistEnabled(String),
    /// Per-policy recipient whitelist: (policy_id, recipient) -> true. Keys the
    /// approved destination directory of one organization rule set.
    RecipientWhitelist(String, Address),
    /// Whether a policy enforces its recipient whitelist (default: off).
    RecipientWhitelistEnabled(String),
    /// Ordered index of the recipients listed under a policy. Soroban contract
    /// storage cannot be enumerated, so this vector is kept in sync with
    /// `RecipientWhitelist` to make the directory readable back to callers.
    RecipientWhitelistIndex(String),
    /// Per-(policy, asset) multi-token spending allowance.
    Allowance(String, Address),
    /// Composite rule tree for a policy (set via `set_composite_rule`).
    CompositeRule(String),
    /// Stack of independently registered rule trees for a policy (all must
    /// pass; managed through `add_policy_rule` / `remove_policy_rule`).
    PolicyRules(String),
}

/// A per-asset spending allowance attached to a policy.
///
/// Multiple Stellar asset types (native XLM and Soroban SAC tokens) are tracked
/// independently under the (policy_id, asset) key, so a policy can express a
/// granular quota per token rather than a single default denomination.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetAllowance {
    /// The policy this allowance belongs to.
    pub policy_id: String,
    /// The asset contract address (SAC) or the native XLM contract.
    pub asset: Address,
    /// Cumulative spending limit for this asset. `0` means disabled.
    pub limit: i128,
    /// Amount already spent against the limit.
    pub spent: i128,
    /// Unix timestamp the allowance expires at (`0` = never).
    pub expires_at: u64,
    /// Rate-limit window length in seconds. `0` = cumulative (never resets).
    pub window_seconds: u64,
    /// Start of the current window (unix seconds). Sits on a window boundary
    /// once the allowance has rolled over at least once.
    pub window_start: u64,
}

/// Settle every rate-limit window boundary that has passed by `now`.
///
/// With `k = (now - window_start) / window_seconds` whole windows elapsed
/// (integer division, rounding down), `k >= 1` resets `spent` and moves
/// `window_start` forward by exactly `k * window_seconds`. A ledger time
/// earlier than `window_start` settles nothing, so the current usage stays in
/// force (the conservative outcome). Cumulative allowances are untouched.
fn settle_window(allowance: &mut AssetAllowance, now: u64) -> Result<(), Error> {
    if allowance.window_seconds == 0 || now < allowance.window_start {
        return Ok(());
    }
    let periods = (now - allowance.window_start) / allowance.window_seconds;
    if periods == 0 {
        return Ok(());
    }
    let advance = periods
        .checked_mul(allowance.window_seconds)
        .ok_or(Error::Overflow)?;
    allowance.window_start = allowance
        .window_start
        .checked_add(advance)
        .ok_or(Error::Overflow)?;
    allowance.spent = 0;
    Ok(())
}

#[contract]
pub struct PolicyContract;

#[contractimpl]
#[allow(clippy::too_many_arguments)]
impl PolicyContract {
    pub fn initialize(env: Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Count) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Count, &0u32);
        Ok(())
    }

    /// Register a policy. `owner` gates subsequent rotations. Cheap scalar gates
    /// are stored on-chain; the full configuration is hashed for tamper-evidence.
    /// The `rule_combination_strategy` determines how multiple policy rules are combined
    /// (All by default for backward compatibility).
    #[allow(clippy::too_many_arguments)]
    pub fn register_policy(
        env: Env,
        owner: Address,
        policy_id: String,
        config_hash: BytesN<32>,
        max_amount: i128,
        allowed_recipient: Option<Address>,
        allowed_asset: Option<Address>,
        expires_at: u64,
        rule_combination_strategy: Option<PolicyCombinationStrategy>,
    ) -> Result<(), Error> {
        owner.require_auth();
        require_non_empty(&policy_id)?;
        if env
            .storage()
            .persistent()
            .has(&DataKey::Policy(policy_id.clone()))
        {
            return Err(Error::AlreadyExists);
        }
        let policy = Policy {
            owner,
            config_hash,
            max_amount,
            allowed_recipient,
            allowed_asset,
            expires_at,
            enabled: true,
            rule_combination_strategy: rule_combination_strategy
                .unwrap_or_else(PolicyCombinationStrategy::default_strategy),
            // New policies start with no operating-window restriction; the
            // owner narrows them with `set_transfer_window` when required.
            window_start_time: 0,
            window_end_time: 0,
            window_days: 0,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("registd")),
            policy_id,
        );
        Ok(())
    }

    /// Rotate an existing policy hash — e.g. after the backend recomputes it.
    pub fn rotate_policy(
        env: Env,
        caller: Address,
        policy_id: String,
        new_hash: BytesN<32>,
        new_max: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy.config_hash = new_hash;
        policy.max_amount = new_max;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rotated")),
            policy_id,
        );
        Ok(())
    }

    /// Disable / enable a policy (owner only).
    pub fn set_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy.enabled = enabled;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        // Issue #222 — an enable/disable toggle is a state change an indexer
        // must see: identifiers first, then the ledger timestamp as the final
        // payload field (the standardized event convention).
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("enabled")),
            (policy_id, enabled, env.ledger().timestamp()),
        );
        Ok(())
    }

    /// Set the rule combination strategy for a policy (owner only).
    /// This determines how multiple policy rules are combined during evaluation.
    pub fn set_rule_combination_strategy(
        env: Env,
        caller: Address,
        policy_id: String,
        strategy: PolicyCombinationStrategy,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy.rule_combination_strategy = strategy;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("stratgy")),
            (policy_id, strategy as u32),
        );
        Ok(())
    }

    /// Restrict transfers to a daily operating time window (owner only).
    ///
    /// `start_time` and `end_time` are times of day in seconds since midnight
    /// UTC; the window repeats every `window_days` seconds (86 400 for a
    /// standard day, shared with [`astroid_shared::constants::SECONDS_PER_DAY`]).
    /// A transaction whose time of day — read from `env.ledger().timestamp()` —
    /// falls outside `[start_time, end_time)` is denied by `check_transfer`
    /// with [`Error::PolicyDenied`]. A window may cross midnight
    /// (`start_time > end_time` wraps over the day boundary); passing
    /// `window_days == 0` clears the restriction entirely.
    ///
    /// Validation rejects a `window_days` longer than one calendar month and
    /// bounds that cannot occur in a day of that length, so the modular
    /// time-of-day arithmetic in [`Self::is_within_transfer_window`] can never
    /// overflow or divide by zero.
    pub fn set_transfer_window(
        env: Env,
        caller: Address,
        policy_id: String,
        start_time: u64,
        end_time: u64,
        window_days: u64,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        // A non-zero day must be able to contain both bounds, otherwise the
        // `now % window_days` arithmetic below would compare times that can
        // never occur. The month cap keeps a mistyped value (e.g. ms instead
        // of s) from silently disabling the gate.
        if window_days != 0 && (start_time >= window_days || end_time >= window_days) {
            return Err(Error::InvalidInput);
        }
        if window_days > SECONDS_PER_MONTH {
            return Err(Error::InvalidInput);
        }
        let mut policy = Self::load(&env, &policy_id)?;
        policy.window_start_time = start_time;
        policy.window_end_time = end_time;
        policy.window_days = window_days;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("timewin")),
            (policy_id, start_time, end_time, window_days),
        );
        Ok(())
    }

    /// Read the configured operating window for a policy.
    ///
    /// Returns `(start_time, end_time, window_days)`; `window_days == 0` means
    /// no time restriction is enforced (the default for every policy).
    pub fn get_transfer_window(env: Env, policy_id: String) -> (u64, u64, u64) {
        match Self::load(&env, &policy_id) {
            Ok(policy) => (
                policy.window_start_time,
                policy.window_end_time,
                policy.window_days,
            ),
            // An unknown policy has no window; the caller's own lookup will
            // surface the canonical `NotFound` when it matters.
            Err(_) => (0, 0, 0),
        }
    }

    /// Add an asset to the policy's whitelist (owner only). When the asset
    /// whitelist is enabled for a policy, only whitelisted assets are permitted
    /// in `check_transfer`.
    pub fn add_asset_to_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelist(policy_id.clone(), asset.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &true);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("asset_add")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Remove an asset from the policy's whitelist (owner only).
    pub fn remove_asset_from_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelist(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("asset_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Blacklist an asset for a policy (owner only). Once listed, no transfer
    /// evaluated against `policy_id` may move that token, whatever the policy's
    /// other asset gates say.
    pub fn add_asset_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::AssetBlacklist(policy_id.clone(), asset.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &());
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("ablk_add")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Remove an asset from a policy's blacklist (owner only).
    pub fn remove_asset_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::AssetBlacklist(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("ablk_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Whether `asset` is blacklisted under `policy_id`.
    pub fn is_asset_blacklisted(env: Env, policy_id: String, asset: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::AssetBlacklist(policy_id, asset))
    }

    /// Enable or disable the asset whitelist for a policy (owner only).
    /// When enabled, only assets explicitly added via `add_asset_to_whitelist`
    /// are permitted.
    pub fn set_asset_whitelist_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelistEnabled(policy_id.clone());
        env.storage().persistent().set(&key, &enabled);
        // Issue #222 — same schema as `set_recipient_whitelist_enabled`'s
        // `wl_mode`, namespaced by the whitelist it toggles, ending with the
        // ledger timestamp.
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("awl_mode")),
            (policy_id, enabled, env.ledger().timestamp()),
        );
        Ok(())
    }

    /// Check whether an asset is whitelisted for a given policy.
    /// Returns Ok(()) if allowed, or AssetNotAuthorized if the whitelist is
    /// enabled and the asset is not present.
    pub fn validate_asset(env: Env, policy_id: String, asset: Address) -> Result<(), Error> {
        if Self::asset_whitelist_denied(&env, &policy_id, &asset) {
            events_policy_violation(&env, &policy_id, "asset_not_whitelisted");
            return Err(Error::AssetNotAuthorized);
        }
        Ok(())
    }

    /// Pure membership probe behind the asset allow-list gate: `true` when the
    /// policy enforces its asset allow-list and `asset` is not in it. Publishes
    /// nothing, so the modular rule walk can report the denial once.
    fn asset_whitelist_denied(env: &Env, policy_id: &String, asset: &Address) -> bool {
        let whitelist_enabled: bool = env
            .storage()
            .persistent()
            .get(&DataKey::AssetWhitelistEnabled(policy_id.clone()))
            .unwrap_or(false);
        whitelist_enabled
            && !env
                .storage()
                .persistent()
                .has(&DataKey::AssetWhitelist(policy_id.clone(), asset.clone()))
    }

    /// Add an address to the restricted blacklist (owner only).
    pub fn add_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::Blacklist(address.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_add")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Remove an address from the restricted blacklist (owner only).
    pub fn remove_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::Blacklist(address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_rem")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Add a merchant address to the merchant blacklist (owner only).
    pub fn add_merchant_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        merchant_address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::MerchantBlacklist(merchant_address.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("merch_add")),
            (policy_id, merchant_address),
        );
        Ok(())
    }

    /// Remove a merchant address from the merchant blacklist (owner only).
    pub fn remove_merchant_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        merchant_address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::MerchantBlacklist(merchant_address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("merch_rem")),
            (policy_id, merchant_address),
        );
        Ok(())
    }

    /// Add a spending category to the category blacklist (owner only).
    pub fn add_category_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        category: String,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        require_non_empty(&category)?;
        let key = DataKey::CategoryBlacklist(category.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("cat_add")),
            (policy_id, category),
        );
        Ok(())
    }

    /// Remove a spending category from the category blacklist (owner only).
    pub fn remove_category_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        category: String,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::CategoryBlacklist(category.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("cat_rem")),
            (policy_id, category),
        );
        Ok(())
    }

    /// Add a recipient address to the blocklist (owner only). Blocked
    /// addresses are rejected immediately in `check_transfer` before any
    /// other policy gate is evaluated (Issue #32).
    pub fn add_to_blocklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Blacklist(address.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_add")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Remove a recipient address from the blocklist (owner only).
    pub fn remove_from_blocklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Blacklist(address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_rem")),
            (policy_id, address),
        );
        Ok(())
    }

    // --- recipient whitelist ---

    /// Turn recipient whitelist mode on or off for a policy (owner only).
    ///
    /// While enabled, `check_transfer` only permits destinations listed in this
    /// policy's approved directory — an **empty** whitelist therefore denies
    /// every recipient (fail closed by default). Disabling restores the
    /// permissive behaviour without touching the stored entries, so a directory
    /// can be staged before it is enforced.
    pub fn set_recipient_whitelist_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        env.storage().persistent().set(
            &DataKey::RecipientWhitelistEnabled(policy_id.clone()),
            &enabled,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("wl_mode")),
            (policy_id, enabled),
        );
        Ok(())
    }

    /// Add a recipient to the policy's whitelist (owner only).
    ///
    /// Fails with [`Error::AlreadyExists`] when the address is already listed
    /// for this policy, so the directory stays duplicate-free.
    pub fn add_recipient_to_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::RecipientWhitelist(policy_id.clone(), recipient.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &true);
        // Mirror the entry in the read index so the directory can be listed
        // back (Soroban offers no key enumeration).
        let index_key = DataKey::RecipientWhitelistIndex(policy_id.clone());
        let mut index: soroban_sdk::Vec<Address> = env
            .storage()
            .persistent()
            .get(&index_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        index.push_back(recipient.clone());
        env.storage().persistent().set(&index_key, &index);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("wl_add")),
            (policy_id, recipient),
        );
        Ok(())
    }

    /// Remove a recipient from the policy's whitelist (owner only).
    ///
    /// Fails with [`Error::NotFound`] when the address was never listed (or
    /// was already removed), so a stale governance transaction cannot silently
    /// no-op. Dropping the last entry also drops the index key.
    pub fn remove_recipient_from_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::RecipientWhitelist(policy_id.clone(), recipient.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        let index_key = DataKey::RecipientWhitelistIndex(policy_id.clone());
        let mut index: soroban_sdk::Vec<Address> = env
            .storage()
            .persistent()
            .get(&index_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if let Some(pos) = index.iter().position(|a| a == recipient) {
            // `position` reports a `usize`; convert without panicking so a
            // malformed index surfaces as an error rather than an abort.
            index.remove(u32::try_from(pos).map_err(|_| Error::InvalidInput)?);
        }
        if index.is_empty() {
            env.storage().persistent().remove(&index_key);
        } else {
            env.storage().persistent().set(&index_key, &index);
        }
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("wl_rem")),
            (policy_id, recipient),
        );
        Ok(())
    }

    /// Whether `recipient` is on `policy_id`'s approved destination directory.
    ///
    /// A pure membership probe: it reports the stored state regardless of
    /// whether whitelist mode is currently enforced, so callers can diff the
    /// directory against an off-chain list.
    pub fn is_recipient_whitelisted(env: Env, policy_id: String, recipient: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::RecipientWhitelist(policy_id, recipient))
    }

    /// Read back every recipient whitelisted for `policy_id`, in insertion
    /// order. Returns an empty vector when the directory has no entries.
    pub fn get_recipient_whitelist(env: Env, policy_id: String) -> soroban_sdk::Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::RecipientWhitelistIndex(policy_id))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Evaluate `payload` against the policy's active recipient whitelist.
    ///
    /// This is the whitelist's evaluation entry point: it is called by
    /// `check_transfer` for every proposed transfer and can also be invoked
    /// directly to dry-run a destination. Returns `Ok(())` when whitelist mode
    /// is off (gate not enforced) or when `payload.recipient` is listed, and
    /// [`Error::PolicyDenied`] — with a `not_whitelisted` violation event —
    /// when an untrusted destination is targeted while the mode is active.
    ///
    /// The policy itself is resolved by the caller (`check_transfer` loads it
    /// before any gate runs), so an unknown policy never reaches this probe.
    pub fn evaluate_recipient_whitelist(
        env: Env,
        policy_id: String,
        payload: TransactionPayload,
    ) -> Result<(), Error> {
        Self::check_recipient_whitelist(&env, &policy_id, &payload.recipient)
    }

    /// Recipient whitelist gate shared by `evaluate_recipient_whitelist` and
    /// `check_transfer`; only the recipient matters.
    fn check_recipient_whitelist(
        env: &Env,
        policy_id: &String,
        recipient: &Address,
    ) -> Result<(), Error> {
        if Self::recipient_whitelist_denied(env, policy_id, recipient) {
            events_policy_violation(env, policy_id, "not_whitelisted");
            return Err(Error::PolicyDenied);
        }
        Ok(())
    }

    /// Pure membership probe behind the recipient whitelist gate: `true` when
    /// the policy enforces its approved destination directory and `recipient` is
    /// not in it. Publishes nothing, so the modular rule walk can report the
    /// denial once at the boundary.
    fn recipient_whitelist_denied(env: &Env, policy_id: &String, recipient: &Address) -> bool {
        let enabled: bool = env
            .storage()
            .persistent()
            .get(&DataKey::RecipientWhitelistEnabled(policy_id.clone()))
            .unwrap_or(false);
        enabled
            && !env.storage().persistent().has(&DataKey::RecipientWhitelist(
                policy_id.clone(),
                recipient.clone(),
            ))
    }

    /// Short alias of [`PolicyContract::set_recipient_whitelist_enabled`].
    pub fn set_whitelist_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        Self::set_recipient_whitelist_enabled(env, caller, policy_id, enabled)
    }

    /// Short alias of [`PolicyContract::add_recipient_to_whitelist`].
    pub fn add_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
    ) -> Result<(), Error> {
        Self::add_recipient_to_whitelist(env, caller, policy_id, recipient)
    }

    /// Short alias of [`PolicyContract::remove_recipient_from_whitelist`].
    pub fn remove_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
    ) -> Result<(), Error> {
        Self::remove_recipient_from_whitelist(env, caller, policy_id, recipient)
    }

    /// Check if a spending category is restricted. Returns Ok(()) if the category
    /// is allowed, or PolicyCategoryRestricted if it's blacklisted.
    pub fn check_category(env: Env, policy_id: String, category: String) -> Result<(), Error> {
        // Empty category is always allowed
        if category.is_empty() {
            return Ok(());
        }

        if env
            .storage()
            .persistent()
            .has(&DataKey::CategoryBlacklist(category.clone()))
        {
            events_policy_violation(&env, &policy_id, "category_restricted");
            return Err(Error::PolicyCategoryRestricted);
        }
        Ok(())
    }

    // --- multi-token allowances ---

    /// Create or update the spending allowance for `(policy_id, asset)`.
    /// `owner` only. Rejects a negative limit. `expires_at == 0` means never.
    /// An existing rate-limit window is kept; a new allowance is cumulative.
    pub fn set_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        limit: i128,
        expires_at: u64,
    ) -> Result<(), Error> {
        Self::store_allowance(&env, &caller, policy_id, asset, limit, None, expires_at)
    }

    /// Create or update a recurring (rate-limited) allowance: at most `limit`
    /// of `asset` per fixed window of `window_seconds`. `owner` only.
    /// `window_seconds == 0` makes the allowance cumulative. Changing the
    /// window length re-anchors the window at the current ledger time; spend
    /// already recorded in the current window is kept either way.
    pub fn set_recurring_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        limit: i128,
        window_seconds: u64,
        expires_at: u64,
    ) -> Result<(), Error> {
        Self::store_allowance(
            &env,
            &caller,
            policy_id,
            asset,
            limit,
            Some(window_seconds),
            expires_at,
        )
    }

    fn store_allowance(
        env: &Env,
        caller: &Address,
        policy_id: String,
        asset: Address,
        limit: i128,
        window_seconds: Option<u64>,
        expires_at: u64,
    ) -> Result<(), Error> {
        Self::require_policy_owner(env, caller, &policy_id)?;
        require_non_negative_amount(limit)?;
        // Updating an allowance keeps existing spend so limits are enforced
        // cumulatively across updates. Settling first means a reset that is
        // already due is neither lost nor deferred by the update.
        let now = env.ledger().timestamp();
        let mut allowance = Self::get_allowance(env.clone(), policy_id.clone(), asset.clone());
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Allowance(policy_id.clone(), asset.clone()))
        {
            allowance.window_start = now;
        }
        if let Some(window) = window_seconds {
            if window != allowance.window_seconds {
                allowance.window_seconds = window;
                allowance.window_start = now;
            }
        }
        allowance.limit = limit;
        allowance.expires_at = expires_at;
        allowance.policy_id = policy_id.clone();
        allowance.asset = asset.clone();
        env.storage().persistent().set(
            &DataKey::Allowance(policy_id.clone(), asset.clone()),
            &allowance,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_set")),
            (policy_id, asset, limit),
        );
        Ok(())
    }

    /// Remove the spending allowance for `(policy_id, asset)`. `owner` only.
    pub fn remove_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Allowance(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Read the current allowance for `(policy_id, asset)`. Returns the stored
    /// record, or a zeroed record when none has been configured (so callers can
    /// treat an unset allowance as "unrestricted"). A recurring allowance is
    /// reported as of the current window: a window boundary that has passed
    /// shows `spent == 0` even before the next spend persists the reset.
    pub fn get_allowance(env: Env, policy_id: String, asset: Address) -> AssetAllowance {
        let mut allowance = env
            .storage()
            .persistent()
            .get(&DataKey::Allowance(policy_id.clone(), asset.clone()))
            .unwrap_or(AssetAllowance {
                policy_id,
                asset,
                limit: 0,
                spent: 0,
                expires_at: 0,
                window_seconds: 0,
                window_start: 0,
            });
        // `window_start + k * window_seconds <= now` always holds, so settling
        // cannot overflow; keep the stored record if it somehow would.
        let mut settled = allowance.clone();
        if settle_window(&mut settled, env.ledger().timestamp()).is_ok() {
            allowance = settled;
        }
        allowance
    }

    /// Check whether spending `amount` of `asset` under `policy_id` is within
    /// the configured allowance. Returns the remaining headroom after the spend
    /// (0 = the allowance would be fully consumed, which is permitted). An
    /// unset allowance is unrestricted. Returns
    /// [`Error::AllowanceExceeded`] when the spend would breach the
    /// allowance, or [`Error::AllowanceExpired`] when the envelope has lapsed.
    pub fn check_allowance(
        env: Env,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<i128, Error> {
        require_non_negative_amount(amount)?;
        match Self::consume_allowance(&env, &policy_id, &asset, amount)? {
            // No configured allowance => unrestricted for this asset.
            None => Ok(i128::MAX),
            Some(allowance) => checked_sub(allowance.limit, allowance.spent),
        }
    }

    /// Atomically consume `amount` against the `(policy_id, asset)` allowance.
    /// Policy `owner` only; `amount` must be strictly positive. Returns
    /// `Ok(())` when the allowance was decremented (or none is configured), or
    /// [`Error::AllowanceExceeded`] when it would be breached.
    pub fn update_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        require_positive_amount(amount)?;
        if let Some(allowance) = Self::consume_allowance(&env, &policy_id, &asset, amount)? {
            Self::persist_spend(&env, &allowance, amount);
        }
        Ok(())
    }

    // --- granular rule evaluation (Issue #314) ---

    /// Evaluate `payload` against a policy and return the granular decision:
    /// whether the transfer is permitted, and — when it is not — exactly which
    /// rule refused it.
    ///
    /// This is the read-only counterpart of `check_transfer`: same rules, same
    /// order, same violation event, but the refusal is reported as a
    /// [`PolicyDenialReason`] instead of being collapsed onto `PolicyDenied`. A
    /// keeper, a wallet building a pre-flight confirmation screen or an
    /// off-chain simulator can therefore tell a transaction over the
    /// single-transaction ceiling
    /// ([`PolicyDenialReason::AboveMaxTransactionLimit`]) from an unapproved
    /// destination ([`PolicyDenialReason::RecipientNotWhitelisted`] or
    /// [`PolicyDenialReason::RecipientNotAllowed`]) without decoding events.
    ///
    /// Errors are reserved for malformed input and broken state: a non-positive
    /// `amount` is [`Error::InvalidAmount`], an unknown `policy_id` is
    /// [`Error::NotFound`], and a rule tree that cannot be read is
    /// [`Error::InvalidInput`]. A policy refusal itself is never an `Err`.
    ///
    /// Nothing is persisted: the allowance the spend would consume is only
    /// computed, so a dry run can be repeated freely.
    pub fn evaluate_policy(
        env: Env,
        policy_id: String,
        payload: TransactionPayload,
    ) -> Result<PolicyDecision, Error> {
        // Zero and negative amounts are malformed requests, not policy
        // denials: they never reach the rule walk.
        require_positive_amount(payload.amount)?;
        let decision = Self::evaluate_policy_decision(&env, &policy_id, &payload)?;
        // A refusal is observable here exactly as it is through
        // `check_transfer`: one `PolicyViolation` event naming the rule.
        if let Some(reason) = decision.reason() {
            Self::report_denial(&env, &policy_id, reason);
        }
        Ok(decision)
    }

    // --- multi-asset spending requests ---

    /// Evaluate a request that moves several assets to `recipient`, without
    /// recording it. Entries for the same asset are summed before any gate
    /// runs, then every asset must pass the same gates as `check_transfer`
    /// against its own allowance. Every amount must be strictly positive and
    /// the request must hold between 1 and `MAX_SPEND_ENTRIES` entries.
    pub fn check_multi_asset_transfer(
        env: Env,
        policy_id: String,
        recipient: Address,
        amounts: Vec<AssetAmount>,
    ) -> Result<(), Error> {
        Self::evaluate_spend(&env, &policy_id, &recipient, &amounts)?;
        Ok(())
    }

    /// Evaluate a multi-asset request exactly as `check_multi_asset_transfer`
    /// and, only if every asset passes, record the spend against each asset's
    /// allowance. Policy `owner` only. A request with one failing asset
    /// records nothing for any asset.
    pub fn record_multi_asset_spend(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
        amounts: Vec<AssetAmount>,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let (totals, updated) = Self::evaluate_spend(&env, &policy_id, &recipient, &amounts)?;
        for allowance in updated.iter() {
            let amount = totals.get(allowance.asset.clone()).ok_or(Error::NotFound)?;
            Self::persist_spend(&env, &allowance, amount);
        }
        Ok(())
    }

    // --- composite rules ---

    /// Register or replace the composite rule tree for a policy.
    ///
    /// The rule tree is evaluated during `check_transfer` **after** all the
    /// standard scalar gates (blocklist, max amount, recipient, asset, etc.)
    /// have passed. If the rule tree evaluates to `false`, the transfer is
    /// denied with [`Error::PolicyDenied`].
    ///
    /// `owner` only. The tree must contain at least one node with the root at
    /// index 0.
    pub fn set_composite_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        rule_tree: RuleTree,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        validate_rule_tree(&rule_tree)?;
        let key = DataKey::CompositeRule(policy_id.clone());
        env.storage().persistent().set(&key, &rule_tree);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_set")),
            policy_id,
        );
        Ok(())
    }

    /// Remove the composite rule tree for a policy (owner only).
    pub fn clear_composite_rule(env: Env, caller: Address, policy_id: String) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::CompositeRule(policy_id.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_clr")),
            policy_id,
        );
        Ok(())
    }

    /// Read the composite rule tree for a policy, if one is set.
    pub fn get_composite_rule(env: Env, policy_id: String) -> Result<RuleTree, Error> {
        let key = DataKey::CompositeRule(policy_id.clone());
        env.storage().persistent().get(&key).ok_or(Error::NotFound)
    }

    /// Evaluate a composite rule tree against a transaction payload.
    ///
    /// Returns `Ok(true)` when the rule permits the transaction, or
    /// `Err(Error::PolicyDenied)` when it denies it. If no composite rule
    /// is registered for the policy the function returns `Ok(true)` (permissive
    /// default — standard scalar gates still apply).
    pub fn evaluate_composite_rule(
        env: Env,
        policy_id: String,
        payload: TransactionPayload,
    ) -> Result<bool, Error> {
        let mut context = RuleEvaluationContext::default();
        Self::evaluate_composite_rule_with_context(&env, &policy_id, &payload, &mut context)
    }

    fn evaluate_composite_rule_with_context(
        env: &Env,
        policy_id: &String,
        payload: &TransactionPayload,
        context: &mut RuleEvaluationContext,
    ) -> Result<bool, Error> {
        let key = DataKey::CompositeRule(policy_id.clone());
        let tree: RuleTree = match env.storage().persistent().get(&key) {
            Some(t) => t,
            None => return Ok(true),
        };
        if tree.is_empty() {
            return Ok(true);
        }
        evaluate_node(env, &tree, 0, payload, MAX_RULE_DEPTH, context)
    }

    // --- multi-rule composition ---

    /// Register an additional rule tree on the policy's rule stack.
    ///
    /// Every rule on the stack is evaluated during `check_transfer` and **all**
    /// of them must pass: the first rule that evaluates to `false`
    /// short-circuits the evaluation and the transfer is denied with
    /// [`Error::PolicyDenied`]. This is how a policy composes independent
    /// governance constraints — e.g. an allow-listed recipient *plus* a maximum
    /// amount — without folding them into a single hand-built tree.
    ///
    /// `owner` only. The tree must be non-empty and structurally sound (see
    /// [`validate_rule_tree`]) so a malformed rule is rejected at write time
    /// rather than aborting evaluation later. Returns the number of rules now
    /// registered for the policy and fails with [`Error::InvalidInput`] once
    /// [`MAX_POLICY_RULES`] rules are stacked.
    pub fn add_policy_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        rule_tree: RuleTree,
    ) -> Result<u32, Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        validate_rule_tree(&rule_tree)?;
        let key = DataKey::PolicyRules(policy_id.clone());
        let mut stack: RuleStack = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if stack.len() >= MAX_POLICY_RULES {
            return Err(Error::InvalidInput);
        }
        stack.push_back(rule_tree);
        let count = stack.len();
        env.storage().persistent().set(&key, &stack);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_add")),
            (policy_id, count),
        );
        Ok(count)
    }

    /// Remove the rule at `index` from the policy's rule stack (owner only).
    ///
    /// The index is bounds-checked against the current stack length, so an
    /// out-of-range removal fails with [`Error::InvalidInput`] instead of
    /// panicking. Removing the last rule drops the storage key entirely.
    pub fn remove_policy_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        index: u32,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::PolicyRules(policy_id.clone());
        let mut stack: RuleStack = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        if index >= stack.len() {
            return Err(Error::InvalidInput);
        }
        stack.remove(index);
        if stack.is_empty() {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &stack);
        }
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_rem")),
            (policy_id, index),
        );
        Ok(())
    }

    /// Drop every registered rule for a policy (owner only).
    pub fn clear_policy_rules(env: Env, caller: Address, policy_id: String) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::PolicyRules(policy_id.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rules_clr")),
            policy_id,
        );
        Ok(())
    }

    /// Read the whole rule stack for a policy. Returns an empty stack when no
    /// rule has been registered yet (permissive default).
    pub fn get_policy_rules(env: Env, policy_id: String) -> RuleStack {
        env.storage()
            .persistent()
            .get(&DataKey::PolicyRules(policy_id))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Evaluate every registered rule against `payload`.
    ///
    /// Rules are combined according to the policy's rule_combination_strategy:
    /// - `All`: All rules must pass (conjunctive, default for backward compatibility)
    /// - `Any`: At least one rule must pass (disjunctive). An empty stack is permissive.
    ///
    /// Malformed trees surface as [`Error::InvalidInput`] (defensive: registration already
    /// validates the shape).
    pub fn evaluate_policy_rules(
        env: Env,
        policy_id: String,
        payload: TransactionPayload,
    ) -> Result<bool, Error> {
        let mut context = RuleEvaluationContext::default();
        let policy = Self::load(&env, &policy_id)?;
        Self::evaluate_policy_rules_with_context(
            &env,
            &policy_id,
            &payload,
            &mut context,
            policy.rule_combination_strategy,
        )
    }

    fn evaluate_policy_rules_with_context(
        env: &Env,
        policy_id: &String,
        payload: &TransactionPayload,
        context: &mut RuleEvaluationContext,
        strategy: PolicyCombinationStrategy,
    ) -> Result<bool, Error> {
        let stack: RuleStack = env
            .storage()
            .persistent()
            .get(&DataKey::PolicyRules(policy_id.clone()))
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));
        let count = stack.len();

        match strategy {
            PolicyCombinationStrategy::All => {
                // All rules must pass (existing behavior)
                for i in 0..count {
                    // `get` bounds-checks the index; a miss means the stack changed
                    // under us, which storage cannot do mid-invocation — fail closed.
                    let tree = stack.get(i).ok_or(Error::InvalidInput)?;
                    if tree.is_empty() {
                        continue;
                    }
                    if !evaluate_node(env, &tree, 0, payload, MAX_RULE_DEPTH, context)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            PolicyCombinationStrategy::Any => {
                // At least one rule must pass (new behavior)
                // If no rules are registered, allow by default
                if count == 0 {
                    return Ok(true);
                }
                for i in 0..count {
                    // `get` bounds-checks the index; a miss means the stack changed
                    // under us, which storage cannot do mid-invocation — fail closed.
                    let tree = stack.get(i).ok_or(Error::InvalidInput)?;
                    if tree.is_empty() {
                        continue;
                    }
                    if evaluate_node(env, &tree, 0, payload, MAX_RULE_DEPTH, context)? {
                        return Ok(true);
                    }
                }
                // No rules passed
                Ok(false)
            }
        }
    }

    // --- views ---

    pub fn get(env: Env, policy_id: String) -> Result<Policy, Error> {
        Self::load(&env, &policy_id)
    }

    // --- internels ---

    fn load(env: &Env, id: &String) -> Result<Policy, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Policy(id.clone()))
            .ok_or(Error::NotFound)
    }

    /// Authenticate `caller` and require it to own `policy_id`.
    fn require_policy_owner(env: &Env, caller: &Address, policy_id: &String) -> Result<(), Error> {
        caller.require_auth();
        if Self::load(env, policy_id)?.owner != *caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Return the `(policy_id, asset)` allowance with `amount` consumed in the
    /// current window, or the error that denies the spend. Nothing is
    /// persisted. `None` means no allowance is configured (limit `0`), so there
    /// is nothing to enforce or record. `amount == headroom` is permitted.
    fn consume_allowance(
        env: &Env,
        policy_id: &String,
        asset: &Address,
        amount: i128,
    ) -> Result<Option<AssetAllowance>, Error> {
        let mut allowance: AssetAllowance = match env
            .storage()
            .persistent()
            .get(&DataKey::Allowance(policy_id.clone(), asset.clone()))
        {
            Some(a) => a,
            None => return Ok(None),
        };
        if allowance.limit == 0 {
            return Ok(None);
        }
        let now = env.ledger().timestamp();
        if allowance.expires_at != 0 && now >= allowance.expires_at {
            events_policy_violation(env, policy_id, "allowance_expired");
            // A lapsed envelope is not a rule denial: the operator's remedy is
            // to renew it, not to loosen the policy. `Error::AllowanceExpired`
            // keeps that distinct from `PolicyDenied` and from
            // `AllowanceExceeded`.
            return Err(Error::AllowanceExpired);
        }
        settle_window(&mut allowance, now)?;
        // Negative when the limit was lowered below what is already spent, in
        // which case every positive amount is rejected.
        let headroom = checked_sub(allowance.limit, allowance.spent)?;
        if amount > headroom {
            events_policy_violation(env, policy_id, "allowance_exceeded");
            return Err(Error::AllowanceExceeded);
        }
        allowance.spent = checked_add(allowance.spent, amount)?;
        Ok(Some(allowance))
    }

    /// Store an allowance returned by [`Self::consume_allowance`] and emit the
    /// `allow_use` event.
    fn persist_spend(env: &Env, allowance: &AssetAllowance, amount: i128) {
        env.storage().persistent().set(
            &DataKey::Allowance(allowance.policy_id.clone(), allowance.asset.clone()),
            allowance,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_use")),
            (
                allowance.policy_id.clone(),
                allowance.asset.clone(),
                amount,
                allowance.spent,
            ),
        );
    }

    /// Sum a multi-asset request per asset. Rejects an empty or oversized
    /// request with [`Error::InvalidInput`], a non-positive entry with
    /// [`Error::InvalidAmount`] and a per-asset total that does not fit an
    /// `i128` with [`Error::Overflow`].
    fn aggregate_amounts(
        env: &Env,
        amounts: &Vec<AssetAmount>,
    ) -> Result<Map<Address, i128>, Error> {
        if amounts.is_empty() || amounts.len() > MAX_SPEND_ENTRIES {
            return Err(Error::InvalidInput);
        }
        let mut totals: Map<Address, i128> = Map::new(env);
        for entry in amounts.iter() {
            require_positive_amount(entry.amount)?;
            let total = checked_add(totals.get(entry.asset.clone()).unwrap_or(0), entry.amount)?;
            totals.set(entry.asset, total);
        }
        Ok(totals)
    }

    /// Validate a whole multi-asset request. Returns the per-asset totals and
    /// the allowance records as they would be after the spend (only for
    /// assets with a configured allowance). Persists nothing.
    fn evaluate_spend(
        env: &Env,
        policy_id: &String,
        recipient: &Address,
        amounts: &Vec<AssetAmount>,
    ) -> Result<(Map<Address, i128>, Vec<AssetAllowance>), Error> {
        let totals = Self::aggregate_amounts(env, amounts)?;
        let policy = Self::load(env, policy_id)?;
        let mut rule_context = RuleEvaluationContext::default();
        // The recipient- and policy-level rules are the same for every leg, so
        // they run once; only the per-asset rules repeat per leg.
        if let Some(reason) =
            Self::screen_recipient_rules(env, policy_id, &policy, recipient, &mut rule_context)?
        {
            Self::report_denial(env, policy_id, reason);
            return Err(reason.to_error());
        }
        let mut updated = Vec::new(env);
        for (asset, total) in totals.iter() {
            let (allowance, denial) = Self::screen_asset_rules(
                env,
                &policy,
                policy_id,
                &asset,
                recipient,
                total,
                &mut rule_context,
            )?;
            if let Some(reason) = denial {
                Self::report_denial(env, policy_id, reason);
                return Err(reason.to_error());
            }
            if let Some(allowance) = allowance {
                updated.push_back(allowance);
            }
        }
        Ok((totals, updated))
    }

    /// The recipient- and policy-level rules, in the order the violation
    /// events have always reported them: enabled → recipient blocklist →
    /// merchant blocklist → recipient whitelist → transfer window → expiry.
    ///
    /// Returns `Ok(None)` when every rule passes, or the first rule that refused
    /// the transfer. Blocklist membership is cached on `context`, so the
    /// composite rule leaves reuse it instead of re-reading storage. Publishes
    /// nothing: the boundary reports the refusal once (Issue #314).
    fn screen_recipient_rules(
        env: &Env,
        policy_id: &String,
        policy: &Policy,
        recipient: &Address,
        context: &mut RuleEvaluationContext,
    ) -> Result<Option<PolicyDenialReason>, Error> {
        // Disabled policies deny every spend.
        if !policy.enabled {
            return Ok(Some(PolicyDenialReason::Disabled));
        }
        // Blocklist checks (Issue #32) — evaluated first, so a compromised or
        // malicious address is rejected before any allowance, asset or amount
        // work is done.
        if context.recipient_blacklisted(env, recipient) {
            return Ok(Some(PolicyDenialReason::RecipientBlacklisted));
        }
        if context.merchant_blacklisted(env, recipient) {
            return Ok(Some(PolicyDenialReason::MerchantBlacklisted));
        }
        // Recipient whitelist: approved destinations only (Issue #63). Runs
        // with the other recipient gates and fails closed: an enabled whitelist
        // with no entries denies every destination.
        if Self::recipient_whitelist_denied(env, policy_id, recipient) {
            return Ok(Some(PolicyDenialReason::RecipientNotWhitelisted));
        }
        // Operating time window: approved hours only. Ledger time is the only
        // trusted clock — `env.ledger().timestamp()` is consensus-provided, so
        // no caller input reaches this comparison. Like every rule in this walk
        // the refusal is published once, at the boundary (Issue #314).
        if !policy.is_within_transfer_window(env.ledger().timestamp()) {
            return Ok(Some(PolicyDenialReason::OutsideTransferWindow));
        }
        if policy.expires_at != 0 && env.ledger().timestamp() >= policy.expires_at {
            return Ok(Some(PolicyDenialReason::Expired));
        }
        Ok(None)
    }

    /// The per-asset rules for one spend of `amount` of `asset`, in order:
    /// single-transaction ceiling → allowed recipient → allowed asset → asset
    /// deny list → asset allow-list → allowance → composite rule → rule stack.
    ///
    /// Returns the allowance record as it would be after the spend (not yet
    /// persisted, see [`Self::consume_allowance`]) together with the first rule
    /// that refused it, if any.
    fn screen_asset_rules(
        env: &Env,
        policy: &Policy,
        policy_id: &String,
        asset: &Address,
        recipient: &Address,
        amount: i128,
        context: &mut RuleEvaluationContext,
    ) -> Result<(Option<AssetAllowance>, Option<PolicyDenialReason>), Error> {
        // The single-transaction ceiling: `max_amount` is the largest amount a
        // single transfer may move (0 = no ceiling).
        if policy.max_amount != 0 && amount > policy.max_amount {
            return Ok((None, Some(PolicyDenialReason::AboveMaxTransactionLimit)));
        }
        if let Some(allow_recip) = &policy.allowed_recipient {
            if allow_recip != recipient {
                return Ok((None, Some(PolicyDenialReason::RecipientNotAllowed)));
            }
        }
        if let Some(allow_asset) = &policy.allowed_asset {
            if allow_asset != asset {
                return Ok((None, Some(PolicyDenialReason::AssetNotAllowed)));
            }
        }
        // The asset deny list wins over every allow gate, so blacklisting an
        // allow-listed or whitelisted asset takes effect immediately.
        if env
            .storage()
            .persistent()
            .has(&DataKey::AssetBlacklist(policy_id.clone(), asset.clone()))
        {
            return Ok((None, Some(PolicyDenialReason::AssetBlacklisted)));
        }
        // Asset allow-list (Issue #37).
        if Self::asset_whitelist_denied(env, policy_id, asset) {
            return Ok((None, Some(PolicyDenialReason::AssetNotWhitelisted)));
        }
        // Multi-token allowance gate: reject a spend that would breach the
        // per-(policy, asset) allowance. An unset allowance is unrestricted.
        // The allowance gate publishes its own violation event, which is why
        // the reason it yields is flagged `self_reported`.
        let allowance = match Self::consume_allowance(env, policy_id, asset, amount) {
            Ok(allowance) => allowance,
            Err(Error::AllowanceExpired) => {
                return Ok((None, Some(PolicyDenialReason::AllowanceExpired)))
            }
            Err(Error::AllowanceExceeded) => {
                return Ok((None, Some(PolicyDenialReason::AllowanceExceeded)))
            }
            Err(other) => return Err(other),
        };
        let payload = TransactionPayload {
            asset: asset.clone(),
            recipient: recipient.clone(),
            amount,
        };
        // Composite rule evaluation: the context carries the blocklist results
        // from `screen_recipient_rules`, so `RecipientBlacklisted` /
        // `MerchantBlacklisted` leaves reuse them instead of re-reading storage
        // on every node.
        if !Self::evaluate_composite_rule_with_context(env, policy_id, &payload, context)? {
            return Ok((None, Some(PolicyDenialReason::CompositeRuleDenied)));
        }
        // Multi-rule stack: evaluation respects the policy's combination
        // strategy. For `All` every registered rule must pass; for `Any` at
        // least one must.
        if !Self::evaluate_policy_rules_with_context(
            env,
            policy_id,
            &payload,
            context,
            policy.rule_combination_strategy,
        )? {
            return Ok((None, Some(PolicyDenialReason::RuleStackDenied)));
        }
        Ok((allowance, None))
    }

    /// Walk every rule for a single transfer and report the granular decision.
    ///
    /// This is the one modular evaluation path behind `check_transfer`, the
    /// dry-run [`Self::evaluate_policy`] and the multi-asset spend evaluation,
    /// so all three can never disagree about which rule refused a transaction.
    /// A refusal is a decision, not an error; only malformed input or broken
    /// state surfaces as `Err`.
    fn evaluate_policy_decision(
        env: &Env,
        policy_id: &String,
        payload: &TransactionPayload,
    ) -> Result<PolicyDecision, Error> {
        let policy = Self::load(env, policy_id)?;
        let max_transaction_amount = policy.max_amount;
        let mut context = RuleEvaluationContext::default();
        if let Some(reason) =
            Self::screen_recipient_rules(env, policy_id, &policy, &payload.recipient, &mut context)?
        {
            return Ok(PolicyDecision::deny(reason, max_transaction_amount));
        }
        let (_, denial) = Self::screen_asset_rules(
            env,
            &policy,
            policy_id,
            &payload.asset,
            &payload.recipient,
            payload.amount,
            &mut context,
        )?;
        match denial {
            Some(reason) => Ok(PolicyDecision::deny(reason, max_transaction_amount)),
            None => Ok(PolicyDecision::allow(max_transaction_amount)),
        }
    }

    /// Publish the violation event for a denial, unless the rule that produced it
    /// already reported itself (see [`PolicyDenialReason::is_self_reported`]).
    fn report_denial(env: &Env, policy_id: &String, reason: PolicyDenialReason) {
        if !reason.is_self_reported() {
            events_policy_violation(env, policy_id, reason.as_str());
        }
    }

    /// Map a granular decision onto the error `check_transfer` has always
    /// reported, publishing the violation event exactly once.
    fn enforce_decision(
        env: &Env,
        policy_id: &String,
        decision: &PolicyDecision,
    ) -> Result<(), Error> {
        match decision.reason() {
            None => Ok(()),
            Some(reason) => {
                Self::report_denial(env, policy_id, reason);
                Err(reason.to_error())
            }
        }
    }
}

/// Allow the interface trait to call `check_transfer` on this contract.
#[contractimpl]
impl PolicyInterface for PolicyContract {
    /// Evaluate a transfer request against the named policy. All gates must pass.
    ///
    /// Blocklist checks run **first** so that compromised or malicious
    /// addresses are rejected immediately, before any allowance, asset or
    /// amount evaluation (Issue #32). The recipient whitelist gate follows in
    /// the same family: while a policy enforces its approved destination
    /// directory, an untrusted recipient is denied with
    /// [`Error::PolicyDenied`].
    ///
    /// The rules themselves live in one modular walk (Issue #314), and this
    /// entrypoint maps its decision onto the error code each rule has always
    /// reported, so existing callers see no change. Callers that want the
    /// granular reason instead of the collapsed code can dry-run
    /// [`PolicyContract::evaluate_policy`], which uses the identical walk.
    fn check_transfer(
        env: Env,
        policy_id: String,
        asset: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        // A transfer moves a strictly positive amount; zero and negative
        // requests are malformed and never reach the policy gates.
        require_positive_amount(amount)?;
        let payload = TransactionPayload {
            asset,
            recipient,
            amount,
        };
        let decision = Self::evaluate_policy_decision(&env, &policy_id, &payload)?;
        Self::enforce_decision(&env, &policy_id, &decision)
    }
}

/// Emit a `PolicyViolation` event with a stable reason symbol, using both the
/// legacy tuple-topic helper and the canonical [`ContractEvent`] schema.
fn events_policy_violation(env: &Env, policy_id: &String, reason: &str) {
    let r = soroban_sdk::Symbol::new(env, reason);
    astroid_shared::events::policy_violation(env, policy_id, r.clone());
    astroid_shared::events::publish(
        env,
        ContractEvent::PolicyViolation {
            policy_id: policy_id.clone(),
            reason: r,
        },
    );
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for PolicyContract {
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
    /// `wasm_hash` must be approved for `ModuleKind::Policy` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Policy,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
