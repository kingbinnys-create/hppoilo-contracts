//! Threshold verification and approval tracking (issue #290).
//!
//! The multisig's whole security property is one sentence: an action runs only
//! once the *distinct* current signers behind it carry at least the configured
//! approval weight. Two ways to break that sentence, and both are closed here:
//!
//! * **The same signer counting twice.** A repeated approval, or the same
//!   address listed repeatedly among batch signatories, would let one key
//!   manufacture a quorum it never earned. Approvals are therefore recorded
//!   once per `(proposal, signer)` pair and rejected as
//!   [`Error::AlreadySigned`] on any repeat, and the running tally is rebuilt
//!   from the approval flags of the *current* signer set rather than by
//!   incrementing a stored counter — so a duplicate cannot stack weight even
//!   if one is somehow written.
//! * **A tally that lies.** Weights are accumulated in `i128` through the
//!   shared [`checked_add`] helper and narrowed back to `u32` only after an
//!   explicit range check ([`narrow`]). An overflowing sum therefore surfaces
//!   as [`Error::Overflow`] instead of wrapping into a *smaller* number that
//!   would silently fail a quorum check — or, worse, wrap into a larger one
//!   that would falsely satisfy it.
//!
//! ## The comparison
//!
//! Execution triggers strictly on `weight >= threshold`: an exact match is
//! enough and exceeding it is never a problem. [`is_met`] is that single
//! predicate, and every quorum decision in the contract resolves through it,
//! so a proposal flow and a batch flow can never disagree about the same tally.
//!
//! Approval state is always read back against the live signer set (see
//! `MultiSigContract::live_tally`), so an approval from a signer who has since
//! been removed stops counting, and a re-weighted signer is credited at their
//! current weight.
//!
//! ## Observability
//!
//! Two events, deliberately distinct so a consumer can tell them apart:
//!
//! * an approval being recorded — published by the entrypoint that recorded it
//!   (`("proposal", "approved")`, `("batch", …)`); and
//! * the threshold actually being met — [`publish_threshold_met`] below, which
//!   fires **once**, on the transition from "short" to "met", carrying the
//!   full verified tally as [`QuorumStatus`].

use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use soroban_sdk::{contracttype, symbol_short, Env, Symbol};

/// The verified tally for a proposal or batch against the current signer set.
///
/// Derived on each check rather than cached, so it is a pure function of
/// on-chain state. It is a `#[contracttype]` because it *is* the payload of the
/// threshold-met event: a consumer gets the numbers that justified execution,
/// not just the fact that it happened.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuorumStatus {
    /// Sum of the current weights of the signers that have approved.
    pub approval_weight: u32,
    /// How many current signers carry an approval — the deduplicated count.
    pub approvers: u32,
    /// The configured approval weight threshold the tally is measured against.
    pub threshold: u32,
    /// Aggregate weight currently registered across the signer set.
    pub total_weight: u32,
    /// Weight still required before the threshold is met; `0` once met.
    pub remaining: u32,
    /// Whether the tally has met or exceeded the threshold.
    pub met: bool,
}

impl QuorumStatus {
    /// Build the verdict for a tally. All arithmetic is saturating or exact —
    /// `remaining` never wraps below zero, so a tally that exceeds the
    /// threshold reports `0` rather than a huge number.
    pub fn evaluate(
        approval_weight: u32,
        approvers: u32,
        threshold: u32,
        total_weight: u32,
    ) -> Self {
        Self {
            approval_weight,
            approvers,
            threshold,
            total_weight,
            remaining: remaining(approval_weight, threshold),
            met: is_met(approval_weight, threshold),
        }
    }

    /// Whether this tally was already short of the threshold — the "before"
    /// half of the transition [`publish_threshold_met`] reports.
    pub fn was_short(&self) -> bool {
        !self.met
    }

    /// Refuse a tally short of the threshold, reporting the caller's own
    /// shortfall code ([`Error::InsufficientWeight`] for proposal approvals,
    /// [`Error::ThresholdNotMet`] for signature-verified batches), so every
    /// quorum decision reports failure in one place.
    pub fn ensure_met(&self, shortfall: Error) -> Result<(), Error> {
        if self.met {
            Ok(())
        } else {
            Err(shortfall)
        }
    }
}

/// Checked accumulation of one signer's weight into a running approval total.
///
/// The sum is computed in `i128` and narrowed only by [`narrow`], so an
/// overflowing weight sum surfaces as [`Error::Overflow`] rather than
/// truncating into a value that could wrongly satisfy (or fail) the threshold.
pub fn add_weight(total: i128, weight: u32) -> Result<i128, Error> {
    checked_add(total, weight as i128)
}

/// Narrow an accumulated `i128` weight back to `u32`, refusing to truncate.
///
/// This is the last line of defence for the tally: any sum above `u32::MAX` is
/// rejected instead of being wrapped down into a smaller number that would
/// wrongly fail a legitimate quorum.
pub fn narrow(total: i128) -> Result<u32, Error> {
    if total > u32::MAX as i128 {
        return Err(Error::Overflow);
    }
    Ok(total as u32)
}

/// Whether a tally has met or exceeded the configured threshold.
///
/// The single threshold predicate in the contract: `>=`, so an exact match is
/// sufficient and exceeding the threshold is never a failure.
pub fn is_met(weight: u32, threshold: u32) -> bool {
    weight >= threshold
}

/// Weight still required before the threshold is met. Saturating at `0`, so a
/// tally that exceeds the threshold reports nothing outstanding.
pub fn remaining(weight: u32, threshold: u32) -> u32 {
    threshold.saturating_sub(weight)
}

/// Quorum verification helper: validate a signer weight sum against the
/// configured threshold, reporting the caller's own shortfall code.
///
/// `sum` is built exclusively through [`add_weight`] and [`narrow`], i.e. it
/// is wrap-free by construction.
pub fn require(sum: u32, threshold: u32, shortfall: Error) -> Result<(), Error> {
    if is_met(sum, threshold) {
        Ok(())
    } else {
        Err(shortfall)
    }
}

/// Publish the threshold-met event for a subject (`(id, tally)`), under the
/// caller's event category — `("proposal", "quorum")` or `("batch", "quorum")`.
///
/// Fired only on the transition from short to met (see [`QuorumStatus::was_short`]),
/// so a stream of further approvals past the threshold does not re-announce a
/// quorum that has already been reached.
pub fn publish_threshold_met(env: &Env, category: Symbol, subject: u64, status: &QuorumStatus) {
    env.events()
        .publish((category, symbol_short!("quorum")), (subject, *status));
}
