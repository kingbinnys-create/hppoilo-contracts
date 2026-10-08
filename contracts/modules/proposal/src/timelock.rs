//! # Proposal time-lock verification (issue #209)
//!
//! Governance is only as safe as the window in which a takeover can be
//! spotted. Executing a freshly-approved proposal in the same block leaves no
//! time for an honest approver to notice and pull support, so the contract
//! refuses to release a proposal until a mandatory cooling-off period has
//! elapsed on the deterministic ledger clock.
//!
//! This module is the single place that arithmetic and comparison for that
//! delay live. Every gate — the `execute` entrypoint, the `can_execute` view
//! and the read-only `release_at` view — resolves through the same functions,
//! so a client that pre-checks can never get an answer the entrypoint would
//! then contradict.
//!
//! ## Release criteria
//!
//! A proposal's release instant is `approved_at + delay`, where
//!
//! * `approved_at` is the ledger timestamp stamped on the record the moment it
//!   reaches `Approved` (`0` while it is still `Pending`), and
//! * `delay` is the protocol-wide timelock in seconds stored once by
//!   [`ProposalContract::initialize`](super::ProposalContract::initialize)
//!   (`0` disables the delay entirely).
//!
//! The clock is `env.ledger().timestamp()` — a value the host fixes once for
//! the whole invocation — so every node evaluating the same ledger derives the
//! identical verdict. Ledger *sequence* moves with it; the delay is expressed
//! in seconds, so the timestamp is the term the comparison uses.
//!
//! ## Boundary
//!
//! The gate is **inclusive at the release instant**: `now == release_at` is
//! already released. One second earlier is not. That is the same convention
//! `require_time_reached` applies protocol-wide, and it is what
//! `release_at - now` reports as the remaining wait.
//!
//! ```text
//! now <  release_at ──▶ Error::TimelockNotExpired (still cooling off)
//! now >= release_at ──▶ released; execution may proceed
//! ```
//!
//! ## Failing closed
//!
//! The release instant must be representable as a ledger timestamp. A
//! misconfigured delay (or an absurd `approved_at`) can make `approved_at +
//! delay` exceed `u64::MAX`; truncating or wrapping that sum would move the
//! threshold into the past and release the proposal the instant it is
//! approved — the exact failure the time-lock exists to prevent. Every
//! arithmetic path here therefore goes through the shared checked helpers and
//! reports [`Error::Overflow`] instead, so an unrepresentable deadline is a
//! refusal, never a premature release.

use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use soroban_sdk::{contracttype, Env};

/// The verdict of the time-lock check for one proposal on the current ledger.
///
/// Derived on demand from the stored record and the configured delay rather
/// than cached, so the answer is a pure function of on-chain state. A
/// `#[contracttype]` so the very same verdict is readable on-chain through the
/// `timelock_status` view, letting a client tell *how long* remains instead of
/// only that the attempt was refused.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeLockStatus {
    /// The proposal's approval timestamp (`0` while it is not yet approved).
    pub approved_at: u64,
    /// The protocol-wide delay in seconds this check was run against.
    pub delay: u64,
    /// The earliest ledger timestamp at which the proposal may execute; `0`
    /// when the time-lock is not armed.
    pub release_at: u64,
    /// Seconds still to wait before `release_at`; `0` once released (and `0`
    /// whenever the time-lock is not armed). Saturating, so an elapsed delay
    /// never wraps into a huge number.
    pub remaining: u64,
    /// Whether the time-lock is armed at all: a non-zero delay on a proposal
    /// that has already been approved. An unarmed time-lock never blocks.
    pub armed: bool,
    /// Whether the cooling-off period has elapsed on the current ledger.
    pub released: bool,
}

impl TimeLockStatus {
    /// Whether the time-lock is still holding the proposal back — armed and
    /// not yet released. The exact condition
    /// [`require_released`](super::timelock::require_released) refuses.
    pub fn blocking(&self) -> bool {
        self.armed && !self.released
    }
}

/// Whether `delay` bytes of cooling-off actually gate a proposal stamped at
/// `approved_at`.
///
/// A `0` delay is the documented "disabled" configuration and a `0`
/// `approved_at` means the proposal has not been approved yet, so there is no
/// instant to wait from. Both leave the time-lock unarmed, and an unarmed
/// time-lock must never block execution.
pub fn is_armed(approved_at: u64, delay: u64) -> bool {
    delay != 0 && approved_at != 0
}

/// The release instant: `approved_at + delay`, in ledger timestamp seconds.
///
/// Computed with the shared checked helpers and required to be representable
/// as a `u64` ledger timestamp. An unrepresentable sum fails closed with
/// [`Error::Overflow`] rather than truncating into the past, which would
/// release the proposal the moment it is approved.
///
/// Returns `0` — the "nothing to wait for" sentinel the `release_at` view
/// reports — when the time-lock is not armed, so callers never have to
/// special-case a disabled delay.
pub fn release_at(approved_at: u64, delay: u64) -> Result<u64, Error> {
    if !is_armed(approved_at, delay) {
        return Ok(0);
    }
    let release = checked_add(approved_at as i128, delay as i128)?;
    u64::try_from(release).map_err(|_| Error::Overflow)
}

/// Evaluate the full time-lock verdict for a proposal on the current ledger.
///
/// One call derives every field the views and the enforcement gate need, so
/// they cannot disagree: [`time_lock_status`][self] is the single source and
/// [`is_released`] and [`remaining`] are read straight off its result.
pub fn time_lock_status(env: &Env, approved_at: u64, delay: u64) -> Result<TimeLockStatus, Error> {
    let armed = is_armed(approved_at, delay);
    let release_at = release_at(approved_at, delay)?;
    let now = env.ledger().timestamp();
    let released = !armed || now >= release_at;
    // Saturating: a delay that has elapsed reports `0`, never a wrap.
    let remaining = if released {
        0
    } else {
        release_at.saturating_sub(now)
    };
    Ok(TimeLockStatus {
        approved_at,
        delay,
        release_at,
        remaining,
        armed,
        released,
    })
}

/// Whether the cooling-off period for `approved_at` / `delay` has elapsed on
/// the current ledger. An unarmed time-lock is always released.
#[cfg(test)]
pub fn is_released(env: &Env, approved_at: u64, delay: u64) -> Result<bool, Error> {
    Ok(time_lock_status(env, approved_at, delay)?.released)
}

/// Whether the time-lock is still holding the proposal back on the current
/// ledger — the predicate behind every premature-execution refusal.
#[cfg(test)]
pub fn is_active(env: &Env, approved_at: u64, delay: u64) -> Result<bool, Error> {
    Ok(time_lock_status(env, approved_at, delay)?.blocking())
}

/// The enforcement block: refuse while the time-lock is still running.
///
/// Returns `Ok(())` once `now >= approved_at + delay`, and the deterministic
/// protocol-wide [`Error::TimelockNotExpired`] for any attempt made before the
/// stored release criteria are met. A disabled time-lock passes immediately.
///
/// An unrepresentable release instant propagates [`Error::Overflow`] — the
/// check fails closed rather than releasing early.
///
/// This is the gate [`ProposalContract::execute`](super::ProposalContract::execute)
/// applies, so the error a caller sees is exactly the error this function
/// returns.
pub fn require_released(env: &Env, approved_at: u64, delay: u64) -> Result<(), Error> {
    let status = time_lock_status(env, approved_at, delay)?;
    if status.blocking() {
        return Err(Error::TimelockNotExpired);
    }
    Ok(())
}
