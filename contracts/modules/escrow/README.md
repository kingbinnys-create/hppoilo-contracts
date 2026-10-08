# astroid-escrow

Escrow contract — temporary custody until a designated arbiter resolves the
release condition. A single agreement can hold several distinct Stellar
assets, and can optionally require multi-party sign-off before the recipient is
paid, and/or be released early by a set of pre-configured ed25519 signers
instead of the named arbiter.

```text
funder ──► create(sender, recipient, arbiter, assets[], deadline, memo,
                   release_signers[], release_threshold) ──► Escrow-Funded
       │
       └─► create_with_release_condition(config{participants[],
                                    approval_threshold})  ──► Escrow-Funded
              │
              ├─► participant.approve_release(id)  (x N) ──► threshold met
              │
              ├─► arbiter.release(id)                     ──► Released ──► assets move
              ├─► override_release(id, nonce, signatures) ──► Released ──► assets move
              ├─► sender.refund(id)                       ──► Refunded   (after deadline)
              └─► sender.cancel / refund_timelock / reclaim (never gated)
```

## State machine

`Created → Funded → (Released | Refunded | Expired) → Closed`

- `create` funds immediately (atomic in a single call), pulling every listed
  `(asset, amount)` pair into custody.
- `release` requires the arbiter and a live deadline.
- `override_release` requires at least `release_threshold` distinct, valid
  ed25519 signatures from `release_signers`, each over a deterministic
  payload (contract address, network id, escrow id, nonce), and a live
  deadline. It is permissionless — the signatures are the authorization, so
  any relayer may submit them. Pass an empty signer set (and threshold `0`)
  at `create` time to disable this path for an escrow.
- `refund` requires the recorded sender and opens once the escrow has timed
  out: before `deadline` it fails with `TimeLockActive` (81), during the
  grace period with `GraceActive` (82), and from `deadline + grace_period`
  (inclusive, by ledger timestamp) it returns the funds to the sender. That is
  the same instant `release` starts failing with `EscrowExpired` (80), so the
  release and refund windows never overlap.
- `close` (terminal) requires one of the three roles once the escrow is final.

## Time-lock release schedules

Escrows created through `create_timelock`, `create_scheduled` or
`initialize_timelock` carry a release schedule that is enforced on the ledger
clock (`env.ledger().timestamp()`) on every value-leaving path:

- `Cliff` schedules unlock 100% at `cliff_time` (= `end_time`); `Linear`
  schedules vest continuously between `start_time` and `end_time`, with an
  optional cliff.
- `withdraw` / `claim` are the beneficiary's partial-payout paths: they pay
  exactly the amount vested minus already released, and fail with
  `TimeLockActive` (81) while nothing is claimable.
- The arbiter's `release` and the signature-override path settle the escrow
  in full, so they are refused with `TimeLockActive` (81) while the
  outstanding balance has not fully vested on a `Linear` schedule, and
  before `cliff_time` on either schedule kind.
- `cancel` cannot route around the lock either: a scheduled escrow may only
  be cancelled while nothing has vested.
- Settlement paths move the remaining custody balance (funded minus released)
  pro-rata across the assets, so a release following partial withdrawals
  never over-draws custody.
- `is_unlocked(id)` reports whether the schedule has matured at the current
  ledger time so clients need not recompute it off-chain.

## Multi-party release conditions

`create_with_release_condition` takes the full creation argument set plus two
extra fields, `participants` (an allow-list of `Address`es) and
`approval_threshold`, and stores them as a `ReleaseCondition` beside the
escrow. Each participant then signs off on its own Soroban account via
`approve_release(id)`, which returns the running approval count. Once
`approvals >= approval_threshold`, the recipient can be paid.

The condition is **additive, not substitutive**: it never replaces the arbiter
or the override signatures, so a caller has to clear both gates. It is checked
on every path that moves value *to the recipient* on an escrow that carries one —
`release`, `override_release`, `claim` and `withdraw` — and is always
the last check before the first state mutation, so it can only ever prevent a
payout that would otherwise have succeeded (it never masks a more specific
error such as an expired deadline, an active time lock, or a double release).
Milestone escrows come from `deposit_with_milestones`, which never records a
condition, so `release_milestone` needs no gate.

The sender side is deliberately **not** gated. `cancel`, `refund`,
`refund_timelock` and `reclaim` stay open regardless of the approval count, so
a multi-party escrow can delay a payout but can never lock up the funder's
money — a condition on a stale dispute always still resolves back to the
depositor.

- Approvals require the caller's own `require_auth`, so no relayer can vote on
  a participant's behalf, and only while the escrow is `Funded` — a settled
  escrow has nothing left to sign off on.
- Approvals are recorded one storage key per participant, so a repeat approval
  fails with `AlreadySigned` (62) and can never inflate the count.
- A caller outside the participant set fails with `NotASigner` (63); an
  unmet threshold fails the payout with `ThresholdNotMet` (61).
- Creating with more than `MAX_SIGNERS` participants fails with
  `TooManySigners` (66); a threshold outside `[1, participants.len()]`, or a
  non-zero threshold with no participants, fails with `InvalidThreshold` (64);
  repeated participants fail with `InvalidInput` (4). The set is validated
  *before* any tokens move.
- An empty participant list with a `0` threshold records no condition at all,
  so such an escrow behaves exactly like one from `create` and pays nothing for
  the extra key.
- `get_release_condition` returns the stored condition (or `NotFound`), and
  `release_approvals` returns the participants that have signed off, in
  declaration order. `approve_release` also emits an
  `("escrow", "approval")` event carrying `(id, caller, approvals, threshold)`.

Because the condition lives under its own storage key rather than inside the
`Escrow` struct, single-party escrows neither read nor write it, and escrows
written by an earlier deployment keep deserializing after an upgrade.

## Invariants

- Caller must be the recorded role for `release` / `refund` / `close`.
- Every asset amount must be positive (shared `require_positive_amount`), the
  asset list may not be empty, exceed `MAX_ESCROW_ASSETS`, or repeat an asset.
- Releasing after the deadline auto-marks the escrow `Expired` and aborts.
- Override signatures must come from distinct, pre-configured signers and
  meet the threshold; a nonce is only accepted once and must strictly
  increase per escrow, which makes a captured signature set unusable a
  second time (replay protection).
- No path to the recipient's balance skips an unmet release condition, and no
  sender-side exit is blocked by one.
- `EscrowReleased` is emitted (via the shared, structured event schema)
  detailing the escrow id, recipient and every asset transferred, on both the
  arbiter and signature-override release paths.

## Use-cases

- Milestone payments between ON-CHAIN purchased services.
- Agent-to-agent micro-settlement with audit trail.
- Marketplace / freelance payouts where a human arbiter adjudicates.
- Settlement that needs several independent sign-offs (buyer agent, seller
  agent and a validator oracle) before the recipient is paid.
