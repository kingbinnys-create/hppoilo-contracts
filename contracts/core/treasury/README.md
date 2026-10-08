# astroid-treasury

Treasury contract — custody for organizational funds with policy + budget gates
on every outflow.

## Responsibilities

- `initialize(org, admin)` — DCP deploys the treasury for an org.
- `deposit(from, asset, amount)` — anyone can fund the pot.
- `withdraw(admin, asset, to, amount)` — policy + budget verified, then assets move.
- `set_policy(policy)` / `set_budget(budget)` — wire enforcement contracts.
- `freeze` / `unfreeze` — emergency stop on outflows (multisig only).
- `pause` / `unpause` — circuit breaker: guardian or multisig stops all
  outflows (`Error::TreasuryPaused`) while deposits keep flowing in. A pause
  lapses automatically after `MAX_PAUSE_DURATION` (one month) so a lost
  guardian key cannot strand the treasury forever; indefinite stops must go
  through `freeze`.
- `set_guardian(guardian)` — rotate the account that may pause / unpause.
- `set_registry(registry)` — wire the registry used to verify contract
  callers (Issue #308); `None` clears the gate.
- `allocate_budget(asset, budget_id)` — attach an envelope to an asset.

## Invariants

A withdrawal can only succeed when:
1. The caller is the recorded admin (`require_auth` gated).
2. The circuit breaker is not paused (`Error::TreasuryPaused`).
3. The treasury is not frozen.
4. The policy contract's `check_transfer` passes (when wired).
5. The budget's `consume` does not return `BudgetExceeded` (when wired).
6. The treasury's tracked balance for the asset covers the request.

Deposits are exempt from 2 and 3: inbound funding stays available during an
emergency so the treasury can be replenished while paused or frozen.

A pause older than `MAX_PAUSE_DURATION` no longer blocks outflows (2 stops
applying on its own); the stale flag remains until the next `pause` re-engages
a fresh window or `unpause` clears it and resets the recorded timestamp.

## Registry-verified callers and reentrancy (Issue #308)

Every value path (`deposit`, `withdraw`, `batch_transfer`,
`release_next_milestone`) is additionally guarded by two defenses:

1. **Caller verification.** When a registry is wired (`set_registry`),
   movement calls made *by contract addresses* must resolve to the expected
   module record for the treasury's organization: deposits verify a contract
   depositor against the org's `Wallet` record, outbound movements verify
   their caller against the org's `Multisig` record. Anything else — an
   unregistered contract, a contract registered under a different kind, a
   frozen or otherwise unanswerable registry — is refused deterministically
   with `UnverifiedCaller` (86). Account callers pass through to the ordinary
   role checks, and clearing the registry restores the pre-registry
   behaviour.
2. **Reentrancy lock.** A flag in instance storage is engaged before the
   first external call of a movement and released when it completes; a
   re-entered movement finds the lock engaged and fails with `InvalidState`
   instead of double-spending the ledger. Because the flag lives in instance
   storage, the host rolls it back if the invocation aborts.

Note that Soroban's test address generator mints contract-format addresses,
so unit/integration tests that exercise gated flows must register their test
admin/funder under the expected module kinds (see
`contracts/core/treasury/src/test.rs` and `tests/src/gated_fund_flows.rs`).

## Events

- `("treasury", "deposited")` on every deposit.
- `("transfer", "executed")` on successful withdrawals (shared standard).
- `("treasury", "policy")` / `("treasury", "budget")` when enforcement contracts are wired.
- `("treasury", "paused")` / `("treasury", "unpaused")` when the circuit breaker
  is engaged or released.
- `("treasury", "allow_set")` / `("treasury", "allow_use")` /
  `("treasury", "allow_rem")` across the withdrawal-allowance lifecycle — the
  same schema the policy contract publishes under, each payload ending with
  the ledger timestamp (Issue #222).
- `("treasury", "bgt_alloc")` when a budget envelope is bound to an asset,
  carrying the asset, the budget id and the ledger timestamp (Issue #222).

## Cross-contract flow

```text
Treasury.withdraw ──► PolicyClient (Policy contract)
                  ──► BudgetClient (Budget contract)
                  ──► events::transfer_executed
```

Both dependencies use the typed interfaces in `astroid-interfaces` so the
workspace graph stays acyclic.
