# astroid-policy

Policy contract — hash-verified enforcement of financial rules.

The backend manages human-readable policy JSON (e.g. `{ maxAmount: 25000, recipients: [...], window: {...} }`). This contract stores only:

- a SHA-256 `config_hash` of that JSON (tamper-evidence),
- a small set of scalar gates that are cheap to check on-chain (`max_amount`, `allowed_recipient`, `allowed_asset`, `expires_at`, and the daily operating time window).

The [`check_transfer`](src/lib.rs) entry point evaluates a proposed transfer
against a named policy and returns [`Error::PolicyDenied`] when any gate fails.
Violations emit a `PolicyViolation` event so the backend's analytics / audit
modules can record the block.

## Why hash-verified?

Storing `config_hash` instead of the full JSON keeps storage cost minimal and
makes upgrades fast — the backend rotates the hash when a policy is updated.
Because the recorded max/timing gates live on-chain too, the verification path
stays fully deterministic and cheap.

## Recipient whitelist

A policy can own an on-chain directory of approved destinations. Entries are
stored per policy under `(policy_id, recipient)` and managed dynamically:

- `set_recipient_whitelist_enabled` — turn enforcement on/off (owner-gated).
- `add_recipient_to_whitelist` / `remove_recipient_from_whitelist` — edit the
  directory (owner-gated, duplicate/missing entries are rejected).
- `is_recipient_whitelisted` / `get_recipient_whitelist` — query the directory.
- `evaluate_recipient_whitelist` — evaluation entry point used by
  `check_transfer` for every payload; denies with `Error::PolicyDenied` and a
  `not_whitelisted` violation when an untrusted destination is targeted.

While enforcement is active the gate fails closed: an empty whitelist denies
every recipient. With enforcement off the gate is a no-op, so existing policies
are unaffected until governance opts in.

## Transfer time windows

Agents should only spend during approved operating hours. The owner confines a
policy to a daily window in ledger time:

- `set_transfer_window` — set `start_time` / `end_time` (seconds since
  midnight UTC) repeating every `window_days` seconds (owner-gated).
  `window_days == 0` clears the restriction; the window may wrap over
  midnight (e.g. `22:00 → 06:00`).
- `get_transfer_window` — read back `(start_time, end_time, window_days)`.

While a window is configured, `check_transfer` denies a transaction whose time
of day — always `env.ledger().timestamp()`, never caller input — falls outside
`[start_time, end_time)` with `Error::PolicyDenied` and an `outside_window`
violation event. The start is inclusive, the end exclusive; a zero-length
window (`start == end`) fails closed and allows no time at all. Policies
created before this feature default to no window and behave exactly as before.

## Operations

- `register_policy` — install a new policy.
- `rotate_policy` — replace hash + max threshold (owner-gated).
- `set_enabled` — disable (deny-all) or re-enable.
- `set_transfer_window` — restrict transfers to a daily operating window
  (owner-gated).
- `check_transfer` (via [`PolicyInterface`]) — called by treasury / wallet.
- `set_allowance` / `set_recurring_allowance` — per-(policy, asset) spending
  allowance; with `window_seconds > 0` it is a rate limit of `limit` per fixed
  window (`window_seconds == 0` = cumulative).
- `check_multi_asset_transfer` / `record_multi_asset_spend` — evaluate (and,
  owner-gated, record) one request moving several assets to one recipient.

## Multi-asset and rate-limit rules

- Every amount must be strictly positive (`InvalidAmount`); a request holds
  1–10 entries (`InvalidInput`).
- Entries for the same asset are summed with checked math (`Overflow`) before
  any gate runs, so a spend cannot be split to slip under a limit.
- Each asset is checked against its own gates and allowance only; amounts of
  different assets are never summed or compared (their decimals differ).
- Spending exactly the remaining allowance is allowed; one unit more is
  `AllowanceExceeded`.
- All-or-nothing: if any asset fails, nothing is recorded for any asset.
- Windows are fixed and anchored at `window_start`. With
  `k = (now - window_start) / window_seconds`, `k >= 1` resets `spent` and
  moves `window_start` to `window_start + k * window_seconds`. A request at
  exactly the window end belongs to the new window. Time is always
  `env.ledger().timestamp()`.

## Events

- `("policy", "registd")` on registration.
- `("policy", "rotated")` on rotation.
- `("policy", "timewin")` on operating-window changes.
- `("policy", "wl_mode")` / `("policy", "wl_add")` / `("policy", "wl_rem")` on
  recipient whitelist edits.
- `("policy", "violation")` on every denial, with a short `Symbol` reason.
