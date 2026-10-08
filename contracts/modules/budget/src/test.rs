#![cfg(test)]
extern crate std;

use crate::{AssetSpend, Budget, BudgetContract, BudgetContractClient, Period};
use astroid_shared::constants::MAX_BATCH_TOKENS;
use astroid_shared::errors::{BudgetError, Error};
use astroid_shared::types::ResourceState;
use soroban_sdk::testutils::Events;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{vec, Address, Env, IntoVal, String, Symbol, Val, Vec};

struct Harness {
    env: Env,
    client: BudgetContractClient<'static>,
    owner: Address,
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let contract_id = env.register_contract(None, BudgetContract);
    let client = BudgetContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let owner = Address::generate(&env);
    Harness { env, client, owner }
}

fn id(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

#[test]
fn allocate_creates_active_budget() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.limit, 1_000);
    assert_eq!(b.spent, 0);
    assert_eq!(b.state, ResourceState::Active);
    assert!(!b.rollover_enabled);
    assert_eq!(b.rollover_credit, 0);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
}

#[test]
fn duplicate_allocation_fails() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let res = h.client.try_allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &2_000,
        &Period::None,
        &false,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn consume_reduces_remaining() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &400);
    assert_eq!(rem, 600);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 600);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.spent, 400);
}

#[test]
fn over_budget_consume_fails_budget_exceeded() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &800);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &300);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
    // Spend up to the exact limit is allowed.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &200);
    assert_eq!(rem, 0);
}

#[test]
fn consume_zero_or_negative_rejected() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &0);
    assert_eq!(res, Err(Ok(BudgetError::InvalidAmount)));
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &-5);
    assert_eq!(res, Err(Ok(BudgetError::InvalidAmount)));
}

#[test]
fn non_owner_cannot_consume() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let stranger = Address::generate(&h.env);
    let res = h.client.try_consume(&stranger, &id(&h.env, "eng"), &100);
    assert_eq!(res, Err(Ok(BudgetError::Unauthorized)));
}

#[test]
fn reset_clears_spent() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &900);
    h.client.reset(&h.owner, &id(&h.env, "eng"));
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
}

#[test]
fn frozen_budget_rejects_consume() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.freeze(&h.owner, &id(&h.env, "eng"));
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(res, Err(Ok(BudgetError::BudgetFrozen)));
    // Unfreeze restores spending.
    h.client.unfreeze(&h.owner, &id(&h.env, "eng"));
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(rem, 900);
}

#[test]
fn archived_budget_rejects_consume() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.archive(&h.owner, &id(&h.env, "eng"));
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(res, Err(Ok(BudgetError::BudgetArchived)));
}

#[test]
fn daily_budget_auto_resets_after_window() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Daily,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000);
    // Exhausted within the window.
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
    // Advance one full day; the window rolls over and spending resets.
    h.env.ledger().set_timestamp(1_000 + 86_400);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &250);
    assert_eq!(rem, 750);
}

#[test]
fn rollover_carries_unspent_into_next_period() {
    let h = setup();
    // Weekly budget with rollover enabled, starting at t=1_000.
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 400);
    // Advance past the weekly window; unspent (400) rolls over into the new period.
    h.env.ledger().set_timestamp(1_000 + 604_800);
    // New effective capacity = base limit (1000) + rollover credit (400) = 1400.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 400);
    assert_eq!(b.spent, 0);
    // Can now spend up to 1400.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &1_400);
    assert_eq!(rem, 0);
}

#[test]
fn rollover_disabled_clears_unspent() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    h.env.ledger().set_timestamp(1_000 + 604_800);
    // Rollover disabled: unspent is cleared, capacity stays at the base limit.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 0);
}

#[test]
fn explicit_rollover_requires_owner() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    // Stranger cannot trigger rollover.
    let stranger = Address::generate(&h.env);
    let res = h.client.try_rollover(&stranger, &id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    // Owner advances ledger and triggers rollover explicitly.
    h.env.ledger().set_timestamp(1_000 + 604_800);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
}

#[test]
fn expired_budget_rejects_consume() {
    let h = setup();
    // Expires at t = 10_000.
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &10_000,
    );
    // Before expiry, spending works.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(rem, 900);
    // Past expiry, consumption is rejected.
    h.env.ledger().set_timestamp(20_000);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExpired)));
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 0);
}

#[test]
fn expired_budget_rejects_reset_and_set_limit() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &10_000,
    );
    h.env.ledger().set_timestamp(20_000);
    let res = h.client.try_reset(&h.owner, &id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
    let res = h.client.try_set_limit(&h.owner, &id(&h.env, "eng"), &2_000);
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
}

#[test]
fn set_limit_below_spent_rejected() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    let res = h.client.try_set_limit(&h.owner, &id(&h.env, "eng"), &500);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    // Raising the limit works and increases remaining.
    h.client.set_limit(&h.owner, &id(&h.env, "eng"), &2_000);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
}

#[test]
fn transfer_allocation_moves_unspent_limit() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.allocate(
        &h.owner,
        &id(&h.env, "ops"),
        &500,
        &Period::None,
        &false,
        &0,
    );
    h.client
        .transfer_allocation(&h.owner, &id(&h.env, "eng"), &id(&h.env, "ops"), &300);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 700);
    assert_eq!(h.client.remaining(&id(&h.env, "ops")), 800);
}

#[test]
fn transfer_allocation_over_available_fails() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.allocate(
        &h.owner,
        &id(&h.env, "ops"),
        &500,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &900);
    // Only 100 unspent remains in "eng".
    let res =
        h.client
            .try_transfer_allocation(&h.owner, &id(&h.env, "eng"), &id(&h.env, "ops"), &200);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));
}

#[test]
fn get_missing_budget_fails_not_found() {
    let h = setup();
    let res = h.client.try_get(&id(&h.env, "nope"));
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

// ---------------------------------------------------------------------------
// Recurring allowance hooks
// ---------------------------------------------------------------------------

const DAY: u64 = 86_400;
const WEEK: u64 = 604_800;
const MONTH: u64 = astroid_shared::constants::SECONDS_PER_MONTH;

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

/// Allocate a budget under the harness owner with the common defaults.
fn allocate(h: &Harness, budget_id: &str, limit: i128, period: Period, rollover: bool) {
    h.client.allocate(
        &h.owner,
        &id(&h.env, budget_id),
        &limit,
        &period,
        &rollover,
        &0,
    );
}

#[test]
fn several_elapsed_periods_are_all_settled_at_once() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    // Nobody touches the budget for three whole weeks.
    h.env.ledger().set_timestamp(1_000 + 3 * WEEK);

    // Week 1 leaves 400 unspent; weeks 2 and 3 went by entirely unspent and
    // contribute a full base limit each: 400 + 1_000 + 1_000 = 2_400 credit.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000 + 2_400);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 2_400);
    // Rollover does not compound across the gap: the credit is the sum of the
    // per-window parts (see the #246 gap-semantics decision in lib.rs), not a
    // surplus rebased on ever-larger capacity in each lapsed window.
    assert_eq!(b.rollover_credit, 400 + 2 * 1_000);
    assert_ne!(b.rollover_credit, 400 + 2 * 1_400);
    assert_eq!(b.spent, 0);
    // The window is re-anchored to the period boundary, not to "now".
    assert_eq!(b.window_start, 1_000 + 3 * WEEK);
}

#[test]
fn several_elapsed_periods_without_rollover_reset_once() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    h.env.ledger().set_timestamp(1_000 + 5 * WEEK);
    // No rollover: idle periods accrue nothing, the budget simply starts over.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 0);
    assert_eq!(b.window_start, 1_000 + 5 * WEEK);
}

#[test]
fn windows_do_not_drift_when_transitions_land_mid_period() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);

    // A query part-way through the second day settles day one only, and anchors
    // the window to the day boundary rather than to the moment of the query.
    h.env.ledger().set_timestamp(1_000 + DAY + 100);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    assert_eq!(h.client.get(&id(&h.env, "eng")).window_start, 1_000 + DAY);

    // Because the anchor did not drift, the next reset still falls due on the
    // original schedule.
    h.env.ledger().set_timestamp(1_000 + 2 * DAY);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &10);
    assert_eq!(
        h.client.get(&id(&h.env, "eng")).window_start,
        1_000 + 2 * DAY
    );
}

#[test]
fn consecutive_rollovers_do_not_double_count_credit() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);

    // Week 1 goes by entirely unspent, so the whole base allowance carries as
    // credit and the week-2 capacity is 1_000 + 1_000 = 2_000.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 2_000);

    // Spend that entire rolled-over capacity during week 2.
    assert_eq!(h.client.consume(&h.owner, &id(&h.env, "eng"), &2_000), 0);

    // Nothing is left to carry, so week 3 must fall back to the base limit.
    // Re-adding the prior credit on the transition would leave a phantom 1_000
    // in `rollover_credit` and hand the agent an unearned second allowance.
    h.env.ledger().set_timestamp(1_000 + 2 * WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 0);
    assert_eq!(b.spent, 0);
}

#[test]
fn consecutive_rollovers_carry_only_the_unspent_remainder() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);

    // Week 1 idle -> credit 1_000, so week 2 starts with a 2_000 capacity.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 2_000);

    // Spend 1_500 of it, leaving 500 to carry into week 3.
    assert_eq!(h.client.consume(&h.owner, &id(&h.env, "eng"), &1_500), 500);

    h.env.ledger().set_timestamp(1_000 + 2 * WEEK);
    // Capacity is base 1_000 + remaining 500 = 1_500, not 2_500.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_500);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 500);
}

#[test]
fn multi_period_jump_settles_remnant_and_idle_periods_once() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);

    // Settle week 1 first so a non-zero credit is already in force.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 2_000);
    assert_eq!(h.client.get(&id(&h.env, "eng")).window_start, 1_000 + WEEK);

    // Jump three more whole weeks untouched. Week 2 contributes its unspent
    // 2_000 capacity; weeks 3 and 4 each contribute a full base limit (1_000).
    h.env.ledger().set_timestamp(1_000 + 4 * WEEK);
    // The check itself settles the jump; `get` then reflects the new state.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 5_000);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 4_000);
    // The window is still anchored to the original weekly boundary.
    assert_eq!(
        h.client.get(&id(&h.env, "eng")).window_start,
        1_000 + 4 * WEEK
    );
}

#[test]
fn rollover_credit_is_clamped_to_its_cap() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // Cap the accrual at 1_500 so a long idle stretch cannot build up a
    // balance the agent could drain in a single period.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &1_500,
        &0,
    );

    h.env.ledger().set_timestamp(1_000 + 10 * WEEK);
    // Uncapped this would be 10_000; the cap holds it at 1_500.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000 + 1_500);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 1_500);
}

#[test]
fn custom_period_recurs_on_its_configured_interval() {
    let h = setup();
    allocate(&h, "agent", 1_000, Period::None, false);
    // An hourly agent allowance.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "agent"),
        &Period::Custom,
        &3_600,
        &false,
        &0,
        &0,
    );
    let b: Budget = h.client.get(&id(&h.env, "agent"));
    assert_eq!(b.period, Period::Custom);
    assert_eq!(b.period_seconds, 3_600);

    h.client.consume(&h.owner, &id(&h.env, "agent"), &1_000);
    assert_eq!(h.client.remaining(&id(&h.env, "agent")), 0);

    // Just short of the hour the allowance is still exhausted.
    h.env.ledger().set_timestamp(1_000 + 3_599);
    assert_eq!(h.client.remaining(&id(&h.env, "agent")), 0);

    // On the hour it replenishes.
    h.env.ledger().set_timestamp(1_000 + 3_600);
    assert_eq!(h.client.remaining(&id(&h.env, "agent")), 1_000);
}

#[test]
fn custom_period_requires_an_interval() {
    let h = setup();
    allocate(&h, "agent", 1_000, Period::None, false);
    let res = h.client.try_set_recurrence(
        &h.owner,
        &id(&h.env, "agent"),
        &Period::Custom,
        &0,
        &false,
        &0,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));

    let res = h.client.try_set_recurrence(
        &h.owner,
        &id(&h.env, "agent"),
        &Period::Daily,
        &0,
        &true,
        &-1,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn set_recurrence_settles_the_old_policy_before_switching() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &400);

    // A day has already turned over when the cadence is changed to weekly.
    h.env.ledger().set_timestamp(1_000 + DAY);
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,
        &0,
    );

    // The reset owed under the daily policy was applied, not discarded.
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.period, Period::Weekly);
    assert_eq!(b.spent, 0);
    assert_eq!(b.rollover_credit, 600);
    // ...and the new cadence counts from the switch.
    assert_eq!(b.window_start, 1_000 + DAY);
}

#[test]
fn set_recurrence_requires_the_owner() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);
    let stranger = Address::generate(&h.env);
    let res = h.client.try_set_recurrence(
        &stranger,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &false,
        &0,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn disabling_rollover_drops_accrued_credit() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &200);
    h.env.ledger().set_timestamp(1_000 + WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_800);

    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &false,
        &0,
        &0,
    );
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 0);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
}

#[test]
fn consume_across_a_boundary_spends_the_replenished_allowance() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &900);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &200);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // The disbursement itself evaluates the transition hook, so the very first
    // spend of the new period already sees the replenished allowance.
    h.env.ledger().set_timestamp(1_000 + DAY);
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &200);
    assert_eq!(rem, 800);
}

#[test]
fn rollover_and_reset_events_are_emitted() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    h.env.ledger().set_timestamp(1_000 + WEEK);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_event(&h.env, "BudgetUpdated");
}

// ---------------------------------------------------------------------------
// Period transition boundaries (issue #46): the rollover hook must settle
// exactly when — and only when — a boundary is crossed, must settle lazily and
// idempotently off the ledger timestamp, and must never hand out more
// allowance than the budget was actually granted.
// ---------------------------------------------------------------------------

/// One second short of the boundary the old period still stands; on the exact
/// boundary it turns over; one second later the *new* period still stands
/// (no second reset). Every assertion is driven by `env.ledger().timestamp()`.
#[test]
fn daily_window_rolls_on_the_exact_boundary_timestamp() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000);

    h.env.ledger().set_timestamp(1_000 + DAY - 1);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 0);
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.spent, 1_000);
    assert_eq!(b.window_start, 1_000);

    // The exact boundary is inclusive: the period turns over at
    // `window_start + window`, not one second later.
    h.env.ledger().set_timestamp(1_000 + DAY);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.spent, 0);
    assert_eq!(b.window_start, 1_000 + DAY);

    h.env.ledger().set_timestamp(1_000 + DAY + 1);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    assert_eq!(h.client.get(&id(&h.env, "eng")).window_start, 1_000 + DAY);
}

/// The transition is evaluated lazily: raw storage keeps the old period until
/// a view or a disbursement runs the hook, and running the hook again is a
/// no-op rather than a second reset.
#[test]
fn transitions_settle_lazily_and_idempotently() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    // Nobody touched the budget a day later: storage still shows period one.
    h.env.ledger().set_timestamp(1_000 + DAY + 100);
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.spent, 600);
    assert_eq!(b.window_start, 1_000);

    // First read settles exactly one period and persists it.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.spent, 0);
    assert_eq!(b.rollover_credit, 400);
    assert_eq!(b.window_start, 1_000 + DAY);

    // Idempotent: a second read changes nothing.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
    assert_eq!(h.client.get(&id(&h.env, "eng")).window_start, 1_000 + DAY);
}

/// Regression: the closing balance *replaces* the carried credit instead of
/// stacking on top of it. Compounding would let an untouched budget inflate
/// its ceiling past everything it was ever granted.
#[test]
fn rollover_credit_does_not_compound_across_consecutive_periods() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    // Period 1 closes with 400 unspent.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 400);

    // Period 2 closes untouched: 1_000 fresh + 400 carried = 1_400, never 1_800.
    h.env.ledger().set_timestamp(1_000 + 2 * WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 2_400);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 1_400);

    // Period 3 closes untouched: 1_000 fresh + 1_400 carried = 2_400.
    h.env.ledger().set_timestamp(1_000 + 3 * WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 3_400);
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 2_400);
    assert_eq!(b.spent, 0);
    assert_eq!(b.window_start, 1_000 + 3 * WEEK);

    // The whole carried balance is spendable in one call — and not a unit more.
    assert_eq!(h.client.consume(&h.owner, &id(&h.env, "eng"), &3_400), 0);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
}

/// Catch-up across several missed periods on top of an existing credit: every
/// period is settled, idle ones contribute one base limit each, and the window
/// lands on the schedule rather than on the moment of the call.
#[test]
fn catch_up_settles_every_period_when_credit_is_already_carried() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    // Period 1 settles: credit 400, anchored to the first boundary.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);

    // Three more weeks pass untouched: period 2 closes with 1_400 unspent,
    // periods 3 and 4 went by fully unspent and add one base limit each.
    h.env.ledger().set_timestamp(1_000 + 4 * WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000 + 3_400);
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 3_400);
    assert_eq!(b.spent, 0);
    assert_eq!(b.window_start, 1_000 + 4 * WEEK);
}

/// A budget spent to the limit every single period never accrues credit, no
/// matter how many transitions it goes through.
#[test]
fn full_spend_each_period_never_accrues_rollover_credit() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, true);
    for i in 0..5u64 {
        let now = 1_000 + i * DAY;
        h.env.ledger().set_timestamp(now);
        assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
        assert_eq!(h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000), 0);
        let b = h.client.get(&id(&h.env, "eng"));
        assert_eq!(b.rollover_credit, 0);
        assert_eq!(b.window_start, now);
    }
}

/// The cap is re-applied on *every* transition, so settling period by period
/// can never overshoot it the way a long catch-up would.
#[test]
fn rollover_cap_holds_when_periods_are_settled_one_at_a_time() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &1_500,
        &0, // percentage ceiling uncapped
    );
    let expected = [1_000i128, 1_500, 1_500, 1_500, 1_500];
    for (i, credit) in expected.iter().enumerate() {
        h.env.ledger().set_timestamp(1_000 + (i as u64 + 1) * WEEK);
        assert_eq!(
            h.client.remaining(&id(&h.env, "eng")),
            1_000 + *credit,
            "period {} over- or undershot the cap",
            i + 1
        );
        assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, *credit);
    }
}

/// Tightening the cap mid-period can leave `spent` above the new capacity.
/// That shortfall must not be carried as a negative credit — it would pin the
/// budget to a reduced (even negative) ceiling for every period after.
#[test]
fn a_shortfall_is_never_carried_as_negative_credit() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // Period 1 idle -> credit 1_000, so period 2 has a 2_000 capacity.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 2_000);
    assert_eq!(h.client.consume(&h.owner, &id(&h.env, "eng"), &2_000), 0);

    // The owner tightens the cap to 100 while 2_000 is still spent: the new
    // capacity (1_100) is now below what has already been spent.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &100,
        &0, // percentage ceiling uncapped
    );
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 100);

    // On the next boundary the shortfall carries as zero, so the budget falls
    // back to its base limit instead of carrying a negative allowance.
    h.env.ledger().set_timestamp(1_000 + 2 * WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 0);
    assert_eq!(b.spent, 0);
    assert_eq!(b.window_start, 1_000 + 2 * WEEK);
}

#[test]
fn monthly_window_resets_on_its_boundary() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Monthly, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000);

    h.env.ledger().set_timestamp(1_000 + MONTH - 1);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 0);

    h.env.ledger().set_timestamp(1_000 + MONTH);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    assert_eq!(h.client.get(&id(&h.env, "eng")).window_start, 1_000 + MONTH);
}

/// `Period::None` has no window: the elapsed-time check must be a no-op.
#[test]
fn one_shot_budget_never_rolls_over() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::None, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    h.env.ledger().set_timestamp(1_000 + 10 * DAY);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 400);
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.spent, 600);
    assert_eq!(b.window_start, 1_000);
}

/// Expiration and a rollover boundary that land on the same timestamp must
/// resolve the same way every time: expiration is checked first, so the budget
/// dies instead of quietly opening a fresh window.
#[test]
fn expiry_at_the_rollover_boundary_wins_deterministically() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Daily,
        &false,
        &(1_000 + DAY),
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000);

    h.env.ledger().set_timestamp(1_000 + DAY - 1);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 0);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    h.env.ledger().set_timestamp(1_000 + DAY);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExpired)));
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 0);
    // No reset was granted: the expired budget still holds its old window.
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.spent, 1_000);
    assert_eq!(b.window_start, 1_000);
}

// --- per-asset recurring limits ---

#[test]
fn per_asset_limit_replenishes_on_its_own_window() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    // 100 per hour for this token.
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &100, &3_600);

    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &80);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 20);
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &30);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // The hour turns over and the per-asset allowance is whole again.
    h.env.ledger().set_timestamp(1_000 + 3_600);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 100);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 0);
    let b = h.client.get_asset_budget(&id(&h.env, "eng"), &token);
    assert_eq!(b.window_start, 1_000 + 3_600);
    assert_eq!(b.window_seconds, 3_600);
}

/// Same boundary rule as the envelope budget: the per-asset window turns over
/// on `window_start + window_seconds` exactly, and the anchor stays on that
/// boundary instead of drifting to the moment of the spend.
#[test]
fn per_asset_window_rolls_on_the_exact_boundary_timestamp() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &100, &3_600);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);

    h.env.ledger().set_timestamp(1_000 + 3_600 - 1);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 0);
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    h.env.ledger().set_timestamp(1_000 + 3_600);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 100);
    let b = h.client.get_asset_budget(&id(&h.env, "eng"), &token);
    assert_eq!(b.spent, 0);
    assert_eq!(b.window_start, 1_000 + 3_600);

    // One second later it is still the same window: no second reset, no drift.
    h.env.ledger().set_timestamp(1_000 + 3_600 + 1);
    let b = h.client.get_asset_budget(&id(&h.env, "eng"), &token);
    assert_eq!(b.window_start, 1_000 + 3_600);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 100);
}

#[test]
fn per_asset_limit_without_a_window_never_resets() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &100, &0);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);

    h.env.ledger().set_timestamp(1_000 + 10 * DAY);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 0);
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
}

#[test]
fn per_asset_window_catches_up_across_many_periods() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &100, &3_600);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);

    // Five hours later the allowance is one period's worth, not five.
    h.env.ledger().set_timestamp(1_000 + 5 * 3_600);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 100);
    let b = h.client.get_asset_budget(&id(&h.env, "eng"), &token);
    assert_eq!(b.window_start, 1_000 + 5 * 3_600);
}

#[test]
fn unknown_asset_budget_is_rejected() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    let res = h.client.try_asset_remaining(&id(&h.env, "eng"), &token);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
}

#[test]
fn test_rollover_prevention() {
    let env = Env::default();
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let contract_id = env.register_contract(None, BudgetContract);
    let client = BudgetContractClient::new(&env, &contract_id);

    let token = Address::generate(&env);
    let b_id = soroban_sdk::String::from_str(&env, "b1");

    client.allocate(&owner, &b_id, &1000, &crate::Period::None, &false, &0);
    client.set_budget_limit(&owner, &b_id, &token, &100, &3600); // 1 hour window

    env.ledger().set_timestamp(100);
    client.check_and_record_spend(&owner, &b_id, &token, &60);

    // if they spend 50 more in same window, it should fail
    let res = client.try_check_and_record_spend(&owner, &b_id, &token, &50);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // fast forward 1 hour (3600 seconds)
    env.ledger().set_timestamp(100 + 3600 + 1);

    // Now it should succeed because window resets!
    client.check_and_record_spend(&owner, &b_id, &token, &50);
}

// --- Issue #35: Deficit carryforward tests ---

#[test]
fn deficit_carryforward_allows_overspend() {
    let h = setup();
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &true, // allow_deficit
        &0,
    );
    // Spend beyond the limit — deficit allowed.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &1_200);
    assert_eq!(rem, -200); // negative remaining = deficit
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert!(b.allow_deficit);
    assert_eq!(b.spent, 1_200);
}

#[test]
fn deficit_carryforward_reduces_next_period() {
    let h = setup();
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &true, // allow_deficit
        &0,
    );
    // Spend 1200 (200 over limit)
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_200);
    // Advance past the weekly window
    h.env.ledger().set_timestamp(1_000 + 604_800);
    // Call remaining to trigger window transition and persist the rollover state
    // Use rollover to trigger the window transition explicitly
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.window_start, 1_000 + 604_800);
    assert_eq!(b.deficit_amount, 200);
    assert_eq!(b.spent, 0);
    // effective_capacity = limit (1000) - deficit (200) = 800
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 800);
    // Can spend up to 800 (1000 - 200 deficit)
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &800);
    assert_eq!(rem, 0);
    // One more unit should fail since effective capacity is exhausted
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
}

#[test]
fn deficit_not_allowed_rejects_overspend() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    // Spending beyond limit should fail without allow_deficit
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1_200);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
}

#[test]
fn deficit_without_period_rejected() {
    let h = setup();
    // Deficit carryforward requires a recurring period
    let res = h.client.try_allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &true, // allow_deficit
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn deficit_surplus_rollover_combined() {
    let h = setup();
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &true, // allow_deficit
        &0,
    );
    // Spend only 600 — surplus of 400
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    h.env.ledger().set_timestamp(1_000 + 604_800);
    // Call remaining to trigger window transition and persist rollover state
    let rem = h.client.remaining(&id(&h.env, "eng"));
    assert_eq!(rem, 1_400);
    // After rollover: deficit=0, rollover_credit=400, spent=0
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.deficit_amount, 0);
    assert_eq!(b.rollover_credit, 400);
    assert_eq!(b.spent, 0);
}

// ---------------------------------------------------------------------------
// Issue #223: near-maximum boundary values. Every arithmetic path touching
// token balances / budget limits must go through the shared checked helpers
// and surface `Error::Overflow` instead of panicking or silently wrapping.
// ---------------------------------------------------------------------------

#[test]
fn allocate_accepts_maximum_limit() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::None,
        &false,
        &0,
    );
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.limit, i128::MAX);
    // remaining = (limit + 0 credit) - 0 spent: fits exactly, no overflow.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), i128::MAX);
}

#[test]
fn consume_up_to_max_capacity_succeeds() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::None,
        &false,
        &0,
    );
    // spent = 0 + MAX and remaining = MAX - MAX: both fit exactly.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    assert_eq!(rem, 0);
}

#[test]
fn consume_beyond_max_capacity_returns_overflow() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    // spent + amount = MAX + 1 overflows i128: checked math returns the
    // contract error instead of a panic or a wrapped value.
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(BudgetError::Overflow)));
}

#[test]
fn release_refunds_the_full_maximum_spend() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    // Refund the whole period's spend: spent = MAX - MAX, remaining = MAX - 0.
    let rem = h.client.release(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    assert_eq!(rem, i128::MAX);
}

#[test]
fn uncapped_rollover_accrual_past_max_returns_overflow() {
    let h = setup();
    // Three whole idle periods accrue 3 * limit, which overflows i128 when
    // limit is ~MAX/2. The uncapped path uses checked math on purpose.
    let limit = i128::MAX / 2;
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &limit,
        &Period::Weekly,
        &true, // rollover_enabled, uncapped (cap = 0)
        &0,
    );
    h.env.ledger().set_timestamp(1_000 + 3 * WEEK);
    let res = h.client.try_rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

#[test]
fn capped_rollover_accrual_saturates_instead_of_overflowing() {
    let h = setup();
    // Same near-max setup, but with a cap: the accrual saturates and the
    // credit is clamped to the cap, so the budget stays usable.
    let limit = i128::MAX / 2;
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &limit,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &limit, // rollover_cap
        &0,     // percentage ceiling uncapped
    );
    h.env.ledger().set_timestamp(1_000 + 3 * WEEK);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, limit);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 2 * limit);
}

#[test]
fn rollover_accrual_of_second_idle_period_overflows() {
    let h = setup();
    // Two whole idle periods accrue credit + limit = 2 * (MAX - 5), which
    // overflows i128 on the checked accrual path.
    let limit = i128::MAX - 5;
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &limit,
        &Period::Weekly,
        &true,
        &0,
    );
    h.env.ledger().set_timestamp(1_000 + 2 * WEEK);
    let res = h.client.try_rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

#[test]
fn remaining_with_max_limit_and_credit_returns_overflow() {
    let h = setup();
    // Rollover itself succeeds (credit = MAX - 10 fits), but the next
    // capacity computation limit + credit = MAX + (MAX - 10) overflows and
    // must surface as the contract error, not a wrapped value.
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &10);
    h.env.ledger().set_timestamp(1_000 + WEEK);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let res = h.client.try_remaining(&id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

#[test]
fn deficit_remaining_near_max_stays_negative_and_checked() {
    let h = setup();
    let limit = i128::MAX - 1_000;
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &limit,
        &Period::Weekly,
        &true,
        &true, // allow_deficit
        &0,
    );
    // Overspend into a deficit: remaining = (MAX - 1_000) - MAX = -1_000.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    assert_eq!(rem, -1_000);
    // The transition carries the deficit; next period's remaining is
    // (limit - deficit) - spent = (MAX - 1_000) - 1_000 - 0 = MAX - 2_000.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.deficit_amount, 1_000);
    assert_eq!(b.spent, 0);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), i128::MAX - 2_000);
}

#[test]
fn transfer_allocation_past_max_returns_overflow() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "src"),
        &(i128::MAX - 10),
        &Period::None,
        &false,
        &0,
    );
    h.client.allocate(
        &h.owner,
        &id(&h.env, "dst"),
        &(i128::MAX - 10),
        &Period::None,
        &false,
        &0,
    );
    // First hop fills dst exactly to i128::MAX.
    h.client
        .transfer_allocation(&h.owner, &id(&h.env, "src"), &id(&h.env, "dst"), &10);
    assert_eq!(h.client.remaining(&id(&h.env, "dst")), i128::MAX);
    // A further increase of dst.limit would overflow: checked math rejects it.
    let res =
        h.client
            .try_transfer_allocation(&h.owner, &id(&h.env, "src"), &id(&h.env, "dst"), &20);
    assert_eq!(res, Err(Ok(Error::Overflow)));
    // Atomic: dst is untouched by the failed transfer.
    assert_eq!(h.client.remaining(&id(&h.env, "dst")), i128::MAX);
    assert_eq!(h.client.remaining(&id(&h.env, "src")), i128::MAX - 20);
}

#[test]
fn per_asset_spend_past_max_returns_overflow() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &i128::MAX, &0);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &i128::MAX);
    // spent + amount = MAX + 1 overflows the i128 spent counter.
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1);
    assert_eq!(res, Err(Ok(BudgetError::Overflow)));
    // The spend was not recorded.
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 0);
}

// ---------------------------------------------------------------------------
// Issue #246: budget window expiration checks and rollover logic.
// ---------------------------------------------------------------------------

/// Sanity-check the boundary rule at the helper level (no storage access: the
/// helper is a pure predicate over the caller's instant and the stored window).
#[test]
fn window_expiration_helper_matches_the_transition_boundary() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &100);

    let budget = h.client.get(&id(&h.env, "eng"));

    // Well inside the window: not lapsed.
    assert!(!crate::BudgetContract::is_window_expired(&budget, 1_000 + DAY - 1).unwrap());

    // The boundary itself: the window end is *exclusive*, so the first instant
    // at-or-after `start + window` counts as expired.
    assert!(crate::BudgetContract::is_window_expired(&budget, 1_000 + DAY).unwrap());
}

#[test]
fn window_rolls_over_at_exactly_the_boundary_timestamp() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000);

    // One second before the boundary the allowance is still exhausted...
    h.env.ledger().set_timestamp(1_000 + DAY - 1);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // ...and at the boundary itself the window is already expired: the very
    // first timestamp at-or-after `start + window` belongs to the next window.
    h.env.ledger().set_timestamp(1_000 + DAY);
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(rem, 999);
    // Re-anchored to the period boundary, not to `now` (equal here anyway).
    assert_eq!(h.client.get(&id(&h.env, "eng")).window_start, 1_000 + DAY);
}

#[test]
fn rollover_at_exactly_the_max_percentage_cap_is_allowed() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // Exactly 25% of the 1_000 base limit (2_500 bps).
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0, // absolute cap uncapped
        &2_500,
    );

    h.client.consume(&h.owner, &id(&h.env, "eng"), &750); // 250 unspent
    h.env.ledger().set_timestamp(1_000 + WEEK);
    // Unspent 250 is exactly 25% of the limit: the boundary is inclusive.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_250);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 250);
}

#[test]
fn rollover_under_the_max_percentage_cap_carries_in_full() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // 10% cap (1_000 bps) on a 1_000 limit -> 100 units of credit.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0, // absolute cap uncapped
        &1_000,
    );

    h.client.consume(&h.owner, &id(&h.env, "eng"), &950); // 50 unspent
    h.env.ledger().set_timestamp(1_000 + WEEK);
    // 50 < 100: the whole unspent remainder rolls over untouched.
    // (`remaining` evaluates the lazy transition hook and persists it.)
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_050);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 50);
}

#[test]
fn rollover_over_the_max_percentage_cap_is_clamped() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // 25% cap (2_500 bps) on a 1_000 limit -> 250 units of credit.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0, // absolute cap uncapped
        &2_500,
    );

    h.client.consume(&h.owner, &id(&h.env, "eng"), &100); // 900 unspent
    h.env.ledger().set_timestamp(1_000 + WEEK);
    // 900 unspent would blow past the cap; the credit is clamped to 250.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_250);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 250);
}

#[test]
fn percentage_cap_tightens_a_looser_absolute_cap() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // Absolute cap 1_500, percentage cap 10% (100): effective cap = 100.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &1_500, // absolute cap
        &1_000, // 10% of the limit
    );

    h.client.consume(&h.owner, &id(&h.env, "eng"), &100); // 900 unspent
    h.env.ledger().set_timestamp(1_000 + WEEK);
    // The tighter percentage ceiling wins over the looser absolute one.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_100);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 100);
}

#[test]
fn absolute_cap_tightens_a_looser_percentage_cap() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // Absolute cap 300, percentage cap 50% (500): effective cap = 300.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &300,   // absolute cap
        &5_000, // 50% of the limit
    );

    h.client.consume(&h.owner, &id(&h.env, "eng"), &100); // 900 unspent
    h.env.ledger().set_timestamp(1_000 + WEEK);
    // The tighter absolute ceiling wins over the looser percentage one.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_300);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 300);
}

#[test]
fn rollover_max_bps_of_100_or_more_is_rejected() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // 100% would not bound anything, so the boundary itself is invalid.
    let res = h.client.try_set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,
        &10_000,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    // Strictly greater is rejected too, and no state was written.
    let res = h.client.try_set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,
        &20_000,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_max_bps, 0);
}

#[test]
fn negative_rollover_max_bps_is_rejected() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    let res = h.client.try_set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,
        &-1,
    );
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn multi_window_gap_does_not_compound_rollover() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    // Ten whole windows pass with no activity in between.
    h.env.ledger().set_timestamp(1_000 + 10 * WEEK);
    // Only the immediately preceding window contributes its unspent
    // remainder (400) and each fully idle window contributes one base limit:
    // 400 + 9 * 1_000 = 9_400 — *not* the compounded 4_000 + 9 * 1_400.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000 + 9_400);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 9_400);
}

#[test]
fn percentage_cap_bounds_a_multi_window_gap() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0, // absolute cap uncapped
        &2_500,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    h.env.ledger().set_timestamp(1_000 + 10 * WEEK);
    // Uncapped-credit-wise the gap would accrue 400 + 9 * 1_000; the 25%
    // percentage cap holds the credit at 250 across the whole gap.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_250);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 250);
}

#[test]
fn large_balance_percentage_accrual_saturates_at_the_cap_not_overflow() {
    let h = setup();
    // Pathological near-i128::MAX balance with a percentage cap: computing
    // limit * bps overflows a raw i128 product, but the checked arithmetic
    // routes the accrual through saturating fallbacks instead of panicking or
    // silently wrapping.
    let limit = i128::MAX - 5;
    allocate(&h, "eng", limit, Period::Weekly, true);
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &limit, // absolute cap = one base limit
        &5_000, // and 50% of the limit
    );

    h.env.ledger().set_timestamp(1_000 + 5 * WEEK);
    // The effective cap is min(limit, limit/2) = 50% of the limit; the accrual
    // saturates at that cap rather than overflowing. (Calling `remaining` here
    // would legitimately surface Error::Overflow — limit + limit/2 no longer
    // fits i128 — so the explicit `rollover` entry settles and persists the
    // window, and only the stored credit is asserted.)
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let expected = limit / 2;
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, expected);
}

#[test]
fn capacity_beyond_i128_max_surfaces_overflow_not_wrapping() {
    let h = setup();
    // Near-max limit with a percentage cap: the cap itself is computed
    // exactly (limit/4 fits), the rollover succeeds, but the *effective
    // capacity* limit + limit/4 no longer fits i128. The checked addition in
    // the allowance view must surface Error::Overflow instead of a wrapped
    // value or a panic.
    let limit = i128::MAX - 5;
    allocate(&h, "eng", limit, Period::Weekly, true);
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,     // absolute cap uncapped
        &2_500, // 25% of the limit
    );

    h.env.ledger().set_timestamp(1_000 + WEEK);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    // The percentage cap was applied exactly: floor(limit * 2_500 / 10_000).
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, limit / 4);
    // limit + limit/4 overflows i128: the allowance view reports the
    // contract error rather than wrapping to a negative number.
    let res = h.client.try_remaining(&id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

// ---------------------------------------------------------------------------
// Deterministic validation (issue #325)
// ---------------------------------------------------------------------------

#[test]
fn zero_limit_budget_rejects_every_spend() {
    let h = setup();
    allocate(&h, "closed", 0, Period::None, false);
    assert_eq!(h.client.remaining(&id(&h.env, "closed")), 0);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "closed"), &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
    // Nothing was spent, so nothing can be released either.
    let res = h.client.try_release(&h.owner, &id(&h.env, "closed"), &1);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn exact_limit_match_is_allowed_and_one_more_is_not() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::None, false);
    assert_eq!(h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000), 0);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
    assert_eq!(h.client.get(&id(&h.env, "eng")).spent, 1_000);
}

#[test]
fn negative_limits_are_rejected_everywhere() {
    let h = setup();
    let res = h
        .client
        .try_allocate(&h.owner, &id(&h.env, "neg"), &-1, &Period::None, &false, &0);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));

    allocate(&h, "eng", 1_000, Period::None, false);
    let res = h.client.try_set_limit(&h.owner, &id(&h.env, "eng"), &-1);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));

    let token = Address::generate(&h.env);
    let res = h
        .client
        .try_set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &-1, &0);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
    // Rejected before any state was written.
    assert_eq!(h.client.get(&id(&h.env, "eng")).limit, 1_000);
}

#[test]
fn allocation_with_past_expiry_is_rejected() {
    let h = setup();
    // `setup` pins the ledger at t = 1_000.
    for expires_at in [1u64, 999, 1_000] {
        let res = h.client.try_allocate(
            &h.owner,
            &id(&h.env, "stale"),
            &1_000,
            &Period::None,
            &false,
            &expires_at,
        );
        assert_eq!(res, Err(Ok(Error::InvalidInput)));
    }
    // A future expiry (and 0 = never) are accepted.
    allocate(&h, "never", 1_000, Period::None, false);
    h.client.allocate(
        &h.owner,
        &id(&h.env, "soon"),
        &1_000,
        &Period::None,
        &false,
        &1_001,
    );
}

#[test]
fn scheduled_budget_rejects_spending_until_its_start_and_expires_at_boundary() {
    let h = setup();
    h.client.allocate_scheduled(
        &h.owner,
        &id(&h.env, "scheduled"),
        &1_000,
        &Period::None,
        &false,
        &2_000,
        &3_000,
    );
    assert_eq!(h.client.get(&id(&h.env, "scheduled")).window_start, 2_000);
    assert_eq!(h.client.remaining(&id(&h.env, "scheduled")), 0);

    h.env.ledger().set_timestamp(1_999);
    assert_eq!(
        h.client.try_consume(&h.owner, &id(&h.env, "scheduled"), &1),
        Err(Ok(BudgetError::BudgetNotActive))
    );

    h.env.ledger().set_timestamp(2_000);
    assert_eq!(h.client.remaining(&id(&h.env, "scheduled")), 1_000);
    assert_eq!(
        h.client.consume(&h.owner, &id(&h.env, "scheduled"), &250),
        750
    );

    h.env.ledger().set_timestamp(3_000);
    assert_eq!(
        h.client.try_consume(&h.owner, &id(&h.env, "scheduled"), &1),
        Err(Ok(BudgetError::BudgetExpired))
    );
}

#[test]
fn scheduled_budget_with_past_or_current_start_is_immediately_active() {
    let h = setup();
    for (budget_id, start_at) in [("past", 999), ("current", 1_000)] {
        h.client.allocate_scheduled(
            &h.owner,
            &id(&h.env, budget_id),
            &100,
            &Period::None,
            &false,
            &start_at,
            &0,
        );
        assert_eq!(h.client.consume(&h.owner, &id(&h.env, budget_id), &40), 60);
    }
}

#[test]
fn scheduled_budget_blocks_per_asset_spending_until_start() {
    let h = setup();
    let token = Address::generate(&h.env);
    h.client.allocate_scheduled(
        &h.owner,
        &id(&h.env, "scheduled_asset"),
        &1_000,
        &Period::None,
        &false,
        &2_000,
        &0,
    );
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "scheduled_asset"), &token, &500, &0);
    assert_eq!(
        h.client
            .get_asset_budget(&id(&h.env, "scheduled_asset"), &token)
            .window_start,
        2_000
    );
    assert_eq!(
        h.client
            .asset_remaining(&id(&h.env, "scheduled_asset"), &token),
        0
    );

    h.env.ledger().set_timestamp(1_999);
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &id(&h.env, "scheduled_asset"), &token, &100,),
        Err(Ok(BudgetError::BudgetNotActive))
    );

    h.env.ledger().set_timestamp(2_000);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "scheduled_asset"), &token, &100);
    assert_eq!(
        h.client
            .asset_remaining(&id(&h.env, "scheduled_asset"), &token),
        400
    );
}

#[test]
fn scheduled_custom_budget_can_be_configured_without_moving_its_start() {
    let h = setup();
    h.client.allocate_scheduled(
        &h.owner,
        &id(&h.env, "scheduled_custom"),
        &1_000,
        &Period::Custom,
        &false,
        &2_000,
        &0,
    );
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "scheduled_custom"),
        &Period::Custom,
        &3_600,
        &false,
        &0,
        &0,
    );
    assert_eq!(
        h.client.get(&id(&h.env, "scheduled_custom")).window_start,
        2_000
    );

    h.env.ledger().set_timestamp(2_000);
    assert_eq!(
        h.client
            .consume(&h.owner, &id(&h.env, "scheduled_custom"), &100),
        900
    );
}

#[test]
fn scheduled_budget_rejects_expiry_at_or_before_start() {
    let h = setup();
    for expires_at in [1_000, 1_999, 2_000] {
        let result = h.client.try_allocate_scheduled(
            &h.owner,
            &id(&h.env, "invalid_schedule"),
            &100,
            &Period::None,
            &false,
            &2_000,
            &expires_at,
        );
        assert_eq!(result, Err(Ok(Error::InvalidInput)));
    }
}

#[test]
fn overflowing_spend_returns_overflow_not_panic() {
    let h = setup();
    allocate(&h, "max", i128::MAX, Period::None, false);
    h.client.consume(&h.owner, &id(&h.env, "max"), &i128::MAX);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "max"), &1);
    assert_eq!(res, Err(Ok(BudgetError::Overflow)));
}

#[test]
fn overflowing_reallocation_returns_overflow() {
    let h = setup();
    allocate(&h, "full", i128::MAX, Period::None, false);
    allocate(&h, "spare", 10, Period::None, false);
    let res =
        h.client
            .try_transfer_allocation(&h.owner, &id(&h.env, "spare"), &id(&h.env, "full"), &10);
    assert_eq!(res, Err(Ok(Error::Overflow)));
    // Neither side changed.
    assert_eq!(h.client.get(&id(&h.env, "spare")).limit, 10);
    assert_eq!(h.client.get(&id(&h.env, "full")).limit, i128::MAX);
}

#[test]
fn non_owner_cannot_change_limits() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::None, false);
    let stranger = Address::generate(&h.env);
    let res = h
        .client
        .try_set_limit(&stranger, &id(&h.env, "eng"), &5_000);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    let res = h.client.try_release(&stranger, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn archived_budget_rejects_administrative_changes() {
    let h = setup();
    allocate(&h, "old", 1_000, Period::Daily, false);
    h.client.archive(&h.owner, &id(&h.env, "old"));
    let res = h.client.try_set_limit(&h.owner, &id(&h.env, "old"), &2_000);
    assert_eq!(res, Err(Ok(Error::BudgetArchived)));
    let res = h.client.try_reset(&h.owner, &id(&h.env, "old"));
    assert_eq!(res, Err(Ok(Error::BudgetArchived)));
    let res = h.client.try_rollover(&h.owner, &id(&h.env, "old"));
    assert_eq!(res, Err(Ok(Error::BudgetArchived)));
    assert_eq!(h.client.get(&id(&h.env, "old")).limit, 1_000);
}

#[test]
fn expired_budget_rejects_release_and_per_asset_activity() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "exp"),
        &1_000,
        &Period::None,
        &false,
        &2_000,
    );
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "exp"), &token, &500, &0);
    h.client.consume(&h.owner, &id(&h.env, "exp"), &100);
    allocate(&h, "live", 1_000, Period::None, false);

    h.env.ledger().set_timestamp(2_000);
    let res = h.client.try_release(&h.owner, &id(&h.env, "exp"), &50);
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "exp"), &token, &10);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExpired)));
    let res = h
        .client
        .try_set_budget_limit(&h.owner, &id(&h.env, "exp"), &token, &900, &0);
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
    let res =
        h.client
            .try_transfer_allocation(&h.owner, &id(&h.env, "live"), &id(&h.env, "exp"), &10);
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
    assert_eq!(h.client.get(&id(&h.env, "exp")).spent, 100);
}

#[test]
fn release_reports_the_same_remaining_as_the_view() {
    let h = setup();
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "agent"),
        &1_000,
        &Period::Daily,
        &false,
        &true,
        &0,
    );
    // First overspend is allowed and becomes next period's deficit.
    h.client.consume(&h.owner, &id(&h.env, "agent"), &1_500);
    h.env.ledger().set_timestamp(1_000 + 86_400);
    h.client.consume(&h.owner, &id(&h.env, "agent"), &200);

    let after_release = h.client.release(&h.owner, &id(&h.env, "agent"), &100);
    assert_eq!(after_release, h.client.remaining(&id(&h.env, "agent")));
    // limit 1_000 - deficit 500 - spent 100
    assert_eq!(after_release, 400);
}

// ---------------------------------------------------------------------------
// Rollover calculation helper (Issue #313)
// ---------------------------------------------------------------------------

/// The pure calculation surfaced through `rollover_preview`.
#[test]
fn rollover_preview_reports_carry_periods_and_due_flag() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    // Before the boundary the window is not yet due and the carry is the
    // credit already banked (none).
    let outcome = h.client.rollover_preview(&id(&h.env, "eng"));
    assert!(!outcome.is_due);
    assert_eq!(outcome.periods, 0);
    assert_eq!(outcome.carry_over, 0);

    // At the boundary the unspent 400 is what moves into the next period.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    let outcome = h.client.rollover_preview(&id(&h.env, "eng"));
    assert!(outcome.is_due);
    assert_eq!(outcome.periods, 1);
    assert_eq!(outcome.carry_over, 400);

    // Consuming the preview transitions the budget to exactly that state.
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let b = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 400);
    assert_eq!(b.spent, 0);
    assert_eq!(b.window_start, 1_000 + WEEK);
}

#[test]
fn rollover_preview_matches_transition_for_multi_period_gaps() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,
        &0,
    );
    // 300 spent, then three whole periods idle: the remainder (700) plus two
    // fully idle periods at the base limit (2 x 1_000) settle in one step.
    h.client.consume(&h.owner, &id(&h.env, "eng"), &300);
    h.env.ledger().set_timestamp(1_000 + 3 * WEEK);

    let outcome = h.client.rollover_preview(&id(&h.env, "eng"));
    assert_eq!(outcome.periods, 3);
    assert_eq!(outcome.carry_over, 700 + 2 * 1_000);

    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(
        h.client.get(&id(&h.env, "eng")).rollover_credit,
        outcome.carry_over
    );
}

#[test]
fn rollover_preview_clamps_to_absolute_cap() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    // Absolute cap of 500: a 900 unspent remainder carries only 500.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &500,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &100);
    h.env.ledger().set_timestamp(1_000 + WEEK);

    let outcome = h.client.rollover_preview(&id(&h.env, "eng"));
    assert_eq!(outcome.carry_over, 500);

    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 500);
}

#[test]
fn rollover_preview_clamps_to_percentage_cap() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    // 25% of the 1_000 limit = 250: the tighter of the two bounds wins even
    // though the absolute cap would allow more.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,
        &2_500,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &100);
    h.env.ledger().set_timestamp(1_000 + WEEK);

    let outcome = h.client.rollover_preview(&id(&h.env, "eng"));
    assert_eq!(outcome.carry_over, 250);
}

#[test]
fn rollover_preview_zero_carry_when_rollover_disabled() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &400);
    h.env.ledger().set_timestamp(1_000 + WEEK);

    // The window is due but the unspent remainder is dropped.
    let outcome = h.client.rollover_preview(&id(&h.env, "eng"));
    assert!(outcome.is_due);
    assert_eq!(outcome.carry_over, 0);

    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 0);
}

#[test]
fn rollover_preview_reports_deficit_as_negative_carry() {
    let h = setup();
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "agent"),
        &1_000,
        &Period::Daily,
        &false,
        &true,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "agent"), &1_500);
    h.env.ledger().set_timestamp(1_000 + DAY);

    // The over-spend is what crosses the boundary — carried as a deficit,
    // so the preview reports it negative and no surplus is banked.
    let outcome = h.client.rollover_preview(&id(&h.env, "agent"));
    assert!(outcome.is_due);
    assert_eq!(outcome.carry_over, -500);

    h.client.rollover(&h.owner, &id(&h.env, "agent"));
    let b = h.client.get(&id(&h.env, "agent"));
    assert_eq!(b.deficit_amount, 500);
    assert_eq!(b.rollover_credit, 0);
}

// ---------------------------------------------------------------------------
// Multi-token allowance validation (issue #294)
// ---------------------------------------------------------------------------

fn asset_spend(_env: &Env, token: &Address, amount: i128) -> AssetSpend {
    AssetSpend {
        token: token.clone(),
        amount,
    }
}

#[test]
fn batch_spend_records_multiple_tokens_atomically() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let usdc = Address::generate(&h.env);
    let xlm = Address::generate(&h.env);
    let euro = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &usdc, &500, &0);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &xlm, &1_000, &3_600);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &euro, &200, &0);

    let batch = vec![
        &h.env,
        asset_spend(&h.env, &usdc, 100),
        asset_spend(&h.env, &xlm, 300),
        asset_spend(&h.env, &euro, 50),
    ];
    h.client
        .check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &batch);

    // Each token tracks its own spent counter inside its own window.
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &usdc), 400);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &xlm), 700);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &euro), 150);
    // The token-agnostic budget is untouched by per-asset spends.
    assert_eq!(h.client.get(&id(&h.env, "eng")).spent, 0);
}

#[test]
fn batch_spend_rejects_the_whole_batch_when_one_leg_exceeds() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let usdc = Address::generate(&h.env);
    let xlm = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &usdc, &500, &0);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &xlm, &500, &0);

    // The second leg breaches; the first leg must not be recorded either.
    let batch = vec![
        &h.env,
        asset_spend(&h.env, &usdc, 100),
        asset_spend(&h.env, &xlm, 600),
    ];
    let res = h
        .client
        .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &batch);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &usdc), 500);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &xlm), 500);

    // All-within-limits legs go through and emit one event per token.
    let ok = vec![
        &h.env,
        asset_spend(&h.env, &usdc, 100),
        asset_spend(&h.env, &xlm, 500),
    ];
    h.client
        .check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &ok);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &usdc), 400);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &xlm), 0);
}

#[test]
fn batch_spend_rejects_unknown_and_duplicate_tokens() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let usdc = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &usdc, &500, &0);

    // An unregistered token is refused before any state is touched.
    let with_stranger = vec![
        &h.env,
        asset_spend(&h.env, &usdc, 100),
        asset_spend(&h.env, &stranger, 10),
    ];
    let res =
        h.client
            .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &with_stranger);
    assert_eq!(res, Err(Ok(BudgetError::AssetNotAuthorized)));
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &usdc), 500);

    // The same token twice would validate each leg against a stale counter,
    // letting 300 + 300 slip past a 500 cap — rejected outright.
    let duplicated = vec![
        &h.env,
        asset_spend(&h.env, &usdc, 300),
        asset_spend(&h.env, &usdc, 300),
    ];
    let res = h
        .client
        .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &duplicated);
    assert_eq!(res, Err(Ok(BudgetError::InvalidInput)));
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &usdc), 500);
}

#[test]
fn batch_spend_rejects_empty_oversized_and_nonpositive_legs() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let usdc = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &usdc, &500, &0);

    // Empty batch.
    let empty: Vec<AssetSpend> = Vec::new(&h.env);
    let res = h
        .client
        .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &empty);
    assert_eq!(res, Err(Ok(BudgetError::InvalidInput)));

    // Batches beyond MAX_BATCH_TOKENS are capped for cost predictability.
    let mut oversized: Vec<AssetSpend> = Vec::new(&h.env);
    for _ in 0..=MAX_BATCH_TOKENS {
        oversized.push_back(asset_spend(&h.env, &usdc, 1));
    }
    let res = h
        .client
        .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &oversized);
    assert_eq!(res, Err(Ok(BudgetError::InvalidInput)));

    // Zero and negative amounts are refused before anything is validated.
    for bad in [0i128, -5] {
        let batch = vec![&h.env, asset_spend(&h.env, &usdc, bad)];
        let res = h
            .client
            .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &batch);
        assert_eq!(res, Err(Ok(BudgetError::InvalidAmount)));
    }
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &usdc), 500);
}

#[test]
fn batch_spend_enforces_aggregate_window_consumption() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let usdc = Address::generate(&h.env);
    let xlm = Address::generate(&h.env);
    // Both tokens share a one-hour window.
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &usdc, &300, &3_600);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &xlm, &300, &3_600);

    let first = vec![
        &h.env,
        asset_spend(&h.env, &usdc, 250),
        asset_spend(&h.env, &xlm, 250),
    ];
    h.client
        .check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &first);

    // Same window: only 50 more per token fits, individually or in a batch.
    let second = vec![
        &h.env,
        asset_spend(&h.env, &usdc, 50),
        asset_spend(&h.env, &xlm, 50),
    ];
    h.client
        .check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &second);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &usdc), 0);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &xlm), 0);

    let over = vec![
        &h.env,
        asset_spend(&h.env, &usdc, 1),
        asset_spend(&h.env, &xlm, 1),
    ];
    let res = h
        .client
        .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &over);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // A fresh window replenishes every registered token at once.
    h.env.ledger().set_timestamp(1_000 + 3_600);
    h.client
        .check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &first);
}

#[test]
fn batch_spend_still_settles_windows_and_rejects_frozen_or_expired() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::Weekly, false);
    let usdc = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &usdc, &500, &3_600);

    // A due per-asset window reset is settled as part of validation.
    h.env.ledger().set_timestamp(1_000 + 3_600);
    let batch = vec![&h.env, asset_spend(&h.env, &usdc, 500)];
    h.client
        .check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &batch);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &usdc), 0);

    // A frozen budget refuses the batch with the same code as a single spend.
    h.client.freeze(&h.owner, &id(&h.env, "eng"));
    let res = h
        .client
        .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "eng"), &batch);
    assert_eq!(res, Err(Ok(BudgetError::BudgetFrozen)));
    h.client.unfreeze(&h.owner, &id(&h.env, "eng"));

    // An expired budget refuses the batch too.
    h.client.allocate(
        &h.owner,
        &id(&h.env, "tmp"),
        &100,
        &Period::None,
        &false,
        &(1_000 + DAY),
    );
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "tmp"), &usdc, &100, &0);
    h.env.ledger().set_timestamp(1_000 + DAY + 1);
    let res = h.client.try_check_and_record_batch_spend(
        &h.owner,
        &id(&h.env, "tmp"),
        &vec![&h.env, asset_spend(&h.env, &usdc, 1)],
    );
    assert_eq!(res, Err(Ok(BudgetError::BudgetExpired)));

    // Only the owner can drive the batch.
    let intruder = Address::generate(&h.env);
    let res = h.client.try_check_and_record_batch_spend(
        &intruder,
        &id(&h.env, "eng"),
        &vec![&h.env, asset_spend(&h.env, &usdc, 1)],
    );
    assert_eq!(res, Err(Ok(BudgetError::Unauthorized)));
}

// Issue #236: deterministic validation for amount allocations and period
// eligibility.
//
// The zero/negative amount guards already existed, but the two creation
// entrypoints that reach `allocate_at` without a `limit` of their own were not
// exercised, and the deficit-carryforward guard tested only `Period::None` —
// not `Period::Custom`, which is equally non-recurring until `set_recurrence`
// supplies an interval.
// ---------------------------------------------------------------------------

#[test]
fn deficit_is_rejected_on_every_non_recurring_period() {
    let h = setup();
    // `window_of` returns `None` for both, and `allocate_at` now asks that same
    // predicate, so neither can be admitted with a deficit policy.
    for (name, period) in [("none", Period::None), ("custom", Period::Custom)] {
        let res = h.client.try_allocate_with_deficit(
            &h.owner,
            &id(&h.env, name),
            &1_000,
            &period,
            &false,
            &true, // allow_deficit
            &0,
        );
        assert_eq!(res, Err(Ok(Error::InvalidInput)), "period {:?}", period);
        // Nothing was written by the rejection.
        let res = h.client.try_get(&id(&h.env, name));
        assert_eq!(res, Err(Ok(Error::NotFound)), "period {:?}", period);
    }
}

#[test]
fn deficit_remains_available_on_every_recurring_period() {
    let h = setup();
    // The other side of the guard: rejecting `Custom` must not take the fixed
    // cadences with it.
    for (name, period, window) in [
        ("daily", Period::Daily, 86_400u64),
        ("weekly", Period::Weekly, 604_800),
        ("monthly", Period::Monthly, 2_592_000),
    ] {
        let bid = id(&h.env, name);
        h.client
            .allocate_with_deficit(&h.owner, &bid, &1_000, &period, &false, &true, &0);
        // The first overspend is admitted; the deficit is only booked once the
        // window actually turns over, so the ledger has to reach the boundary.
        assert_eq!(
            h.client.consume(&h.owner, &bid, &1_200),
            -200,
            "{:?}",
            period
        );
        // Anchored on the stored window rather than a fixed timestamp, since
        // each iteration allocates at the ledger's current time.
        let start = h.client.get(&bid).window_start;
        h.env.ledger().set_timestamp(start + window);
        h.client.rollover(&h.owner, &bid);
        let b: Budget = h.client.get(&bid);
        assert_eq!(b.deficit_amount, 200, "period {:?}", period);
        assert_eq!(b.spent, 0, "period {:?}", period);
        // The deficit is repaid out of the next period's capacity.
        assert_eq!(h.client.remaining(&bid), 800, "period {:?}", period);
    }
}

#[test]
fn a_custom_period_budget_cannot_accrue_an_unrepayable_deficit() {
    let h = setup();
    let bid = id(&h.env, "eng");
    // A `Custom` budget with no interval never rolls over, so an admitted
    // deficit would have no window to be repaid from: `window_transition`
    // returns before its deficit branch, leaving `deficit_amount` at 0 while
    // `spent` runs past the limit, and `consume` keeps granting the overspend
    // on `allow_deficit && deficit_amount == 0`. Rejecting the combination is
    // what stops `remaining` from falling without bound.
    let res = h.client.try_allocate_with_deficit(
        &h.owner,
        &bid,
        &1_000,
        &Period::Custom,
        &false,
        &true,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    // A `Custom` budget without a deficit policy is still creatable and still
    // recurs once `set_recurrence` supplies an interval.
    allocate(&h, "custom", 1_000, Period::Custom, false);
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "custom"),
        &Period::Custom,
        &3_600,
        &false,
        &0,
        &0,
    );
    assert_eq!(h.client.consume(&h.owner, &id(&h.env, "custom"), &1_000), 0);
    h.env.ledger().set_timestamp(1_000 + 3_600);
    assert_eq!(h.client.remaining(&id(&h.env, "custom")), 1_000);
}

#[test]
fn negative_limits_are_rejected_on_every_creation_entrypoint() {
    let h = setup();
    let res = h.client.try_allocate_with_deficit(
        &h.owner,
        &id(&h.env, "a"),
        &-1,
        &Period::Weekly,
        &false,
        &true,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));

    let res = h.client.try_allocate_scheduled(
        &h.owner,
        &id(&h.env, "b"),
        &-1,
        &Period::None,
        &false,
        &2_000,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));

    // The scheduled entrypoint's own period overlap rule still applies, and is
    // checked independently of the amount.
    let res = h.client.try_allocate_scheduled(
        &h.owner,
        &id(&h.env, "c"),
        &1_000,
        &Period::None,
        &false,
        &2_000,
        &2_000,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));

    for bid in ["a", "b", "c"] {
        let res = h.client.try_get(&id(&h.env, bid));
        assert_eq!(res, Err(Ok(Error::NotFound)), "budget {} created", bid);
    }
}

#[test]
fn negative_and_zero_caps_and_limits_are_rejected_consistently() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);
    let token = Address::generate(&h.env);

    // `rollover_cap`, like `rollover_max_bps`, is non-negative: a negative cap
    // would make `apply_cap` clamp credit to a negative bound.
    let res = h.client.try_set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Daily,
        &0,
        &true,
        &-1, // rollover_cap
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
    // 0 is the documented "uncapped" sentinel and stays valid.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Daily,
        &0,
        &true,
        &0,
        &0,
    );

    // A zero limit is a valid, closed budget — it rejects spends rather than
    // failing to be created.
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &0, &3_600);
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // A zero limit with no window is the one-shot form; still closed, still
    // creatable.
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &0, &0);
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
}

// ---------------------------------------------------------------------------
// AI Agent Sliding Window Budget Tracking & Rate Limiting Tests
// ---------------------------------------------------------------------------

#[test]
fn ai_agent_sliding_window_rate_limiting_and_consumption_tracking() {
    let h = setup();
    let agent_budget_id = id(&h.env, "ai_agent_treasury");
    let limit = 5_000i128;

    // Allocate budget for autonomous AI agent with daily sliding window
    allocate(&h, "ai_agent_treasury", limit, Period::Daily, false);

    // Agent performs smaller incremental spends within active sliding window
    assert_eq!(h.client.consume(&h.owner, &agent_budget_id, &1_500), 3_500);
    assert_eq!(h.client.consume(&h.owner, &agent_budget_id, &2_000), 1_500);
    assert_eq!(h.client.consume(&h.owner, &agent_budget_id, &1_500), 0);

    // Total spent equals limit (5_000). Further spending breaches limit and returns BUDGET_EXCEEDED
    let res = h.client.try_consume(&h.owner, &agent_budget_id, &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // Advance ledger timestamp past the 24-hour sliding window boundary
    h.env.ledger().set_timestamp(1_000 + DAY);

    // Sliding window auto-resets consumption totals and restores full allowance
    assert_eq!(h.client.remaining(&agent_budget_id), limit);
    let rem = h.client.consume(&h.owner, &agent_budget_id, &2_500);
    assert_eq!(rem, 2_500);
}

#[test]
fn ai_agent_sliding_window_custom_interval_rate_limiting() {
    let h = setup();
    let agent_budget_id = id(&h.env, "ai_agent_hourly");
    let limit = 1_000i128;
    let hourly_window = 3_600u64;

    // Allocate custom budget and configure 1-hour recurring window
    allocate(&h, "ai_agent_hourly", limit, Period::None, false);
    h.client.set_recurrence(
        &h.owner,
        &agent_budget_id,
        &Period::Custom,
        &hourly_window,
        &false,
        &0,
        &0,
    );

    // Agent spends up to limit inside the 1-hour window
    assert_eq!(h.client.consume(&h.owner, &agent_budget_id, &600), 400);
    assert_eq!(h.client.consume(&h.owner, &agent_budget_id, &400), 0);

    // Spend exceeding limit is rejected with deterministic BudgetExceeded error
    let res = h.client.try_consume(&h.owner, &agent_budget_id, &100);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // 59 minutes later (still within sliding window): spend still rejected
    h.env.ledger().set_timestamp(1_000 + 3_540);
    let res = h.client.try_consume(&h.owner, &agent_budget_id, &100);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // Exactly on the 1-hour boundary (3,600s): sliding window resets spend counter
    h.env.ledger().set_timestamp(1_000 + hourly_window);
    assert_eq!(h.client.remaining(&agent_budget_id), limit);
    assert_eq!(h.client.consume(&h.owner, &agent_budget_id, &500), 500);
}

// ---------------------------------------------------------------------------
// Issue #232: Budget rollover accounting tests
// ---------------------------------------------------------------------------

#[test]
fn budget_rollover_with_custom_percentage_and_cap() {
    let h = setup();
    let budget_id = id(&h.env, "agent-rollover");
    let limit = 1_000i128;
    let period = Period::Daily;
    let window = 86_400u64;
    let rollover_bps = 5_000i128; // 50%
    let max_rollover_cap = 300i128;

    // Allocate budget with 50% rollover and 300 cap
    h.client.allocate_with_rollover(
        &h.owner,
        &budget_id,
        &limit,
        &period,
        &true,
        &rollover_bps,
        &max_rollover_cap,
        &0,
    );

    // Period 1: Spend 400. Unspent = 600.
    assert_eq!(h.client.consume(&h.owner, &budget_id, &400), 600);
    assert_eq!(h.client.remaining(&budget_id), 600);

    // Advance to Period 2:
    // Unspent: 600. 50% of 600 = 300. Cap = 300. Clamped to min(300, 300) = 300.
    // Fresh allowance = limit (1000) + rollover (300) = 1300.
    h.env.ledger().set_timestamp(1_000 + window);
    assert_eq!(h.client.remaining(&budget_id), 1_300);
    let b: Budget = h.client.get(&budget_id);
    assert_eq!(b.rollover_credit, 300);

    // Can spend up to 1_300 in period 2
    assert_eq!(h.client.consume(&h.owner, &budget_id, &1_000), 300);
    assert_eq!(h.client.consume(&h.owner, &budget_id, &300), 0);
    let res = h.client.try_consume(&h.owner, &budget_id, &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));
}

#[test]
fn budget_rollover_percentage_below_cap() {
    let h = setup();
    let budget_id = id(&h.env, "agent-bps-below-cap");
    let limit = 1_000i128;
    let period = Period::Daily;
    let window = 86_400u64;
    let rollover_bps = 2_500i128; // 25%
    let max_rollover_cap = 500i128;

    h.client.allocate_with_rollover(
        &h.owner,
        &budget_id,
        &limit,
        &period,
        &true,
        &rollover_bps,
        &max_rollover_cap,
        &0,
    );

    // Spend 200 => Unspent = 800
    assert_eq!(h.client.consume(&h.owner, &budget_id, &200), 800);

    // Period 2: 25% of 800 = 200. Cap is 500. 200 < 500, so credit is 200.
    h.env.ledger().set_timestamp(1_000 + window);
    assert_eq!(h.client.remaining(&budget_id), 1_200);
    let b: Budget = h.client.get(&budget_id);
    assert_eq!(b.rollover_credit, 200);
}

#[test]
fn budget_rollover_clamped_by_cap() {
    let h = setup();
    let budget_id = id(&h.env, "agent-bps-clamped");
    let limit = 1_000i128;
    let period = Period::Daily;
    let window = 86_400u64;
    let rollover_bps = 5_000i128; // 50%
    let max_rollover_cap = 200i128;

    h.client.allocate_with_rollover(
        &h.owner,
        &budget_id,
        &limit,
        &period,
        &true,
        &rollover_bps,
        &max_rollover_cap,
        &0,
    );

    // Spend 200 => Unspent = 800
    assert_eq!(h.client.consume(&h.owner, &budget_id, &200), 800);

    // Period 2: 50% of 800 = 400. Cap is 200. 400 > 200 => clamped to 200.
    h.env.ledger().set_timestamp(1_000 + window);
    assert_eq!(h.client.remaining(&budget_id), 1_200);
    let b: Budget = h.client.get(&budget_id);
    assert_eq!(b.rollover_credit, 200);
}

#[test]
fn budget_rollover_zero_unspent_and_zero_bps() {
    let h = setup();
    let budget_id = id(&h.env, "agent-zero-bps");
    let limit = 1_000i128;
    let period = Period::Daily;
    let window = 86_400u64;

    // Rollover enabled but bps = 0
    h.client
        .allocate_with_rollover(&h.owner, &budget_id, &limit, &period, &true, &0, &500, &0);

    // Spend 200 => unspent = 800
    h.client.consume(&h.owner, &budget_id, &200);
    h.env.ledger().set_timestamp(1_000 + window);

    // 0 bps => 0 credit
    assert_eq!(h.client.remaining(&budget_id), 1_000);
    let b: Budget = h.client.get(&budget_id);
    assert_eq!(b.rollover_credit, 0);
}

#[test]
fn rollover_preview_non_recurring_budget_is_never_due() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &true,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &400);
    h.env.ledger().set_timestamp(1_000 + 30 * DAY);

    let outcome = h.client.rollover_preview(&id(&h.env, "eng"));
    assert!(!outcome.is_due);
    assert_eq!(outcome.periods, 0);
    // A one-shot budget carries nothing between periods.
    assert_eq!(outcome.carry_over, 0);
}

#[test]
fn rollover_preview_remaining_stays_consistent_across_transition() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &0,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    // Remaining before the boundary is plain: limit - spent.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 400);

    h.env.ledger().set_timestamp(1_000 + WEEK);
    // After the boundary the preview's carry becomes the new capacity
    // (base limit + banked credit), with the spent counter cleared.
    let outcome = h.client.rollover_preview(&id(&h.env, "eng"));
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(
        h.client.remaining(&id(&h.env, "eng")),
        1_000 + outcome.carry_over
    );
}

#[test]
fn rollover_preview_unknown_budget_is_not_found() {
    let h = setup();
    let res = h.client.try_rollover_preview(&id(&h.env, "ghost"));
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn rollover_preview_expired_budget_is_rejected() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &2_000,
    );
    h.env.ledger().set_timestamp(2_000);
    let res = h.client.try_rollover_preview(&id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
}

#[test]
fn multiple_period_rollovers_simulation() {
    let h = setup();
    let budget_id = id(&h.env, "agent-multi-period");
    let limit = 1_000i128;
    let period = Period::Daily;
    let window = 86_400u64;
    let rollover_bps = 5_000i128; // 50%
    let max_rollover_cap = 400i128;

    h.client.allocate_with_rollover(
        &h.owner,
        &budget_id,
        &limit,
        &period,
        &true,
        &rollover_bps,
        &max_rollover_cap,
        &0,
    );

    // --- Period 1 (t = 1_000) ---
    // Capacity = 1_000. Spend 400. Unspent = 600.
    assert_eq!(h.client.consume(&h.owner, &budget_id, &400), 600);

    // --- Period 2 (t = 1_000 + 86_400) ---
    // Rollover = min(600 * 50%, 400) = 300.
    // Capacity = 1_000 + 300 = 1_300.
    h.env.ledger().set_timestamp(1_000 + window);
    assert_eq!(h.client.remaining(&budget_id), 1_300);
    // Spend 500. Remaining unspent = 1_300 - 500 = 800.
    assert_eq!(h.client.consume(&h.owner, &budget_id, &500), 800);

    // --- Period 3 (t = 1_000 + 2 * 86_400) ---
    // Rollover = min(800 * 50%, 400) = min(400, 400) = 400.
    // Capacity = 1_000 + 400 = 1_400.
    h.env.ledger().set_timestamp(1_000 + 2 * window);
    assert_eq!(h.client.remaining(&budget_id), 1_400);
    let b: Budget = h.client.get(&budget_id);
    assert_eq!(b.rollover_credit, 400);

    // Spend 1_400 in full
    assert_eq!(h.client.consume(&h.owner, &budget_id, &1_400), 0);
    assert_eq!(
        h.client.try_consume(&h.owner, &budget_id, &1),
        Err(Ok(BudgetError::BudgetExceeded))
    );

    // --- Period 4 (t = 1_000 + 3 * 86_400) ---
    // Unspent was 0 => Rollover = 0.
    // Capacity = 1_000.
    h.env.ledger().set_timestamp(1_000 + 3 * window);
    assert_eq!(h.client.remaining(&budget_id), 1_000);
    let b: Budget = h.client.get(&budget_id);
    assert_eq!(b.rollover_credit, 0);
}

#[test]
fn set_rollover_config_dynamically() {
    let h = setup();
    let budget_id = id(&h.env, "agent-dynamic-rollover");
    let limit = 1_000i128;
    let period = Period::Daily;
    let window = 86_400u64;

    // Initially allocate without rollover
    h.client
        .allocate(&h.owner, &budget_id, &limit, &period, &false, &0);

    // Dynamically enable rollover with 40% (4_000 bps) and cap 300
    h.client
        .set_rollover_config(&h.owner, &budget_id, &true, &4_000, &300);

    // Spend 500 => Unspent = 500
    h.client.consume(&h.owner, &budget_id, &500);

    // Advance to Period 2: 40% of 500 = 200. Cap = 300.
    h.env.ledger().set_timestamp(1_000 + window);
    assert_eq!(h.client.remaining(&budget_id), 1_200);
    let b: Budget = h.client.get(&budget_id);
    assert_eq!(b.rollover_credit, 200);
    assert_eq!(b.rollover_bps, 4_000);
    assert_eq!(b.rollover_cap, 300);
}

#[test]
fn per_asset_budget_rollover_accounting() {
    let h = setup();
    let budget_id = id(&h.env, "asset-rollover-test");
    let token = Address::generate(&h.env);
    let limit = 1_000i128;
    let window_seconds = 86_400u64;

    h.client
        .allocate(&h.owner, &budget_id, &10_000, &Period::Daily, &false, &0);

    // Set asset budget with 50% rollover and 300 cap
    h.client.set_budget_limit_with_rollover(
        &h.owner,
        &budget_id,
        &token,
        &limit,
        &window_seconds,
        &true,
        &5_000,
        &300,
    );

    // Spend 400 of 1000 => unspent = 600
    h.client
        .check_and_record_spend(&h.owner, &budget_id, &token, &400);
    assert_eq!(h.client.asset_remaining(&budget_id, &token), 600);

    // Advance to next window
    // 50% of 600 = 300 (cap is 300) => credit = 300
    // Total capacity = 1_000 + 300 = 1_300
    h.env.ledger().set_timestamp(1_000 + window_seconds);
    assert_eq!(h.client.asset_remaining(&budget_id, &token), 1_300);
    let ab = h.client.get_asset_budget(&budget_id, &token);
    assert_eq!(ab.rollover_credit, 300);
    assert_eq!(ab.spent, 0);

    // Spend full 1300
    h.client
        .check_and_record_spend(&h.owner, &budget_id, &token, &1_300);
    assert_eq!(h.client.asset_remaining(&budget_id, &token), 0);
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &budget_id, &token, &1);
    assert_eq!(res, Err(Ok(BudgetError::BudgetExceeded)));

    // Next window: unspent was 0 => credit = 0, capacity = 1_000
    h.env.ledger().set_timestamp(1_000 + 2 * window_seconds);
    assert_eq!(h.client.asset_remaining(&budget_id, &token), 1_000);
    let ab = h.client.get_asset_budget(&budget_id, &token);
    assert_eq!(ab.rollover_credit, 0);
}

// ---------------------------------------------------------------------------
// Issue #215 — expenditure tracking, limit enforcement and deterministic
// refusals across every spend entrypoint.
// ---------------------------------------------------------------------------

/// The cumulative expenditure of a period lives in persistent storage and is
/// readable across invocations: each authorized spend adds to the stored
/// `spent` counter, the remaining headroom shrinks by the same amount, and the
/// period boundary resets the ledger for the next window.
#[test]
fn cumulative_expenditure_is_tracked_per_period_in_persistent_storage() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);

    // Several spend requests accumulate into one per-period ledger.
    h.client.consume(&h.owner, &id(&h.env, "eng"), &100);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &250);
    assert_eq!(h.client.get(&id(&h.env, "eng")).spent, 350);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 650);

    // A later invocation reads the same persisted totals and can drive the
    // ledger to its exact ceiling.
    h.client.consume(&h.owner, &id(&h.env, "eng"), &650);
    assert_eq!(h.client.get(&id(&h.env, "eng")).spent, 1_000);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 0);

    // The period boundary resets the stored ledger: the view settles the
    // transition and persists it, so the record itself reads a fresh period.
    h.env.ledger().set_timestamp(1_000 + DAY);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    assert_eq!(h.client.get(&id(&h.env, "eng")).spent, 0);
}

/// Storage updates are transactional: an over-limit request is refused with
/// the deterministic `BudgetExceeded` code and never moves the stored ledger,
/// on the aggregate envelope, the per-asset allowance or a batch alike.
#[test]
fn a_refused_spend_leaves_the_period_ledger_untouched() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::None, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &500, &0);

    h.client.consume(&h.owner, &id(&h.env, "eng"), &800);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &400);

    // Over-limit attempts on every entrypoint are refused with the same code.
    assert_eq!(
        h.client.try_consume(&h.owner, &id(&h.env, "eng"), &300),
        Err(Ok(BudgetError::BudgetExceeded))
    );
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &200),
        Err(Ok(BudgetError::BudgetExceeded))
    );
    assert_eq!(
        h.client.try_check_and_record_batch_spend(
            &h.owner,
            &id(&h.env, "eng"),
            &vec![&h.env, asset_spend(&h.env, &token, 200)],
        ),
        Err(Ok(BudgetError::BudgetExceeded))
    );

    // Nothing was persisted by any of the refusals: the ledgers still hold
    // exactly the authorized totals and the original headroom.
    assert_eq!(h.client.get(&id(&h.env, "eng")).spent, 800);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 200);
    assert_eq!(
        h.client.get_asset_budget(&id(&h.env, "eng"), &token).spent,
        400
    );
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 100);
}

/// An exhausted envelope refuses every spend path with one deterministic code
/// and only admits spending again once its window has rolled and replenished.
#[test]
fn limit_exhaustion_blocks_every_spend_path_until_the_window_rolls() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &100, &3_600);

    // Exhaust both the aggregate envelope and the per-asset allowance.
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);

    // One more unit is refused identically by every entrypoint.
    assert_eq!(
        h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1),
        Err(Ok(BudgetError::BudgetExceeded))
    );
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1),
        Err(Ok(BudgetError::BudgetExceeded))
    );
    assert_eq!(
        h.client.try_check_and_record_batch_spend(
            &h.owner,
            &id(&h.env, "eng"),
            &vec![&h.env, asset_spend(&h.env, &token, 1)],
        ),
        Err(Ok(BudgetError::BudgetExceeded))
    );

    // The per-asset window rolls and replenishes; spending works again, and
    // the fresh allowance is itself enforced to the unit.
    h.env.ledger().set_timestamp(1_000 + 3_600);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 0);
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1),
        Err(Ok(BudgetError::BudgetExceeded))
    );
    // The aggregate envelope is on its own weekly window: still exhausted.
    assert_eq!(
        h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1),
        Err(Ok(BudgetError::BudgetExceeded))
    );
}

/// The same over-limit request on the same ledger yields the same refusal
/// every time, and repeated refusals never erode the headroom actually left.
#[test]
fn over_limit_refusals_are_deterministic_across_attempts() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);

    for _ in 0..3 {
        assert_eq!(
            h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1_001),
            Err(Ok(BudgetError::BudgetExceeded))
        );
    }
    assert_eq!(h.client.get(&id(&h.env, "eng")).spent, 0);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);

    // The exact ceiling is still spendable — one unit of headroom means one
    // unit more than the limit is refused, exactly at the boundary.
    assert_eq!(h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000), 0);
    assert_eq!(
        h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1),
        Err(Ok(BudgetError::BudgetExceeded))
    );
}

/// The batch entrypoint honours a scheduled budget's start gate exactly like
/// the single-spend paths: before the inclusive start every attempt reports
/// the distinct `BudgetNotActive` code and records nothing, and at the start
/// instant all paths open together.
#[test]
fn batch_spend_respects_a_scheduled_budgets_start_gate() {
    let h = setup();
    h.client.allocate_scheduled(
        &h.owner,
        &id(&h.env, "scheduled"),
        &1_000,
        &Period::None,
        &false,
        &2_000,
        &0,
    );
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "scheduled"), &token, &500, &0);

    h.env.ledger().set_timestamp(1_999);
    let batch = vec![&h.env, asset_spend(&h.env, &token, 100)];
    assert_eq!(
        h.client
            .try_check_and_record_batch_spend(&h.owner, &id(&h.env, "scheduled"), &batch),
        Err(Ok(BudgetError::BudgetNotActive))
    );
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &id(&h.env, "scheduled"), &token, &100),
        Err(Ok(BudgetError::BudgetNotActive))
    );
    // Neither attempt recorded anything.
    assert_eq!(
        h.client
            .get_asset_budget(&id(&h.env, "scheduled"), &token)
            .spent,
        0
    );

    // At the start instant both paths open together.
    h.env.ledger().set_timestamp(2_000);
    h.client
        .check_and_record_batch_spend(&h.owner, &id(&h.env, "scheduled"), &batch);
    assert_eq!(
        h.client
            .get_asset_budget(&id(&h.env, "scheduled"), &token)
            .spent,
        100
    );
    assert_eq!(
        h.client.asset_remaining(&id(&h.env, "scheduled"), &token),
        400
    );
}
