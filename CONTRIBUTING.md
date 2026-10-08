# Contributing to Astroid Contracts

Thanks for your interest in improving the smart contracts for Astroid — the
Financial Operating System for autonomous AI agents on Stellar. We develop in
the open and welcome issues, discussion, and pull requests.

## Getting started

```bash
git clone https://github.com/ASTROIDX556/hppoilo-contracts.git
cd hppoilo-contracts
cargo build                                     # build the root workspace (core contracts)
cargo test                                      # run the root test suites
(cd contracts/modules && cargo build && cargo test)   # module contracts workspace
stellar contract build                          # build optimized WASM (root workspace)
(cd contracts/modules && stellar contract build)      # optimized WASM (modules workspace)
```

This repository contains **two Cargo workspaces**: the root workspace (shared
libraries, interface definitions, the four core Soroban contracts and the
integration tests) and `contracts/modules/` (the four governance/extension
module contracts). Run cargo commands in both directories — see the root
`README.md` for the full command list.

## Ground rules

- **Minimize on-chain logic.** Only store what must be trusted by everyone.
  Never store AI reasoning, chat history, analytics, or UI state.
- **Verify, don't think.** Backend computes → Contract verifies → Execute.
  Contracts never make subjective decisions.
- **Deterministic error codes.** Every error type is a named constant
  (`INSUFFICIENT_FUNDS`, `POLICY_DENIED`, `BUDGET_EXCEEDED`, etc.).
- **Conventional Commits.** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- **Tests are required.** Unit, integration, and edge-case tests. Target 100%
  coverage for critical financial logic.
- **Gas optimization.** Minimize storage writes, reuse data structures, emit
  concise events, batch operations, avoid redundant lookups.

## Pull request checklist

1. `cargo build && cargo test` pass in both workspaces (repository root and `contracts/modules/`).
2. New contracts include `README.md` explaining the purpose, interface, and storage layout.
3. Events follow the standard naming conventions in `shared/events.rs`.
4. Error codes are added to `shared/errors.rs`.

## Branch strategy

`main` is always releasable. Use `feature/*` and `fix/*` branches and open PRs
against `main`. See the PRD (Document 3) for the full branching model.

By contributing you agree that your contributions are licensed under the MIT License.
..
