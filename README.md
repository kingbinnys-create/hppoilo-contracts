# hppoilo-contracts

[![CI](https://github.com/ASTROIDX556/hppoilo-contracts/actions/workflows/ci.yml/badge.svg)](https://github.com/ASTROIDX556/hppoilo-contracts/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Stellar](https://img.shields.io/badge/Built%20on-Stellar%20Soroban-7C3AED)](https://stellar.org)
[![Drips Wave](https://img.shields.io/badge/Drips-Stellar%20Wave-blue)](https://www.drips.network/wave/stellar)

> Soroban smart contracts — the **on-chain backbone** of Astroid, the Financial Operating System for autonomous AI agents on Stellar. Built for the [Drips Stellar Wave Program](https://www.drips.network/wave/stellar).

Eight production-grade Soroban contracts that form the protocol layer of Astroid: a system that lets AI agents spend real funds on-chain only within cryptographically-enforced governance rules set by human organizations.

## Architecture

```
Registry ──► Wallet ──► Treasury
    │             └──► Budget
    │             └──► Policy
    │             └──► Escrow
    └──► Multisig ──► Proposal
```

**Deployment order:** `registry → wallet → treasury → multisig → proposal → budget → policy → escrow`

## Contracts

| Contract | WASM | Responsibility |
|---|---|---|
| **Registry** | `astroid_registry.wasm` | Single source of truth. Stores org owners, module addresses, and the version upgrade map. |
| **Wallet** | `astroid_wallet.wasm` | Per-org Stellar wallet. Holds funds, enforces policy before any transfer. |
| **Treasury** | `astroid_treasury.wasm` | Organization treasury. Manages asset pools and allocation to wallets. |
| **Multisig** | `astroid_multisig.wasm` | k-of-n threshold signing. Guards high-value transactions requiring multiple approvals. |
| **Proposal** | `astroid_proposal.wasm` | Approval proposal lifecycle (create → approve/reject → execute/cancel/expire). |
| **Budget** | `astroid_budget.wasm` | Spending limits per time period. Tracks consumption and blocks over-limit transfers. |
| **Policy** | `astroid_policy.wasm` | Pluggable transfer rule engine. Checks every transfer against registered policy modules. |
| **Escrow** | `astroid_escrow.wasm` | Time-locked or condition-based fund escrow with release/refund/expire paths. |

## Registry Contract — Public API

| Function | Auth | Description |
|---|---|---|
| `initialize(admin)` | — | One-time initialization. Sets the protocol admin. |
| `register_org(caller, org, owner)` | Admin | Register an organization and its owner. |
| `set_org_owner(caller, org, new_owner)` | Org owner or admin | Transfer org ownership. |
| `register_module(caller, org, kind, address)` | Org owner or admin | Record a module address for an org. |
| `remove_module(caller, org, kind)` | Org owner or admin | Remove a module registration. |
| `register_version(caller, kind, version, address, wasm_hash)` | Admin | Record a contract version in the global upgrade map, bound to the WASM hash it runs. `wasm_hash` must be approved for `kind` (`add_approved_wasm`), else `Unauthorized`. Versions are immutable: re-registering a `(kind, version)` fails with `AlreadyExists`. Blocked while frozen. Emits `RegistryVersionRegistered`. |
| `add_approved_wasm(caller, kind, wasm_hash)` / `remove_approved_wasm(...)` | Admin | Approve or revoke implementation code for a module kind. |
| `get_version(kind, version)` | — | Look up an implementation address by version. |
| `get_version_wasm(kind, version)` | — | Read the WASM hash a version is bound to. `NotFound` for unknown keys. |
| `verify_version(kind, version, wasm_hash)` | — | Return the version's address only if it is bound to `wasm_hash` (`InvalidInput` on mismatch) and that hash is still approved (`Unauthorized` once revoked). `NotFound` for unknown keys. |
| `get_latest(kind)` | — | Look up the latest implementation address for a module kind. |
| `get_org_owner(org)` | — | Read the owner of an organization. |
| `get_admin()` | — | Read the current protocol admin. |
| `set_admin(caller, new_admin)` | Admin | Rotate the admin address. |
| `lookup(org, kind)` | — | Interface method: resolve a module address for an org. |
| `verify_owner(org, owner)` | — | Interface method: check if an address is the org owner. |
| `get_modules_batch(ids)` | — | Interface method: resolve up to `MAX_REGISTRY_BATCH` (10) `(org, kind)` modules in one call. `result[i]` answers `ids[i]`; missing modules are `None`, deprecated ones are flagged. Oversized batches fail with `InvalidInput`. |

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Rust (edition 2021) |
| SDK | soroban-sdk 21.7.7 |
| Build target | `wasm32v1-none` |
| Build tool | Stellar CLI |
| Test runner | `cargo test` (Soroban test environment) |

## Quick Start

```bash
# Prerequisites: Rust stable + Stellar CLI
cargo install --locked stellar-cli

# Build all contracts (the repo is split into two Cargo workspaces)
stellar contract build                            # root: registry, wallet, treasury, multisig
(cd contracts/modules && stellar contract build)  # modules: proposal, budget, policy, escrow

# Run all tests (root workspace includes the cross-contract integration suite)
cargo test --workspace
cargo test --workspace --manifest-path contracts/modules/Cargo.toml

# Format check (both workspaces)
cargo fmt --check
cargo fmt --check --manifest-path contracts/modules/Cargo.toml

# Lint (both workspaces)
cargo clippy --workspace -- -D warnings
cargo clippy --workspace --manifest-path contracts/modules/Cargo.toml -- -D warnings
```

## Deployment (Testnet)

```bash
# 1. Generate and fund a deployer identity
stellar keys generate alice --network testnet
stellar keys fund alice --network testnet

# 2. Deploy the registry (deploy other contracts in dependency order)
stellar contract deploy \
  --wasm target/wasm32v1-none/release/astroid_registry.wasm \
  --source alice \
  --network testnet
# → Save the output Contract ID (C...)
```

**Deployed Registry (Testnet):** `CCUYI4DSYDNOQC377NFIU6K3GVRQ5VQ3MLTG2CUK5N2E7DUPCIJJC4H7`

## Workspace Structure

The repository is divided into **two Cargo workspaces**, each with its own
`Cargo.toml`, `Cargo.lock` and `target/` directory. They reference each other
through plain path dependencies (the root integration tests need all eight
contracts; the proposal tests need multisig), so build and test **both**.

```
hppoilo-contracts/                # workspace 1 (root): core + shared + tests
├── contracts/
│   └── core/                    # Core Protocol contracts
│       ├── registry/            # Protocol source of truth
│       ├── wallet/              # Per-org Stellar wallet
│       ├── treasury/            # Asset pool management
│       └── multisig/            # k-of-n threshold signing
├── interfaces/                  # Shared contract interface traits
├── shared/                      # Shared types, errors, constants, validation
└── tests/                       # Integration tests across all eight contracts

contracts/modules/               # workspace 2: governance & extension modules
├── Cargo.toml                   # Separate workspace root
├── proposal/                    # Approval lifecycle
├── budget/                      # Spending limits
├── policy/                      # Transfer rule engine
└── escrow/                      # Time-locked escrow
```

## Related Repositories

| Repo | Description |
|---|---|
| [astroid-api](https://github.com/ASTROIDX556/astroid-api) | NestJS backend that calls these contracts |
| [astroid-web](https://github.com/ASTROIDX556/astroid-web) | Next.js dashboard |
| [astroid-sdk](https://github.com/ASTROIDX556/astroid-sdk) | TypeScript SDK and React hooks |

## Maintainers

| Name | GitHub | Contact |
|---|---|---|
| Astroid Team | [@ASTROIDX556](https://github.com/ASTROIDX556) | Open an issue or discussion |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs require passing `cargo test`, `cargo fmt --check`, and `cargo clippy`.

## Security

These contracts are **unaudited**. Use on testnet only until a professional audit is completed. See [SECURITY.md](SECURITY.md) for the disclosure policy.

## License

MIT — see [LICENSE](LICENSE).

...
