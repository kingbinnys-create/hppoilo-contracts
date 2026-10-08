# TypeScript Scripts

Off-chain tooling for hppoilo-contracts.

## Setup

```bash
cd scripts
npm install
cp .env.example .env
```

## Usage

```bash
# Run local deployment scaffold
npm run deploy:local
# or
npx tsx src/deploy-local.ts
```

Contracts remain written in Rust (Soroban). These scripts are for deployment, setup, and utilities.
