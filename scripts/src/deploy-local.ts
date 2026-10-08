#!/usr/bin/env tsx
import * as dotenv from "dotenv";
import { Keypair, Networks } from "@stellar/stellar-sdk";

dotenv.config();

async function main() {
  const adminSecret = process.env.ADMIN_SECRET_KEY;
  if (!adminSecret) {
    throw new Error("ADMIN_SECRET_KEY not set in .env");
  }

  const keypair = Keypair.fromSecret(adminSecret);
  console.log("Deploying with admin:", keypair.publicKey());
  console.log(
    "Local deployment script scaffolded. Add wasm deployment steps here.",
  );
}

main().catch((e) => {
  console.error("Error:", e);
  process.exit(1);
});
