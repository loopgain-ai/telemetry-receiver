#!/usr/bin/env node
/**
 * Issue a new bearer token for a customer.
 *
 * Usage:
 *   node scripts/issue-token.mjs --name "ACME Corp" --email "ops@acme.com" [--local]
 *
 * Prints the customer_id and the plain-text token. The plain token is shown
 * ONCE and never stored — only its SHA-256 hash is persisted in the DB.
 * Hand the token to the customer; they put it in their `LoopGain.send_telemetry(token=...)`.
 */

import { execSync } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";

const args = process.argv.slice(2);
function getArg(flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : null;
}
function hasFlag(flag) {
  return args.includes(flag);
}

const name = getArg("--name") || "anonymous";
const email = getArg("--email") || "";
const local = hasFlag("--local");

const customerId = `cust_${randomBytes(8).toString("hex")}`;
const token = `lgk_${randomBytes(24).toString("base64url")}`;
const tokenHash = createHash("sha256").update(token).digest("hex");
const createdAt = Math.floor(Date.now() / 1000);

const sql = `INSERT INTO customers (customer_id, token_hash, name, contact_email, created_at)
  VALUES ('${customerId}', '${tokenHash}', '${name.replace(/'/g, "''")}',
          '${email.replace(/'/g, "''")}', ${createdAt});`;

const cmd = [
  "wrangler",
  "d1",
  "execute",
  "loopgain-telemetry",
  local ? "--local" : "--remote",
  "--command",
  `"${sql}"`,
].join(" ");

console.log(`Issuing token for "${name}"...`);
execSync(cmd, { stdio: "inherit" });

console.log("");
console.log("=".repeat(70));
console.log(`Customer ID:  ${customerId}`);
console.log(`Bearer Token: ${token}`);
console.log("=".repeat(70));
console.log("");
console.log("The bearer token above is shown ONCE. Hand it to the customer.");
console.log("They configure it in their library call:");
console.log("");
console.log(`    lg.send_telemetry(`);
console.log(`        endpoint="https://telemetry.loopgain.ai/v1/aggregate",`);
console.log(`        token="${token}",`);
console.log(`    )`);
