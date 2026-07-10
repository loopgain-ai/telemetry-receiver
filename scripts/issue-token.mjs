#!/usr/bin/env node
/**
 * Issue a new bearer token for a customer.
 *
 * Usage:
 *   node scripts/issue-token.mjs --name "ACME Corp" --email "ops@acme.com" --tier team [--local]
 *
 * --tier is one of individual|team|enterprise. If omitted, the customer
 * is provisioned unclassified (tier NULL) — exempt from the free-tier daily
 * cap and from retention pruning until a tier is assigned. There is no
 * silent default; an omitted --tier prints a warning so it's a deliberate
 * choice, not an accident (see migrations/0009_tier.sql for why NULL is the
 * safe default rather than defaulting new tokens to 'individual').
 *
 * Prints the customer_id and the plain-text token. The plain token is shown
 * ONCE and never stored — only its SHA-256 hash is persisted in the DB.
 * Hand the token to the customer; they put it in their `LoopGain.send_telemetry(token=...)`.
 *
 * Hardening notes:
 *   - SQL is written to a temp file and executed via `wrangler d1 execute --file`.
 *     No string interpolation into a shell command line; no shell injection
 *     surface even if --name / --email contain quotes, backslashes, or
 *     shell metacharacters.
 *   - The temp file lives in an mkdtemp directory and is removed after.
 */

import { execFileSync } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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

const VALID_TIERS = ["individual", "team", "enterprise"];
const tierArg = getArg("--tier");
if (tierArg && !VALID_TIERS.includes(tierArg)) {
  console.error(`Invalid --tier "${tierArg}". Must be one of: ${VALID_TIERS.join(", ")}`);
  process.exit(1);
}
if (!tierArg) {
  console.warn(
    "No --tier given — customer will be provisioned unclassified (no daily cap, no retention pruning) until a tier is assigned.",
  );
}
const tier = tierArg ?? null;

const customerId = `cust_${randomBytes(8).toString("hex")}`;
const token = `lgk_${randomBytes(24).toString("base64url")}`;
const tokenHash = createHash("sha256").update(token).digest("hex");
const createdAt = Math.floor(Date.now() / 1000);

// SQL with single-quote-escaped string literals. Embedded into a .sql file
// (no shell), so shell metachars in name/email are irrelevant. Single-quote
// escaping (double them up) handles SQL-side correctness.
function sqlEscape(s) {
  return s.replace(/'/g, "''");
}
const tierSql = tier ? `'${sqlEscape(tier)}'` : "NULL";
const sql = `INSERT INTO customers (customer_id, token_hash, name, contact_email, created_at, tier)
  VALUES ('${customerId}', '${tokenHash}', '${sqlEscape(name)}',
          '${sqlEscape(email)}', ${createdAt}, ${tierSql});\n`;

const dir = mkdtempSync(join(tmpdir(), "loopgain-issue-"));
const sqlPath = join(dir, "insert.sql");

console.log(`Issuing token for "${name}"...`);

try {
  writeFileSync(sqlPath, sql, { encoding: "utf8", mode: 0o600 });
  execFileSync(
    "wrangler",
    [
      "d1",
      "execute",
      "loopgain-telemetry",
      local ? "--local" : "--remote",
      `--file=${sqlPath}`,
    ],
    { stdio: "inherit" },
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log("");
console.log("=".repeat(70));
console.log(`Customer ID:  ${customerId}`);
console.log(`Tier:         ${tier ?? "(unclassified)"}`);
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
