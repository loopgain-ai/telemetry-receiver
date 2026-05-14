#!/usr/bin/env node
/**
 * Rotate a customer's bearer token.
 *
 * The public `POST /v1/token/rotate` route was removed (2026-05-14) so that
 * a leaked token cannot lock its legitimate owner out. Rotation is now an
 * operator action only: it requires Cloudflare account access via wrangler.
 *
 * Usage:
 *   node scripts/rotate-token.mjs --customer-id cust_xxxxxxxxxxxxxxxx [--local]
 *
 * Prints the new plain-text token. The plain token is shown ONCE and never
 * stored — only its SHA-256 hash replaces the existing hash in the DB.
 * The old token stops working the moment this script's UPDATE commits.
 *
 * Hardening notes (mirrors issue-token.mjs):
 *   - SQL is written to a temp file and executed via `wrangler d1 execute --file`.
 *     No shell-string interpolation; no shell injection surface.
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

const customerId = getArg("--customer-id");
const local = hasFlag("--local");

if (!customerId) {
  console.error("Usage: node scripts/rotate-token.mjs --customer-id <id> [--local]");
  process.exit(2);
}
if (!/^cust_[a-f0-9]{16}$/.test(customerId)) {
  console.error(
    `Refusing to rotate: --customer-id ${JSON.stringify(customerId)} does not match cust_<16-hex>.`,
  );
  process.exit(2);
}

const token = `lgk_${randomBytes(24).toString("base64url")}`;
const tokenHash = createHash("sha256").update(token).digest("hex");
const rotatedAt = Math.floor(Date.now() / 1000);

// `customerId` already passed the regex above (alphanumeric + underscore +
// hex only); the additional SQL-side single-quote handling is defense in
// depth in case the regex is ever loosened.
function sqlEscape(s) {
  return s.replace(/'/g, "''");
}
const sql = `UPDATE customers
  SET token_hash = '${tokenHash}',
      last_seen_at = ${rotatedAt}
  WHERE customer_id = '${sqlEscape(customerId)}';\n`;

const dir = mkdtempSync(join(tmpdir(), "loopgain-rotate-"));
const sqlPath = join(dir, "rotate.sql");

console.log(`Rotating token for ${customerId} (${local ? "local" : "remote"} D1)...`);

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
console.log(`New Token:    ${token}`);
console.log(`Rotated at:   ${rotatedAt} (unix seconds)`);
console.log("=".repeat(70));
console.log("");
console.log("The bearer token above is shown ONCE. Hand it to the customer.");
console.log("Any client still using the OLD token will start getting 401s on its next request.");
