# loopgain-telemetry-receiver

Cloudflare Worker that ingests anonymized telemetry from the [loopgain](https://github.com/loopgain-ai/loopgain) Python library and serves aggregated reads to the [LoopGain dashboard](https://github.com/loopgain-ai/dashboard).

**Privacy contract** (enforced by the library at the source): only structural statistics are sent and stored — state transitions, Aβ summaries (min/max/median), rollback flag, library version, optional opaque `workload_id`, threshold config. Never prompts, completions, error contents, output buffers, or any per-iteration Aβ.

---

## Endpoints

| Route | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/v1/aggregate` | POST | Bearer | Ingest one telemetry payload (called by the library; server-to-server only — browser-origin requests are rejected). |
| `/v1/funnel` | POST | **none** | Ingest a batch of **anonymous** adoption-funnel events from the library's `loopgain.funnel` module (install → first `observe()` → recurring use). Separate table from `/v1/aggregate`; no bearer token, no customer, **no IP stored**. |
| `/v1/stats` | GET | Bearer | 30-day aggregate stats (outcome counts, totals, distinct framework / loop_type / team values for filter dropdowns). |
| `/v1/profiles` | GET | Bearer | Convergence-profile events. Optional `workload_id`, `since_hours`, `framework`, `loop_type`, `team` filters. |
| `/v1/events` | GET | Bearer | Recent loop events. Optional `rollbacks_only=true` plus the same filter set. |
| `/v1/calibration` | GET | Bearer | Converged loops with first-ETA-prediction snapshots (drives the ETA Accuracy panel). |
| `/v1/event/:id` | GET | Bearer | Full detail for one event including per-iteration trajectories (drives Loop Detail scrubbing). |
| `/v1/alerts/rules` | GET / POST | Bearer | List or create alert rules. |
| `/v1/alerts/rules/:id` | PUT / DELETE | Bearer | Update or delete an alert rule. |
| `/v1/alerts/deliveries` | GET | Bearer | Audit log of alert deliveries (recent first). |
| `/health` | GET | none | Liveness probe. |

All authenticated routes expect `Authorization: Bearer <token>`. Tokens are mapped to a `customer_id`; only that customer's data is returned.

A `scheduled` cron handler runs every minute and evaluates each enabled alert rule against the recent `loop_events` window, recording fires to `alert_deliveries`.

### Webhook signature verification

If an alert rule has an `action_secret` set, every webhook delivery is signed so your endpoint can verify it genuinely came from the receiver (and reject forgeries from anyone who learns the URL). Two headers are sent:

- `X-LoopGain-Timestamp` — the fire time, unix seconds.
- `X-LoopGain-Signature` — `sha256=<hex>`, where `<hex>` is `HMAC-SHA256(action_secret, "{timestamp}.{raw_request_body}")`.

To verify: recompute the HMAC over `` `${X-LoopGain-Timestamp}.${rawBody}` `` using your shared secret, compare against the header value in **constant time**, and reject deliveries whose timestamp is outside your tolerance window (e.g. ±5 min) to defeat replay. Example (Node):

```js
import { createHmac, timingSafeEqual } from "node:crypto";

function verify(rawBody, headers, secret, toleranceSec = 300) {
  const ts = headers["x-loopgain-timestamp"];
  const got = headers["x-loopgain-signature"];
  if (!ts || !got) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > toleranceSec) return false;
  const want = "sha256=" + createHmac("sha256", secret).update(`${ts}.${rawBody}`).digest("hex");
  const a = Buffer.from(got), b = Buffer.from(want);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

Rules without an `action_secret` are delivered unsigned. The secret is write-only — it is never returned by the read endpoints.

---

## Architecture

```
[loopgain library] --POST--> [Cloudflare Worker] --D1--> [loopgain-telemetry]
                                     |                          ^
                                     +--GET--> [dashboard]      |
                                     |                          |
                                     +--cron (1m)--> [alert evaluator]
```

- **Worker**: stateless, edge-deployed, TypeScript. Auth + write + aggregated reads + alert evaluation.
- **D1**: SQLite at the edge. Tables: `customers` (bearer-token → customer_id), `loop_events` (append-only event log), `alert_rules`, `alert_deliveries`.
- **No application server.** Pre-scale, the operational footprint is one Worker + one D1 database.

**Schema versions.** The receiver accepts payloads at schema v1, v2, and v3. v2 added `first_eta_prediction` + `first_eta_at_iteration`; v3 added per-iteration trajectory JSON plus optional `framework` / `loop_type` / `team` classification labels. Older payloads store NULL for newer fields.

**Rate limiting.** Cloudflare first-party rate-limit bindings: per-IP across the authenticated routes (unauth abuse), per-customer on `/v1/aggregate` (ingestion ceiling), per-customer on read routes (dashboard polling ceiling), and a separate per-IP bucket on the unauthenticated `/v1/funnel` route so anonymous funnel traffic never touches the authed-route ceiling. CORS locked to `dashboard.loopgain.ai` plus a small set of localhost origins; `/v1/aggregate` does not accept browser-origin requests at all.

**Token rotation** is intentionally *not* available over HTTP. Rotation happens via the operator-side `scripts/rotate-token.mjs`, which requires Cloudflare account access — this eliminates the "leaked token can lock the owner out" blast radius.

---

## First-time deployment

Prereqs: Node 18+, Cloudflare account, `wrangler` CLI.

```bash
# 1. Install
npm install

# 2. Authenticate with Cloudflare (one-time)
npx wrangler login

# 3. Create the D1 database
npx wrangler d1 create loopgain-telemetry
# → prints a database_id. Copy it into wrangler.toml under [[d1_databases]].database_id

# 4. Apply the schema (remote = production D1)
npm run db:schema:remote

# 5. Deploy the worker
npx wrangler deploy
# → prints the worker URL, e.g. https://loopgain-telemetry-receiver.<your-account>.workers.dev

# 6. (Optional) Map a custom subdomain.
# Prerequisite: the target domain is on Cloudflare (a zone in your account).
# The bundled wrangler.toml has a [[routes]] block pre-set to
# telemetry.loopgain.ai — edit both fields for your own deployment:
#   pattern   = "your-host.example.com/*"
#   zone_name = "example.com"
# Then re-run `npx wrangler deploy`. Cloudflare provisions the route
# automatically — no DNS CNAME needed (Workers routes attach by URL
# pattern, not by hostname).
```

---

## Local development

```bash
# Apply schema to local D1
npm run db:schema:local

# Start the dev server (local D1, hot reload)
npm run dev
# → worker at http://localhost:8787

# In another shell, watch live logs
npm run tail
```

---

## Issuing a bearer token

Tokens are issued via a one-liner. The plain token is printed once; only its SHA-256 hash is stored.

```bash
# Production:
npm run issue-token -- --name "ACME Corp" --email "ops@acme.com"

# Local (against local D1):
npm run issue-token -- --name "test-account" --local
```

Output:

```
Customer ID:  cust_<16-hex-chars>
Bearer Token: lgk_<32-char-base64url>   # shown ONCE; never re-derivable
```

Hand the token to the customer; they configure it in their library call:

```python
lg.send_telemetry(
    endpoint="https://telemetry.loopgain.ai/v1/aggregate",
    token="lgk_...",
    workload_id="my-rag-pipeline",
)
```

To rotate, run `scripts/rotate-token.mjs` (or issue a fresh token and null out the previous `token_hash`).

---

## Schema

See [`schema.sql`](./schema.sql) for the full DDL. Five tables:

- **`customers`** — `customer_id`, `token_hash` (SHA-256), `name`, `contact_email`, timestamps.
- **`loop_events`** — one row per loop run. Columns mirror the telemetry payload across schema versions: outcome, iterations_used, gain_margin, savings, rollback flag, profile stats, threshold config, smoothing window, library_version, workload_id, timestamp_hour, received_at, plus the v2/v3 additions (eta snapshots, per-iteration JSON, framework / loop_type / team).
- **`alert_rules`** — per-customer rule definitions (enabled flag, predicate JSON, filter JSON, window seconds, cooldown).
- **`alert_deliveries`** — append-only fire log used by the dashboard's alert audit view.
- **`funnel_events`** — anonymous adoption-funnel events from `/v1/funnel` (`loopgain.funnel`). One row per event (`first_init` / `first_observe` / `session`): random `instance_id`, hour-bucketed `ts_hour`, library/python/os versions, adapter, session_seq, coarse outcome counts. **No `customer_id`, no token, no IP** — wholly separate from the product tables.

Indexes are tuned for the dashboard's dominant query shapes: `(customer_id, timestamp_hour DESC)` for time-range scans and `(customer_id, workload_id, timestamp_hour DESC)` for per-workload drilldown.

---

## Self-hosting

Apache-2.0. To keep telemetry under your own control: fork or clone, deploy to your own Cloudflare account, and point the library at your endpoint:

```python
lg.send_telemetry(
    endpoint="https://telemetry.acme.internal/v1/aggregate",
    token="...",
)
```

---

## License

[Apache-2.0](LICENSE).
