# loopgain-telemetry-receiver

Cloudflare Worker that ingests anonymized telemetry from the [loopgain](https://github.com/loopgain-ai/loopgain) Python library and serves aggregated reads to the LoopGain dashboard.

**Privacy contract** (enforced by the library at the source): only structural statistics are sent and stored — state transitions, Aβ summaries (min/max/median), gain margin, rollback flag, library version, optional opaque `workload_id`, threshold config. Never prompts, completions, error contents, output buffers, or any per-iteration Aβ.

---

## Endpoints

| Route | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/v1/aggregate` | POST | Bearer | Ingest a single telemetry payload (called by the library). |
| `/v1/stats` | GET | Bearer | 30-day aggregate stats (outcome counts, totals, workload list). |
| `/v1/profiles` | GET | Bearer | Convergence-profile events (optional `?workload_id=` and `?since_hours=` filters). |
| `/v1/events` | GET | Bearer | Recent loop events (optional `?rollbacks_only=true`). |
| `/health` | GET | none | Liveness probe. |

All authenticated endpoints expect `Authorization: Bearer <token>`. Tokens are mapped to a `customer_id`; only that customer's data is returned.

---

## Architecture

```
[loopgain library] --POST--> [Cloudflare Worker] --D1--> [loopgain-telemetry]
                                     |
                                     +--GET--> [LoopGain dashboard]
```

- **Worker**: stateless, edge-deployed, TypeScript. Auth + write + simple aggregated reads.
- **D1**: SQLite at the edge. Two tables: `customers` (bearer-token → customer_id) and `loop_events` (immutable append-only events).
- **No application server.** This is intentional — pre-scale, the operational footprint is one Worker + one D1 database.

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
# In wrangler.toml, uncomment the [[routes]] block and set your zone.
# In your DNS, add a CNAME: telemetry.loopgain.ai → <your-account>.workers.dev.
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

## Issuing a bearer token to a customer

Tokens are issued via a one-liner script. The plain token is printed once; only its SHA-256 hash is stored.

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

Hand the bearer token to the customer; they configure it in their library call:

```python
lg.send_telemetry(
    endpoint="https://telemetry.loopgain.ai/v1/aggregate",
    token="lgk_...",
    workload_id="my-rag-pipeline",
)
```

To rotate a token, issue a new one and `DELETE FROM customers WHERE customer_id = '...'` (or null out `token_hash`) when ready.

---

## Schema

See [`schema.sql`](./schema.sql) for the full DDL. Two tables:

- **`customers`**: `customer_id` (primary), `token_hash` (SHA-256 of bearer token), `name`, `contact_email`, `created_at`, `last_seen_at`.
- **`loop_events`**: one row per loop run. Columns mirror the v1 telemetry payload: outcome, iterations_used, gain_margin, savings, rollback flag, profile_{min,max,median,samples}, threshold config, smoothing window, library_version, workload_id, timestamp_hour, received_at.

Indexes are tuned for the dashboard's two dominant query shapes: `(customer_id, timestamp_hour DESC)` for time-range scans and `(customer_id, workload_id, timestamp_hour DESC)` for per-workload drilldown.

---

## Self-hosting

The receiver is licensed under Apache-2.0. Customers who want to keep telemetry under their own control can fork or clone this repo, deploy to their own Cloudflare account, and point the library at their endpoint instead of `telemetry.loopgain.ai`:

```python
lg.send_telemetry(
    endpoint="https://telemetry.acme.internal/v1/aggregate",
    token="...",
)
```

---

## License

[Apache-2.0](LICENSE).
