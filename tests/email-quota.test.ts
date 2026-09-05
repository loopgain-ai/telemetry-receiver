import { describe, it, expect, vi, afterEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { reserveEmailQuota } from '../src/email-quota';
import { deliverEmail } from '../src/index';

const migration = readFileSync(new URL('../migrations/0010_email_quota.sql', import.meta.url), 'utf8');
function database() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(`CREATE TABLE alert_deliveries(id INTEGER PRIMARY KEY, customer_id TEXT, fired_at INTEGER, delivery_status TEXT);`);
  sql.exec(migration);
  const db = { prepare(query) { return { bind(...args) { return { async first() { return sql.prepare(query).get(...args) ?? null; } }; } }; } };
  return { sql, db };
}
const rule = { id: 1, customer_id: 'a', name: 'test', action_url: 'test@example.com' };
const result = {};
afterEach(() => vi.unstubAllGlobals());

describe('immutable email quota', () => {
  it('allows exactly the cap across concurrent requests and isolates customers', async () => {
    const {sql, db} = database();
    const ids = await Promise.all(Array.from({length: 60}, () => reserveEmailQuota(db, 'a', 50)));
    expect(ids.filter(Boolean)).toHaveLength(50);
    expect(await reserveEmailQuota(db, 'b', 50)).toBeTruthy();
    sql.exec('DELETE FROM alert_deliveries');
    expect(await reserveEmailQuota(db, 'a', 50)).toBeNull();
    sql.exec("UPDATE email_quota_reservations SET reserved_at = unixepoch() - 86401 WHERE customer_id = 'a'");
    expect(await reserveEmailQuota(db, 'a', 50)).toBeTruthy();
    sql.close();
  });
  it('serializes competing SQLite connections at the final quota slot', async () => {
    let query = '';
    await reserveEmailQuota({prepare(sql) { query = sql; return {bind() {return {first: async () => null};}};}}, 'a', 50);
    const dir = mkdtempSync(join(tmpdir(), 'email-quota-'));
    try {
      const path = join(dir, 'quota.sqlite');
      const sql = new DatabaseSync(path);
      sql.exec('CREATE TABLE alert_deliveries(id INTEGER PRIMARY KEY, customer_id TEXT, fired_at INTEGER, delivery_status TEXT)');
      sql.exec(migration); sql.close();
      const counts = await Promise.all(Array.from({length: 4}, (_, index) => new Promise((resolve, reject) => {
        const worker = new Worker(`
          const {parentPort,workerData:d}=require('node:worker_threads');
          const {DatabaseSync}=require('node:sqlite'); const db=new DatabaseSync(d.path);
          db.exec('PRAGMA busy_timeout=5000'); let n=0;
          for(let i=0;i<30;i++) if(db.prepare(d.query).get(d.index+'-'+i,'a','a',50)) n++;
          db.close(); parentPort.postMessage(n);
        `, {eval:true, workerData:{path,query,index}});
        worker.once('message', resolve); worker.once('error', reject);
      })));
      expect(counts.reduce((a,b) => a+b, 0)).toBe(50);
    } finally { rmSync(dir, {recursive:true, force:true}); }
  });
  it('backfills retained history regardless of channel and is repeatable', () => {
    const {sql} = database();
    sql.exec(`INSERT INTO alert_deliveries VALUES (1, 'a', unixepoch(), 'sent'), (2, 'a', unixepoch(), 'test_sent'), (3, 'a', unixepoch(), 'failed'), (4, 'a', unixepoch()-86401, 'sent');`);
    sql.exec(migration); sql.exec(migration);
    expect(sql.prepare('SELECT COUNT(*) AS n FROM email_quota_reservations').get().n).toBe(2);
    sql.close();
  });
  it('actual email path sends once, uses its reservation key, then refuses exhausted quota', async () => {
    const {sql, db} = database();
    const fetch = vi.fn(async () => new Response('', {status: 200})); vi.stubGlobal('fetch', fetch);
    const env = {DB: db, RESEND_API_KEY: 'synthetic', ALERT_FROM: 'sender@example.com'};
    expect((await deliverEmail(env, rule, result, 0, true)).status).toBe('sent');
    const id = sql.prepare('SELECT id FROM email_quota_reservations').get().id;
    expect(fetch.mock.calls[0][1].headers['Idempotency-Key']).toBe(id);
    await Promise.all(Array.from({length: 49}, () => reserveEmailQuota(db, 'a', 50)));
    expect((await deliverEmail(env, {...rule, id: 999}, result, 0, true)).error).toBe('email_daily_cap_reached');
    expect(fetch).toHaveBeenCalledTimes(1); sql.close();
  });
  it('provider rejection retains usage; missing ledger fails before fetch', async () => {
    const {sql, db} = database(); const fetch = vi.fn(async () => new Response('', {status: 400})); vi.stubGlobal('fetch', fetch);
    const env = {DB: db, RESEND_API_KEY: 'synthetic', ALERT_FROM: 'sender@example.com'};
    expect((await deliverEmail(env, rule, result, 0, true)).status).toBe('failed');
    expect(sql.prepare('SELECT COUNT(*) AS n FROM email_quota_reservations').get().n).toBe(1);
    sql.exec('DROP TABLE email_quota_reservations');
    await expect(deliverEmail(env, rule, result, 0, true)).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1); sql.close();
  });
  it('unconfigured or invalid destinations consume no reservation', async () => {
    const {sql, db} = database(); const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    await deliverEmail({DB: db}, rule, result, 0, true);
    await deliverEmail({DB: db, RESEND_API_KEY:'synthetic', ALERT_FROM:'sender@example.com'}, {...rule, action_url:'invalid'}, result, 0, true);
    expect(sql.prepare('SELECT COUNT(*) AS n FROM email_quota_reservations').get().n).toBe(0);
    expect(fetch).not.toHaveBeenCalled(); sql.close();
  });
});
