/** Single SQLite write: concurrent requests cannot both claim the last slot. */
export async function reserveEmailQuota(
  db: D1Database, customerId: string, cap: number,
): Promise<string | null> {
  const id = crypto.randomUUID();
  const result = await db.prepare(`
    INSERT INTO email_quota_reservations (id, customer_id, reserved_at)
    SELECT ?, ?, unixepoch()
    WHERE (SELECT COUNT(*) FROM email_quota_reservations
           WHERE customer_id = ? AND reserved_at >= unixepoch() - 86400) < ?
    RETURNING id
  `).bind(id, customerId, customerId, cap).first<{ id: string }>();
  return result?.id ?? null;
}
