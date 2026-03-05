type Bucket = { count: number; resetAt: number };
const buckets = new Map<string, Bucket>();

export function rateLimitOrThrow(key: string, opts: { limit: number; windowMs: number }) {
  const now = Date.now();
  const existing = buckets.get(key);

  if (!existing || existing.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + opts.windowMs });
    return;
  }

  existing.count++;
  if (existing.count > opts.limit) {
    throw createError({ statusCode: 429, statusMessage: "Too many requests (rate limit)" });
  }
}
