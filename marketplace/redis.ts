import { RedisClient } from "bun";

let _redis: RedisClient | null = null;
let _available = false;

export async function getRedis(): Promise<RedisClient | null> {
  if (_redis && _available) return _redis;

  const url = process.env.REDIS_URL || process.env.REDIS_PRIVATE_URL;
  if (!url) return null;

  try {
    _redis = new RedisClient(url);
    await _redis.connect();
    _available = true;
    return _redis;
  } catch {
    _available = false;
    return null;
  }
}

export function isRedisAvailable(): boolean {
  return _available;
}

// ─── Rate Limiting ───────────────────────────────────────

interface RateLimitConfig {
  windowSec: number;
  maxRequests: number;
}

const RATE_LIMITS: Record<string, RateLimitConfig> = {
  auth: { windowSec: 900, maxRequests: 10 },
  write: { windowSec: 60, maxRequests: 20 },
  read: { windowSec: 60, maxRequests: 100 },
  global: { windowSec: 60, maxRequests: 200 },
};

// In-memory fallback
const memoryLimits = new Map<string, { count: number; resetAt: number }>();
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of memoryLimits) {
    if (entry.resetAt < now) memoryLimits.delete(key);
  }
}, 300_000);

export async function checkRateLimit(
  ip: string,
  bucket: string,
): Promise<{ allowed: boolean; remaining: number; resetIn: number }> {
  const config = RATE_LIMITS[bucket] || RATE_LIMITS["global"]!;
  const key = `rl:${bucket}:${ip}`;

  const redis = await getRedis();
  if (redis) {
    try {
      const count = await redis.incr(key);
      if (count === 1) {
        await redis.expire(key, config.windowSec);
      }
      const ttl = await redis.ttl(key);
      const remaining = Math.max(0, config.maxRequests - count);
      return {
        allowed: count <= config.maxRequests,
        remaining,
        resetIn: ttl > 0 ? ttl : config.windowSec,
      };
    } catch {
      // Fall through to in-memory
    }
  }

  // In-memory fallback
  const now = Date.now();
  let entry = memoryLimits.get(key);
  if (!entry || entry.resetAt < now) {
    entry = { count: 0, resetAt: now + config.windowSec * 1000 };
    memoryLimits.set(key, entry);
  }
  entry.count++;
  const remaining = Math.max(0, config.maxRequests - entry.count);
  const resetIn = Math.ceil((entry.resetAt - now) / 1000);
  return { allowed: entry.count <= config.maxRequests, remaining, resetIn };
}

// ─── Caching ─────────────────────────────────────────────

export async function cacheGet(key: string): Promise<string | null> {
  const redis = await getRedis();
  if (!redis) return null;
  try {
    return await redis.get(key);
  } catch {
    return null;
  }
}

export async function cacheSet(
  key: string,
  value: string,
  ttlSec: number = 300,
): Promise<void> {
  const redis = await getRedis();
  if (!redis) return;
  try {
    await redis.set(key, value, "EX", ttlSec);
  } catch {
    /* noop */
  }
}

export async function cacheDel(key: string): Promise<void> {
  const redis = await getRedis();
  if (!redis) return;
  try {
    await redis.del(key);
  } catch {
    /* noop */
  }
}

// ─── Pub/Sub for real-time notifications ─────────────────

export async function publishEvent(
  channel: string,
  data: unknown,
): Promise<void> {
  const redis = await getRedis();
  if (!redis) return;
  try {
    const pub = await redis.duplicate();
    await pub.publish(channel, JSON.stringify(data));
    pub.close();
  } catch {
    /* noop */
  }
}
