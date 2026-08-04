import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";

import logger from "../config/logger.js";
import redisService from "../config/redis.js";
import finalConfig from "../config/keys.js";
import ApiError from "../Utils/ApiError.js";

/**
 * Rate limiter factory with Redis-backed and in-memory limiters.
 * - Both limiters are created eagerly at app initialization (module load),
 *   which is required by express-rate-limit (ERR_ERL_CREATED_IN_REQUEST_HANDLER).
 * - The RedisStore is created before Redis connects; its sendCommand waits for
 *   the client to be ready (waitUntilReady) so the store's init-time SCRIPT LOAD
 *   simply resolves once the connection is up instead of crashing on a null client.
 * - Per request, the wrapper routes to the Redis limiter when Redis is ready,
 *   and falls back to the memory limiter otherwise (auto-recovers when Redis
 *   comes online — counts do not carry across the switch).
 * - passOnStoreError: a Redis outage mid-flight fails OPEN (requests pass)
 *   instead of erroring every request — DB-level account lockout still protects accounts.
 * - In testing environment, rate limiting is disabled to prevent test failures.
 *
 * @param {Object} config
 * @param {string} config.storePrefix - Redis key prefix (e.g. "rl:register:")
 * @param {number} config.windowMs - Window size in milliseconds
 * @param {number} config.max - Max requests per window per IP
 * @param {string} config.label - Human-readable name used in logs
 * @param {string} config.message - Message returned to the client on 429
 * @returns {Function} Express middleware
 */
const createRateLimiterWithFallback = ({
  storePrefix,
  windowMs,
  max,
  label,
  message,
}) => {
  const sharedOptions = {
    windowMs,
    max,
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    passOnStoreError: true, // Fail open if the store errors mid-flight

    handler: (req, res, next) => {
      next(ApiError.tooManyRequests(message));
    },
  };

  // Memory-store limiter — fallback when Redis is unavailable
  const memoryLimiter = rateLimit({ ...sharedOptions });

  // Redis-store limiter — created eagerly; commands only run at request time
  let redisLimiter = null;
  try {
    redisLimiter = rateLimit({
      ...sharedOptions,
      store: new RedisStore({
        // Wait for the client to be ready — the store runs SCRIPT LOAD
        // at creation time, before redisService.connect() has been called
        sendCommand: async (...args) => {
          const client = await redisService.waitUntilReady();
          return client.call(...args);
        },
        prefix: storePrefix,
      }),
    });
  } catch (error) {
    logger.warn(`Redis Store creation failed for [${label}]:`, error);
  }

  let activeStore = null; // "redis" | "memory" — tracked to log transitions once

  return (req, res, next) => {
    // Bypass rate limiting in testing environment
    if (finalConfig.env === "testing" || finalConfig.env === "test") {
      return next();
    }

    const useRedis = redisLimiter && redisService.isConnected();
    const target = useRedis ? "redis" : "memory";

    if (target !== activeStore) {
      activeStore = target;
      if (useRedis) {
        logger.info(`Using Redis store for rate limiting: ${label}`);
      } else {
        logger.warn(`Using memory store for rate limiting: ${label}`);
      }
    }

    return useRedis ?
        redisLimiter(req, res, next)
      : memoryLimiter(req, res, next);
  };
};

/**
 * Rate limiter for registration route
 * Limits requests to 5 per minute per IP address
 */
export const registerRateLimiter = createRateLimiterWithFallback({
  storePrefix: "rl:register:",
  label: "register",
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 requests per minute per IP
  message:
    "Too many registration attempts from this IP, please try again in a minute.",
});

/**
 * General authentication rate limiter for login/refresh/logout routes
 * More lenient than registration rate limiter
 */
export const authRateLimiter = createRateLimiterWithFallback({
  storePrefix: "rl:auth:",
  label: "auth",
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 requests per 15 minutes per IP
  message:
    "Too many authentication attempts from this IP, please try again later.",
});

/**
 * Email verification rate limiter (send/resend verification email)
 * Strict — these routes send email; abuse gets the domain blacklisted
 */
export const emailVerificationRateLimiter = createRateLimiterWithFallback({
  storePrefix: "rl:email-verify:",
  label: "email-verification",
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 requests per 15 minutes per IP
  message: "Too many verification email requests, please try again later.",
});

/**
 * Password reset rate limiter (forgot-password / reset-password)
 * Strict — sends email and is a common enumeration/abuse target
 */
export const passwordResetRateLimiter = createRateLimiterWithFallback({
  storePrefix: "rl:password-reset:",
  label: "password-reset",
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 requests per 15 minutes per IP
  message: "Too many password reset requests, please try again later.",
});

/**
 * Global rate limiter applied to all API routes
 * Coarse flood protection; per-route limiters above are stricter
 */
export const generalRateLimiter = createRateLimiterWithFallback({
  storePrefix: "rl:general:",
  label: "general",
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 minutes per IP
  message: "Too many requests from this IP, please try again later.",
});

export default {
  registerRateLimiter,
  authRateLimiter,
  emailVerificationRateLimiter,
  passwordResetRateLimiter,
  generalRateLimiter,
};
