import Redis from "ioredis";
import finalConfig from "./keys.js";
import logger from "./logger.js";

/**
 * Redis service class
 * Using ioredis package for Redis operations
 */
class RedisService {
  static #instance;

  // Resolvers waiting for the client to reach "ready" (see waitUntilReady)
  #readyWaiters = [];

  /**
   * Get the singleton instance of RedisService
   * @param {Object} options - Redis connection options
   * @returns {RedisService} - The singleton instance
   */
  static getInstance(options = {}) {
    if (!RedisService.#instance) {
      RedisService.#instance = new RedisService(options);
    }
    return RedisService.#instance;
  }

  /**
   * Create a new RedisService instance (private constructor)
   * @param {Object} options - Redis connection options
   */
  constructor(options = {}) {
    //Prevent multiple instances
    if (RedisService.#instance) {
      return RedisService.#instance;
    }

    this.options = {
      host: options.host || finalConfig.redis?.host || "127.0.0.1",
      port: options.port || finalConfig.redis?.port || 6379,
      username: options.username || finalConfig.redis?.username || "",
      password: options.password || finalConfig.redis?.password || "",
      db: options.db || finalConfig.redis?.db || 0,
      onConnect: options.onConnect || (() => {}),
      onError: options.onError || (() => {}),
    };

    this.client = null;
    RedisService.#instance = this;
  }

  /**
   * Initialize Redis Client if not already initialized
   * @returns {Promise<boolean>} - True if successfully connected or already connected
   */
  async connect() {
    if (this.client && this.isConnected()) {
      logger.info("Redis already connected, reusing existing connection");
      return true;
    }

    try {
      // Create Redis instance
      this.client = new Redis({
        port: this.options.port,
        host: this.options.host,
        username: this.options.username,
        password: this.options.password,
        db: this.options.db,
        retryStrategy: times => {
          // Custom retry strategy
          const delay = Math.min(times * 50, 2000);
          return delay;
        },
        lazyConnect: true,
        connectTimeout: 10000,
        maxRetriesPerRequest: 3, // Fail commands fast during an outage instead of hanging
      });

      // Attach listeners BEFORE connecting, so initial connect/error events are not missed
      this.client.on("connect", () => {
        logger.info("Redis client connected");
        this.options.onConnect();
      });

      this.client.on("error", err => {
        logger.error(`Redis client error:`,err);
        this.options.onError(err);
      });

      this.client.on("ready", () => {
        logger.info("Redis client ready");
        // Wake up anything blocked in waitUntilReady()
        for (const resolve of this.#readyWaiters) resolve(this.client);
        this.#readyWaiters = [];
      });

      this.client.on("reconnecting", () => {
        logger.warn("Redis client reconnecting");
      });

      this.client.on("end", () => {
        logger.info("Redis client connection closed");
      });

      await this.client.connect();

      return true;
    } catch (err) {
      logger.error(`Redis initialization error:`, err);
      return false;
    }
  }

  /**
   * Get Redis connection status
   * @returns {boolean} - True if connected, false otherwise
   */
  isConnected() {
    return this.client && this.client.status === "ready";
  }

  /**
   * Resolve with the client once it is ready.
   * Lets consumers created before connect() (e.g. rate-limit stores built at
   * module load) defer their first command until the connection exists.
   * @returns {Promise<Redis>} - Promise resolving to the ready client
   */
  waitUntilReady() {
    if (this.isConnected()) {
      return Promise.resolve(this.client);
    }
    return new Promise(resolve => {
      this.#readyWaiters.push(resolve);
    });
  }

  /**
   * Close Redis Connection
   * @returns {Promise<void>}
   */
  async disconnect() {
    if (this.client) {
      await this.client.quit();
      this.client = null;
      logger.info("Redis connection closed gracefully");
    }
  }

  /**
   * Get a value from Redis
   * @param {string} key - Key to get value for
   * @returns {Promise<any>} - Promise resolving to the value or null if not found
   */
  async get(key) {
    try {
      const value = await this.client.get(key);
      return value ? JSON.parse(value) : null;
    } catch (err) {
      logger.error(`Redis GET error: ${err.message}`, { op: "GET", key });
      return null;
    }
  }

  /**
   * Set a value in Redis
   * @param {string} key - Key to set
   * @param {any} value - Value to store (will be stringified)
   * @param {number} [expiry] - Expire time in seconds (optional)
   * @returns {Promise<boolean>} - Promise resolving to true if successful
   */
  async set(key, value, expiry = null) {
    try {
      const stringValue = JSON.stringify(value);
      if (expiry) {
        await this.client.set(key, stringValue, "EX", expiry);
      } else {
        await this.client.set(key, stringValue);
      }
      return true;
    } catch (err) {
      logger.error(`Redis SET error: ${err.message}`, { op: "SET", key });
      return false;
    }
  }

  /**
   * Delete a key from Redis
   * @param {string} key - Key to delete
   * @returns {Promise<boolean>} - Promise resolving to true if sucessful
   */
  async del(key) {
    try {
      await this.client.del(key);
      return true;
    } catch (err) {
      logger.error(`Redis DEL error: ${err.message}`, { op: "DEL", key });
      return false;
    }
  }

  /**
   * Check if a key exist in Redis
   * @param {string} key - Key to check
   * @returns {Promise<boolean>} - Promise resolving to true if key exist
   */
  async exists(key) {
    try {
      const result = await this.client.exists(key);
      return result === 1;
    } catch (err) {
      logger.error(`Redis EXISTS error: ${err.message}`, {
        op: "EXISTS",
        key,
      });
      return false;
    }
  }

  /**
   * Set expiration time  on a key
   * @param {string} key - key to expire
   * @param {number} seconds - seconds until expiration
   * @returns {Promise<boolean>} - Promise resolving to true if successful
   */
  async expires(key, seconds) {
    try {
      await this.client.expire(key, seconds);
      return true;
    } catch (err) {
      logger.error(`Redis EXPIRE error: ${err.message}`, {
        op: "EXPIRE",
        key,
      });
      return false;
    }
  }

  /**
   * Increment a key's value
   * @param {string} key - key to increment
   * @returns {Promise<number|null>} - Promise resolving to the new value
   */
  async incr(key) {
    try {
      return await this.client.incr(key);
    } catch (err) {
      logger.error(`Redis INCR error: ${err.message}`, { op: "INCR", key });
      return null;
    }
  }

  /**
   * Atomically increment a key and set its TTL if it has none.
   * Safe for rate-limit counters (no gap between INCR and EXPIRE).
   * @param {string} key - key to increment
   * @param {number} windowSeconds - TTL in seconds, applied only if the key has no TTL
   * @returns {Promise<number|null>} - Promise resolving to the new count, or null on error
   */
  async incrWithExpire(key, windowSeconds) {
    try {
      const results = await this.client
        .multi()
        .incr(key)
        .expire(key, windowSeconds, "NX") // NX: only set TTL if none exists
        .exec();
      return results[0][1]; // the INCR result
    } catch (err) {
      logger.error(`Redis INCR+EXPIRE error: ${err.message}`, {
        op: "INCR+EXPIRE",
        key,
      });
      return null;
    }
  }

  /**
   * Set multiple hash fields to multiple values
   * @param {string} key - Hash key
   * @param {Object} fields - Object containing fields-value pairs
   * @return {Promise<boolean>} - Promise resolving to true if successful
   */
  async hset(key, fields) {
    try {
      const args = [key];
      for (const [field, value] of Object.entries(fields)) {
        args.push(
          field,
          typeof value === "object" ? JSON.stringify(value) : value,
        );
      }
      await this.client.hset(...args);
      return true;
    } catch (err) {
      logger.error(`Redis HSET error: ${err.message}`, { op: "HSET", key });
      return false;
    }
  }

  /**
   * Get all fields and values in a hash
   * @param {string} key - Hash key
   * @returns {Promise<Object|null>} - Promise resolving to an object with all field-value pairs
   */
  async hgetall(key) {
    try {
      return await this.client.hgetall(key);
    } catch (err) {
      logger.error(`Redis HGETALL error: ${err.message}`, {
        op: "HGETALL",
        key,
      });
      return null;
    }
  }

  /**
   * Push a value to the end of a list
   * @param {string} key - List key
   * @param {any} value -  value to push
   * @returns {Promise<number|null} - Promise resolving to the new lenght of the list
   */
  async rpush(key, value) {
    try {
      return await this.client.rpush(
        key,
        typeof value === "object" ? JSON.stringify(value) : value,
      );
    } catch (err) {
      logger.error(`Redis RPUSH error: ${err.message}`, { op: "RPUSH", key });
      return null;
    }
  }

  /**
   * Get a range of element from a list
   * @param {string} key - List key
   * @param {number} start - start index
   * @param {number} stop - stop index
   * @returns {Promise<Array|null>} - Promise resolving to array of elements
   */
  async lrange(key, start, stop) {
    try {
      const result = await this.client.lrange(key, start, stop);
      return result.map(items => {
        try {
          return JSON.parse(items);
        } catch {
          return items;
        }
      });
    } catch (err) {
      logger.error(`Redis LRANGE error: ${err.message}`, {
        op: "LRANGE",
        key,
      });
      return null;
    }
  }
}

// Export the Redis Service singleton instance (not connected yet)
const redisService = new RedisService();

export default redisService;
