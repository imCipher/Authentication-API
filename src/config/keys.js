import "dotenv/config";

// Storing configuration values in a single object makes it easier
// to manage and access them throughout the application.
// This object can be imported wherever needed,
// ensuring consistency and reducing the risk of typos
// or mismatched values.
const config = {
  // Server
  env: (process.env.NODE_ENV || "development").toLowerCase(),
  port: parseInt(process.env.PORT, 10) || 5000,
  apiVersion: process.env.API_VERSION || "v1",

  // Lockout
  lockout: {
    maxFailedAttempts:
      parseInt(process.env.LOCKOUT_MAX_FAILED_ATTEMPTS, 10) || 5,
    lockoutDuration:
      parseInt(process.env.LOCKOUT_DURATION, 10) || 15 * 60 * 1000, // 15 minutes
  },

  // Nodemailer
  email: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10) || 587,
    secure: process.env.EMAIL_SECURE === "true", // true for 465, false for other ports
    user: process.env.EMAIL_USER.toLowerCase(),
    pass: process.env.EMAIL_PASS,
    from: process.env.EMAIL_FROM,
  },

  // Google OAuth
  googleOAuth: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackUrl: process.env.GOOGLE_CALLBACK_URL,
  },

  // Github OAuth
  githubOAuth: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackUrl: process.env.GITHUB_CALLBACK_URL,
  },

  // Redis
  redis: {
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB, 10) || 0,
  },

  // JWT
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiresIn: parseInt(process.env.JWT_REFRESH_EXPIRES_IN, 10) || 7, // Default 7 days
  },

  // Cors
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  },

  // Rate Limit
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
    maxRequest: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
  },
};

/**
 * Validates the configuration object to ensure that all required
 * environment variables are set and that they have secure values,
 * especially in production.
 */
export const validateConfig = () => {
  if (config.env === "production") {
    const required = ["DATABASE_URL"];
    const missing = required.filter(key => !process.env[key]);

    if (missing.length > 0) {
      throw new Error(
        `Missing required environment variables: ${missing.join(", ")}`,
      );
    }
  }

  if (!config.jwt.refreshSecret || config.jwt.refreshSecret.length < 32) {
    throw new Error(
      "JWT_REFRESH_SECRET is not set or is too short. Token signing cannot work.",
    );
  }

  if (!/^[0-9]$/.test(String(config.jwt.refreshExpiresIn))) {
    throw new Error(
      `JWT_REFRESH_EXPIRES_IN must be a number (e.g. "7"), got "${config.jwt.refreshExpiresIn}"`,
    );
  }

  if (!config.jwt.accessSecret || config.jwt.accessSecret.length < 32) {
    throw new Error(
      "JWT_ACCESS_SECRET is not set or is too short. Token signing cannot work.",
    );
  }

  if (!/^\d+(ms|s|m|h|d)$/.test(String(config.jwt.accessExpiresIn))) {
    throw new Error(
      `JWT_ACCESS_EXPIRES_IN must include a unit (e.g. "15m"), got "${config.jwt.accessExpiresIn}"`,
    );
  }
};

/**
 *
 * To Freeze Nested Objects in JavaScript
 */
const deepfreeze = obj => {
  for (const val of Object.values(obj)) {
    if (val && typeof val === "object") {
      deepfreeze(val);
    }
  }
  return Object.freeze(obj);
};

let finalConfig;

if (config.env === "development" || config.env === "testing") {
  finalConfig = config;
} else {
  finalConfig = deepfreeze(config);
}

export default finalConfig;
