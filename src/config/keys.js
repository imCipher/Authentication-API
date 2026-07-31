import "dotenv/config";

const config = {
  // Server
  env: (process.env.NODE_ENV || "development").toLowerCase(),
  port: parseInt(process.env.PORT, 10) || 5000,
  apiVersion: process.env.API_VERSION || "v1",

  // JWT
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
  },

  // Rate Limit
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
    maxRequest: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
  },
};

export const validateConfig = () => {
  if (config.env === "production") {
    const required = [
      "JWT_ACCESS_SECRET",
      "JWT_REFRESH_SECRET",
      "DATABASE_URL",
    ];
    const missing = required.filter(key => !process.env[key]);

    if (missing.length > 0) {
      throw new Error(
        `Missing required environment variables: ${missing.join(", ")}`,
      );
    }

    if (
      config.jwt.accessSecret.includes("default") ||
      config.jwt.refreshSecret.includes("default")
    ) {
      throw new Error("JWT Secrets must be set to secure values in production");
    }
  }
};

let finalConfig;

if (config.env === "development" || config.env === "testing") {
  finalConfig = config;
} else {
  finalConfig = Object.freeze(config);
}

export default finalConfig;
