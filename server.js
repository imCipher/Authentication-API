import app from "./src/app.js";
import finalConfig, { validateConfig } from "./src/config/keys.js";
import logger from "./src/config/logger.js";
import prisma from "./src/config/db.js";
import redisService from "./src/config/redis.js";

// Handle unhandled Promise Rejections
process.on("unhandledRejection", err => {
  logger.error(
    `Unhandled Rejection: ${err instanceof Error ? err.message : err}`,
    {
      stack: err instanceof Error ? err.stack : err,
    },
  );
  process.exit(1);
});

// Handle uncaught Exceptions
process.on("uncaughtException", err => {
  logger.error(
    `Uncaught Exception: ${err instanceof Error ? err.message : err}`,
    {
      stack: err instanceof Error ? err.stack : err,
    },
  );
  process.exit(1);
});

validateConfig();

const PORT = finalConfig.port;

/**
 * Start the Express server after ensuring that the database and Redis connections are established.
 * This function also sets up graceful shutdown handlers for SIGTERM and SIGINT signals.
 * In case of any errors during startup, it logs the error and exits the process.
 */
const startServer = async () => {
  try {
    // 1. Initialize the connection pool
    await prisma.$connect();

    logger.info("✅ Database connected successfully");

    // Seed the default admin user if it doesn't exist
    await import("./src/config/seedAdmin.js").then(module =>
      module.seedAdmin(),
    );

    // Connection to redis
    await redisService.connect();

    // Start the server
    const server = app.listen(PORT, () => {
      logger.info(`Server running in ${finalConfig.env} mode on port ${PORT}`);
    });

    // Graceful shutdown
    const shutdown = async signal => {
      logger.info(`${signal} received. Shutting Server Down Now...`);

      // Close the server
      server.close(async () => {
        logger.info("Http Server Closed");

        // Disconnect Database
        await prisma.$disconnect();
        logger.info("Database Connection Closed");

        // Disconnect Redis
        await redisService.disconnect();

        // Exit the process
        process.exit(0);
      });

      // Force Server shutdown after 10s
      setTimeout(() => {
        logger.error("Forced Shutdown after timeout");
        process.exit(1);
      }, 10000);
    };

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  } catch (err) {
    logger.error(`Failed to start Server: ${err.message}`);
    process.exit(1);
  }
};

startServer();
