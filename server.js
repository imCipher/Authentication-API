import app from "./src/app.js";
import finalConfig, { validateConfig } from "./src/config/keys.js";
import logger from "./src/config/logger.js";
import prisma from "./src/config/db.js";

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

const startServer = async () => {
  try {
    // 1. Initialize the connection pool
    await prisma.$connect();

    logger.info("✅ Database connected successfully");

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
