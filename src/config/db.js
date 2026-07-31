import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../../generated/prisma/client.ts";
import finalConfig from "./keys.js";
import logger from "./logger.js";

const isDev = finalConfig.env === "development";

// Store the connection string in an environment variable for security and flexibility
const connectionString = process.env.DATABASE_URL;

// Create a new PrismaPg adapter with the connection string
const adapter = new PrismaPg({ connectionString });

// PrismaClient log levels
const logLevels =
  isDev ? ["query", "info", "warn", "error"]
  : ["error"];

// Create a new PrismaClient instance with the adapter and log settings based on the environment
// `emit: "event"` routes each level through winston instead of Prisma's own stdout writer
const prisma = new PrismaClient({
  adapter,
  log: logLevels.map(level => ({ emit: "event", level })),
  errorFormat: "pretty",
});

// listen to events in development for richer logging and debugging
if (isDev) {
  prisma.$on("query", e => logger.debug(`Query (${e.duration}ms): ${e.query}`));
  prisma.$on("info", e => logger.info(`Prisma info: ${e.message}`));
  prisma.$on("warn", e => logger.warn(`Prisma warn: ${e.message}`));
}

prisma.$on("error", e => logger.error(`Prisma error: ${e.message}`));

export default prisma;
