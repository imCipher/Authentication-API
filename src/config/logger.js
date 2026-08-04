import winston from "winston";
import finalConfig from "./keys.js";

// Define Custom log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define different log level based on environment
const getLevel = () => {
  const env = finalConfig.env;

  switch (env) {
    case "production":
      return "info"; // Only logs info and above in production
    case "testing":
      return "warn"; // Only logs warn and above in testing
    default:
      return "debug"; // Logs everything in development
  }
};

// Define colors for each level
const colors = {
  error: "redBG", // White for the font color and redBg for the background color
  warn: "yellow",
  info: "blue",
  http: "green",
  debug: "white",
};

// Add colors to winston
winston.addColors(colors);

// Metadata keys that add no value to the log line: `splat` is a winston
// internal, and the ApiError fields below are already carried by the HTTP
// response, so printing them on every handled 4xx is pure noise
const noisyKeys = new Set(["splat", "statusCode", "status", "isOperational"]);

// Define format for console logs with colors
//Old way
/**
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    info => `${info.timestamp} [${info.level}]: ${info.message}`,
  ),
);
*/
// New way
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  winston.format.colorize({ all: true }),
  winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
    let line = `${timestamp} [${level}]: ${message}`;

    // Append the stack trace if it exists
    if (stack) line += `\nStack trace: ${stack}`;

    // Append any remaining metadata so it isn't silently dropped
    const keys = Object.keys(meta).filter(
      key => !noisyKeys.has(key) && meta[key] !== undefined,
    );

    if (keys.length) {
      const picked = Object.fromEntries(keys.map(k => [k, meta[k]]));
      let rendered;
      try {
        rendered = JSON.stringify(picked, (_k, v) =>
          typeof v === "bigint" ? v.toString() : v,
        );
      } catch {
        rendered = "[unserializable metadata]";
      }
      line += `\nMetadata: ${rendered}`;
    }
    return line;
  }),
);

// Create a transport to log to console and also file
/** const transports = [
    new winston.transports.Console(),
    new winston.transports.File({filename: ``)
] */

// Create a logger for only Console output
const logger = winston.createLogger({
  level: getLevel(),
  levels,
  // errors() must live here, not in consoleFormat — a transport format never
  // sees the raw Error, so logger.error(err) would print "undefined"
  format: winston.format.combine(
    winston.format.errors({ stack: true }),
    winston.format.splat(),
  ),
  transports: [
    // Console only transport
    new winston.transports.Console({
      format: consoleFormat,
    }),
  ],
  // Don't exit on uncaught exception
  exitOnError: false,
});

// Create a stream object for morgan integration
logger.stream = {
  write: message => {
    logger.http(message.trim());
  },
};

export default logger;
