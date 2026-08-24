import ApiError, { DEFAULT_CODES } from "../utils/ApiError.js";
import logger from "../config/logger.js";
import finalConfig from "../config/keys.js";

/**
 * Middleware to handle 404 Not Found errors for undefined routes.
 * It creates an ApiError instance with a 404 status code and passes it to the next middleware.
 * This middleware should be placed after all route definitions to catch any requests
 * that do not match existing routes.
 */
export const notFound = (req, res, next) => {
  next(
    ApiError.notFound(`Route ${req.originalUrl} not found`, {
      code: "ROUTE_NOT_FOUND",
    }),
  );
};

/**
 * Global Error Handling Middleware
 * Handles errors passed from controllers or thrown in the application
 * and sends a structured response to the client.
 */
export const errorHandler = (err, req, res, next) => {
  let error = err;

  /*
  // Handle Duplicate Error
  if (error.code === "P2002") {
    const target =
      error.meta?.driverAdapterError?.cause?.constraint?.fields || [];
    const field = target.length > 0 ? target[0] : "unknown field(s)";

    error = ApiError.conflict(
      `${field.charAt(0).toUpperCase() + field.slice(1)} is already in use. Please choose a different ${field}.`,
      {
        code: "DUPLICATE_FIELD",
      },
    );
  }
    */

  // Set default values for error properties if they are not provided
  error.statusCode = error.statusCode || 500;
  error.status =
    error.status || (`${error.statusCode}`.startsWith("4") ? "fail" : "error");
  if (finalConfig.env === "production") {
    error.message =
      error.isOperational ? error.message : "Something went wrong";
  }

  // Choose appropriate error log level based on the error type
  if (error.statusCode >= 500) {
    // 5xx are server errors and should be logged as 'error'
    logger.error("SERVER ERROR 💥 ", error, { cause: error.cause?.message });
  } else if (error.statusCode >= 400 && error.statusCode < 500) {
    // 4xx are client errors
    if (error.isOperational) {
      // Expected operational errors like validation errors, authentication errors, etc. can be logged as 'warn'
      logger.warn(`CLIENT ERROR (Operational) 🔍 ${error.message}`, {
        code: error.code,
        cause: error.cause?.message,
        method: req.method,
        path: req.route?.path,
        url: req.originalUrl,
        ip: req.ip,
        userId: req.user?.id,
      });
    } else {
      // Unexpected client errors can be logged as 'warn'
      logger.error("CLIENT ERROR 🚨", error, { cause: error.cause?.message });
    }
  } else {
    // Fallback for any other errors that don't fit the above categories
    logger.error("UNHANDLED ERROR 💥", error, { cause: error.cause?.message });
  }

  // Send error response
  res.status(error.statusCode).json({
    success: false,
    error: {
      status: error.status,
      code:
        error.code ||
        DEFAULT_CODES[error.statusCode] ||
        (error.statusCode >= 500 ? "INTERNAL_ERROR" : "CLIENT_ERROR"),
      message: error.message,
      errors: error.isOperational ? error.errors : undefined,
      stack: finalConfig.env === "development" ? err.stack : undefined,
    },
  });
};
