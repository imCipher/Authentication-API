import ApiError, { DEFAULT_CODES } from "../Utils/ApiError.js";
import logger from "../config/logger.js";
import finalConfig from "../config/keys.js";

/**
 * 404 Handler - catched unmatched routes
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

  // Set default values for error properties if they are not provided
  error.statusCode = error.statusCode || 500;
  error.status =
    error.status || (`${error.statusCode}`.startsWith("4") ? "fail" : "error");
  if (finalConfig.env === "production") {
    error.message = err.isOperational ? error.message : "Something went wrong";
  }

  // Choose appropriate error log level based on the error type
  if (error.statusCode >= 500) {
    // 5xx are server errors and should be logged as 'error'
    logger.error("SERVER ERROR 💥 ", err, { cause: err.cause?.message });
  } else if (error.statusCode >= 400 && error.statusCode < 500) {
    // 4xx are client errors
    if (err.isOperational) {
      // Expected operational errors like validation errors, authentication errors, etc. can be logged as 'warn'
      logger.warn(`CLIENT ERROR (Operational) 🔍 ${err.message}`, {
        code: err.code,
        method: req.method,
        path: req.route?.path,
        url: req.originalUrl,
        ip: req.ip,
        userId: req.user?.id,
      });
    } else {
      // Unexpected client errors can be logged as 'warn'
      logger.error("CLIENT ERROR 🚨", err, { cause: err.cause?.message });
    }
  } else {
    // Fallback for any other errors that don't fit the above categories
    logger.error("UNHANDLED ERROR 💥", err, { cause: err.cause?.message });
  }

  // Handle specific error types and customize the response accordingly
  // Handle Validation Error
  if (err.name === "ValidationError") {
    const errors = Object.values(err.errors).map(el => ({
      field: el.path,
      message: el.message,
    }));
    error = ApiError.badRequest("Validation Failed", errors);
  }

  // Handle Duplicate Error

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
      errors: err.isOperational ? error.errors : undefined,
      stack: finalConfig.env === "development" ? err.stack : undefined,
    },
  });
};
