// Default machine-readable slug per status. Factories can override with
// something more specific; these are the fallbacks.
export const DEFAULT_CODES = {
  400: "BAD_REQUEST",
  401: "UNAUTHORIZED",
  403: "FORBIDDEN",
  404: "NOT_FOUND",
  409: "CONFLICT",
  429: "RATE_LIMITED",
  500: "INTERNAL_ERROR",
};

/**
 * Custom ApiError class to standardize error handling
 * Can be thrown anywhere in the code to trigger error middleware
 */
class ApiError extends Error {
  /**
   * Create an Operational error instance.
   * @param {string} message - Error message to show to client
   * @param {number} statusCode - HTTP status code (e.g. 400, 404).
   */
  constructor(message, statusCode, errors = undefined, options = {}) {
    super(message, options); // Error natively reads options.cause

    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
    this.isOperational = true;
    this.code =
      options.code ||
      DEFAULT_CODES[statusCode] ||
      (this.statusCode >= 500 ? "INTERNAL_ERROR" : "CLIENT_ERROR");

    /**
     * For error that contains multiple validation errors,
     * we can pass an array of error messages to the constructor.
     * This will be useful for sending detailed error information back to the client.
     */
    if (errors) this.errors = errors;

    // Always capture our own frames; the original failure lives on `this.cause`
    Error.captureStackTrace(this, this.constructor);
  }

  // To handle bad requests like validation errors
  static badRequest(message, errors = undefined, options = {}) {
    return new ApiError(message, 400, errors, {
      code: "VALIDATION_ERROR",
      ...options,
    });
  }

  // To handle unauthorized access errors
  static unauthorized(message = "Unauthorized", options = {}) {
    return new ApiError(message, 401, undefined, options);
  }

  // To handle forbidden access errors
  static forbidden(message = "Forbidden", options = {}) {
    return new ApiError(message, 403, undefined, options);
  }

  // To handle not found errors
  static notFound(message = "Resource Not Found", options = {}) {
    return new ApiError(message, 404, undefined, {
      code: "RESOURCE_NOT_FOUND",
      ...options,
    });
  }

  // To handle conflict errors, e.g., duplicate entries
  static conflict(message, options = {}) {
    return new ApiError(message, 409, undefined, options);
  }

  // To handle too many requests errors, e.g., rate limiting
  static tooManyRequests(
    message = "Too Many Requests, Try again later",
    options = {},
  ) {
    return new ApiError(message, 429, undefined, options);
  }

  // To handle internal server errors
  static internal(message = "Internal Server Error", options = {}) {
    return new ApiError(message, 500, undefined, options);
  }
}

export default ApiError;
