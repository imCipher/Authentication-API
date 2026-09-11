import {
  notFound,
  errorHandler,
} from "../../../src/middlewares/error.middleware.js";
import ApiError from "../../../src/utils/ApiError.js";
import logger from "../../../src/config/logger.js";
import finalConfig from "../../../src/config/keys.js";
import { success } from "zod";

describe("Error Middleware", () => {
  let req, res, next, originalEnv;

  beforeEach(() => {
    vi.clearAllMocks();
    originalEnv = finalConfig.env;

    req = {
      method: "GET",
      originalUrl: "/api/v1/unknown-endpoint",
      ip: "192.168.1.1",
      route: { path: "/unknown-endpoint" },
      user: { id: "user123" },
    };

    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };

    next = vi.fn();
  });

  afterEach(() => {
    finalConfig.env = originalEnv; // Restore the original environment after each test
  });

  describe("notFound Middleware", () => {
    it("should forward a 404 ApiError to next() with ROUTE_NOT_FOUND code and request URL", () => {
      req.originalUrl = "/api/v1/non-existent-route";

      notFound(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];

      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(404);
      expect(error.code).toBe("ROUTE_NOT_FOUND");
      expect(error.status).toBe("fail");
      expect(error.message).toBe(`Route /api/v1/non-existent-route not found`);
      expect(error.isOperational).toBe(true);
    });
  });

  describe("errorHandler Middleware - Status Code & Default Fallbacks", () => {
    it("should default statusCode to 500, status to 'error', and code to 'INTERNAL_ERROR' for generic unhandled errors", () => {
      const genericError = new Error("Database query crashed");

      errorHandler(genericError, req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            status: "error",
            code: "INTERNAL_ERROR",
            message: "Database query crashed",
          }),
        }),
      );
    });

    it("should map 4xx status to 'fail' and resolve default code from DEFAULT_CODES", () => {
      const clientError = new Error("Invalid request data");
      clientError.statusCode = 404;

      errorHandler(clientError, req, res, next);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            status: "fail",
            code: "NOT_FOUND",
          }),
        }),
      );
    });

    it("should fallback code to 'CLIENT_ERROR' for non-standard 4xx codes missing from DEFAULT_CODES", () => {
      const customClientError = new Error("Custom client error");
      customClientError.statusCode = 422; // Unprocessable Entity, not in DEFAULT_CODES

      errorHandler(customClientError, req, res, next);

      expect(res.status).toHaveBeenCalledWith(422);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            status: "fail",
            code: "CLIENT_ERROR", // Fallback code for non-standard 4xx
          }),
        }),
      );
    });

    it("should preserve existing status and code if already defined on error", () => {
      const error = ApiError.badRequest("Validation failed", [], {
        code: "VALIDATION_ERROR",
      });

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            status: "fail",
            code: "VALIDATION_ERROR",
            message: "Validation failed",
          }),
        }),
      );
    });
  });

  describe("errorHandler Middleware - Environment Behaviors", () => {
    it("should include stack trace in development environment", () => {
      finalConfig.env = "development";

      const error = new Error("Development debug error");

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            stack: error.stack,
          }),
        }),
      );
    });

    it("should omit stack trace in non-development environments", () => {
      finalConfig.env = "production";

      const error = new Error("Production error");

      errorHandler(error, req, res, next);

      const response = res.json.mock.calls[0][0];
      expect(response.error.stack).toBeUndefined();
    });

    it("should mask non-operational error messages to 'Something went wrong' in production", () => {
      finalConfig.env = "production";
      const programmerError = new TypeError(
        "Cannot read property id of undefined",
      );
      programmerError.isOperational = false;

      errorHandler(programmerError, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            message: "Something went wrong",
          }),
        }),
      );
    });

    it("should NOT mask operational error messages in production", () => {
      finalConfig.env = "production";
      const operationalError = ApiError.badRequest(
        "Invalid email address format",
      );

      errorHandler(operationalError, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            message: "Invalid email address format",
          }),
        }),
      );
    });
  });

  describe("errorHandler Middleware  - Logging Strategies", () => {
    it("should log 5xx errors as logger.error with cause metadata", () => {
      const underlyingCause = new Error("Connection refused");
      const serverError = new Error("Redis Cluster unreachable", {
        cause: underlyingCause,
      });
      serverError.statusCode = 503;

      errorHandler(serverError, req, res, next);

      expect(logger.error).toHaveBeenCalledTimes(1);
      expect(logger.error).toHaveBeenCalledWith(
        "SERVER ERROR 💥 ",
        serverError,
        { cause: "Connection refused" },
      );
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it("should log 4xx operational errors as logger.warn with full request context", () => {
      const operationalError = ApiError.forbidden(
        "Access denied to admin panel",
        {
          code: "FORBIDDEN",
        },
      );

      errorHandler(operationalError, req, res, next);

      expect(logger.warn).toHaveBeenCalledTimes(1);
      expect(logger.warn).toHaveBeenCalledWith(
        "CLIENT ERROR (Operational) 🔍 Access denied to admin panel",
        {
          code: "FORBIDDEN",
          cause: undefined,
          method: "GET",
          path: "/unknown-endpoint",
          url: "/api/v1/unknown-endpoint",
          ip: "192.168.1.1",
          userId: "user123",
        },
      );
      expect(logger.error).not.toHaveBeenCalled();
    });

    it("should log 4xx non-operational errors as logger.error", () => {
      const unexpectedClientError = new Error("Malformed request syntax");
      unexpectedClientError.statusCode = 400;
      unexpectedClientError.isOperational = false;

      errorHandler(unexpectedClientError, req, res, next);

      expect(logger.error).toHaveBeenCalledTimes(1);
      expect(logger.error).toHaveBeenCalledWith(
        "CLIENT ERROR 🚨",
        unexpectedClientError,
        { cause: undefined },
      );
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it("should log fallback non-standard status codes (<400) as UNHANDLED ERROR", () => {
      const weirdError = new Error("Unexpected 3xx redirect error");
      weirdError.statusCode = 302;

      errorHandler(weirdError, req, res, next);

      expect(logger.error).toHaveBeenCalledTimes(1);
      expect(logger.error).toHaveBeenCalledWith(
        "UNHANDLED ERROR 💥",
        weirdError,
        { cause: undefined },
      );
    });
  });

  describe("errorHandler Middleware - Response Payload & Validation Errors", () => {
    it("should include detailed errors array when error is operational and contains errors", () => {
      const validationIssues = [
        { field: "email", message: "Invalid email" },
        { field: "password", message: "Password too short" },
      ];
      const error = ApiError.badRequest("Validation Failed", validationIssues);

      errorHandler(error, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: expect.objectContaining({
            message: "Validation Failed",
            errors: validationIssues,
          }),
        }),
      );
    });

    it("should omit errors array when error is not operational even if errors property exists", () => {
      const nonOperationalError = new Error(
        "Unexpected error with errors property",
      );
      nonOperationalError.statusCode = 500;
      nonOperationalError.isOperational = false;
      nonOperationalError.errors = [{ raw: "corrupted stream" }];

      errorHandler(nonOperationalError, req, res, next);

      const response = res.json.mock.calls[0][0];
      expect(response.error.errors).toBeUndefined();
    });
  });
});
