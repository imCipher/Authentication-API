import ApiError, { DEFAULT_CODES } from "../../../src/utils/ApiError.js";

describe("ApiError", () => {
  describe("DEFAULT_CODES constant", () => {
    it("should export standard HTTP status code mappings", () => {
      expect(DEFAULT_CODES).toEqual({
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        409: "CONFLICT",
        429: "RATE_LIMITED",
        500: "INTERNAL_ERROR",
      });
    });
  });

  describe("Constructor & Core Properties", () => {
    it("should properly inherit from native Error and ApiError", () => {
      const error = new ApiError("Something went wrong", 500);

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(ApiError);
      expect(error.name).toBe("Error");
      expect(error.message).toBe("Something went wrong");
    });

    it("should initialize default operational and status properties for 4xx errors", () => {
      const error = new ApiError("Client fault", 400);

      expect(error.statusCode).toBe(400);
      expect(error.status).toBe("fail");
      expect(error.isOperational).toBe(true);
      expect(error.code).toBe("BAD_REQUEST");
      expect(error.errors).toBeUndefined();
    });

    it("should initialize default operational and status properties for 5xx errors", () => {
      const error = new ApiError("Server fault", 500);

      expect(error.statusCode).toBe(500);
      expect(error.status).toBe("error");
      expect(error.isOperational).toBe(true);
      expect(error.code).toBe("INTERNAL_ERROR");
      expect(error.errors).toBeUndefined();
    });

    it("should capture a valid stack trace that excludes constructor frames", () => {
      const error = new ApiError("Stack test", 400);

      expect(typeof error.stack).toBe("string");
      expect(error.stack).toContain("Stack test");
      // captureStackTrace should ensure the constructor itself is excluded from stack frames
      expect(error.stack).not.toMatch(/at new ApiError/);
    });
  });

  describe("Status calculation ('fail' vs 'error')", () => {
    it.each([
      [400, "fail"],
      [401, "fail"],
      [403, "fail"],
      [404, "fail"],
      [409, "fail"],
      [422, "fail"],
      [429, "fail"],
      [499, "fail"],
      [500, "error"],
      [502, "error"],
      [503, "error"],
      [301, "error"],
    ])("should assign status '%s' for HTTP status code %i", (statusCode, expectedStatus) => {
      const error = new ApiError("Test message", statusCode);
      expect(error.status).toBe(expectedStatus);
    });
  });

  describe("Machine-readable error code resolution", () => {
    it("should prioritize custom code provided in options", () => {
      const error = new ApiError("Custom code error", 400, undefined, {
        code: "CUSTOM_USER_ERROR",
      });

      expect(error.code).toBe("CUSTOM_USER_ERROR");
    });

    it.each([
      [400, "BAD_REQUEST"],
      [401, "UNAUTHORIZED"],
      [403, "FORBIDDEN"],
      [404, "NOT_FOUND"],
      [409, "CONFLICT"],
      [429, "RATE_LIMITED"],
      [500, "INTERNAL_ERROR"],
    ])("should resolve default code for status %i to %s", (statusCode, expectedCode) => {
      const error = new ApiError("Code mapping test", statusCode);
      expect(error.code).toBe(expectedCode);
    });

    it("should fallback to 'CLIENT_ERROR' for unknown 4xx status codes", () => {
      const error = new ApiError("Unprocessable entity", 422);
      expect(error.code).toBe("CLIENT_ERROR");
    });

    it("should fallback to 'INTERNAL_ERROR' for unknown 5xx status codes", () => {
      const error = new ApiError("Service unavailable", 503);
      expect(error.code).toBe("INTERNAL_ERROR");
    });
  });

  describe("Validation errors property", () => {
    it("should attach errors array when provided", () => {
      const validationIssues = [
        { field: "email", message: "Email is required" },
        { field: "password", message: "Password too short" },
      ];
      const error = new ApiError("Validation failed", 400, validationIssues);

      expect(error.errors).toEqual(validationIssues);
      expect(Array.isArray(error.errors)).toBe(true);
      expect(error.errors).toHaveLength(2);
    });

    it("should not set errors property when errors parameter is undefined", () => {
      const error = new ApiError("No errors passed", 400);

      expect(error.errors).toBeUndefined();
      expect("errors" in error).toBe(false);
    });

    it("should not set errors property when errors parameter is null", () => {
      const error = new ApiError("Null errors", 400, null);

      expect(error.errors).toBeUndefined();
      expect("errors" in error).toBe(false);
    });
  });

  describe("Error cause and chaining support", () => {
    it("should preserve original error cause via options.cause", () => {
      const rootCause = new Error("Database connection timed out");
      const error = new ApiError("Service failure", 500, undefined, {
        cause: rootCause,
      });

      expect(error.cause).toBe(rootCause);
      expect(error.cause.message).toBe("Database connection timed out");
    });
  });

  describe("Static Factory Methods", () => {
    describe("ApiError.badRequest", () => {
      it("should create a 400 error with default code VALIDATION_ERROR", () => {
        const error = ApiError.badRequest("Invalid request data");

        expect(error).toBeInstanceOf(ApiError);
        expect(error.message).toBe("Invalid request data");
        expect(error.statusCode).toBe(400);
        expect(error.status).toBe("fail");
        expect(error.code).toBe("VALIDATION_ERROR");
        expect(error.isOperational).toBe(true);
        expect(error.errors).toBeUndefined();
      });

      it("should attach validation errors when provided", () => {
        const errors = ["Username is required", "Invalid email format"];
        const error = ApiError.badRequest("Validation error", errors);

        expect(error.errors).toEqual(errors);
        expect(error.code).toBe("VALIDATION_ERROR");
      });

      it("should allow overriding options such as code and cause", () => {
        const originalError = new Error("Zod parsing error");
        const error = ApiError.badRequest(
          "Validation error",
          [{ field: "age", message: "Must be positive" }],
          {
            code: "SCHEMA_VALIDATION_FAILED",
            cause: originalError,
          },
        );

        expect(error.code).toBe("SCHEMA_VALIDATION_FAILED");
        expect(error.cause).toBe(originalError);
      });
    });

    describe("ApiError.unauthorized", () => {
      it("should create a 401 error with default message and code", () => {
        const error = ApiError.unauthorized();

        expect(error).toBeInstanceOf(ApiError);
        expect(error.message).toBe("Unauthorized");
        expect(error.statusCode).toBe(401);
        expect(error.status).toBe("fail");
        expect(error.code).toBe("UNAUTHORIZED");
        expect(error.isOperational).toBe(true);
      });

      it("should accept custom message and options", () => {
        const rootCause = new Error("jwt expired");
        const error = ApiError.unauthorized("Access token has expired", {
          code: "TOKEN_EXPIRED",
          cause: rootCause,
        });

        expect(error.message).toBe("Access token has expired");
        expect(error.code).toBe("TOKEN_EXPIRED");
        expect(error.cause).toBe(rootCause);
      });
    });

    describe("ApiError.forbidden", () => {
      it("should create a 403 error with default message and code", () => {
        const error = ApiError.forbidden();

        expect(error).toBeInstanceOf(ApiError);
        expect(error.message).toBe("Forbidden");
        expect(error.statusCode).toBe(403);
        expect(error.status).toBe("fail");
        expect(error.code).toBe("FORBIDDEN");
        expect(error.isOperational).toBe(true);
      });

      it("should accept custom message and options", () => {
        const error = ApiError.forbidden("You do not have administrative privileges", {
          code: "INSUFFICIENT_PERMISSIONS",
        });

        expect(error.message).toBe("You do not have administrative privileges");
        expect(error.statusCode).toBe(403);
        expect(error.code).toBe("INSUFFICIENT_PERMISSIONS");
      });
    });

    describe("ApiError.notFound", () => {
      it("should create a 404 error with default message and RESOURCE_NOT_FOUND code", () => {
        const error = ApiError.notFound();

        expect(error).toBeInstanceOf(ApiError);
        expect(error.message).toBe("Resource Not Found");
        expect(error.statusCode).toBe(404);
        expect(error.status).toBe("fail");
        expect(error.code).toBe("RESOURCE_NOT_FOUND");
        expect(error.isOperational).toBe(true);
      });

      it("should accept custom message and allow overriding code", () => {
        const error = ApiError.notFound("User not found with id 123", {
          code: "USER_NOT_FOUND",
        });

        expect(error.message).toBe("User not found with id 123");
        expect(error.statusCode).toBe(404);
        expect(error.code).toBe("USER_NOT_FOUND");
      });
    });

    describe("ApiError.conflict", () => {
      it("should create a 409 error with specified message and CONFLICT code", () => {
        const error = ApiError.conflict("Email is already in use");

        expect(error).toBeInstanceOf(ApiError);
        expect(error.message).toBe("Email is already in use");
        expect(error.statusCode).toBe(409);
        expect(error.status).toBe("fail");
        expect(error.code).toBe("CONFLICT");
        expect(error.isOperational).toBe(true);
      });

      it("should allow overriding options", () => {
        const error = ApiError.conflict("Username taken", {
          code: "DUPLICATE_USERNAME",
        });

        expect(error.message).toBe("Username taken");
        expect(error.code).toBe("DUPLICATE_USERNAME");
      });
    });

    describe("ApiError.tooManyRequests", () => {
      it("should create a 429 error with default message and RATE_LIMITED code", () => {
        const error = ApiError.tooManyRequests();

        expect(error).toBeInstanceOf(ApiError);
        expect(error.message).toBe("Too Many Requests, Try again later");
        expect(error.statusCode).toBe(429);
        expect(error.status).toBe("fail");
        expect(error.code).toBe("RATE_LIMITED");
        expect(error.isOperational).toBe(true);
      });

      it("should accept custom message and options", () => {
        const error = ApiError.tooManyRequests("Rate limit exceeded for login attempts", {
          code: "AUTH_RATE_LIMIT_EXCEEDED",
        });

        expect(error.message).toBe("Rate limit exceeded for login attempts");
        expect(error.code).toBe("AUTH_RATE_LIMIT_EXCEEDED");
      });
    });

    describe("ApiError.internal", () => {
      it("should create a 500 error with default message and INTERNAL_ERROR code", () => {
        const error = ApiError.internal();

        expect(error).toBeInstanceOf(ApiError);
        expect(error.message).toBe("Internal Server Error");
        expect(error.statusCode).toBe(500);
        expect(error.status).toBe("error");
        expect(error.code).toBe("INTERNAL_ERROR");
        expect(error.isOperational).toBe(true);
      });

      it("should accept custom message, cause, and options", () => {
        const dbError = new Error("Connection reset by peer");
        const error = ApiError.internal("Database transaction failed", {
          code: "DATABASE_ERROR",
          cause: dbError,
        });

        expect(error.message).toBe("Database transaction failed");
        expect(error.statusCode).toBe(500);
        expect(error.status).toBe("error");
        expect(error.code).toBe("DATABASE_ERROR");
        expect(error.cause).toBe(dbError);
      });
    });
  });

  describe("Throwability & Usage in Control Flow", () => {
    it("should be catchable in a synchronous try/catch block", () => {
      const throwError = () => {
        throw ApiError.notFound("Item missing");
      };

      expect(throwError).toThrow(ApiError);
      expect(throwError).toThrow("Item missing");

      try {
        throwError();
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        expect(err.statusCode).toBe(404);
        expect(err.code).toBe("RESOURCE_NOT_FOUND");
      }
    });

    it("should reject properly in asynchronous Promise workflows", async () => {
      const asyncOperation = async () => {
        throw ApiError.unauthorized("Session expired");
      };

      await expect(asyncOperation()).rejects.toThrow(ApiError);
      await expect(asyncOperation()).rejects.toMatchObject({
        statusCode: 401,
        code: "UNAUTHORIZED",
        isOperational: true,
      });
    });
  });
});
