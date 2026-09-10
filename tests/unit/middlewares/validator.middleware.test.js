import * as z from "zod";
import validateRequest from "../../../src/middlewares/validator.middleware.js";
import ApiError from "../../../src/utils/ApiError.js";

describe("Validator Middleware (validateRequest)", () => {
  let req;
  let res;
  let next;

  // Mocking req, res, and next for each test to ensure isolation and prevent state leakage between tests
  beforeEach(() => {
    req = {
      body: {},
      params: {},
      query: {},
      headers: {},
    };
    res = {};
    next = vi.fn();
  });

  describe("Basic Middleware Execution & Defaults", () => {
    it("should call next() and initialize req.validated when no schemas are provided", () => {
      const middleware = validateRequest();
      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      expect(req.validated).toEqual({});
    });

    it("should preserve pre-existing req.validated properties when merging results", () => {
      req.validated = { existingMetadata: "token-123" };

      // Middleware with a simple query schema
      const middleware = validateRequest({
        query: z.object({ page: z.string().default("1") }),
      });

      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.validated).toEqual({
        existingMetadata: "token-123",
        query: { page: "1" },
      });
    });
  });

  describe("Single Source Validation", () => {
    it("should validate and attach parsed body to req.validated.body", () => {
      const schema = {
        body: z.object({
          email: z.string().pipe(z.email()),
          count: z.coerce.number(),
        }),
      };

      req.body = { email: "user@example.com", count: "42" };
      const middleware = validateRequest(schema);
      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.validated.body).toEqual({
        email: "user@example.com",
        count: 42, // verified type coercion
      });
    });

    it("should validate query parameters and attach to req.validated.query", () => {
      const schema = {
        query: z.object({
          search: z.string().trim(),
        }),
      };

      req.query = { search: "  test query  " };
      const middleware = validateRequest(schema);
      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.validated.query).toEqual({ search: "test query" });
    });

    it("should validate route params and attach to req.validated.params", () => {
      const schema = {
        params: z.object({
          id: z.string().pipe(z.uuid()),
        }),
      };

      const validId = "123e4567-e89b-12d3-a456-426614174000";
      req.params = { id: validId };
      const middleware = validateRequest(schema);
      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.validated.params).toEqual({ id: validId });
    });

    it("should validate headers and attach to req.validated.headers", () => {
      const schema = {
        headers: z.object({
          "x-api-version": z.string().min(1),
        }),
      };

      req.headers = { "x-api-version": "1.0.0" };
      const middleware = validateRequest(schema);
      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.validated.headers).toEqual({ "x-api-version": "1.0.0" });
    });
  });

  describe("Validation Failures & Error Formatting", () => {
    it("should call next() with a 400 ApiError with code VALIDATION_ERROR when validation fails", () => {
      const schema = {
        body: z.object({
          username: z.string().min(3, "Username too short"),
        }),
      };

      req.body = { username: "ab" };
      const middleware = validateRequest(schema);
      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];

      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(400);
      expect(error.status).toBe("fail");
      expect(error.code).toBe("VALIDATION_ERROR");
      expect(error.message).toBe("Validation Failed");
      expect(error.errors).toEqual([
        {
          field: "username",
          message: "Username too short", // Ensuring the error message matches the schema's custom message
        },
      ]);
    });

    it("should format nested Zod issue paths using dot-notation", () => {
      const schema = {
        body: z.object({
          user: z.object({
            profile: z.object({
              age: z.number().min(18, "Must be at least 18"),
            }),
          }),
        }),
      };

      req.body = { user: { profile: { age: 15 } } };
      const middleware = validateRequest(schema);
      middleware(req, res, next);

      const error = next.mock.calls[0][0];
      expect(error.errors).toEqual([
        {
          field: "user.profile.age",
          message: "Must be at least 18", 
        },
      ]);
    });

    it("should fallback to the request source name when an issue path is empty (root-level refinement)", () => {
      const schema = {
        body: z
          .object({
            password: z.string(),
            confirmPassword: z.string(),
          })
          .refine(data => data.password === data.confirmPassword, {
            message: "Passwords do not match", 
          }),
      };

      req.body = { password: "Password1!", confirmPassword: "Password2!" };
      const middleware = validateRequest(schema);
      middleware(req, res, next);

      const error = next.mock.calls[0][0];
      expect(error.errors).toEqual([
        {
          field: "body",
          message: "Passwords do not match",
        },
      ]);
    });

    it("should aggregate multiple validation errors into the errors array", () => {
      const schema = {
        body: z.object({
          email: z.string().pipe(z.email()),
          password: z.string().min(8, "Password too short"),
        }),
      };

      req.body = { email: "invalid-email", password: "short" };
      const middleware = validateRequest(schema);
      middleware(req, res, next);

      const error = next.mock.calls[0][0];
      expect(error.errors).toHaveLength(2);
      expect(error.errors).toEqual([
        { field: "email", message: "Invalid email" },
        { field: "password", message: "Password too short" },
      ]);
    });
  });

  describe("Multi-Source & Lifecycle Behavior", () => {
    it("should validate multiple request targets simultaneously", () => {
      const schema = {
        params: z.object({
          id: z.coerce.number(),
        }),
        body: z.object({
          name: z.string(),
        }),
      };

      req.params = { id: "100" };
      req.body = { name: "Alice" };

      const middleware = validateRequest(schema);
      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.validated).toEqual({
        params: { id: 100 },
        body: { name: "Alice" },
      });
    });

    it("should short-circuit on the first failing source without evaluating subsequent sources", () => {
      const paramsSafeParseSpy = vi.fn();
      const schema = {
        body: z.object({
          username: z.string().min(5),
        }),
        params: {
          safeParse: paramsSafeParseSpy,
        },
      };

      req.body = { username: "abc" }; // Fails body validation
      req.params = { id: "1" };

      const middleware = validateRequest(schema);
      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error.errors[0].field).toBe("username");
      expect(paramsSafeParseSpy).not.toHaveBeenCalled();
    });

    it("should ignore unsupported request sources (e.g. cookies)", () => {
      const schema = {
        cookies: z.object({ token: z.string() }),
      };

      const middleware = validateRequest(schema);
      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.validated).toEqual({});
    });
  });
});
