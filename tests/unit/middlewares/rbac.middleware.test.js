import { authorize } from "../../../src/middlewares/rbac.middleware.js";
import ApiError from "../../../src/utils/ApiError.js";
import logger from "../../../src/config/logger.js";

describe("RBAC Middleware", () => {
  let req;
  let res;
  let next;

  beforeEach(() => {
    vi.clearAllMocks();
    req = {
      user: { id: "user-uuid-123", role: "USER" },
      method: "GET",
      originalUrl: "/api/v1/admin/users",
      ip: "127.0.0.1",
    };
    res = {};
    next = vi.fn();
  });

  describe("Initialization & Factory Constraints", () => {
    it("should throw an error if no roles are provided to authorize()", () => {
      expect(() => authorize()).toThrow(
        "RBAC authorize middleware requires at least one role to be specified.",
      );
    });

    it("should throw an error if an empty array is passed to authorize([])", () => {
      expect(() => authorize([])).toThrow(
        "RBAC authorize middleware requires at least one role to be specified.",
      );
    });

    it("should accept multiple role arguments as rest parameters or arrays", () => {
      expect(() => authorize("ADMIN", "SUPERADMIN")).not.toThrow();
      expect(() => authorize(["ADMIN", "SUPERADMIN"])).not.toThrow();
      expect(() => authorize(["ADMIN"], "MODERATOR")).not.toThrow();
    });
  });

  describe("Authentication Guard (req.user missing)", () => {
    it("should call next() with 401 ApiError if req.user is missing", () => {
      const middleware = authorize("ADMIN");
      delete req.user;

      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(401);
      expect(error.status).toBe("fail");
      expect(error.code).toBe("UNAUTHORIZED");
      expect(error.message).toBe(
        "Authentication required to access this route.",
      );
      expect(error.isOperational).toBe(true);
    });
  });

  describe("Role Authorization & Access Control", () => {
    it("should call next() without error if user possesses the required role", () => {
      const middleware = authorize("ADMIN");
      req.user.role = "ADMIN";

      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith(); // Called without arguments (success)
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it("should allow access when user has any one of multiple allowed roles", () => {
      const middleware = authorize(["ADMIN", "MODERATOR"]);
      req.user.role = "MODERATOR";

      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it("should handle case-insensitive role matching for both policy and user role", () => {
      const middleware = authorize("admin"); // Lowercase policy
      req.user.role = "AdMiN"; // Mixed-case user role

      middleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
    });

    it("should call next() with 403 ApiError if user does not possess the required role", () => {
      const middleware = authorize("ADMIN");
      req.user.role = "USER";

      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(403);
      expect(error.status).toBe("fail");
      expect(error.code).toBe("FORBIDDEN");
      expect(error.message).toBe(
        "You do not have permission to perform this resource.",
      );
      expect(error.isOperational).toBe(true);
    });

    it("should log a security warning with request and user audit metadata on 403 forbidden", () => {
      const middleware = authorize("ADMIN");
      req.user = { id: "suspicious-user-99", role: "USER" };
      req.method = "DELETE";
      req.originalUrl = "/api/v1/admin/users/123";
      req.ip = "192.168.1.50";

      middleware(req, res, next);

      expect(logger.warn).toHaveBeenCalledTimes(1);
      expect(logger.warn).toHaveBeenCalledWith(
        "Access forbidden: user [suspicious-user-99] with role [USER] attempted to access a restricted resource",
        {
          userId: "suspicious-user-99",
          userRole: "USER",
          requiredRoles: ["ADMIN"],
          method: "DELETE",
          path: "/api/v1/admin/users/123",
          ip: "192.168.1.50",
        },
      );
    });
  });

  describe("Malformed User & Boundary Cases", () => {
    it("should deny access with 403 if req.user exists but role property is missing", () => {
      const middleware = authorize("ADMIN");
      req.user = { id: "user-without-role" }; // role is undefined

      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error.statusCode).toBe(403);
      expect(error.code).toBe("FORBIDDEN");
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining("user [user-without-role] with role [null]"),
        expect.objectContaining({
          userId: "user-without-role",
          userRole: null,
        }),
      );
    });

    it("should deny access with 403 if req.user.role is an empty string", () => {
      const middleware = authorize("ADMIN");
      req.user = { id: "user-empty-role", role: "" };

      middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error.statusCode).toBe(403);
    });
  });
});
