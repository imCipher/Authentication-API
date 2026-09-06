import { authorize } from "../../../src/middlewares/rbac.middleware.js";
import ApiError from "../../../src/utils/ApiError.js";

describe("RBAC Middleware", () => {
  it("should throw an error if no roles are provided to authorize()", () => {
    expect(() => authorize()).toThrow(
      "RBAC authorize middleware requires at least one role to be specified.",
    );
  });

  it("should call next() with 401 ApiError if req.user is missing", () => {
    const middleware = authorize("ADMIN");
    const req = {}; // No user
    const res = {};
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const error = next.mock.calls[0][0];
    expect(error).toBeInstanceOf(ApiError);
    expect(error.statusCode).toBe(401);
    expect(error.code).toBe("UNAUTHORIZED");
  });

  it("should call next() with 403 ApiError if user does not posses the required role", () => {
    const middleware = authorize("ADMIN");
    const req = { user: { id: "user-uuid", role: "USER" } }; // User with role USER
    const res = {};
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const error = next.mock.calls[0][0];
    expect(error.statusCode).toBe(403);
    expect(error.code).toBe("FORBIDDEN");
  });

  it("should call next() without error if user possesses the required role", () => {
    const middleware = authorize("ADMIN");
    const req = { user: { id: "user-uuid", role: "ADMIN" } }; // User with role ADMIN
    const res = {};
    const next = vi.fn();

    middleware(req, res, next);

    expect(next).toHaveBeenCalledWith(); // Called without arguments (success)
  });
});
