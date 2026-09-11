import { protect } from "../../../src/middlewares/auth.middleware.js";
import ApiError from "../../../src/utils/ApiError.js";
import tokenUtils from "../../../src/utils/token.utils.js";
import authService from "../../../src/modules/auth/auth.service.js";
import redisService from "../../../src/config/redis.js";

vi.mock("../../../src/utils/token.utils.js", () => ({
  default: {
    verifyAccessToken: vi.fn(),
  },
}));

vi.mock("../../../src/config/redis.js", () => ({
  default: {
    exists: vi.fn(),
  },
}));

vi.mock("../../../src/modules/auth/auth.service.js", () => ({
  default: {
    getUserById: vi.fn(),
  },
}));

describe("Auth Middleware - protect", () => {
  let req, res, next;

  const validToken = "valid.jwt.token";
  const decodedPayload = {
    sub: "userId123",
    role: "USER",
    jti: "token-uuid-123",
    iat: 1700000000,
    exp: 1700000900,
  };

  const mockUser = {
    id: "userId123",
    fullName: "John Doe",
    email: "john.doe@example.com",
    role: "USER",
    passwordChangedAt: null,
    sessionsRevokedAt: null,
  };
  beforeEach(() => {
    vi.clearAllMocks();

    req = {
      cookies: {},
      headers: {},
    };
    res = {};
    next = vi.fn();

    //Default baseline happy-path mocks
    tokenUtils.verifyAccessToken.mockResolvedValue(decodedPayload);
    redisService.exists.mockResolvedValue(false);
    authService.getUserById.mockResolvedValue(mockUser);
  });

  describe("Token Extraction & Missing Credentials Guard", () => {
    it("should call next() with 401 ApiError if no token is found in cookies or authorization headers", () => {
      protect(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(401);
      expect(error.status).toBe("fail");
      expect(error.code).toBe("UNAUTHORIZED");
      expect(error.message).toBe(
        "You are not logged in! Please log in to get access.",
      );
      expect(error.isOperational).toBe(true);
    });

    it("should call next() with 401 ApiError if authorization header does not start with 'Bearer'", () => {
      req.headers.authorization = "Basic dXNlcjpwYXNz"; // Invalid format

      protect(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(401);
      expect(error.status).toBe("fail");
    });

    it("should call next() with 401 ApiError if authorization header 'Bearer ' with no token string", () => {
      req.headers.authorization = "Bearer "; // No token provided

      protect(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const error = next.mock.calls[0][0];
      expect(error).toBeInstanceOf(ApiError);
      expect(error.statusCode).toBe(401);
      expect(error.status).toBe("fail");
      expect(error.code).toBe("UNAUTHORIZED");
      expect(error.message).toBe(
        "You are not logged in! Please log in to get access.",
      );
      expect(error.isOperational).toBe(true);
    });

    it("should extract token from cookies if req.cookies.accessToken is present", async () => {
      req.cookies.accessToken = validToken;

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(tokenUtils.verifyAccessToken).toHaveBeenCalledWith(validToken);
        expect(next).toHaveBeenCalledWith(); // No error, proceed to next middleware
      });
    });

    it("should extract token from authorization header if req.headers.authorization is present", async () => {
      req.headers.authorization = `Bearer ${validToken}`;

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(tokenUtils.verifyAccessToken).toHaveBeenCalledWith(validToken);
        expect(next).toHaveBeenCalledWith(); // No error, proceed to next middleware
      });
    });

    it("should prioritize cookies accessToken over authorization header if both are present", async () => {
      req.cookies.accessToken = "cookie.jwt.token";
      req.headers.authorization = `Bearer header.jwt.token`;

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(tokenUtils.verifyAccessToken).toHaveBeenCalledWith(
          "cookie.jwt.token",
        );
        expect(tokenUtils.verifyAccessToken).not.toHaveBeenCalledWith(
          "header.jwt.token",
        );
      });
    });
  });
  describe("Token Verification & Signature Integrity", () => {
    it("should forward TOKEN_EXPIRED error to next() when token verification fails due to expiration", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      const expiredError = ApiError.unauthorized("Access token expired", {
        code: "TOKEN_EXPIRED",
      });
      tokenUtils.verifyAccessToken.mockRejectedValue(expiredError);

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledTimes(1);
        expect(next).toHaveBeenCalledWith(expiredError);
      });
    });

    it("should forward TOKEN_INVALID error to next() when token verification fails due to invalid signature", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      const invalidError = ApiError.unauthorized("Invalid access token", {
        code: "TOKEN_INVALID",
      });
      tokenUtils.verifyAccessToken.mockRejectedValue(invalidError);

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledTimes(1);
        expect(next).toHaveBeenCalledWith(invalidError);
      });
    });
  });

  describe("Redis Denylist & Token Revocation", () => {
    it("should check Redis denylist using the decoded JTI key format 'denylist:<jti>'", async () => {
      req.headers.authorization = `Bearer ${validToken}`;

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(redisService.exists).toHaveBeenCalledWith(
          `denylist:${decodedPayload.jti}`,
        );
      });
    });

    it("should call next() with 401 ApiError and code TOKEN_REVOKED if token is in Redis denylist", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      redisService.exists.mockResolvedValue(true); // Simulate token is revoked

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledTimes(1);
        const error = next.mock.calls[0][0];
        expect(error).toBeInstanceOf(ApiError);
        expect(error.statusCode).toBe(401);
        expect(error.status).toBe("fail");
        expect(error.code).toBe("TOKEN_REVOKED");
        expect(error.message).toBe(
          "This token has been revoked. Please log in again.",
        );
        expect(error.isOperational).toBe(true);
      });

      // Short-circuit guarantees: authService.getUserById should not be called if token is revoked
      expect(authService.getUserById).not.toHaveBeenCalled();
    });

    it("should forward Redis service errors to next() via catchAsync", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      const redisError = new Error("Redis connection failed");
      redisService.exists.mockRejectedValue(redisError);

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledWith(redisError);
      });
    });
  });

  describe("User Retrieval & Account Existence", () => {
    it("should query authService.getUserById using decoded subject (sub) and role", async () => {
      req.headers.authorization = `Bearer ${validToken}`;

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(authService.getUserById).toHaveBeenCalledWith(
          decodedPayload.sub,
          decodedPayload.role,
        );
      });
    });

    it("should call next() with 401 ApiError if user is not found in database", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      authService.getUserById.mockResolvedValue(null); // Simulate user not found

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledTimes(1);
        const error = next.mock.calls[0][0];
        expect(error).toBeInstanceOf(ApiError);
        expect(error.statusCode).toBe(401);
        expect(error.status).toBe("fail");
        expect(error.message).toBe(
          "This user no longer exists. Please log in or register again.",
        );
      });

      expect(req.user).toBeUndefined(); // Ensure req.user is not set when user is not found
      expect(req.token).toBeUndefined(); // Ensure req.token is not set when user is not found
    });

    it("should forward database retrieval errors to next()", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      const dbError = new Error("Database connection lost");
      authService.getUserById.mockRejectedValue(dbError);

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledWith(dbError);
      });
    });
  });

  describe("Password Changed & Session Invalidation Guards", () => {
    it("should call next() with 401 ApiError if password was changed after token was issued", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      // Token iat: 1700000000 (seconds). Password changed at: 1700000050 (milliseconds) -> token was issued BEFORE change
      const userWithChangedPassword = {
        ...mockUser,
        passwordChangedAt: new Date(1700000050 * 1000), // Convert to milliseconds
      };
      authService.getUserById.mockResolvedValue(userWithChangedPassword);

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledTimes(1);
        const error = next.mock.calls[0][0];
        expect(error).toBeInstanceOf(ApiError);
        expect(error.statusCode).toBe(401);
        expect(error.status).toBe("fail");
        expect(error.message).toBe(
          "You have recently changed your password. Please log in again.",
        );
      });
    });

    it("should allow access if password was changed before or at the time token was issued", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      // Token iat: 1700000000 (seconds). Password changed at: 1699999999 (milliseconds) -> token was issued AFTER change
      const userWithOldPasswordChange = {
        ...mockUser,
        passwordChangedAt: new Date(1699999999 * 1000), // Convert to milliseconds
      };
      authService.getUserById.mockResolvedValue(userWithOldPasswordChange);

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledWith();
        expect(req.user).toEqual(userWithOldPasswordChange);
      });
    });

    it("should call next() with 401 ApiError if all sessions were revoked after token was issued", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      // Token iat: 1700000000 (seconds). Sessions revoked at 1700000050 -> token was issued BEFORE revocation
      const userWithRevokedSessions = {
        ...mockUser,
        sessionsRevokedAt: new Date(1700000050 * 1000),
      };
      authService.getUserById.mockResolvedValue(userWithRevokedSessions);

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledTimes(1);
        const error = next.mock.calls[0][0];
        expect(error).toBeInstanceOf(ApiError);
        expect(error.statusCode).toBe(401);
        expect(error.message).toBe(
          "You have logged out from all sessions. Please log in again.",
        );
      });
    });

    it("should allow access if sessions were revoked before or at the time token was issued", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      // Token iat: 1700000000. Sessions revoked at 1699999000 -> token was issued AFTER revocation
      const userWithOldSessionRevocation = {
        ...mockUser,
        sessionsRevokedAt: new Date(1699999000 * 1000),
      };
      authService.getUserById.mockResolvedValue(userWithOldSessionRevocation);

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledWith();
        expect(req.user).toEqual(userWithOldSessionRevocation);
      });
    });

    it("should allow access if passwordChangedAt and sessionsRevokedAt are null", async () => {
      req.headers.authorization = `Bearer ${validToken}`;
      // Baseline mockUser has both passwordChangedAt and sessionsRevokedAt as null
      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledWith();
        expect(req.user).toEqual(mockUser);
      });
    });
  });

  describe("Successful Authentication & Request Context Population", () => {
    it("should attach user and token to req and call next() without arguments on successful authentication", async () => {
      req.headers.authorization = `Bearer ${validToken}`;

      protect(req, res, next);

      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledTimes(1);
        expect(next).toHaveBeenCalledWith();
        expect(req.user).toEqual(mockUser);
        expect(req.token).toBe(decodedPayload);
      });
    });
  });
});
