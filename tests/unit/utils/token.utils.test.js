// import { describe, it, expect } from "vitest";
import tokenUtils from "../../../src/utils/token.utils.js";
import ApiError from "../../../src/utils/ApiError.js";

describe("Token Utilities", () => {
  const mockUser = { id: "user-uuid-123", role: "USER" };

  describe("signAccessToken & verifyAccessToken", () => {
    it("should sign a valid JWT and decode it back with minimal claims", () => {
      // Arrange & Act
      const token = tokenUtils.signAccessToken(mockUser);
      const decoded = tokenUtils.verifyAccessToken(token);

      // Assert
      expect(typeof token).toBe("string");
      expect(decoded.sub).toBe(mockUser.id);
      expect(decoded.role).toBe(mockUser.role);
      expect(decoded.jti).toBeDefined();
    });

    it("should throw an unauthorized ApiError with code TOKEN_INVALID for corrupted tokens", () => {
      const corruptedToken = "this.is.not.a.valid.token";

      expect(() => tokenUtils.verifyAccessToken(corruptedToken)).toThrow(
        ApiError,
      );

      try {
        tokenUtils.verifyAccessToken(corruptedToken);
      } catch (error) {
        expect(error.statusCode).toBe(401);
        expect(error).toBeInstanceOf(ApiError);
        expect(error.code).toBe("TOKEN_INVALID");
      }
    });

    // TODO: Add a test for expired tokens. This requires mocking the system time or using a library like `sinon` to simulate token expiration.
  });

  describe("signRefreshToken & secureToken", () => {
    it("should generate a 128-character hex string for refresh tokens", () => {
      const token = tokenUtils.signRefreshToken();
      expect(token).toHaveLength(128);
      expect(/^[0-9a-f]+$/i.test(token)).toBe(true);
    });

    it("should generate a 64-character hex string for one-time secure tokens", () => {
      const token = tokenUtils.secureToken();
      expect(token).toHaveLength(64);
    });
  });

  describe("hashToken", () => {
    it("should generate a consistent SHA-256 hash", () => {
      const rawToken = "my-opaque-token-123";
      const hash1 = tokenUtils.hashToken(rawToken);
      const hash2 = tokenUtils.hashToken(rawToken);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });

    it("should throw a TypeError if token is not a string or empty", () => {
      expect(() => tokenUtils.hashToken(null)).toThrow(TypeError);
      expect(() => tokenUtils.hashToken("")).toThrow(TypeError);
    });
  });

  describe("verificationToken & expiresAt", () => {
    it("should generate a 6-digit zero-padded numeric string", () => {
      const code = tokenUtils.verificationToken(6);
      expect(code).toHaveLength(6);
      expect(/^\d{6}$/.test(code)).toBe(true);
    });

    it("should calculate an expiration date in the future", () => {
      const minutes = 15;
      const now = Date.now();
      const expires = tokenUtils.expiresAt(minutes);

      expect(expires).toBeInstanceOf(Date);
      expect(expires.getTime()).toBeGreaterThan(now);
    });
  });
});
