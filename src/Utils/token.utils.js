import jwt from "jsonwebtoken";
import crypto from "crypto";

import ApiError from "./ApiError.js";
import finalConfig from "../config/keys.js";

/**
 * Sign a short-lived access token (JWT).
 * Keep the payload minimal: { sub: userId, role: user.role}
 * @param {Object} user - Must contain id and role properties
 * @returns {string} - Signed JWT with minimal claims
 */
export const signAccessToken = ({ id, role }) => {
  return jwt.sign({ sub: id, role }, finalConfig.jwt.accessSecret, {
    expiresIn: finalConfig.jwt.accessExpiresIn,
    algorithm: "HS256",
  });
};

/**
 * Generate an opaque refresh token - Not a JWT.
 * 64 random bytes -> 128-char hex string.
 * @returns {string} - Cryptographically random token
 */
export const signRefreshToken = () => {
  return crypto.randomBytes(64).toString("hex");
};

/**
 * Verify and decode an access token (JWT).
 * @param {string} token - The JWT from the Authorization header
 * @returns {Object} - Decoded payload ({sub, role, iat, exp})
 * @throws {ApiError} - 401 on expired or invalid token
 */
export const verifyAccessToken = token => {
  try {
    return jwt.verify(token, finalConfig.jwt.accessSecret, {
      algorithms: ["HS256"],
    });
  } catch (error) {
    // Keep the two cases distinct: TOKEN_EXPIRED is routine (the client should
    // refresh), TOKEN_INVALID can mean forged signatures — worth alerting on.
    // The jwt error goes on `cause`: logged server-side, never sent to clients.
    if (error instanceof jwt.TokenExpiredError) {
      throw ApiError.unauthorized("Access token expired", {
        code: "TOKEN_EXPIRED",
        cause: error,
      });
    }
    throw ApiError.unauthorized("Invalid access token", {
      code: "TOKEN_INVALID",
      cause: error,
    });
  }
};

/**
 * SHA-256 hash a token for database storage.
 * @param {string} token - Plaintext token (refresh/verify/reset)
 * @returns {string} - Hex-encoded hash
 * @throws {TypeError} - If no token is supplied (caller bug, not a client error)
 */
export const hashToken = token => {
  // A missing token here means the caller forgot to pass one — the caller is
  // responsible for validating the request and throwing its own 401. A plain
  // TypeError leaves isOperational falsy, so this is logged as an error with a
  // stack instead of hiding among routine 401 warns.
  if (typeof token !== "string" || token.length === 0) {
    throw new TypeError("hashToken requires a non-empty string token");
  }
  return crypto.createHash("sha256").update(token).digest("hex");
};

export default {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  hashToken,
};
