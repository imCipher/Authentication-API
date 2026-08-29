import tokenUtils from "../utils/token.utils.js";
import ApiError from "../utils/ApiError.js";
import authService from "../modules/auth/auth.service.js";
import CatchAsync from "../utils/catchasync.js";
import redisService from "../config/redis.js";

/**
 * Middleware to protect routes and ensure that the user is authenticated.
 * It checks for the presence of a valid access token in the request headers or cookies.
 * If the token is valid, it retrieves the corresponding user and attaches it to the
 * request object.
 * If the token is missing, invalid, or the user no longer exists,
 * it throws a 401 unauthorized error.
 * If User does not exist or has changed their password after the token was issued,
 * it throws a 401 unauthorized error.
 */
export const protect = CatchAsync(async (req, res, next) => {
  // Check for the presence of an access token in cookies or authorization headers
  let token;
  if (req.cookies && req.cookies.accessToken) {
    token = req.cookies.accessToken;
  } else if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  // If no token is found, return a 401 unauthorized error
  if (!token) {
    return next(
      ApiError.unauthorized(
        "You are not logged in! Please log in to get access.",
      ),
    );
  }

  // Verify the token and decode its payload
  const decoded = await tokenUtils.verifyAccessToken(token);

  // Check if the token is in the denylist
  const isRevoked = await redisService.exists(`denylist:${decoded.jti}`);

  // If the token is revoked, return a 401 unauthorized error
  if (isRevoked) {
    return next(
      ApiError.unauthorized(
        "This token has been revoked. Please log in again.",
        {
          code: "TOKEN_REVOKED",
        },
      ),
    );
  }

  // Retrieve the user associated with the token's subject (sub) and role
  const currentUser = await authService.getUserById(decoded.sub, decoded.role);

  // If the user no longer exists, return a 401 unauthorized error
  if (!currentUser) {
    return next(
      ApiError.unauthorized(
        "This user no longer exists. Please log in or register again.",
      ),
    );
  }

  // Check if the user has changed their password after the token was issued
  if (currentUser.passwordChangedAt) {
    if (decoded.iat < currentUser.passwordChangedAt.getTime() / 1000) {
      return next(
        ApiError.unauthorized(
          "You have recently changed your password. Please log in again.",
        ),
      );
    }
  }

  // Check if the user has revoked all sessions after the token was issued
  if (currentUser.sessionsRevokedAt) {
    if (decoded.iat < currentUser.sessionsRevokedAt.getTime() / 1000) {
      return next(
        ApiError.unauthorized(
          "You have logged out from all sessions. Please log in again.",
        ),
      );
    }
  }

  // Attach the user and token to the request object for downstream middleware and route handlers
  req.user = currentUser;
  req.token = decoded;
  next();
});
