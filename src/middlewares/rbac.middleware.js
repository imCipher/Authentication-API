import ApiError from "../utils/ApiError.js";
import logger from "../config/logger.js";

/**
 * Middleware factory for role-based access control (RBAC).
 * Ensures the authenticated user possesses one of the allowed roles to access the route.
 *
 * NOTE: Must be mounted after the `protect` middleware to ensure that `req.user` is populated.
 *
 * @param  {...(string|string[])} allowedRoles - Single roles or arrays of roles that are permitted to access the route (e.g., 'admin', ['user', 'moderator']).
 * @returns {import("express").RequestHandler} Express middleware function for role-based access control.
 */
export const authorize = (...allowedRoles) => {
  // Flatten the allowedRoles array to handle cases where roles are passed as arrays
  const roles = allowedRoles.flat().map(role => String(role).toUpperCase());

  if (roles.length === 0) {
    throw new Error(
      "RBAC authorize middleware requires at least one role to be specified.",
    );
  }

  return (req, res, next) => {
    //Guard against missing authentication middleware
    if (!req.user) {
      return next(
        ApiError.unauthorized("Authentication required to access this route.", {
          code: "UNAUTHORIZED",
        }),
      );
    }

    const userRole = req.user.role ? String(req.user.role).toUpperCase() : null;

    if (!userRole || !roles.includes(userRole)) {
      logger.warn(`Access forbidden: user [${req.user.id}] with role [${userRole}] attempted to access a restricted resource`, {
        userId: req.user.id,
        userRole,
        requiredRoles: roles,
        method: req.method,
        path: req.originalUrl,
        ip: req.ip,
      })
      return next(
        ApiError.forbidden(
          "You do not have permission to perform this resource.",
          {
            code: "FORBIDDEN",
          },
        ),
      );
    }

    next();
  };
};
