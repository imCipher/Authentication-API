import prisma from "../../config/db.js";
import logger from "../../config/logger.js";
import ApiError from "../../utils/ApiError.js";

/**
 * Standard fields safely exposed for user listings in admin views.
 * Explicitly excludes sensitive fields like password hashes, tokens, and other private data.
 */
const USER_LIST_SELECT = {
  id: true,
  fullName: true,
  email: true,
  username: true,
  role: true,
  status: true,
  emailVerified: true,
  lastLoginAt: true,
  lastLoginIp: true,
  createdAt: true,
  updatedAt: true,
};

/**
 * Detailed user projection for admin inspection.
 * Excludes sensitive secrets like password hashes while exposing operational state.
 */
const USER_DETAIL_SELECT = {
  id: true,
  fullName: true,
  email: true,
  username: true,
  role: true,
  status: true,
  emailVerified: true,
  failedAttempts: true,
  lockedUntil: true,
  lastLoginAt: true,
  lastLoginIp: true,
  sessionsRevokedAt: true,
  passwordChangedAt: true,
  createdAt: true,
  updatedAt: true,
  oauthAccounts: {
    select: {
      provider: true,
      createdAt: true,
    },
  },
};

// UUID regex pattern for validating UUID strings (v1-v5)
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Standardized set of allowed roles for filtering users in admin views.
 * This ensures that only valid roles are used in queries, preventing injection or invalid data issues.
 */
const ALLOWED_ROLES = new Set(["USER", "ADMIN"]);

/**
 * Standardized set of allowed statuses for filtering users in admin views.
 * This ensures that only valid statuses are used in queries, preventing injection or invalid data issues.
 */
const ALLOWED_STATUSES = new Set(["ACTIVE", "SUSPENDED", "DEACTIVATED"]);

/**
 * AdminService class provides administrative functionalities for managing users in the system.
 */
class AdminService {
  /**
   * Fetches a paginated list of users from the database with filtering and search.
   * @param {Object} options - Query options
   * @param {number} [options.page=1] - 1-based page number
   * @param {number} [options.limit=10] - Number of records per page (capped at 100)
   * @param {string} [options.role] - Filter by UserRole (USER, ADMIN)
   * @param {string} [options.status] - Filter by UserStatus (ACTIVE, SUSPENDED, DEACTIVATED)
   * @param {string} [options.search] - Search term matching email, username, or full name
   * @param {string} [options.sortBy="createdAt"] - Field to sort by
   * @param {"asc"|"desc"} [options.sortOrder="desc"] - Sort direction
   * @returns {Promise<{ users: Array, pagination: Object }>}
   */
  async getUsers({
    page = 1,
    limit = 10,
    role,
    status,
    search,
    sortBy = "createdAt",
    sortOrder = "desc",
  } = {}) {
    // Sanitize and defensively bound pagination
    const safePage = Math.max(1, parseInt(page, 10) || 1);
    const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 10));
    const skip = (safePage - 1) * safeLimit;

    // Build explicit, safe where clause (prevents query injection)
    const where = {};

    if (
      role &&
      typeof role === "string" &&
      ALLOWED_ROLES.has(role.toUpperCase())
    ) {
      where.role = role.toUpperCase();
    }

    if (
      status &&
      typeof status === "string" &&
      ALLOWED_STATUSES.has(status.toUpperCase())
    ) {
      where.status = status.toUpperCase();
    }

    if (search && typeof search === "string" && search.trim()) {
      const query = search.trim();
      where.OR = [
        { email: { contains: query, mode: "insensitive" } },
        { username: { contains: query, mode: "insensitive" } },
        { fullName: { contains: query, mode: "insensitive" } },
      ];
    }

    // Whitelist allowed sort fields
    const allowedSortFields = new Set([
      "createdAt",
      "fullName",
      "email",
      "username",
      "lastLoginAt",
    ]);
    const safeSortBy = allowedSortFields.has(sortBy) ? sortBy : "createdAt";
    const safeSortOrder = sortOrder === "asc" ? "asc" : "desc";

    // Fetch records and total count concurrently
    // Use secondary sort on id for deterministic pagination across identical values
    const [users, totalCount] = await Promise.all([
      prisma.user.findMany({
        where,
        select: USER_LIST_SELECT,
        skip,
        take: safeLimit,
        orderBy: [{ [safeSortBy]: safeSortOrder }, { id: safeSortOrder }],
      }),
      prisma.user.count({ where }),
    ]);

    const totalPages = totalCount === 0 ? 0 : Math.ceil(totalCount / safeLimit);

    return {
      users,
      pagination: {
        totalCount,
        totalPages,
        currentPage: safePage,
        limit: safeLimit,
        hasNextPage: safePage < totalPages,
        hasPrevPage: safePage > 1 && totalCount > 0,
      },
    };
  }

  /**
   * Fetches a specific user by their unique ID.
   * @param {string} id - The unique identifier of the user (UUID)
   * @returns {Promise<Object|null>} - Returns the user object if found, otherwise null
   */
  async getUserById(id) {
    if (!id || typeof id !== "string" || !UUID_REGEX.test(id.trim())) {
      throw ApiError.badRequest(
        "User ID is required and must be a valid UUID.",
      );
    }

    const user = await prisma.user.findUnique({
      where: { id: id.trim().toLowerCase() },
      select: USER_DETAIL_SELECT,
    });

    return user;
  }

  /**
   * Updates a user's role and/or status.
   * @param {string} id - The unique identifier of the user (UUID)
   * @param {Object} updates - Object containing role and/or status to update
   * @param {string} [updates.role] - New role for the user (USER or ADMIN)
   * @param {string} [updates.status] - New status for the user (ACTIVE, SUSPENDED, DEACTIVATED)
   * @param {Object} [context] - Execution context for authorization and auditing
   * @param {string} [context.adminId] - ID of the admin performing the action (for auditing purposes).
   * @param {string} [context.ip] - IP address of the request (for auditing purposes).
   * @param {string} [context.userAgent] - User agent string of the request (for auditing purposes).
   * @returns {Promise<Object|null>} - Returns the updated user object if successful, otherwise null
   */
  async updateUser(id, { role, status } = {}, { adminId, ip, userAgent } = {}) {
    const cleanId = typeof id === "string" ? id.trim().toLowerCase() : "";

    // Validate the id and ensure it is a valid UUID
    if (!cleanId || !UUID_REGEX.test(cleanId)) {
      throw ApiError.badRequest(
        "User ID is required and must be a valid UUID.",
      );
    }

    const normalizedRole =
      role && typeof role === "string" ? role.trim().toUpperCase() : undefined;
    const normalizedStatus =
      status && typeof status === "string" ?
        status.trim().toUpperCase()
      : undefined;

    // Validate role and status against allowed values
    if (
      role !== undefined &&
      (!normalizedRole || !ALLOWED_ROLES.has(normalizedRole))
    ) {
      throw ApiError.badRequest(
        "Invalid role. Must be either 'USER' or 'ADMIN'.",
      );
    }

    if (
      status !== undefined &&
      (!normalizedStatus || !ALLOWED_STATUSES.has(normalizedStatus))
    ) {
      throw ApiError.badRequest(
        "Invalid status. Must be either 'ACTIVE', 'SUSPENDED', or 'DEACTIVATED'.",
      );
    }

    const data = {};

    if (normalizedRole) {
      data.role = normalizedRole;
    }

    if (normalizedStatus) {
      data.status = normalizedStatus;
    }

    if (Object.keys(data).length === 0) {
      throw ApiError.badRequest(
        "At least one of 'role' or 'status' must be provided for update.",
      );
    }

    return await prisma.$transaction(async tx => {
      // Fetch current target user state
      const targetUser = await tx.user.findUnique({
        where: { id: cleanId },
        select: { id: true, role: true, status: true },
      });

      if (!targetUser) {
        throw ApiError.notFound("User not found.");
      }

      // Prevent self-demotion or self-deactivation
      if (adminId && adminId === targetUser.id) {
        if (normalizedRole && normalizedRole !== targetUser.role) {
          throw ApiError.forbidden(
            "Administrators cannot change their own role.",
          );
        }
        if (normalizedStatus && normalizedStatus !== "ACTIVE") {
          throw ApiError.forbidden(
            "Administrators cannot deactivate their own accounts.",
          );
        }
      }

      // Prevent locking out the last active admin
      const isDemotingAdmin =
        targetUser.role === "ADMIN" && normalizedRole === "USER";
      const isDeactivatingAdmin =
        targetUser.role === "ADMIN" &&
        normalizedStatus &&
        normalizedStatus !== "ACTIVE";

      if (isDemotingAdmin || isDeactivatingAdmin) {
        const activeAdminCount = await tx.user.count({
          where: { role: "ADMIN", status: "ACTIVE" },
        });
        if (activeAdminCount <= 1) {
          throw ApiError.badRequest(
            "Operation rejected: Cannot demote or deactivate the last active administrator.",
          );
        }
      }

      // Invalidate sessions if role or status changes
      const now = new Date();
      const shouldRevokeSessions =
        (normalizedRole && normalizedRole !== targetUser.role) ||
        (normalizedStatus && normalizedStatus !== "ACTIVE");

      if (shouldRevokeSessions) {
        data.sessionsRevokedAt = now;

        await tx.refreshToken.updateMany({
          where: { userId: cleanId, revokedAt: null },
          data: { revokedAt: now, graceToken: null },
        });

        // Clear any grace tokens for the user to prevent re-authentication
        await tx.refreshToken.updateMany({
          where: { userId: cleanId, graceToken: { not: null } },
          data: { graceToken: null },
        });
      }

      // Update the user record
      const updatedUser = await tx.user.update({
        where: { id: cleanId },
        data,
        select: USER_DETAIL_SELECT,
      });

      // Record the admin action in the audit log
      if (normalizedRole && normalizedRole !== targetUser.role) {
        await tx.auditLog.create({
          data: {
            userId: adminId || null,
            action: "ROLE_CHANGE",
            resource: "USER",
            details: {
              targetUserId: cleanId,
              previousRole: targetUser.role,
              newRole: normalizedRole,
            },
            ipAddress: ip || null,
            userAgent: userAgent || null,
            success: true,
          },
        });
      }

      if (normalizedStatus && normalizedStatus !== targetUser.status) {
        await tx.auditLog.create({
          data: {
            userId: adminId || null,
            action: "STATUS_CHANGE",
            resource: "USER",
            details: {
              targetUserId: cleanId,
              previousStatus: targetUser.status,
              newStatus: normalizedStatus,
            },
            ipAddress: ip || null,
            userAgent: userAgent || null,
            success: true,
          },
        });
      }

      return updatedUser;
    });
  }

  /**
   * Unlock a user's account by resetting failed login attempts and clearing any lockout.
   * @description This method is intended for administrative use to unlock user accounts that have been locked due to failed login attempts or other security policies.
   * It resets the failedAttempts counter and clears the lockedUntil timestamp, allowing the user to attempt to log in again.
   * @param {string} id - The unique identifier of the user (UUID)
   * @param {Object} context - Execution context for authorization and auditing
   * @param {string} [context.adminId] - ID of the admin performing the action (for auditing purposes).
   * @param {string} [context.ip] - IP address of the request (for auditing purposes).
   * @param {string} [context.userAgent] - User agent string of the request (for auditing purposes).
   * @returns {Promise<Object|null>} - Returns the updated user object if successful, otherwise null
   */
  async unlockUserAccount(id, { adminId, ip, userAgent } = {}) {
    const cleanId = typeof id === "string" ? id.trim().toLowerCase() : "";

    // Validate the id and ensure it is a valid UUID
    if (!cleanId || !UUID_REGEX.test(cleanId)) {
      throw ApiError.badRequest(
        "User ID is required and must be a valid UUID.",
      );
    }

    return await prisma.$transaction(async tx => {
      // Fetch current target user state
      const targetUser = await tx.user.findUnique({
        where: { id: cleanId },
        select: {
          id: true,
          failedAttempts: true,
          lockedUntil: true,
          status: true,
        },
      });

      // We only need to check if the user exists; we don't need to fetch sensitive fields for unlocking
      if (!targetUser) {
        throw ApiError.notFound("User not found.");
      }

      // Ensure the user is in a state that can be unlocked
      if (targetUser.status !== "ACTIVE") {
        throw ApiError.badRequest(
          `Cannot unlock an account with status '${targetUser.status}'. Please activate the account first.`,
        );
      }

      const now = new Date();
      const isLocked =
        targetUser.failedAttempts > 0 ||
        (targetUser.lockedUntil && targetUser.lockedUntil > now);

      if (!isLocked) {
        throw ApiError.badRequest("User account is not currently locked.");
      }

      //Invalidate Active Sessions
      await tx.refreshToken.updateMany({
        where: { userId: cleanId, revokedAt: null },
        data: { revokedAt: now, graceToken: null },
      });

      // Clear any grace tokens for the user to prevent re-authentication
      await tx.refreshToken.updateMany({
        where: { userId: cleanId, graceToken: { not: null } },
        data: { graceToken: null },
      });

      // Update the user record to reset failedAttempts and clear lockedUntil
      const updatedUser = await tx.user.update({
        where: { id: targetUser.id },
        data: {
          failedAttempts: 0,
          lockedUntil: null,
          sessionsRevokedAt: now, // Invalidate sessions to ensure security
        },
        select: USER_DETAIL_SELECT,
      });

      // Record the admin action in the audit log
      await tx.auditLog.create({
        data: {
          userId: adminId || null,
          action: "ACCOUNT_UNLOCKED",
          resource: "USER",
          details: {
            targetUserId: cleanId,
            previousFailedAttempts: targetUser.failedAttempts,
            previousLockedUntil: targetUser.lockedUntil,
          },
          ipAddress: ip || null,
          userAgent: userAgent || null,
          success: true,
        },
      });

      return updatedUser;
    });
  }

  /**
   * Logs out a user from all devices by revoking all active refresh tokens and access tokens.
   * @description This method is intended for administrative use to forcefully log out a user from all active sessions across all devices.
   * It revokes all refresh tokens associated with the user and updates the sessionsRevokedAt timestamp to ensure that any existing access tokens are invalidated.
   * @param {string} id - The unique identifier of the user (UUID)
   * @param {Object} context - Execution context for authorization and auditing
   * @param {string} [context.adminId] - ID of the admin performing the action (for auditing purposes).
   * @param {string} [context.ip] - IP address of the request (for auditing purposes).
   * @param {string} [context.userAgent] - User agent string of the request (for auditing purposes).
   * @returns {Promise<string>} - Resolves when the operation is complete
   */
  async logoutUserFromAllDevices(id, { adminId, ip, userAgent } = {}) {
    const cleanId = typeof id === "string" ? id.trim().toLowerCase() : "";

    // Validate the id and ensure it is a valid UUID
    if (!cleanId || !UUID_REGEX.test(cleanId)) {
      throw ApiError.badRequest(
        "User ID is required and must be a valid UUID.",
      );
    }

    return await prisma.$transaction(async tx => {
      // Fetch current target user state
      const targetUser = await tx.user.findUnique({
        where: { id: cleanId },
        select: { id: true, username: true },
      });

      // Check if the user exists before proceeding
      if (!targetUser) {
        throw ApiError.notFound("User not found.");
      }

      const now = new Date();

      // Revoke all active refresh tokens for the user
      await tx.refreshToken.updateMany({
        where: { userId: cleanId, revokedAt: null },
        data: { revokedAt: now, graceToken: null },
      });

      // Clear any grace tokens for the user to prevent re-authentication
      await tx.refreshToken.updateMany({
        where: { userId: cleanId, graceToken: { not: null } },
        data: { graceToken: null },
      });

      // Update the sessionsRevokedAt timestamp to invalidate existing access tokens
      await tx.user.update({
        where: { id: cleanId },
        data: { sessionsRevokedAt: now },
      });

      // Record the admin action in the audit log
      await tx.auditLog.create({
        data: {
          userId: adminId || null,
          action: "LOGOUT_ALL",
          resource: "USER",
          details: {
            message: `${targetUser.username} logged out from all devices by admin.`,
            targetUserId: cleanId,
          },
          ipAddress: ip || null,
          userAgent: userAgent || null,
          success: true,
        },
      });

      return targetUser.username; // Return the username for logging purposes
    });
  }

  /**
   * Deletes a user from the system.
   * @description This method is intended for administrative use to permanently remove a user account from the system.
   * It deletes the user record and all associated data, including refresh tokens and audit logs related to the user.
   * @param {string} id - The unique identifier of the user (UUID)
   * @param {Object} context - Execution context for authorization and auditing
   * @param {string} [context.adminId] - ID of the admin performing the action (for auditing purposes).
   * @param {string} [context.ip] - IP address of the request (for auditing purposes).
   * @param {string} [context.userAgent] - User agent string of the request (for auditing purposes).
   * @returns {Promise<Object|null>} - Returns the deleted user object if successful, otherwise null.
   */
  async deleteUser(id, { adminId, ip, userAgent } = {}) {
    const cleanId = typeof id === "string" ? id.trim().toLowerCase() : "";

    if (!cleanId || !UUID_REGEX.test(cleanId)) {
      throw ApiError.badRequest(
        "User ID is required and must be a valid UUID.",
      );
    }

    return await prisma.$transaction(async tx => {
      // Fetch current target user state
      const targetUser = await tx.user.findUnique({
        where: { id: cleanId },
        select: { id: true, role: true, username: true, status: true },
      });

      // Check if the user exists before proceeding
      if (!targetUser) {
        throw ApiError.notFound("User not found.");
      }

      // Prevent self-deletion by the admin
      if (adminId && adminId === cleanId) {
        throw ApiError.forbidden("Admin cannot delete their own account.");
      }

      // Prevent deletion of the last active admin
      if (targetUser.role === "ADMIN" && targetUser.status === "ACTIVE") {
        const activeAdmins = await tx.user.count({
          where: { role: "ADMIN", status: "ACTIVE" },
        });
        if (activeAdmins <= 1) {
          throw ApiError.badRequest("Cannot delete the last active admin.");
        }
      }

      // Record the admin action in the audit log
      await tx.auditLog.create({
        data: {
          userId: adminId || null,
          action: "ACCOUNT_DELETED",
          resource: "USER",
          details: {
            targetUserId: cleanId,
            targetUsername: targetUser.username,
            targetRole: targetUser.role,
            message: `User '${targetUser.username}' was permanently deleted by admin.`,
          },
          ipAddress: ip || null,
          userAgent: userAgent || null,
          success: true,
        },
      });

      // Delete the user record and associated data
      await tx.user.delete({
        where: { id: cleanId },
      });

      return targetUser; // Return the deleted user's basic info for logging purposes
    });
  }

  /**
   * Fetches a paginated list of audit logs from the database with filtering and search.
   * @param {Object} options - Query options
   * @param {number} [options.page=1] - 1-based page number
   * @param {number} [options.limit=10] - Number of records per page (capped at 100)
   * @param {string} [options.search] - Search term matching email, username, or full name
   * @param {string} [options.sortBy="createdAt"] - Field to sort by createdAt, action, adminId, targetUserId
   * @param {"asc"|"desc"} [options.sortOrder="desc"] - Sort direction
   * @returns {Promise<{ auditLogs: Array, pagination: Object }>}
   */
  async getAuditLogs({
    page = 1,
    limit = 10,
    search,
    sortBy = "createdAt",
    sortOrder = "desc",
  } = {}) {}
}

export default new AdminService();
