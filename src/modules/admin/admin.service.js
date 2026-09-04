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

    const ALLOWED_ROLES = new Set(["USER", "ADMIN"]);
    if (
      role &&
      typeof role === "string" &&
      ALLOWED_ROLES.has(role.toUpperCase())
    ) {
      where.role = role.toUpperCase();
    }

    const ALLOWED_STATUSES = new Set(["ACTIVE", "SUSPENDED", "DEACTIVATED"]);
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
    const allowedSortFields = [
      "createdAt",
      "fullName",
      "email",
      "username",
      "lastLoginAt",
    ];
    const safeSortBy =
      allowedSortFields.includes(sortBy) ? sortBy : "createdAt";
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
}

export default new AdminService();
