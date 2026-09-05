import CatchAsync from "../../utils/catchasync.js";
import AdminService from "./admin.service.js";
import ApiResponse from "../../utils/ApiResponse.js";
import ApiError from "../../utils/ApiError.js";

/**
 * Get request metadata (IP address and user agent) from the request object.
 * @param {Object} req - Express request object
 * @returns {Object} - { userIp, userAgent }
 */
const getRequestMetadata = req => ({
  userIp: req.ip || req.connection?.remoteAddress,
  userAgent: req.headers["user-agent"],
});

/**
 * @route GET /api/v1/admin/users
 * @desc Get a paginated list of all users with optional filters (Admin-only)
 * @access Private/Admin
 */
const getUsers = CatchAsync(async (req, res) => {
  const { page, limit, role, status, search, sortBy, sortOrder } =
    req.validated.query;

  const { users, pagination } = await AdminService.getUsers({
    page,
    limit,
    role,
    status,
    search,
    sortBy,
    sortOrder,
  });

  ApiResponse.success(res, "Users retrieved successfully.", {
    users,
    pagination,
  });
});

/**
 * @route GET /api/v1/admin/users/:id
 * @desc Get a specific user by ID (Admin-only)
 * @access Private/Admin
 */
const getUserById = CatchAsync(async (req, res) => {
  const { id } = req.validated.params;

  const user = await AdminService.getUserById(id);

  if (!user) {
    throw ApiError.notFound("User not found.");
  }

  ApiResponse.success(res, "User retrieved successfully.", { user });
});

/**
 * @route PATCH /api/v1/admin/users/:id
 * @desc Update a user's role and/or status (Admin-only)
 * @access Private/Admin
 */
const updateUser = CatchAsync(async (req, res) => {
  const { id } = req.validated.params;
  const { role, status } = req.validated.body;
  const adminId = req.user.id;
  const { userIp, userAgent } = getRequestMetadata(req);

  const updatedUser = await AdminService.updateUser(
    id,
    { role, status },
    { adminId, ip: userIp, userAgent },
  );

  if (!updatedUser) {
    throw ApiError.notFound("User not found.");
  }

  ApiResponse.success(res, "User updated successfully.", { user: updatedUser });
});

/**
 * @route POST /api/v1/admin/users/:id/unlock
 * @desc Unlock a user's account (Admin-only)
 * @access Private/Admin
 */
const unlockUserAccount = CatchAsync(async (req, res) => {
  const { id } = req.validated.params;
  const adminId = req.user.id;
  const { userIp, userAgent } = getRequestMetadata(req);

  const unlockedUser = await AdminService.unlockUserAccount(id, {
    adminId,
    ip: userIp,
    userAgent,
  });

  if (!unlockedUser) {
    throw ApiError.notFound("User not found.");
  }

  ApiResponse.success(res, "User account unlocked successfully.", {
    user: unlockedUser,
  });
});

/**
 * @route POST /api/v1/admin/users/:id/logout-all
 * @desc Log out a user from all devices (Admin-only)
 * @access Private/Admin
 */
const logoutUserFromAllDevices = CatchAsync(async (req, res) => {
  const { id } = req.validated.params;
  const adminId = req.user.id;
  const { userIp, userAgent } = getRequestMetadata(req);

  const result = await AdminService.logoutUserFromAllDevices(id, {
    adminId,
    ip: userIp,
    userAgent,
  });
  console.log("Logout result:", result); // Debug log

  ApiResponse.success(
    res,
    `${result} logged out from all devices successfully.`,
  );
});

/**
 * @route DELETE /api/v1/admin/users/:id
 * @desc Delete a user (Admin-only)
 * @access Private/Admin
 */
const deleteUser = CatchAsync(async (req, res) => {
  const { id } = req.validated.params;
  const adminId = req.user.id;
  const { userIp, userAgent } = getRequestMetadata(req);

  const deletedUser = await AdminService.deleteUser(id, {
    adminId,
    ip: userIp,
    userAgent,
  });

  ApiResponse.success(
    res,
    `User ${deletedUser.username} deleted successfully.`,
  );
});

export default {
  getUsers,
  getUserById,
  updateUser,
  unlockUserAccount,
  logoutUserFromAllDevices,
  deleteUser,
};
