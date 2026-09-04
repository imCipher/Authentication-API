import CatchAsync from "../../utils/catchasync.js";
import AdminService from "./admin.service.js";
import ApiResponse from "../../utils/ApiResponse.js";

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

export default {
  getUsers,
};
