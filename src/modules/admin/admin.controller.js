import CatchAsync from "../../utils/catchasync.js";
import AdminService from "./admin.service.js";
import ApiResponse from "../../utils/ApiResponse.js";

/**
 * @route GET /api/v1/admin/users
 * @desc Get a paginated list of all users with optional filters (Admin-only)
 * @access Private/Admin
 */
const getUsers = CatchAsync(async (req, res) => {
  const query = req.validated?.query || {};

  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 10));

  const role = query.role ? query.role.toUpperCase() : undefined;
  const status = query.status ? query.status.toUpperCase() : undefined;
  const search = query.search ? query.search.trim() : undefined;

  const { users, pagination } = await AdminService.getUsers({
    page,
    limit,
    role,
    status,
    search,
  });

  ApiResponse.success(res, "Users retrieved successfully.", {
    users,
    pagination,
  });
});

export default {
  getUsers,
};
