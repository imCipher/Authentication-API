import CatchAsync from "../../utils/catchasync.js";
import ApiError from "../../utils/ApiError.js";
import AdminService from "../admin/admin.service.js";
import adminSchema from "../admin/admin.validation.js";

/*
 * Admin pages. Same pattern as the other web pages:
 *   GET  → validate the query string → call AdminService → render
 *   POST → validate → call AdminService → success: redirect with ?done=…
 *                                        → failure: re-render with the error
 * Every business rule (no self-demotion, last-admin protection, session
 * revocation, audit logging) already lives in AdminService — nothing here
 * re-implements it.
 */

// Who did it, from where — AdminService writes this into the audit log
const ctx = req => ({
  adminId: req.user.id,
  ip: req.ip,
  userAgent: req.headers["user-agent"],
});

// Success messages after a redirect (?done=…). Fixed text only, never the raw query.
const DONE = {
  role: "Role updated. The user has been logged out of every device.",
  status: "Status updated.",
  unlocked: "Account unlocked.",
  "logged-out": "The user has been logged out of every device.",
  deleted: "User permanently deleted.",
};

// The AuditAction values from schema.prisma, for the filter dropdown
// (the validation schema still decides what is actually accepted)
const AUDIT_ACTIONS = [
  "PASSWORD_CHANGE",
  "PASSWORD_RESET",
  "EMAIL_CHANGE",
  "EMAIL_VERIFIED",
  "ROLE_CHANGE",
  "STATUS_CHANGE",
  "ACCOUNT_UNLOCKED",
  "OAUTH_ACCOUNT_LINKED",
  "TOKEN_REUSE_DETECTED",
  "LOGOUT_ALL",
  "ACCOUNT_DELETED",
  "ACCOUNT_LOCKED",
];

/**
 * Validate a page's query string with the SAME Zod schema the admin API uses.
 * Only the listed keys are read (the schemas are .strict()). If anything is
 * invalid (e.g. ?page=-3), fall back to the defaults and tell the admin.
 */
const parseQuery = (schema, query, keys) => {
  const picked = {};
  for (const key of keys) {
    if (query[key] !== undefined) picked[key] = query[key];
  }
  const result = schema.safeParse(picked);
  if (result.success) return { filters: result.data, filterError: null };
  return {
    filters: schema.parse({}),
    filterError: "Some filters were invalid and have been reset.",
  };
};

/**
 * URL helpers for templates: keep every current filter, change one thing.
 *   pageUrl(3)          → /admin/users?search=ann&role=ADMIN&page=3
 *   sortUrl("email")    → same filters, sorted by email (click again = reverse)
 */
const urlHelpers = (basePath, filters) => {
  const build = overrides => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries({ ...filters, ...overrides })) {
      if (value !== undefined && value !== null && value !== "") {
        params.set(key, String(value));
      }
    }
    const qs = params.toString();
    return qs ? `${basePath}?${qs}` : basePath;
  };

  return {
    pageUrl: page => build({ page }),
    sortUrl: field =>
      build({
        sortBy: field,
        sortOrder:
          filters.sortBy === field && filters.sortOrder === "desc" ? "asc" : "desc",
        page: 1, // a new sort starts from the first page
      }),
  };
};

// =========================================================================
// Users list
// =========================================================================
const showUsers = CatchAsync(async (req, res) => {
  const { filters, filterError } = parseQuery(
    adminSchema.getUsersSchema.query,
    req.query,
    ["page", "limit", "role", "status", "search", "sortBy", "sortOrder"],
  );

  const { users, pagination } = await AdminService.getUsers(filters);

  res.render("pages/admin/users", {
    title: "Users",
    tab: "users",
    users,
    pagination,
    filters,
    error: filterError,
    notice: DONE[req.query.done] ?? null,
    ...urlHelpers("/admin/users", filters),
  });
});

// =========================================================================
// One user
// =========================================================================

// Validate :id; a malformed id is a 404 page, not a crash
const targetId = req => {
  const parsed = adminSchema.userIdParamsSchema.params.safeParse({ id: req.params.id });
  if (!parsed.success) throw ApiError.notFound("User not found.");
  return parsed.data.id;
};

const renderUserDetail = async (req, res, { status = 200, error = null } = {}) => {
  const id = targetId(req);
  const target = await AdminService.getUserById(id);
  if (!target) throw ApiError.notFound("User not found.");

  // The service searches audit logs by UUID on the ACTOR (userId), so this is
  // "what this user did" — admin actions ON them are recorded under the admin.
  const [{ loginHistory }, { auditLogs }] = await Promise.all([
    AdminService.getLoginHistory({ userId: id, limit: 10 }),
    AdminService.getAuditLogs({ search: id, limit: 10 }),
  ]);

  const now = new Date();
  return res.status(status).render("pages/admin/user", {
    title: target.fullName,
    tab: "users",
    target,
    loginHistory,
    auditLogs,
    isSelf: target.id === req.user.id,
    isLocked:
      target.failedAttempts > 0 || Boolean(target.lockedUntil && target.lockedUntil > now),
    error,
    notice: DONE[req.query.done] ?? null,
  });
};

const showUser = CatchAsync(async (req, res) => renderUserDetail(req, res));

/**
 * Wrap a user action: run it, then redirect back with ?done=…
 * If AdminService refuses (last admin, own account, not locked…), show its
 * message on the same page with the right status code instead.
 */
const userAction = (doneKey, run) =>
  CatchAsync(async (req, res) => {
    const id = targetId(req);
    try {
      await run(req, id);
    } catch (err) {
      if (err instanceof ApiError && err.statusCode !== 404) {
        return renderUserDetail(req, res, { status: err.statusCode, error: err.message });
      }
      throw err; // 404 → the error page; real bugs → errorHandler
    }
    return res.redirect(303, `/admin/users/${id}?done=${doneKey}`);
  });

const updateRole = userAction("role", async (req, id) => {
  const parsed = adminSchema.patchUserSchema.body.safeParse({ role: req.body.role });
  if (!parsed.success) throw ApiError.badRequest("Choose a valid role.");
  await AdminService.updateUser(id, { role: parsed.data.role }, ctx(req));
});

const updateStatus = userAction("status", async (req, id) => {
  const parsed = adminSchema.patchUserSchema.body.safeParse({ status: req.body.status });
  if (!parsed.success) throw ApiError.badRequest("Choose a valid status.");
  await AdminService.updateUser(id, { status: parsed.data.status }, ctx(req));
});

const unlockUser = userAction("unlocked", (req, id) =>
  AdminService.unlockUserAccount(id, ctx(req)),
);

const logoutUser = userAction("logged-out", (req, id) =>
  AdminService.logoutUserFromAllDevices(id, ctx(req)),
);

// Delete needs the admin to type the username — a typo-proof "are you sure?"
// that works without JavaScript (inline confirm() would be blocked by the CSP anyway)
const deleteUser = CatchAsync(async (req, res) => {
  const id = targetId(req);
  const target = await AdminService.getUserById(id);
  if (!target) throw ApiError.notFound("User not found.");

  if ((req.body.confirmUsername ?? "").trim() !== target.username) {
    return renderUserDetail(req, res, {
      status: 422,
      error: `To delete this user, type their username (${target.username}) exactly.`,
    });
  }

  try {
    await AdminService.deleteUser(id, ctx(req));
  } catch (err) {
    if (err instanceof ApiError && err.statusCode !== 404) {
      return renderUserDetail(req, res, { status: err.statusCode, error: err.message });
    }
    throw err;
  }
  return res.redirect(303, "/admin/users?done=deleted");
});

// =========================================================================
// Audit log
// =========================================================================
const showAuditLogs = CatchAsync(async (req, res) => {
  const { filters, filterError } = parseQuery(
    adminSchema.getAuditLogsSchema.query,
    req.query,
    ["page", "limit", "search", "action", "sortBy", "sortOrder"],
  );

  const { auditLogs, pagination } = await AdminService.getAuditLogs(filters);

  res.render("pages/admin/audit-logs", {
    title: "Audit log",
    tab: "audit",
    auditLogs,
    pagination,
    filters,
    actions: AUDIT_ACTIONS,
    error: filterError,
    ...urlHelpers("/admin/audit-logs", filters),
  });
});

// =========================================================================
// Login history
// =========================================================================
const showLoginHistory = CatchAsync(async (req, res) => {
  const { filters, filterError } = parseQuery(
    adminSchema.getLoginHistorySchema.query,
    req.query,
    ["page", "limit", "userId", "sortBy", "sortOrder"],
  );

  const { loginHistory, pagination } = await AdminService.getLoginHistory(filters);

  res.render("pages/admin/login-history", {
    title: "Login history",
    tab: "logins",
    loginHistory,
    pagination,
    filters,
    error: filterError,
    ...urlHelpers("/admin/login-history", filters),
  });
});

// =========================================================================
// Maintenance
// =========================================================================
const renderMaintenance = (res, { status = 200, error = null, result = null, values = {} } = {}) =>
  res.status(status).render("pages/admin/maintenance", {
    title: "Maintenance",
    tab: "maintenance",
    error,
    result,
    values: {
      retentionDays: 7,
      cleanLoginHistory: false,
      loginHistoryRetentionDays: 90,
      ...values,
    },
  });

const showMaintenance = (req, res) => renderMaintenance(res);

const runCleanup = CatchAsync(async (req, res) => {
  const values = {
    retentionDays: req.body.retentionDays,
    // an HTML checkbox sends "on" when ticked and nothing at all when not;
    // the schema wants a real boolean
    cleanLoginHistory: req.body.cleanLoginHistory === "on",
    loginHistoryRetentionDays: req.body.loginHistoryRetentionDays,
  };

  const parsed = adminSchema.cleanupSchema.body.safeParse(values);
  if (!parsed.success) {
    return renderMaintenance(res, {
      status: 422,
      error: parsed.error.issues[0].message,
      values,
    });
  }

  const result = await AdminService.cleanupDatabase(parsed.data, ctx(req));
  return renderMaintenance(res, { result, values: parsed.data });
});

export default {
  showUsers,
  showUser,
  updateRole,
  updateStatus,
  unlockUser,
  logoutUser,
  deleteUser,
  showAuditLogs,
  showLoginHistory,
  showMaintenance,
  runCleanup,
};
