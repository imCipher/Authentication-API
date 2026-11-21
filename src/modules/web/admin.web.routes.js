import { Router } from "express";

import adminWeb from "./admin.web.controller.js";
import { requireAdminPage } from "../../middlewares/pageAuth.middleware.js";
import {
  adminReadRateLimiter,
  adminSensitiveMutationRateLimiter,
  adminHeavyMaintenanceRateLimiter,
} from "../../middlewares/rateLimiter.middleware.js";

/*
 * Mounted at /admin inside the web router, so the web router's sid + CSRF
 * middleware already ran. HTML forms can only GET or POST, so the API's
 * PATCH / DELETE actions become POST routes with a verb in the path.
 *
 * Order on every route: requireAdminPage FIRST (so the rate limiters key on
 * the admin's user id, not just the IP), then the limiter, then the handler.
 */
const router = Router();

router.use(requireAdminPage);

router.get("/", (req, res) => res.redirect(303, "/admin/users"));

// Users
router.get("/users", adminReadRateLimiter, adminWeb.showUsers);
router.get("/users/:id", adminReadRateLimiter, adminWeb.showUser);
router.post("/users/:id/role", adminSensitiveMutationRateLimiter, adminWeb.updateRole);
router.post("/users/:id/status", adminSensitiveMutationRateLimiter, adminWeb.updateStatus);
router.post("/users/:id/unlock", adminSensitiveMutationRateLimiter, adminWeb.unlockUser);
router.post("/users/:id/logout-all", adminSensitiveMutationRateLimiter, adminWeb.logoutUser);
router.post("/users/:id/delete", adminSensitiveMutationRateLimiter, adminWeb.deleteUser);

// Logs
router.get("/audit-logs", adminReadRateLimiter, adminWeb.showAuditLogs);
router.get("/login-history", adminReadRateLimiter, adminWeb.showLoginHistory);

// Maintenance
router.get("/maintenance", adminReadRateLimiter, adminWeb.showMaintenance);
router.post("/maintenance/cleanup", adminHeavyMaintenanceRateLimiter, adminWeb.runCleanup);

export default router;
