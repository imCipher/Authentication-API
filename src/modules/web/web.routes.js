import { Router } from "express";
import webController from "./web.controller.js";
import adminWebRoutes from "./admin.web.routes.js";
import {
  loginRateLimiter,
  registerRateLimiter,
  authRateLimiter,
  emailVerificationRateLimiter,
  passwordResetRateLimiter,
} from "../../middlewares/rateLimiter.middleware.js";
import {
  ensureSessionId,
  doubleCsrfProtection,
  exposeCsrfToken,
} from "../../config/csrf.js";
import {
  requireAuthPage,
  guestOnly,
} from "../../middlewares/pageAuth.middleware.js";

const router = Router();

router.use(ensureSessionId, doubleCsrfProtection, exposeCsrfToken);

router.get("/login", guestOnly, webController.showLogin);
router.post("/login", loginRateLimiter, webController.submitLogin);
// Continue with Google (the callback URL must be registered in Google Cloud Console)
router.get(
  "/auth/google",
  guestOnly,
  authRateLimiter,
  webController.startGoogle,
);
router.get("/auth/google/callback", webController.googleCallback);

router.get("/register", guestOnly, webController.showRegister);
router.post("/register", registerRateLimiter, webController.submitRegister);
router.get("/verify-email", guestOnly, webController.showVerifyEmail);
router.post("/verify-email", authRateLimiter, webController.submitVerifyEmail);
router.post(
  "/verify-email/resend",
  emailVerificationRateLimiter,
  webController.submitResendVerification,
);

router.get("/forgot-password", guestOnly, webController.showForgotPassword);
router.post(
  "/forgot-password",
  passwordResetRateLimiter,
  webController.submitForgotPassword,
);

router.get("/reset-password/:token", webController.showResetPassword);
router.post(
  "/reset-password/:token",
  authRateLimiter,
  webController.submitResetPassword,
);

router.get("/", (req, res) => res.redirect("/dashboard")); // requireAuthPage bounces guests to /login

router.get("/dashboard", requireAuthPage, webController.showDashboard);
router.get("/settings", requireAuthPage, webController.showSettings);
router.post("/settings/profile", requireAuthPage, webController.updateProfile);
router.post(
  "/settings/password",
  requireAuthPage,
  authRateLimiter,
  webController.changePassword,
);
router.post(
  "/settings/password-link",
  requireAuthPage,
  passwordResetRateLimiter,
  webController.sendSetPasswordLink,
);

router.post("/settings/logout-all", requireAuthPage, webController.logoutAll);
router.post("/logout", requireAuthPage, webController.logout);

// Admin pages (every route inside requires the ADMIN role)
router.use("/admin", adminWebRoutes);

router.use((err, req, res, next) => {
  if (err.statusCode !== 429) return next(err);

  if (req.path === "/login") {
    return res
      .status(429)
      .render("pages/login", {
        error: err.message,
        values: { loginIdentifier: req.body?.loginIdentifier ?? "" },
      });
  }

  if (req.path === "/register") {
    const { fullName = "", username = "", email = "" } = req.body ?? {};
    return res
      .status(429)
      .render("pages/register", {
        errors: { form: err.message },
        values: { fullName, username, email },
      });
  }

  if (req.path === "/verify-email" || req.path === "/verify-email/resend") {
    return res
      .status(429)
      .render("pages/verify-email", {
        error: err.message,
        email: req.body?.email ?? null,
        notice: null,
      });
  }

  if (req.path === "/forgot-password") {
    return res
      .status(429)
      .render("pages/forgot-password", {
        errors: { form: err.message },
        values: { email: req.body?.email ?? "" },
        notice: null,
      });
  }

  if (req.path.startsWith("/reset-password/")) {
    return res
      .status(429)
      .render("pages/reset-password", {
        token: req.path.split("/")[2],
        errors: { form: err.message },
        expired: false,
      });
  }

  next(err);
});

export default router;
