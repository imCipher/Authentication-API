import { Router } from "express";
import passport from "passport";

import {
  authRateLimiter,
  registerRateLimiter,
  loginRateLimiter,
  emailVerificationRateLimiter,
} from "../../middlewares/rateLimiter.middleware.js";
import authSchema from "./auth.validation.js";
import validateRequest from "../../middlewares/validator.middleware.js";
import { protect } from "../../middlewares/auth.middleware.js";
import authController from "./auth.controller.js";

const router = Router();

router.use(authRateLimiter); // Apply general auth rate limiter to all routes in this router

router.post(
  "/register",
  registerRateLimiter,
  validateRequest(authSchema.registerSchema),
  authController.register,
);

router.post(
  "/login",
  loginRateLimiter,
  validateRequest(authSchema.loginSchema),
  (req, res) => {
    // Handle login logic here
    if (
      req.body.loginIdentifier === "testuser" &&
      req.body.password === "password"
    ) {
      res.status(200).json({ message: "User logged in successfully" });
    } else {
      res.status(401).json({ message: "Invalid username or password" });
    }
  },
);

router.post(
  "/resend-verification",
  emailVerificationRateLimiter,
  protect,
  authController.resendVerification,
);

router.post(
  "/verify-email",
  emailVerificationRateLimiter,
  validateRequest(authSchema.verifyEmailSchema),
  authController.verifyEmail,
);

router.post(
  "/refresh-token",
  validateRequest(authSchema.refreshTokenSchema),
  authController.refreshToken,
);

export default router;
