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

/**
 * @swagger
 * tags:
 *    name: Authentication
 *    description: Endpoints for user authentication and authorization.
 */

/**
 * @swagger
 * /auth/register:
 *   post:
 *    summary: Register a new user.
 *    tags: [Authentication]
 *    security: []
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required: [fullName, username, email, password, confirmPassword]
 *            properties:
 *              fullName:
 *                type: string
 *                example: John Doe
 *              username:
 *                type: string
 *                example: johndoe
 *              email:
 *                type: string
 *                example: johndoe@example.com
 *              password:
 *                type: string
 *                example: SecureP@ss1
 *              confirmPassword:
 *                type: string
 *                example: SecureP@ss1
 *    responses:
 *      201:
 *        description: Registration successful. Please check your email to verify your account.
 *        content:
 *          application/json:
 *            schema:
 *              allOf:
 *                - $ref: '#/components/schemas/ApiSuccess'
 *                - type: object
 *                  properties:
 *                    data:
 *                      type: object
 *                      properties:
 *                        user:
 *                          $ref: '#/components/schemas/User'
 *      400:
 *        description: Bad request. Please check your input.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *      409:
 *        description: Conflict. Email or username already exists.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 *      429:
 *        description: Too many requests. Please try again later.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.post(
  "/register",
  registerRateLimiter,
  validateRequest(authSchema.registerSchema),
  authController.register,
);

/**
 * @swagger
 * /auth/login:
 *  post:
 *    summary: Login with LoginIdentifier (email or username) and password.
 *    tags: [Authentication]
 *    security: []
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required: [loginIdentifier, password]
 *            properties:
 *              loginIdentifier:
 *                type: string
 *                example: johndoe or johndoe@example.com
 *              password:
 *                type: string
 *                example: SecureP@ss1
 *    responses:
 *      200:
 *        description: Login successful. Returns access and refresh tokens.
 *        content:
 *          application/json:
 *            schema:
 *              allOf:
 *                - $ref: '#/components/schemas/ApiSuccess'
 *                - type: object
 *                  properties:
 *                    data:
 *                      type: object
 *                      properties:
 *                        tokens:
 *                          $ref: '#/components/schemas/AuthTokens'
 *      400:
 *        description: Bad request. Please check your input.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *     401:
 *        description: Unauthorized. Invalid credentials.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 *     429:
 *        description: Too many requests. Please try again later.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.post(
  "/login",
  loginRateLimiter,
  validateRequest(authSchema.loginSchema),
  authController.login,
);

router.post(
  "/resend-verification",
  emailVerificationRateLimiter,
  validateRequest(authSchema.resendVerificationEmailSchema),
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
