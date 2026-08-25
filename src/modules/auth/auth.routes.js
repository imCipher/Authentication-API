import { Router } from "express";
import passport from "passport";

import {
  authRateLimiter,
  registerRateLimiter,
  loginRateLimiter,
  emailVerificationRateLimiter,
  passwordResetRateLimiter,
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
 *    description: This endpoint allows new users to register by providing their full name, username, email, password, and confirm password. Upon successful registration, a verification email will be sent to the provided email address.
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
 *                example: "John Doe"
 *              username:
 *                type: string
 *                example: "johndoe"
 *              email:
 *                type: string
 *                example: "johndoe@example.com"
 *              password:
 *                type: string
 *                example: "SecureP@ss1"
 *              confirmPassword:
 *                type: string
 *                example: "SecureP@ss1"
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
 *    description: This endpoint allows users to log in using either their registered email address or username along with their password. Upon successful authentication, the user will receive an access token and a refresh token for session management.
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
 *                example: "johndoe or johndoe@example.com"
 *              password:
 *                type: string
 *                example: "SecureP@ss1"
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
 *                          $ref: '#/components/schemas/TokenPair'
 *      400:
 *        description: Bad request. Please check your input.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *      401:
 *        description: Unauthorized. Invalid credentials.
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
  "/login",
  loginRateLimiter,
  validateRequest(authSchema.loginSchema),
  authController.login,
);

/**
 * @swagger
 * /auth/resend-verification:
 *   post:
 *    summary: Resend verification email to the user.
 *    description: This endpoint allows users to request a new verification email if they haven't received the original one or if it has expired. The user must provide their registered email address to receive the verification email.
 *    security: []
 *    tags: [Authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required: [email]
 *            properties:
 *              email:
 *                type: string
 *                example: "johndoe@example.com"
 *    responses:
 *      200:
 *        description: Email Sent Successfully
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                success:
 *                  type: boolean
 *                  example: true
 *                message:
 *                  type: string
 *                  example: Email resent successfully. Please check your email to verify your account.
 *      429:
 *        description: Too many requests. Please try again later.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.post(
  "/resend-verification",
  emailVerificationRateLimiter,
  validateRequest(authSchema.resendVerificationEmailSchema),
  authController.resendVerification,
);

/**
 * @swagger
 * /auth/verify-email:
 *   post:
 *    summary: Verifying Email with the token sent to the user's email address.
 *    description: This endpoint allows users to verify their email address by providing the verification token they received via email. The token is typically sent to the user's email after registration or when requesting a new verification email.
 *    security: []
 *    tags: [Authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required: [token]
 *            properties:
 *              token:
 *                type: string
 *                example: "123456"
 *    responses:
 *      200:
 *        description: Email verified successfully.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiSuccess'
 *      400:
 *        description: Bad request or invalid token.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *      429:
 *        description: Too many requests. Please try again later.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.post(
  "/verify-email",
  emailVerificationRateLimiter,
  validateRequest(authSchema.verifyEmailSchema),
  authController.verifyEmail,
);

/**
 * @swagger
 * /auth/refresh-token:
 *   post:
 *    summary: Refresh Access Token using Refresh Token
 *    description: This endpoint allows users to obtain a new access token by providing a valid refresh token. The refresh token is typically issued during the login process and can be used to maintain user sessions without requiring them to log in again.
 *    security: []
 *    tags: [Authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required: [refreshToken]
 *            properties:
 *              refreshToken:
 *                type: string
 *                example: "583nd0jn29jmdin9fnino28"
 *    responses:
 *      200:
 *        description: Token Refreshed Successfully
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiSuccess'
 *      400:
 *        description: Bad request. Please check your input.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *      401:
 *        description: Unauthorized. Please provide valid credentials.
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
  "/refresh-token",
  validateRequest(authSchema.refreshTokenSchema),
  authController.refreshToken,
);

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *    summary: Send forgot password email.
 *    description: This endpoint allows users to request a password reset email. If the email exists in our system, a reset link will be sent.
 *    security: []
 *    tags: [Authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required: [email]
 *            properties:
 *              email:
 *                type: string
 *                example: "johndoe@example.com"
 *    responses:
 *      200:
 *        description: Password reset email sent successfully. Please check your email for further instructions.
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                success:
 *                  type: boolean
 *                  example: true
 *                message:
 *                  type: string
 *                  example: Password reset email sent successfully. Please check your email.
 *      429:
 *        description: Too many requests. Please try again later.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.post(
  "/forgot-password",
  passwordResetRateLimiter,
  validateRequest(authSchema.resendVerificationEmailSchema),
  authController.forgotPassword,
);

/**
 * @swagger
 * /auth/reset-password/{token}:
 *   post:
 *    summary: Reset password using the token sent to the user's email address.
 *    description: This endpoint allows users to reset their password by providing the reset token they received via email along with their new password. The token is typically sent to the user's email after they request a password reset.
 *    security: []
 *    tags: [Authentication]
 *    parameters:
 *      - in: path
 *        name: token
 *        required: true
 *        schema:
 *          type: string
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required: [newPassword, confirmNewPassword]
 *            properties:
 *              newPassword:
 *                type: string
 *                example: "SecureP@ss2"
 *              confirmNewPassword:
 *                type: string
 *                example: "SecureP@ss2"
 *    responses:
 *      200:
 *        description: Email Sent Successfully
 *        content:
 *          application/json:
 *            schema:
 *              type: object
 *              properties:
 *                success:
 *                  type: boolean
 *                  example: true
 *                message:
 *                  type: string
 *                  example: Password reset successfully, please log in with your new password.
 *      400:
 *        description: Bad request. Please check your input.
 *        content:
 *          application/json:
 *            schema:
 *              ref: '#/components/schemas/ApiValidationError'
 *      401:
 *        description: Unauthorized. The token is invalid or has expired.
 *        content:
 *          application/json:
 *            schema:
 *              ref: '#/components/schemas/ApiError'
 *      429:
 *        description: Too many requests. Please try again later.
 *        content:
 *          application/json:
 *            schema:
 *              ref: '#/components/schemas/ApiError'
 */
router.post(
  "/reset-password/:token",
  passwordResetRateLimiter,
  validateRequest(authSchema.resetPasswordSchema),
  authController.resetPassword,
);

export default router;
