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

/**
 * @swagger
 * /auth/logout:
 *   post:
 *    summary: Logout the currently authenticated user
 *    description: This endpoint allows the currently authenticated user to log out by invalidating their refresh token. The user must provide a valid refresh token in the request body. Upon successful logout, the refresh token will be revoked, and the user will need to log in again to obtain new tokens.
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
 *                example: "refresh_token_here"
 *    responses:
 *      200:
 *        description: Logout successful. The refresh token has been revoked, and the user is logged out.
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
 *                  example: Logout successful.
 */
router.post(
  "/logout",
  protect,
  validateRequest(authSchema.refreshTokenSchema),
  authController.logout,
);

/**
 * @swagger
 * /auth/logout-all:
 *   post:
 *    summary: Logout the currently authenticated user from all sessions
 *    description: This endpoint allows the currently authenticated user to log out from all sessions by invalidating all their refresh tokens. Upon successful logout, all active sessions for the user will be terminated, and they will need to log in again to obtain new tokens.
 *    tags: [Authentication]
 *    responses:
 *      200:
 *        description: Successful response description
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiSuccess'
 *      429:
 *        description: Too many requests. Please try again later.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.post("/logout-all", protect, authController.logoutAll);

/**
 * @swagger
 * /auth/me:
 *   get:
 *    summary: Get current user information
 *    description: This endpoint allows the currently authenticated user to retrieve their own user information. The user must be logged in and provide a valid access token in the request headers or cookies. Upon successful authentication, the user's information will be returned.
 *    tags: [Authentication]
 *    responses:
 *      200:
 *        description: Successful response description
 *        content:
 *          application/json:
 *            schema:
 *              allOf:
 *                - $ref: '#/components/schemas/ApiSuccess'
 *                - type: object
 *                  properties:
 *                    data:
 *                      $ref: '#/components/schemas/User'
 *      400:
 *        description: Bad request. Please check your input.
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
router.get("/me", protect, authController.getCurrentUser);

/**
 * @swagger
 * /auth/change-password:
 *   post:
 *    summary: Change the current authenticated user's password
 *    description: This endpoint allows the currently authenticated user to change their password. The user must provide their current password, a new password, and a confirmation of the new password. Upon successful validation and authentication, the user's password will be updated.
 *    tags: [Authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            required: [currentPassword, newPassword, confirmPassword]
 *            properties:
 *              currentPassword:
 *                type: string
 *                example: "SecureP@ss2"
 *              newPassword:
 *                type: string
 *                example: "SecureP@ss1"
 *              confirmNewPassword:
 *                type: string
 *                example: "SecureP@ss1"
 *    responses:
 *      200:
 *        description: Password changed successfully. The user can now log in with the new password.
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
 *                  example: Password changed successfully, please log in with your new password.
 *      400:
 *        description: Bad request. Please check your input.
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
  "/change-password",
  protect,
  passwordResetRateLimiter,
  validateRequest(authSchema.changePasswordSchema),
  authController.changePassword,
);

/**
 * @swagger
 * /auth/me:
 *   patch:
 *    summary: Update the authenticated user details
 *    description: This endpoint allows the currently authenticated user to update their profile information. The user can provide the fields they wish to update, and upon successful validation and authentication, the user's profile will be updated accordingly.
 *    tags: [Authentication]
 *    requestBody:
 *      required: true
 *      content:
 *        application/json:
 *          schema:
 *            type: object
 *            properties:
 *              username:
 *                type: string
 *              email:
 *                type: string
 *              fullName:
 *                type: string
 *    responses:
 *      200:
 *        description: Successful response description
 *        content:
 *          application/json:
 *            schema:
 *             allOf:
 *                - $ref: '#/components/schemas/ApiSuccess'
 *                - type: object
 *                  properties:
 *                    data:
 *                     $ref: '#/components/schemas/User'
 *      400:
 *        description: Bad request. Please check your input.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *      409:
 *        description: Conflict. This resource already exists.
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
router.patch(
  "/me",
  protect,
  validateRequest(authSchema.updateProfileSchema),
  authController.updateProfile,
);

// --------- OAUTH ROUTES ---------
/**
 * @swagger
 * /auth/google:
 *   get:
 *    summary: Initiate Google OAuth2 authentication flow
 *    description: |
 *      Redirects the client to Google's OAuth 2.0 consent page.
 *
 *      **Note:** This endpoint performs a 302 browser redirect. It should be triggered by navigating directly in the browser (e.g. `<a href="/api/v1/auth/google">` or `window.location.href`), **not** via an AJAX/fetch call from Swagger UI, as Google blocks cross-origin requests (CORS).
 *    tags: [Authentication]
 *    security: []
 *    responses:
 *      302:
 *        description: Redirect to Google OAuth 2.0 login/consent screen.
 *        headers:
 *          Location:
 *            description: The Google OAuth 2.0 authorization URL.
 *            schema:
 *              type: string
 *              example: "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=..."
 *      500:
 *        description: Internal server error or OAuth service failure.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  }),
);

/**
 * @swagger
 * /auth/google/callback:
 *   get:
 *     summary: Google OAuth2 callback URL.
 *     description: Google redirects back to this endpoint with an authorization code. The server exchanges it for user information, authenticates/creates the user, and returns access and refresh tokens.
 *     tags: [Authentication]
 *     security: []
 *     parameters:
 *       - in: query
 *         name: code
 *         schema:
 *           type: string
 *         required: false
 *         description: The authorization code provided by Google.
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *         required: false
 *         description: OAuth state parameter (if enabled).
 *     responses:
 *       200:
 *         description: Google OAuth login successful.
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ApiSuccess'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: object
 *                       properties:
 *                         tokens:
 *                           $ref: '#/components/schemas/TokenPair'
 *                         user:
 *                           $ref: '#/components/schemas/User'
 *       302:
 *         description: Redirect to failure URL if Google authentication failed.
 *       401:
 *         description: Authentication failed.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 */
router.get(
  "/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/api/v1/auth/oauth-failure",
  }),
  authController.googleCallback,
);

// For the frontend to be able to exchange the OAuth code for access and refresh tokens, you can create a separate endpoint that the frontend can call after receiving the OAuth code. This endpoint will handle the token exchange and return the tokens to the frontend.
// router.post("/oauth/exchange", authController.exchangeToken);

/**
 * @swagger
 * /auth/oauth-failure:
 *   get:
 *     summary: OAuth authentication failure endpoint.
 *     description: Redirect destination when an OAuth authentication flow fails or is cancelled by the user.
 *     tags: [Authentication]
 *     security: []
 *     responses:
 *       401:
 *         description: OAuth authentication failed.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ApiError'
 */
router.get("/oauth-failure", authController.oauthFailure);

export default router;
