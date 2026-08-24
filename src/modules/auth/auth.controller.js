import CatchAsync from "../../utils/catchasync.js";
import AuthService from "./auth.service.js";
import ApiResponse from "../../utils/ApiResponse.js";

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
 * @route POST /api/v1/auth/register
 * @desc Register a new user and send a verification email
 * @access Public
 */
const register = CatchAsync(async (req, res, next) => {
  const { fullName, email, username, password } = req.validated.body;
  const user = await AuthService.register({
    fullName,
    email,
    username,
    password,
  });

  ApiResponse.created(
    res,
    "Registration successful. Please check your email to verify your account.",
    { user },
  );
});

/**
 * @route POST /api/v1/auth/login
 * @desc Login a user and return access and refresh tokens
 * @access Public
 */
const login = CatchAsync(async (req, res, next) => {
  const { loginIdentifier, password } = req.validated.body;
  const metadata = getRequestMetadata(req);
  const tokenPair = await AuthService.login(
    {
      loginIdentifier,
      password,
    },
    metadata,
  );

  ApiResponse.success(res, "Login Successful.", {
    tokens: {
      accessToken: tokenPair.accessToken,
      refreshToken: tokenPair.refreshToken,
    },
  });
});

/**
 * @route POST /api/v1/auth/refresh-token
 * @desc Rotate access and refresh tokens using a valid refresh token
 * @access Public
 */
const refreshToken = CatchAsync(async (req, res, next) => {
  const { refreshToken } = req.validated.body;
  const { userIp, userAgent } = getRequestMetadata(req);

  const token = await AuthService.rotateRefreshToken(refreshToken, {
    userIp,
    userAgent,
  });

  ApiResponse.success(res, "Token refreshed successfully.", null, {
    tokens: {
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
    },
  });
});

/**
 * @route POST /api/v1/auth/verify-email
 * @desc Verify a user's email using a token sent to their email
 * @access Public
 */
const verifyEmail = CatchAsync(async (req, res, next) => {
  const { token } = req.validated.body;
  await AuthService.verifyEmail(token);

  ApiResponse.success(res, "Email verified successfully.");
});

/**
 * @route POST /api/v1/auth/resend-verification
 * @desc Resend email verification token to a user's email
 * @access Public
 */
const resendVerification = CatchAsync(async (req, res, next) => {
  const { email } = req.validated.body;
  await AuthService.resendVerificationEmail(email);

  ApiResponse.success(
    res,
    "Email resent successfully. Please check your email to verify your account.",
  );
});

/**
 * @route POST /api/v1/auth/forgot-password
 * @desc Send a password reset email to the user
 * @access Public
 */
const forgotPassword = CatchAsync(async (req, res, next) => {
  const { email } = req.validated.body;
  await AuthService.sendPasswordResetEmail(email);

  ApiResponse.success(
    res,
    "Password reset email sent successfully. Please check your email for further instructions.",
  );
});

/**
 * @route POST /api/v1/auth/reset-password
 * @desc Reset a user's password using a token sent to their email
 * @access Public
 */
const resetPassword = CatchAsync(async (req, res, next) => {
  const { newPassword } = req.validated.body;
  const { token } = req.validated.params;
  await AuthService.resetPassword(token, newPassword);

  ApiResponse.success(
    res,
    "Password reset successfully, please log in with your new password.",
  );
});

export default {
  register,
  login,
  resendVerification,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
