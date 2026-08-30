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
  const metadata = getRequestMetadata(req);
  await AuthService.verifyEmail(token, metadata);

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
  const metadata = getRequestMetadata(req);
  await AuthService.resetPassword(token, newPassword, metadata);

  ApiResponse.success(
    res,
    "Password reset successfully, please log in with your new password.",
  );
});

/**
 * @route POST /api/v1/auth/logout
 * @desc Logout a user by invalidating their refresh token
 * @access Private
 */
const logout = CatchAsync(async (req, res, next) => {
  const { refreshToken } = req.validated.body;
  const decoded = req.token;
  console.log("JTI in logout controller:", decoded.jti);
  const { id } = req.user;
  await AuthService.logout(id, refreshToken, decoded);

  ApiResponse.success(res, "Logout successful.");
});

/**
 * @route POST /api/v1/auth/logout-all
 * @desc Logout a user from all sessions by invalidating all their refresh tokens
 * @access Private
 */
const logoutAll = CatchAsync(async (req, res, next) => {
  const { id } = req.user;
  const metadata = getRequestMetadata(req);
  await AuthService.logoutAll(id, metadata);

  ApiResponse.success(res, "Logged out from all sessions successfully.");
});

/**
 * @route GET /api/v1/auth/me
 * @desc Get the currently authenticated user's information
 * @access Private
 */
const getCurrentUser = CatchAsync(async (req, res, next) => {
  const { passwordChangedAt, sessionsRevokedAt, ...user } = req.user;

  ApiResponse.success(res, "Current user retrieved successfully.", { user });
});

/**
 * @route POST /api/v1/auth/change-password
 * @desc Change the password of the currently authenticated user
 * @access Private
 */
const changePassword = CatchAsync(async (req, res, next) => {
  const { currentPassword, newPassword } = req.validated.body;
  const { id } = req.user;
  await AuthService.changePassword(id, currentPassword, newPassword);

  ApiResponse.success(res, "Password changed successfully.");
});

/**
 * @route PATCH /api/v1/auth/me
 * @desc Update the profile of the currently authenticated user
 * @access Private
 */
const updateProfile = CatchAsync(async (req, res, next) => {
  const { fullName, username, email } = req.validated.body;
  const { id } = req.user;
  const metadata = getRequestMetadata(req);
  const updatedUser = await AuthService.updateUserProfile(
    id,
    {
      fullName,
      username,
      email,
    },
    metadata,
  );

  ApiResponse.success(res, "Profile updated successfully.", {
    user: updatedUser,
  });
});

// --------- OAUTH CONTROLLERS ---------
/**
 * @route GET /api/v1/auth/google/callback
 * @desc Handle Google OAuth callback and return access and refresh tokens
 * @access Public
 */
const googleOAuthCallback = CatchAsync(async (req, res, next) => {
  const metadata = getRequestMetadata(req);
  const tokenPair = await AuthService.oauthLogin(req.user, metadata);

})

export default {
  register,
  login,
  resendVerification,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  logout,
  logoutAll,
  getCurrentUser,
  changePassword,
  updateProfile,
};
