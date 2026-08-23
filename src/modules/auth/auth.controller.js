import CatchAsync from "../../Utils/catchasync.js";
import AuthService from "./auth.service.js";
import ApiResponse from "../../Utils/ApiResponse.js";

const getRequestMetadata = req => ({
  userIp: req.ip || req.connection?.remoteAddress,
  userAgent: req.headers["user-agent"],
});

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

const verifyEmail = CatchAsync(async (req, res, next) => {
  const { token } = req.validated.body;
  await AuthService.verifyEmail(token);

  ApiResponse.success(res, "Email verified successfully.");
});

const resendVerification = CatchAsync(async (req, res, next) => {
  const { email } = req.validated.body;
  await AuthService.resendVerificationEmail(email);

  ApiResponse.success(
    res,
    "Email resent successfully. Please check your email to verify your account.",
  );
});

export default {
  register,
  login,
  resendVerification,
  refreshToken,
  verifyEmail,
};
