import CatchAsync from "../../Utils/CatchAsync.js";
import AuthService from "./auth.service.js";

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

  res.status(201).json({
    success: true,
    message:
      "Registration successful. Please check your email to verify your account.",
    data: { user },
  });
});

const refreshToken = CatchAsync(async (req, res, next) => {
  const { refreshToken } = req.validated.body;
  const { userIp, userAgent } = getRequestMetadata(req);

  const token = await AuthService.rotateRefreshToken(refreshToken, {
    userIp,
    userAgent,
  });

  res.status(200).json({
    success: true,
    message: "Token refreshed successfully.",
    tokens: {
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
    },
  });
});

const verifyEmail = CatchAsync(async (req, res, next) => {
  const { token } = req.validated.body;
  await AuthService.verifyEmail(token);
  res.status(200).json({
    success: true,
    message: "Email verified successfully.",
  });
});

const resendVerification = CatchAsync(async (req, res, next) => {
  const { email } = req.validated.body;
  await AuthService.resendVerificationEmail(email);
  res.status(200).json({
    success: true,
    message:
      "Email resent successfully. Please check your email to verify your account.",
  });
});

export default {
  register,
  resendVerification,
  refreshToken,
  verifyEmail,
};
