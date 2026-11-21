import passport from "passport";

import CatchAsync from "../../utils/catchasync.js";
import AuthService from "../auth/auth.service.js";
import ApiError from "../../utils/ApiError.js";
import authSchema from "../auth/auth.validation.js";
import logger from "../../config/logger.js";
import { isGoogleConfigured } from "../../config/passport.js";
import { setAuthCookies, clearAuthCookies } from "../../utils/authCookies.js";

const metaOf = req => ({
  userIp: req.ip,
  userAgent: req.headers["user-agent"],
});

// [{ path: ["email"], message: "…" }, …]  →  { email: "…", … }
const fieldErrors = zodError => {
  const out = {};
  for (const issue of zodError.issues) {
    const key = issue.path[0] ?? "form"; // no path → general form error
    out[key] ??= issue.message; // keep only the first error per field
  }
  return out;
};

const LOGIN_NOTICES = {
  "password-changed": "Password changed. Please log in with your new password.",
  "logged-out": "You've been logged out.",
  "logged-out-all": "You've been logged out of all devices.",
  "password-reset":
    "Your password has been reset. Please log in with your new password.",
  verified: "Email verified! You can now log in.",
};

// Errors that arrive by redirect (?error=…). Same rule as notices: fixed text
// from this table only, never the raw query string.
const LOGIN_ERRORS = {
  "oauth-cancelled": "Google sign-in was cancelled.",
  "oauth-failed": "We couldn't sign you in with Google. Please try again.",
  "oauth-unavailable": "Google sign-in isn't available right now.",
  "oauth-suspended":
    "Your account is suspended or deactivated. Please contact support for assistance.",
};

const showLogin = (req, res) => {
  res.render("pages/login", {
    error: LOGIN_ERRORS[req.query.error] ?? null,
    values: {},
    notice: LOGIN_NOTICES[req.query.reason] ?? null,
  });
};

const submitLogin = CatchAsync(async (req, res) => {
  const { loginIdentifier = "", password = "" } = req.body;
  const values = { loginIdentifier };

  // 1. validate with your existing Zod schema (safeParse = no throw)
  const parsed = authSchema.loginSchema.body.safeParse({
    loginIdentifier,
    password,
  });
  if (!parsed.success) {
    return res
      .status(422)
      .render("pages/login", { error: parsed.error.issues[0].message, values });
  }

  // 2. call the same service the API uses
  try {
    const { accessToken, refreshToken } = await AuthService.login(parsed.data, {
      userIp: req.ip,
      userAgent: req.headers["user-agent"],
    });

    // 3. Store tokens in httpOnly cookies (JS on the page can't read them)
    setAuthCookies(res, { accessToken, refreshToken });

    // 4. Post/Redirect/Get: redirect so a refresh doesn't resubmit the form
    return res.redirect(303, "/dashboard");
  } catch (err) {
    if (err instanceof ApiError) {
      return res
        .status(err.statusCode)
        .render("pages/login", { error: err.message, values });
    }
    throw err;
  }
});

// ---------------------------------------------------------------------------
// Continue with Google
// ---------------------------------------------------------------------------

// Step 1: send the browser to Google (passport adds client_id, scope, state…)
const startGoogle = (req, res, next) => {
  if (!isGoogleConfigured) {
    return res.redirect(303, "/login?error=oauth-unavailable");
  }
  return passport.authenticate("google-web", { session: false })(req, res, next);
};

// Step 2: Google sends the browser back here with ?code=…&state=…
const googleCallback = (req, res, next) => {
  if (!isGoogleConfigured) {
    return res.redirect(303, "/login?error=oauth-unavailable");
  }

  // The user pressed "Cancel" on Google's consent screen (or Google refused)
  if (req.query.error) {
    const reason = req.query.error === "access_denied" ? "oauth-cancelled" : "oauth-failed";
    return res.redirect(303, `/login?error=${reason}`);
  }

  // A "custom callback": instead of passport sending its own response, we get
  // (err, user) back and decide what the page does — cookies + redirect.
  passport.authenticate("google-web", { session: false }, async (err, user) => {
    if (err || !user) {
      // err   → Google/DB problem (logged); !user → state mismatch or similar
      if (err) logger.warn("Google sign-in failed", { message: err.message });
      return res.redirect(303, "/login?error=oauth-failed");
    }

    try {
      const tokens = await AuthService.oauthLogin(user, metaOf(req));
      setAuthCookies(res, tokens);
      return res.redirect(303, "/dashboard");
    } catch (loginErr) {
      if (loginErr instanceof ApiError && loginErr.code === "ACCOUNT_SUSPENDED") {
        return res.redirect(303, "/login?error=oauth-suspended");
      }
      return next(loginErr);
    }
  })(req, res, next);
};

const showRegister = (req, res) => {
  res.render("pages/register", { errors: {}, values: {} });
};

const submitRegister = CatchAsync(async (req, res) => {
  const {
    fullName = "",
    username = "",
    email = "",
    password = "",
    confirmPassword = "",
  } = req.body;
  const values = { fullName, username, email }; // never send passwords back

  const parsed = authSchema.registerSchema.body.safeParse({
    fullName,
    username,
    email,
    password,
    confirmPassword,
  });
  if (!parsed.success) {
    return res
      .status(422)
      .render("pages/register", { errors: fieldErrors(parsed.error), values });
  }

  try {
    // parsed.data, NOT the raw values: the schema trimmed + lowercased username/email,
    // and the service's duplicate check compares exact strings
    await AuthService.register(parsed.data);
  } catch (err) {
    if (err instanceof ApiError) {
      return res
        .status(err.statusCode)
        .render("pages/register", { errors: { form: err.message }, values });
    }
    throw err;
  }

  return res.redirect(
    303,
    `/verify-email?email=${encodeURIComponent(parsed.data.email)}`,
  );
});

// The email comes from the URL (?email=…), so anyone can put anything there.
// Only accept it if it's a valid email; otherwise treat it as missing.
const cleanEmail = raw => {
  const parsed = authSchema.resendVerificationEmailSchema.body.safeParse({
    email: raw ?? "",
  });
  return parsed.success ? parsed.data.email : null;
};

const VERIFY_NOTICES = {
  sent: "If this account still needs verifying, a new code is on its way. It expires in 5 minutes.",
};

const renderVerify = (
  req,
  res,
  { status = 200, error = null, email = null } = {},
) =>
  res
    .status(status)
    .render("pages/verify-email", {
      error,
      email,
      notice: req.query.sent ? VERIFY_NOTICES.sent : null,
    });

const showVerifyEmail = (req, res) =>
  renderVerify(req, res, { email: cleanEmail(req.query.email) });

const submitVerifyEmail = CatchAsync(async (req, res) => {
  const email = cleanEmail(req.body.email);
  const token = (req.body.token ?? "").replace(/\s/g, ""); // "123 456" → "123456"

  const parsed = authSchema.verifyEmailSchema.body.safeParse({
    email: email ?? "",
    token,
  });
  if (!parsed.success) {
    return renderVerify(req, res, {
      status: 422,
      error: parsed.error.issues[0].message,
      email,
    });
  }

  try {
    await AuthService.verifyEmail(parsed.data, metaOf(req));
  } catch (err) {
    if (err instanceof ApiError) {
      return renderVerify(req, res, {
        status: err.statusCode,
        error: err.message,
        email,
      });
    }
    throw err;
  }

  return res.redirect(303, "/login?reason=verified");
});

const submitResendVerification = CatchAsync(async (req, res) => {
  const email = cleanEmail(req.body.email);
  if (!email) {
    return renderVerify(req, res, {
      status: 422,
      error: "Please enter a valid email address.",
    });
  }

  await AuthService.resendVerificationEmail(email); // silently does nothing for unknown/verified emails

  return res.redirect(
    303,
    `/verify-email?email=${encodeURIComponent(email)}&sent=1`,
  );
});

const FORGOT_SENT =
  "If an account exists for that email, we've sent a reset link. It expires in 5 minutes.";

const showForgotPassword = (req, res) =>
  res.render("pages/forgot-password", {
    errors: {},
    values: {},
    notice: req.query.sent ? FORGOT_SENT : null,
  });

const submitForgotPassword = CatchAsync(async (req, res) => {
  const { email = "" } = req.body;

  // same email rules as resend-verification (your API reuses this schema too)
  const parsed = authSchema.resendVerificationEmailSchema.body.safeParse({
    email,
  });
  if (!parsed.success) {
    return res
      .status(422)
      .render("pages/forgot-password", {
        errors: fieldErrors(parsed.error),
        values: { email },
        notice: null,
      });
  }

  await AuthService.sendPasswordResetEmail(parsed.data.email); // silent for unknown emails

  // same redirect whether or not the account exists, and the email is NOT in the URL
  return res.redirect(303, "/forgot-password?sent=1");
});

const renderReset = (
  req,
  res,
  { status = 200, errors = {}, expired = false } = {},
) =>
  res
    .status(status)
    .render("pages/reset-password", {
      token: req.params.token,
      errors,
      expired,
    });

const showResetPassword = (req, res) => renderReset(req, res);

const submitResetPassword = CatchAsync(async (req, res) => {
  // 1. the token comes from the URL → validate it with the schema's "params" part
  const params = authSchema.resetPasswordSchema.params.safeParse(req.params);
  if (!params.success) {
    return renderReset(req, res, { status: 400, expired: true });
  }

  // 2. the passwords come from the form → validate with the "body" part
  const { newPassword = "", confirmNewPassword = "" } = req.body;
  const body = authSchema.resetPasswordSchema.body.safeParse({
    newPassword,
    confirmNewPassword,
  });
  if (!body.success) {
    return renderReset(req, res, {
      status: 422,
      errors: fieldErrors(body.error),
    });
  }

  // 3. call the service
  try {
    await AuthService.resetPassword(
      params.data.token,
      body.data.newPassword,
      metaOf(req),
    );
  } catch (err) {
    if (err instanceof ApiError) {
      return renderReset(req, res, {
        status: err.statusCode,
        errors: { form: err.message },
        expired: err.code === "TOKEN_INVALID",
      });
    }
    throw err;
  }

  // every session was revoked, so clear this browser's cookies too
  clearAuthCookies(res);
  return res.redirect(303, "/login?reason=password-reset");
});

const SETTINGS_NOTICES = { profile: "Your profile has been updated." };

const renderSettings = (
  req,
  res,
  { status = 200, errors = {}, values = {} } = {},
) =>
  res
    .status(status)
    .render("pages/settings", {
      errors,
      values,
      notice: SETTINGS_NOTICES[req.query.updated] ?? null,
    });

const showDashboard = (req, res) => res.render("pages/dashboard");
const showSettings = (req, res) => renderSettings(req, res);

const updateProfile = CatchAsync(async (req, res) => {
  const { fullName = "", username = "" } = req.body;
  const values = { fullName, username };

  const parsed = authSchema.updateProfileSchema.body.safeParse({
    fullName,
    username,
  });
  if (!parsed.success) {
    return renderSettings(req, res, {
      status: 422,
      errors: { profile: parsed.error.issues[0].message },
      values,
    });
  }

  try {
    await AuthService.updateUserProfile(req.user.id, parsed.data, metaOf(req));
    return res.redirect(303, "/settings?updated=profile");
  } catch (err) {
    if (err instanceof ApiError) {
      return renderSettings(req, res, {
        status: err.statusCode,
        errors: { profile: err.message },
        values,
      });
    }
    throw err;
  }
});

const changePassword = CatchAsync(async (req, res) => {
  const {
    currentPassword = "",
    newPassword = "",
    confirmNewPassword = "",
  } = req.body;

  const parsed = authSchema.changePasswordSchema.body.safeParse({
    currentPassword,
    newPassword,
    confirmNewPassword,
  });
  if (!parsed.success) {
    return renderSettings(req, res, {
      status: 422,
      errors: { password: parsed.error.issues[0].message },
    });
  }

  try {
    await AuthService.changePassword(
      req.user.id,
      parsed.data.currentPassword,
      parsed.data.newPassword,
      metaOf(req),
    );
  } catch (err) {
    if (err instanceof ApiError) {
      return renderSettings(req, res, {
        status: err.statusCode,
        errors: { password: err.message },
      });
    }
    throw err;
  }

  // every refresh token was revoked, so this session is over
  clearAuthCookies(res);
  return res.redirect(303, "/login?reason=password-changed");
});

const logout = CatchAsync(async (req, res) => {
  if (req.cookies.refreshToken) {
    await AuthService.logout(req.user.id, req.cookies.refreshToken, req.token);
  }
  clearAuthCookies(res);
  return res.redirect(303, "/login?reason=logged-out");
});

const logoutAll = CatchAsync(async (req, res) => {
  await AuthService.logoutAll(req.user.id, metaOf(req));
  clearAuthCookies(res);
  return res.redirect(303, "/login?reason=logged-out-all");
});

export default {
  showLogin,
  submitLogin,
  startGoogle,
  googleCallback,
  showDashboard,
  showSettings,
  updateProfile,
  changePassword,
  logout,
  logoutAll,
  showRegister,
  submitRegister,
  showVerifyEmail,
  submitVerifyEmail,
  submitResendVerification,
  showForgotPassword,
  submitForgotPassword,
  showResetPassword,
  submitResetPassword,
};
