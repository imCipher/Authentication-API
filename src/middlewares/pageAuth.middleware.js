import { protect } from "./auth.middleware.js";
import AuthService from "../modules/auth/auth.service.js";
import { setAuthCookies, clearAuthCookies } from "../utils/authCookies.js";

// protect() reports its result by calling next(err). Wrap it so we can await it:
// resolves with undefined on success, or with the error on failure.
const runProtect = (req, res) => new Promise((resolve) => protect(req, res, resolve));

export const requireAuthPage = async (req, res, next) => {
  try {
    const ok = () => { res.locals.user = req.user; next(); };

    // 1. access token valid → done
    let err = await runProtect(req, res);
    if (!err) return ok();

    // only auth failures are worth a refresh; anything else (e.g. Redis down) is a real error
    if (err.statusCode !== 401) return next(err);

    // 2. try the refresh token
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      const tokens = await AuthService.rotateRefreshToken(refreshToken, {
        userIp: req.ip,
        userAgent: req.headers["user-agent"],
      });
      setAuthCookies(res, tokens);
      req.cookies.accessToken = tokens.accessToken;   // so protect sees the new token on this request

      err = await runProtect(req, res);
      if (!err) return ok();
    }
  } catch (e) {
    if (e.statusCode !== 401) return next(e);         // real bugs still reach errorHandler
  }

  // 3. nothing worked → back to login
  clearAuthCookies(res);
  return res.redirect(303, "/login");
};

// the opposite: logged-in users shouldn't see /login again
export const guestOnly = async (req, res, next) => {
  const err = await runProtect(req, res);
  return err ? next() : res.redirect(303, "/dashboard");
};
