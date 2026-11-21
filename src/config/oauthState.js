import crypto from "node:crypto";
import finalConfig from "./keys.js";

/**
 * OAuth `state` store backed by a short-lived httpOnly cookie.
 *
 * Why: the `state` parameter stops "login CSRF" — an attacker tricking your
 * browser into finishing THEIR Google login, so you end up silently signed in
 * to the attacker's account. passport-oauth2 normally keeps `state` in a server
 * session, but this app has no sessions, so we keep it in a cookie instead.
 *
 * Flow:
 *   1. GET /auth/google           → store(): random state → cookie + sent to Google
 *   2. Google → /auth/google/callback?state=… → verify(): must match the cookie
 *
 * SameSite=Lax is required (not Strict): the callback is a top-level redirect
 * FROM google.com, and Lax still sends cookies on that kind of navigation.
 */

const COOKIE_NAME = "oauth_state";
const cookieOptions = {
  httpOnly: true,
  sameSite: "lax",
  secure: finalConfig.env === "production",
  path: "/auth/google", // only sent to the OAuth routes, nowhere else
};

const sameString = (a, b) => {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
};

const cookieStateStore = {
  // passport-oauth2 picks the signature by arity: (req, meta, callback)
  store(req, meta, callback) {
    const state = crypto.randomBytes(24).toString("hex");
    req.res.cookie(COOKIE_NAME, state, { ...cookieOptions, maxAge: 10 * 60 * 1000 }); // 10 minutes
    callback(null, state);
  },

  // (req, providedState, callback)
  verify(req, providedState, callback) {
    const expected = req.cookies?.[COOKIE_NAME];
    req.res.clearCookie(COOKIE_NAME, cookieOptions); // single use, success or not

    if (!expected || !providedState || !sameString(expected, providedState)) {
      return callback(null, false, { message: "Invalid or expired OAuth state." });
    }
    return callback(null, true);
  },
};

export default cookieStateStore;
