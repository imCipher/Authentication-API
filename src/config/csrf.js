import crypto from "node:crypto";
import { doubleCsrf } from "csrf-csrf";
import finalConfig from "./keys.js";

const isProd = finalConfig.env === "production";

// Before login there is no session, so give every visitor an anonymous id cookie.
// csrf-csrf ties each token to this id.
export const ensureSessionId = (req, res, next) => {
  if (!req.cookies.sid) {
    const sid = crypto.randomUUID();
    res.cookie("sid", sid, { httpOnly: true, sameSite: "lax", secure: isProd });
    req.cookies.sid = sid; // make it available to this same request too
  }
  next();
};

export const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => finalConfig.csrf.secret,
  getSessionIdentifier: req => req.cookies.sid,
  // "__Host-" cookies are rejected over plain http, so only use that prefix in production
  cookieName: isProd ? "__Host-csrf" : "csrf",
  cookieOptions: { sameSite: "lax", httpOnly: true, secure: isProd, path: "/" },
  // forms send the token as a hidden field, not a header
  getCsrfTokenFromRequest: req => req.body?._csrf,
});

// put the token in res.locals so EVERY template can read it as `csrfToken`
export const exposeCsrfToken = (req, res, next) => {
  res.locals.csrfToken = generateCsrfToken(req, res);
  next();
};
