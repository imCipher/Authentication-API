import morgan from "morgan";
import logger from "./logger.js";

/**
 * Remove secrets from a URL before it is logged.
 *   /reset-password/abc123            → /reset-password/[redacted]
 *   /auth/google/callback?code=x&state=y → …?code=[redacted]&state=[redacted]
 *   /verify-email?email=a@b.com       → /verify-email?email=[redacted]
 */
export const redactUrl = (url = "") =>
  url
    .replace(/(\/reset-password\/)[^/?#]+/gi, "$1[redacted]")
    .replace(/([?&](?:token|code|state|email)=)[^&#]*/gi, "$1[redacted]");

// a new ":safe-url" token that works like ":url", but redacted
morgan.token("safe-url", req => redactUrl(req.originalUrl || req.url));

const format =
  ":remote-addr :method  :safe-url  :status  :res[content-length] - :response-time ms";

// Create Morgan Middleware using winston for logging
const morganLogger = morgan(format, { stream: logger.stream });

export default morganLogger;
