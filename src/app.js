import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import { xss } from "express-xss-sanitizer";
import passport from "passport";
import cors from "cors";

import morganLogger from "./config/morgan.js";
import finalConfig from "./config/keys.js";
import { notFound, errorHandler } from "./middlewares/error.middleware.js";
import { generalRateLimiter } from "./middlewares/rateLimiter.middleware.js";
import healthRoutes from "./modules/health/health.routes.js";

// Initialize Express App
const app = express();

// Trust proxy headers (e.g., X-Forwarded-For) when behind a reverse proxy
app.set("trust proxy", 1);

// Middleware
app.use(cors(finalConfig.cors)); // Cors Configuration
app.use(helmet()); // Secure HTTP headers
app.use(
  express.json({
    limit: "100kb", // Limit the JSON body Size to 100kb
  }),
);
app.use(express.urlencoded({ extended: true, limit: "100kb" })); // Limit the URL-encoded body Size to 100kb

// Rate Limiting
app.use(generalRateLimiter);

app.use(xss()); // Sanitize user input to prevent XSS attack
app.use(morganLogger); // Use custom morgan logger for HTTP request logging

// Initialize Passport for authentication
app.use(passport.initialize());

// Routes
app.use("/health", healthRoutes);

app.use(notFound);
app.use(errorHandler);

export default app;
