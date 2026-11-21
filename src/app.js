import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import passport from "passport";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import path from "node:path";
import cookieParser from "cookie-parser";

import webRoutes from "./modules/web/web.routes.js";
import morganLogger from "./config/morgan.js";
import finalConfig from "./config/keys.js";
import swaggerSpec from "./config/swagger.js";
import { notFound, errorHandler } from "./middlewares/error.middleware.js";
import { generalRateLimiter } from "./middlewares/rateLimiter.middleware.js";
import healthRoutes from "./modules/health/health.routes.js";
import authRoutes from "./modules/auth/auth.routes.js";
import adminRoutes from "./modules/admin/admin.routes.js";

import { isGoogleConfigured } from "./config/passport.js"; // Registers the Passport strategies

// Initialize Express App
const app = express();

// Trust proxy headers (e.g., X-Forwarded-For) when behind a reverse proxy
app.set("trust proxy", 1);

// Middleware
app.use(cors(finalConfig.cors)); // Cors Configuration
app.use(helmet()); // Secure HTTP headers

// Views engine setup
app.set("view engine", "ejs");
app.locals.formatDate = d =>
  d ?
    new Intl.DateTimeFormat("en-GB", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(d))
  : "—";

app.locals.googleEnabled = isGoogleConfigured; // templates only show the Google button when it can work

app.set("views", path.join(import.meta.dirname, "views")); // -> src/views
app.use(express.static(path.join(import.meta.dirname, "..", "public"))); // Serve static files from the public directory

app.use(
  express.json({
    limit: "100kb", // Limit the JSON body Size to 100kb
  }),
);
app.use(express.urlencoded({ extended: true, limit: "100kb" })); // Limit the URL-encoded body Size to 100kb
app.use(cookieParser()); // Parse cookies from incoming requests

// Rate Limiting
app.use(generalRateLimiter);

app.use(morganLogger); // Use custom morgan logger for HTTP request logging

// Initialize Passport for authentication
app.use(passport.initialize());

// API Versioning
const apiPrefix = `/api/${finalConfig.apiVersion}`;

// Routes
app.use(`${apiPrefix}/health`, healthRoutes);
app.use(`${apiPrefix}/auth`, authRoutes);
app.use(`${apiPrefix}/admin`, adminRoutes);
if (finalConfig.env !== "production") {
  app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
}

app.use("/", webRoutes);

app.use(notFound);
app.use(errorHandler);

export default app;
