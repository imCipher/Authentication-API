import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import { xss } from "express-xss-sanitizer";
import passport from "passport";

import morganLogger from "./config/morgan.js";
import finalConfig from "./config/keys.js";
import { notFound, errorHandler } from "./middlewares/error.middleware.js";
import healthRoutes from "./routes/health.routes.js";

// Initialize Express App
const app = express();

// Middleware
app.use(helmet());

app.use(
  express.json({
    limit: "100kb", // Limit the JSON body Size to 100kb
  }),
);
app.use(express.urlencoded({ extended: true, limit: "100kb" }));
app.use(xss());
app.use(morganLogger);

app.use("/health", healthRoutes);

app.use(notFound);
app.use(errorHandler);

export default app;
