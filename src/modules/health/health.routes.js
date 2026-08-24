import { Router } from "express";
import prisma from "../../config/db.js";
import finalConfig from "../../config/keys.js";

// Initiate Express Router
const router = Router();

const startedAt = new Date().toLocaleString("en-US", {
  dateStyle: "full",
  timeStyle: "medium",
});

/**
 * @route GET /health
 * @desc Health check endpoint to verify that the API is running and responsive.
 * @access Public
 */
router.get("/", (req, res) => {
  res.status(200).json({
    status: "ok",
    message: "Welcome to Umzzy Test API",
    environment: finalConfig.env,
    uptimeInSeconds: process.uptime(),
    startedAt,
    memoryUsageMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
    timestamp: new Date().toLocaleString("en-Us", {
      dateStyle: "full",
      timeStyle: "medium",
    }),
  });
});

/**
 * @route GET /health/ready
 * @desc Readiness check endpoint to verify that the API can connect to the database.
 * @access Public
 * @note This endpoint is useful for container orchestration platforms like Kubernetes
 *       to determine if the application is ready to receive traffic.
 */
router.get("/ready", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.status(200).json({
      status: "ok",
      database: "connected",
      timestamp: new Date().toISOString(),
    });
  } catch {
    res.status(503).json({
      status: "error",
      database: "disconnected",
      timestamp: new Date().toISOString(),
    });
  }
});

export default router;
