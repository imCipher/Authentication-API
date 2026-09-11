import { vi } from "vitest";

// Populate minimum required environment variables for testing
process.env.NODE_ENV = "testing";
process.env.PORT = "5001";
process.env.API_VERSION = "v1";
process.env.JWT_ACCESS_SECRET = "61cf3833cef31f401e3b0cc7c8d3a3d1";
process.env.JWT_REFRESH_SECRET = "4bf82fc466d68de51a47a0b357f154cd";
process.env.JWT_ACCESS_EXPIRES_IN = "15m";
process.env.JWT_REFRESH_EXPIRES_IN = "7";
process.env.JWT_REFRESH_GRACE_WINDOW_SECONDS = "30";
process.env.EMAIL_USER = "test@example.com";
process.env.EMAIL_PASS = "testpassword";

// Allow DATABASE_URL from .env or fallback to local Auth_db
process.env.DATABASE_URL =
  process.env.DATABASE_URL ||
  "postgresql://postgres:admin@localhost:5432/Auth_db?schema=public";

// Suppress noisy logs during test runs
vi.mock("../src/config/logger.js", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));
