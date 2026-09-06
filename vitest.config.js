import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Make describe, it, expect, vi globally available (like Jest)
    globals: true,
    // Node.js environment
    environment: "node",
    // Test match patterns
    include: ["tests/**/*.test.js"],
    // Global setup file for environment variables and mocks
    setupFiles: ["./tests/setup.js"],
    // Run test files sequentially to avoid database/redis collisions
    fileParallelism: false,
    // Coverage configuration
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include: ["src/**/*.js"],
      exclude: [
        "/server.js",
        "/src/config/swagger.js",
        "/src/config/morgan.js",
      ],
    },
  },
});
