import request from "supertest";
import app from "../../../src/app.js";

vi.mock("../../src/config/db.js", () => ({
  default: {
    $queryRaw: vi.fn().mockResolvedValue([{ 1: 1 }]),
  },
}));

vi.mock("../../src/config/redis.js", () => ({
  default: {
    exists: vi.fn().mockResolvedValue(true),
    incrWithExpire: vi.fn().mockResolvedValue(1),
  },
}));

describe("Health Check Route", () => {
  it("Get /api/v1/health should return 200 and system health status", async () => {
    const response = await request(app).get("/api/v1/health");

    expect(response.status).toBe(200);
    expect(response.body.status).toBe("ok");
    expect(response.body.message).toBe("Welcome to Umzzy Test API");
    expect(response.body).toHaveProperty("uptimeInSeconds");
    expect(response.body).toHaveProperty("memoryUsageMB");
  });

  it("Get /api/v1/health/ready should return 200 when database is connected", async () => {
    const response = await request(app).get("/api/v1/health/ready");

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        status: "ok",
        database: "connected",
      }),
    );
  });
});
