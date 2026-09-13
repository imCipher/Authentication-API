import request from "supertest";
import crypto from "crypto";

import app from "../../src/app.js";
import prisma from "../../src/config/db.js";
import finalConfig from "../../src/config/keys.js";
import tokenUtils from "../../src/utils/token.utils.js";
import hashUtils from "../../src/utils/hash.utils.js";
import redisService from "../../src/config/redis.js";

// Mock the Email utility so real SMTP calls are never dispatched
vi.mock("../../src/utils/email.utils.js", () => ({
  default: vi.fn().mockImplementation(function () {
    return {
      sendEmailConfirmation: vi.fn().mockResolvedValue(undefined),
      sendWelcomeEmail: vi.fn().mockResolvedValue(undefined),
      sendPasswordReset: vi.fn().mockResolvedValue(undefined),
    };
  }),
}));

describe("Admin Routes Integration - Management & Auditing (Phase 6)", () => {
  const createdUserIds = new Set();
  let originalEnv;

  // Helper to generate unique, schema-compliant user credentials
  const generateTestUser = (suffix = "") => {
    const randomPart = Math.random().toString(36).substring(2, 8);
    const timestamp = Date.now().toString().slice(-6);
    const cleanSuffix = suffix.replace(/[^a-z0-9]/gi, "").toLowerCase();
    const unique = `${timestamp}${randomPart}${cleanSuffix}`;
    const password = "StrongP@ssw0rd123!";

    return {
      fullName: "Integration Test User",
      username: `adm_${unique}`.substring(0, 30),
      email: `adm_${unique}@example.com`,
      password,
    };
  };

  // Helper to directly seed a test user in PostgreSQL and sign an access token
  const createTestUser = async (
    role = "USER",
    status = "ACTIVE",
    overrides = {},
  ) => {
    const userData = generateTestUser(role.toLowerCase());
    const passwordHash = await hashUtils.hashPassword(userData.password);

    const user = await prisma.user.create({
      data: {
        fullName: userData.fullName,
        username: userData.username,
        email: userData.email,
        passwordHash,
        role,
        status,
        emailVerified: true,
        ...overrides,
      },
    });

    createdUserIds.add(user.id);

    const token = tokenUtils.signAccessToken({ id: user.id, role: user.role });
    return { user, token, rawPassword: userData.password };
  };

  beforeAll(async () => {
    await redisService.connect();

    // Clean up any stale records from previously interrupted test runs
    await prisma.user.deleteMany({
      where: {
        OR: [
          { email: { startsWith: "adm_" } },
          { username: { startsWith: "adm_" } },
        ],
      },
    });
  });

  beforeEach(() => {
    vi.clearAllMocks();
    originalEnv = finalConfig.env;
  });

  afterEach(() => {
    finalConfig.env = originalEnv;
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    // Teardown: Purge all created data in foreign key dependency order
    if (createdUserIds.size > 0) {
      const ids = Array.from(createdUserIds);

      await prisma.loginHistory.deleteMany({ where: { userId: { in: ids } } });
      await prisma.refreshToken.deleteMany({ where: { userId: { in: ids } } });
      await prisma.emailVerification.deleteMany({
        where: { userId: { in: ids } },
      });
      await prisma.passwordReset.deleteMany({ where: { userId: { in: ids } } });
      await prisma.auditLog.deleteMany({ where: { userId: { in: ids } } });
      await prisma.user.deleteMany({ where: { id: { in: ids } } });
    }

    await redisService.disconnect();
    await prisma.$disconnect();
  });

  // =========================================================================
  // 1. ACCESS CONTROL GATEKEEPING
  // =========================================================================
  describe("1. Access Control Gatekeeping", () => {
    it("should reject unauthenticated requests with 401 Unauthorized when token is missing", async () => {
      const endpoints = [
        { method: "get", path: "/api/v1/admin/users" },
        { method: "get", path: `/api/v1/admin/users/${crypto.randomUUID()}` },
        { method: "get", path: "/api/v1/admin/audit-logs" },
        { method: "get", path: "/api/v1/admin/login-history" },
        { method: "post", path: "/api/v1/admin/maintenance/cleanup" },
      ];

      for (const { method, path } of endpoints) {
        const res = await request(app)[method](path);
        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
        expect(res.body.error.message).toContain("You are not logged in");
      }
    });

    it("should reject unauthenticated requests with 401 Unauthorized when token is malformed", async () => {
      const response = await request(app)
        .get("/api/v1/admin/users")
        .set("Authorization", "Bearer invalid-malformed-token");

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe("TOKEN_INVALID");
    });

    it("should reject standard users (role: USER) with 403 Forbidden across all admin endpoints", async () => {
      const standardUser = await createTestUser("USER", "ACTIVE");
      const dummyId = crypto.randomUUID();

      const routes = [
        { method: "get", path: "/api/v1/admin/users" },
        { method: "get", path: `/api/v1/admin/users/${dummyId}` },
        {
          method: "patch",
          path: `/api/v1/admin/users/${dummyId}`,
          body: { role: "ADMIN" },
        },
        { method: "post", path: `/api/v1/admin/users/${dummyId}/unlock` },
        { method: "post", path: `/api/v1/admin/users/${dummyId}/logout-all` },
        { method: "delete", path: `/api/v1/admin/users/${dummyId}` },
        { method: "get", path: "/api/v1/admin/audit-logs" },
        { method: "get", path: "/api/v1/admin/login-history" },
        { method: "post", path: "/api/v1/admin/maintenance/cleanup" },
      ];

      for (const route of routes) {
        const req = request(app)
          [route.method](route.path)
          .set("Authorization", `Bearer ${standardUser.token}`);

        if (route.body) req.send(route.body);

        const res = await req;
        expect(res.status).toBe(403);
        expect(res.body.success).toBe(false);
        expect(res.body.error.code).toBe("FORBIDDEN");
        expect(res.body.error.message).toContain("You do not have permission");
      }
    });
  });

  // =========================================================================
  // 2. USER MANAGEMENT: GET /api/v1/admin/users
  // =========================================================================
  describe("2. GET /api/v1/admin/users", () => {
    it("should return a paginated list of users with metadata (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .get("/api/v1/admin/users?page=1&limit=5")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.users).toBeInstanceOf(Array);
      expect(response.body.data.pagination).toBeDefined();
      expect(response.body.data.pagination.currentPage).toBe(1);
      expect(response.body.data.pagination.limit).toBe(5);

      // Verify projection security: sensitive fields must NEVER be returned
      const sampleUser = response.body.data.users[0];
      expect(sampleUser).not.toHaveProperty("passwordHash");
      expect(sampleUser).not.toHaveProperty("password");
      expect(sampleUser).toHaveProperty("id");
      expect(sampleUser).toHaveProperty("email");
      expect(sampleUser).toHaveProperty("role");
      expect(sampleUser).toHaveProperty("status");
    });

    it("should filter users by role and status correctly", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const suspendedUser = await createTestUser("USER", "SUSPENDED");

      const response = await request(app)
        .get("/api/v1/admin/users?role=USER&status=SUSPENDED")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      const { users } = response.body.data;
      expect(users.length).toBeGreaterThanOrEqual(1);

      users.forEach(u => {
        expect(u.role).toBe("USER");
        expect(u.status).toBe("SUSPENDED");
      });

      const found = users.some(u => u.id === suspendedUser.user.id);
      expect(found).toBe(true);
    });

    it("should search users by email, username, or full name (case-insensitive)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const uniqueNameUser = await createTestUser("USER", "ACTIVE", {
        fullName: "Sherlock Holmes Detective",
      });

      const response = await request(app)
        .get("/api/v1/admin/users?search=sherlock")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      const { users } = response.body.data;
      expect(users.length).toBeGreaterThanOrEqual(1);
      expect(users.some(u => u.id === uniqueNameUser.user.id)).toBe(true);
    });

    it("should sort users according to sortBy and sortOrder parameters", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .get("/api/v1/admin/users?sortBy=createdAt&sortOrder=asc&limit=10")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      const { users } = response.body.data;
      if (users.length >= 2) {
        const time1 = new Date(users[0].createdAt).getTime();
        const time2 = new Date(users[1].createdAt).getTime();
        expect(time1).toBeLessThanOrEqual(time2);
      }
    });

    it("should reject invalid query parameters with 400 Bad Request", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .get("/api/v1/admin/users?page=0&limit=999&role=SUPERHERO")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
    });
  });

  // =========================================================================
  // 3. USER INSPECTION: GET /api/v1/admin/users/:id
  // =========================================================================
  describe("3. GET /api/v1/admin/users/:id", () => {
    it("should retrieve full details of a specific user by UUID (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const targetUser = await createTestUser("USER", "ACTIVE");

      const response = await request(app)
        .get(`/api/v1/admin/users/${targetUser.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.user.id).toBe(targetUser.user.id);
      expect(response.body.data.user.email).toBe(targetUser.user.email);
      expect(response.body.data.user).toHaveProperty("failedAttempts");
      expect(response.body.data.user).toHaveProperty("lockedUntil");
      expect(response.body.data.user).toHaveProperty("sessionsRevokedAt");
      expect(response.body.data.user).not.toHaveProperty("passwordHash");
    });

    it("should return 404 Not Found when user UUID does not exist", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const nonExistentId = crypto.randomUUID();

      const response = await request(app)
        .get(`/api/v1/admin/users/${nonExistentId}`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(404);
      expect(response.body.error.message).toBe("User not found.");
    });

    it("should return 400 Bad Request when user ID parameter is not a valid UUID", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .get("/api/v1/admin/users/not-a-valid-uuid")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
    });
  });

  // =========================================================================
  // 4. USER MODIFICATION & INVARIANTS: PATCH /api/v1/admin/users/:id
  // =========================================================================
  describe("4. PATCH /api/v1/admin/users/:id", () => {
    it("should update a user's role, invalidate their sessions, and create an audit log (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const targetUser = await createTestUser("USER", "ACTIVE");

      // Seed an active refresh token for target user
      await prisma.refreshToken.create({
        data: {
          userId: targetUser.user.id,
          tokenHash: "fake_token_hash_patch_role",
          expiresAt: new Date(Date.now() + 1000 * 60 * 60),
        },
      });

      const response = await request(app)
        .patch(`/api/v1/admin/users/${targetUser.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`)
        .send({ role: "ADMIN" });

      expect(response.status).toBe(200);
      expect(response.body.data.user.role).toBe("ADMIN");

      // Invariant: sessionsRevokedAt must be updated and refresh tokens revoked
      const updatedDbUser = await prisma.user.findUnique({
        where: { id: targetUser.user.id },
      });
      expect(updatedDbUser.sessionsRevokedAt).not.toBeNull();

      const activeTokens = await prisma.refreshToken.findMany({
        where: { userId: targetUser.user.id, revokedAt: null },
      });
      expect(activeTokens).toHaveLength(0);

      // Audit Log Verification
      const audit = await prisma.auditLog.findFirst({
        where: {
          action: "ROLE_CHANGE",
          details: { path: ["targetUserId"], equals: targetUser.user.id },
        },
      });
      expect(audit).not.toBeNull();
      expect(audit.userId).toBe(admin.user.id);
    });

    it("should prevent admin self-demotion with 403 Forbidden", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .patch(`/api/v1/admin/users/${admin.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`)
        .send({ role: "USER" });

      expect(response.status).toBe(403);
      expect(response.body.error.message).toBe(
        "Administrators cannot change their own role.",
      );
    });

    it("should prevent admin self-deactivation with 403 Forbidden", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .patch(`/api/v1/admin/users/${admin.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`)
        .send({ status: "DEACTIVATED" });

      expect(response.status).toBe(403);
      expect(response.body.error.message).toBe(
        "Administrators cannot deactivate their own accounts.",
      );
    });

    it("should reject demoting the last active administrator with 400 Bad Request", async () => {
      // Suspend all other active admins so only soleAdmin will be active
      await prisma.user.updateMany({
        where: { role: "ADMIN", status: "ACTIVE" },
        data: { status: "SUSPENDED" },
      });

      // soleAdmin is the ONE AND ONLY active admin in the system
      const soleAdmin = await createTestUser("ADMIN", "ACTIVE");

      // callingAdmin has role: "ADMIN" but status: "SUSPENDED"
      // They pass JWT verification and RBAC, but do not count toward activeAdminCount
      const callingAdmin = await createTestUser("ADMIN", "SUSPENDED");

      const response = await request(app)
        .patch(`/api/v1/admin/users/${soleAdmin.user.id}`)
        .set("Authorization", `Bearer ${callingAdmin.token}`)
        .send({ role: "USER" });

      expect(response.status).toBe(400);
      expect(response.body.error.message).toContain(
        "Cannot demote or deactivate the last active administrator.",
      );
    });

    it("should return 400 Bad Request if neither role nor status is provided", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const targetUser = await createTestUser("USER", "ACTIVE");

      const response = await request(app)
        .patch(`/api/v1/admin/users/${targetUser.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`)
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
    });

    it("should update a user's status to SUSPENDED and record a STATUS_CHANGE audit log (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const targetUser = await createTestUser("USER", "ACTIVE");

      const response = await request(app)
        .patch(`/api/v1/admin/users/${targetUser.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`)
        .send({ status: "SUSPENDED" });

      expect(response.status).toBe(200);
      expect(response.body.data.user.status).toBe("SUSPENDED");

      // Assert STATUS_CHANGE audit log
      const audit = await prisma.auditLog.findFirst({
        where: {
          action: "STATUS_CHANGE",
          details: { path: ["targetUserId"], equals: targetUser.user.id },
        },
      });
      expect(audit).not.toBeNull();
      expect(audit.details.newStatus).toBe("SUSPENDED");
    });

    it("should return 404 Not Found when updating a non-existent user", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const nonExistentId = crypto.randomUUID();

      const response = await request(app)
        .patch(`/api/v1/admin/users/${nonExistentId}`)
        .set("Authorization", `Bearer ${admin.token}`)
        .send({ role: "ADMIN" });

      expect(response.status).toBe(404);
      expect(response.body.error.message).toBe("User not found.");
    });
  });

  // =========================================================================
  // 5. ACCOUNT UNLOCKING: POST /api/v1/admin/users/:id/unlock
  // =========================================================================
  describe("5. POST /api/v1/admin/users/:id/unlock", () => {
    it("should successfully unlock a locked account, reset failedAttempts, and log audit event (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const lockedUser = await createTestUser("USER", "ACTIVE", {
        failedAttempts: 5,
        lockedUntil: new Date(Date.now() + 15 * 60 * 1000), // Locked for 15 mins
      });

      const response = await request(app)
        .post(`/api/v1/admin/users/${lockedUser.user.id}/unlock`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe("User account unlocked successfully.");
      expect(response.body.data.user.failedAttempts).toBe(0);
      expect(response.body.data.user.lockedUntil).toBeNull();

      // Audit Log Verification
      const audit = await prisma.auditLog.findFirst({
        where: {
          action: "ACCOUNT_UNLOCKED",
          details: { path: ["targetUserId"], equals: lockedUser.user.id },
        },
      });
      expect(audit).not.toBeNull();
    });

    it("should return 400 Bad Request when attempting to unlock a user that is not locked", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const unlockedUser = await createTestUser("USER", "ACTIVE", {
        failedAttempts: 0,
        lockedUntil: null,
      });

      const response = await request(app)
        .post(`/api/v1/admin/users/${unlockedUser.user.id}/unlock`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBe(
        "User account is not currently locked.",
      );
    });

    it("should return 400 Bad Request when attempting to unlock an account whose status is not ACTIVE", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const suspendedUser = await createTestUser("USER", "SUSPENDED", {
        failedAttempts: 5,
        lockedUntil: new Date(Date.now() + 15 * 60 * 1000),
      });

      const response = await request(app)
        .post(`/api/v1/admin/users/${suspendedUser.user.id}/unlock`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(400);
      expect(response.body.error.message).toContain(
        "Cannot unlock an account with status 'SUSPENDED'",
      );
    });

    it("should return 404 Not Found when unlocking a non-existent user", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const nonExistentId = crypto.randomUUID();

      const response = await request(app)
        .post(`/api/v1/admin/users/${nonExistentId}/unlock`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(404);
      expect(response.body.error.message).toBe("User not found.");
    });
  });

  // =========================================================================
  // 6. GLOBAL LOGOUT: POST /api/v1/admin/users/:id/logout-all
  // =========================================================================
  describe("6. POST /api/v1/admin/users/:id/logout-all", () => {
    it("should invalidate all sessions for a user and cause existing access tokens to fail protect middleware (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const targetUser = await createTestUser("USER", "ACTIVE");

      // Verify target user can currently access GET /api/v1/auth/me
      const meBefore = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", `Bearer ${targetUser.token}`);
      expect(meBefore.status).toBe(200);

      // Admin executes administrative logout-all
      const response = await request(app)
        .post(`/api/v1/admin/users/${targetUser.user.id}/logout-all`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toContain(
        "logged out from all devices successfully",
      );

      // Target user's previous access token must now immediately fail authentication
      const meAfter = await request(app)
        .get("/api/v1/auth/me")
        .set("Authorization", `Bearer ${targetUser.token}`);

      expect(meAfter.status).toBe(401);
      expect(meAfter.body.error.message).toContain(
        "You have logged out from all sessions",
      );

      // Audit Log Verification
      const audit = await prisma.auditLog.findFirst({
        where: {
          action: "LOGOUT_ALL",
          details: { path: ["targetUserId"], equals: targetUser.user.id },
        },
      });
      expect(audit).not.toBeNull();
    });

    it("should return 404 Not Found when logging out a non-existent user", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const nonExistentId = crypto.randomUUID();

      const response = await request(app)
        .post(`/api/v1/admin/users/${nonExistentId}/logout-all`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(404);
      expect(response.body.error.message).toBe("User not found.");
    });
  });

  // =========================================================================
  // 7. USER DELETION: DELETE /api/v1/admin/users/:id
  // =========================================================================
  describe("7. DELETE /api/v1/admin/users/:id", () => {
    it("should permanently delete a user and create an ACCOUNT_DELETED audit log (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const victim = await createTestUser("USER", "ACTIVE");

      const response = await request(app)
        .delete(`/api/v1/admin/users/${victim.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toContain(
        `User ${victim.user.username} deleted successfully`,
      );

      // Verify deletion from DB
      const dbCheck = await prisma.user.findUnique({
        where: { id: victim.user.id },
      });
      expect(dbCheck).toBeNull();

      // Audit Log Verification: Audit log record remains preserved
      const audit = await prisma.auditLog.findFirst({
        where: {
          action: "ACCOUNT_DELETED",
          details: { path: ["targetUserId"], equals: victim.user.id },
        },
      });
      expect(audit).not.toBeNull();
    });

    it("should prevent admin self-deletion with 403 Forbidden", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .delete(`/api/v1/admin/users/${admin.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(403);
      expect(response.body.error.message).toBe(
        "Admin cannot delete their own account.",
      );
    });

    it("should reject deleting the last active admin with 400 Bad Request", async () => {
      // Suspend all other active admins so only soleAdmin will be active
      await prisma.user.updateMany({
        where: { role: "ADMIN", status: "ACTIVE" },
        data: { status: "SUSPENDED" },
      });

      // soleAdmin is the ONE AND ONLY active admin in the system
      const soleAdmin = await createTestUser("ADMIN", "ACTIVE");

      // callingAdmin has role: "ADMIN" but status: "SUSPENDED"
      const callingAdmin = await createTestUser("ADMIN", "SUSPENDED");

      const response = await request(app)
        .delete(`/api/v1/admin/users/${soleAdmin.user.id}`)
        .set("Authorization", `Bearer ${callingAdmin.token}`);

      expect(response.status).toBe(400);
      expect(response.body.error.message).toBe(
        "Cannot delete the last active admin.",
      );
    });

    it("should return 404 Not Found when deleting a non-existent user", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const nonExistentId = crypto.randomUUID();

      const response = await request(app)
        .delete(`/api/v1/admin/users/${nonExistentId}`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(404);
      expect(response.body.error.message).toBe("User not found.");
    });
  });

  // =========================================================================
  // 8. AUDIT LOGS: GET /api/v1/admin/audit-logs
  // =========================================================================
  describe("8. GET /api/v1/admin/audit-logs", () => {
    it("should fetch paginated audit logs with actor information (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      // Seed an audit log entry
      await prisma.auditLog.create({
        data: {
          userId: admin.user.id,
          action: "ROLE_CHANGE",
          resource: "USER",
          details: { note: "Promoted to Admin" },
        },
      });

      const response = await request(app)
        .get("/api/v1/admin/audit-logs?page=1&limit=5")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      expect(response.body.data.auditLogs).toBeInstanceOf(Array);
      expect(response.body.data.pagination).toBeDefined();

      const log = response.body.data.auditLogs[0];
      expect(log).toHaveProperty("id");
      expect(log).toHaveProperty("action");
      expect(log).toHaveProperty("resource");
      if (log.user) {
        expect(log.user).toHaveProperty("username");
        expect(log.user).toHaveProperty("email");
      }
    });

    it("should filter audit logs by action type", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .get("/api/v1/admin/audit-logs?action=ROLE_CHANGE")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      response.body.data.auditLogs.forEach(log => {
        expect(log.action).toBe("ROLE_CHANGE");
      });
    });

    it("should reject invalid audit action filter with 400 Bad Request", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .get("/api/v1/admin/audit-logs?action=INVALID_NON_EXISTENT_ACTION")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
    });
  });

  // =========================================================================
  // 9. LOGIN HISTORY: GET /api/v1/admin/login-history
  // =========================================================================
  describe("9. GET /api/v1/admin/login-history", () => {
    it("should fetch paginated login history with user filtering (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const targetUser = await createTestUser("USER", "ACTIVE");

      // Seed a login history entry
      await prisma.loginHistory.create({
        data: {
          userId: targetUser.user.id,
          ipAddress: "192.168.1.50",
          userAgent: "Vitest Agent",
          success: true,
        },
      });

      const response = await request(app)
        .get(`/api/v1/admin/login-history?userId=${targetUser.user.id}`)
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(200);
      expect(response.body.data.loginHistory).toBeInstanceOf(Array);
      expect(response.body.data.loginHistory.length).toBeGreaterThanOrEqual(1);

      const item = response.body.data.loginHistory[0];
      expect(item.userId).toBe(targetUser.user.id);
      expect(item).toHaveProperty("ipAddress");
      expect(item).toHaveProperty("success");
      expect(item.user.username).toBe(targetUser.user.username);
    });

    it("should reject invalid userId UUID format with 400 Bad Request", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .get("/api/v1/admin/login-history?userId=12345-not-a-uuid")
        .set("Authorization", `Bearer ${admin.token}`);

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
    });
  });

  // =========================================================================
  // 10. DATABASE MAINTENANCE CLEANUP: POST /api/v1/admin/maintenance/cleanup
  // =========================================================================
  describe("10. POST /api/v1/admin/maintenance/cleanup", () => {
    it("should execute database cleanup and return deletion summary (200 OK)", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");
      const dummyUser = await createTestUser("USER", "ACTIVE");

      // Seed an expired refresh token
      await prisma.refreshToken.create({
        data: {
          userId: dummyUser.user.id,
          tokenHash: "expired_token_for_cleanup",
          expiresAt: new Date(Date.now() - 1000 * 60 * 60), // expired 1 hour ago
        },
      });

      const response = await request(app)
        .post("/api/v1/admin/maintenance/cleanup")
        .set("Authorization", `Bearer ${admin.token}`)
        .send({ retentionDays: 7, cleanLoginHistory: false });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty("summary");
      expect(response.body.data).toHaveProperty("details");
      expect(response.body.data.summary.totalDeleted).toBeGreaterThanOrEqual(1);
      expect(response.body.data.details.refreshTokens).toBeGreaterThanOrEqual(
        1,
      );
    });

    it("should reject invalid retentionDays values exceeding 365 with 400 Bad Request", async () => {
      const admin = await createTestUser("ADMIN", "ACTIVE");

      const response = await request(app)
        .post("/api/v1/admin/maintenance/cleanup")
        .set("Authorization", `Bearer ${admin.token}`)
        .send({ retentionDays: 500 });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
    });

    it("should enforce adminHeavyMaintenanceRateLimiter in production environment (429 Too Many Requests)", async () => {
      // Temporarily enable production mode to activate rate limiters
      finalConfig.env = "production";

      const admin = await createTestUser("ADMIN", "ACTIVE");
      const testIp = `203.0.113.${Math.floor(1 + Math.random() * 250)}`;

      // The limiter allows 5 requests per 15 min window
      for (let attempt = 1; attempt <= 5; attempt++) {
        const res = await request(app)
          .post("/api/v1/admin/maintenance/cleanup")
          .set("Authorization", `Bearer ${admin.token}`)
          .set("X-Forwarded-For", testIp)
          .send({ retentionDays: 7 });
        expect(res.status).toBe(200);
      }

      // Request 6 from the same IP must be blocked
      const blockedRes = await request(app)
        .post("/api/v1/admin/maintenance/cleanup")
        .set("Authorization", `Bearer ${admin.token}`)
        .set("X-Forwarded-For", testIp)
        .send({ retentionDays: 7 });

      expect(blockedRes.status).toBe(429);
      expect(blockedRes.body.success).toBe(false);
      expect(blockedRes.body.error.message).toContain(
        "Too many admin heavy maintenance requests from this IP, please try again later.",
      );
    });
  });
});
