import request from "supertest";
import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  afterAll,
  vi,
} from "vitest";

import app from "../../src/app.js";
import prisma from "../../src/config/db.js";
import finalConfig from "../../src/config/keys.js";
import tokenUtils from "../../src/utils/token.utils.js";
import Email from "../../src/utils/email.utils.js";

// Mock the Email utility so real SMTP network calls are never sent
vi.mock("../../src/utils/email.utils.js", () => {
  return {
    default: vi.fn().mockImplementation(() => ({
      sendEmailConfirmation: vi.fn().mockResolvedValue(undefined),
      sendWelcomeEmail: vi.fn().mockResolvedValue(undefined),
      sendPasswordResetEmail: vi.fn().mockResolvedValue(undefined),
    })),
  };
});

describe("Auth Routes Integration - Registration & Verification Lifecycle", () => {
  const testUserIds = new Set();
  let originalEnv;

  // Helper function to generate unique credentials for test isolation
  const generateTestUser = (suffix = "") => {
    const uniqueId = `${Date.now()}_${Math.random().toString(36).substring(2, 7)}${suffix}`;
    const password = "StrongP@ssw0rd123!";
    return {
      fullName: `Integration User ${uniqueId}`,
      username: `user_${uniqueId}`.substring(0, 30), // Database limit max 30 chars
      email: `test_auth_${uniqueId}@example.com`,
      password,
      confirmPassword: password,
    };
  };

  beforeEach(() => {
    vi.clearAllMocks();
    originalEnv = finalConfig.env;
  });

  afterEach(async () => {
    // Restore environment if modified during rate-limiting tests
    finalConfig.env = originalEnv;
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    // Teardown: Clean up all database records created during this test suite
    if (testUserIds.size > 0) {
      const ids = Array.from(testUserIds);
      await prisma.auditLog.deleteMany({
        where: { userId: { in: ids } },
      });
      await prisma.emailVerification.deleteMany({
        where: { userId: { in: ids } },
      });
      await prisma.user.deleteMany({
        where: { id: { in: ids } },
      });
    }

    // Disconnect Prisma client to release connection pool handles
    await prisma.$disconnect();
  });

  // =========================================================================
  // 1. POST /api/v1/auth/register
  // =========================================================================
  describe("POST /api/v1/auth/register", () => {
    it("should successfully register a new user with 201 Created, hash password, and create an email verification record", async () => {
      const userData = generateTestUser();
      const mockToken = "654321";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(mockToken);

      const response = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);

      // 1. Assert HTTP Response
      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe(
        "Registration successful. Please check your email to verify your account.",
      );
      expect(response.body.data.user).toBeDefined();

      const createdUser = response.body.data.user;
      testUserIds.add(createdUser.id);

      expect(createdUser.email).toBe(userData.email);
      expect(createdUser.username).toBe(userData.username);
      expect(createdUser.fullName).toBe(userData.fullName);
      expect(createdUser.role).toBe("USER");
      expect(createdUser.emailVerified).toBe(false);

      // Security Check: Password hash must NEVER be exposed in the response
      expect(createdUser.passwordHash).toBeUndefined();
      expect(createdUser.password).toBeUndefined();

      // 2. Assert Database State
      const dbUser = await prisma.user.findUnique({
        where: { id: createdUser.id },
      });
      expect(dbUser).not.toBeNull();
      expect(dbUser.passwordHash).toBeDefined();
      expect(dbUser.passwordHash).not.toBe(userData.password);

      // 3. Assert EmailVerification Record Persistence
      const expectedTokenHash = tokenUtils.hashToken(mockToken);
      const dbVerification = await prisma.emailVerification.findFirst({
        where: { userId: createdUser.id },
      });
      expect(dbVerification).not.toBeNull();
      expect(dbVerification.tokenHash).toBe(expectedTokenHash);
      expect(dbVerification.usedAt).toBeNull();
      expect(new Date(dbVerification.expiresAt).getTime()).toBeGreaterThan(
        Date.now(),
      );

      // 4. Assert Asynchronous Confirmation Email Dispatched
      expect(Email).toHaveBeenCalledTimes(1);
    });

    it("should reject registration with 409 Conflict when username is already taken", async () => {
      const existingUser = generateTestUser("_dup_user");

      // Seed first user
      const firstRes = await request(app)
        .post("/api/v1/auth/register")
        .send(existingUser);
      expect(firstRes.status).toBe(201);
      testUserIds.add(firstRes.body.data.user.id);

      // Attempt second registration with same username but different email
      const conflictingPayload = {
        ...generateTestUser("_different_email"),
        username: existingUser.username,
      };

      const response = await request(app)
        .post("/api/v1/auth/register")
        .send(conflictingPayload);

      expect(response.status).toBe(409);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe("CONFLICT");
      expect(response.body.error.message).toBe("Username is already taken");
    });

    it("should reject registration with 409 Conflict when email is already registered", async () => {
      const existingUser = generateTestUser("_dup_email");

      // Seed first user
      const firstRes = await request(app)
        .post("/api/v1/auth/register")
        .send(existingUser);
      expect(firstRes.status).toBe(201);
      testUserIds.add(firstRes.body.data.user.id);

      // Attempt second registration with same email but different username
      const conflictingPayload = {
        ...generateTestUser("_different_user"),
        email: existingUser.email,
      };

      const response = await request(app)
        .post("/api/v1/auth/register")
        .send(conflictingPayload);

      expect(response.status).toBe(409);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe("CONFLICT");
      expect(response.body.error.message).toBe("Email is already registered");
    });

    it("should reject registration with 400 Bad Request on validation schema failures", async () => {
      const invalidPayload = {
        fullName: "J", // Too short (< 2 characters)
        username: "admin", // Reserved username
        email: "not-an-email", // Malformed email
        password: "weak", // Fails complexity requirements
        confirmPassword: "different", // Password mismatch
      };

      const response = await request(app)
        .post("/api/v1/auth/register")
        .send(invalidPayload);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
      expect(response.body.error.errors).toBeInstanceOf(Array);
      expect(response.body.error.errors.length).toBeGreaterThanOrEqual(4);
    });
  });

  // =========================================================================
  // 2. POST /api/v1/auth/verify-email
  // =========================================================================
  describe("POST /api/v1/auth/verify-email", () => {
    it("should successfully verify email with 200 OK, update user record, and mark token as used", async () => {
      const userData = generateTestUser("_verify_ok");
      const validToken = "112233";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(validToken);

      // Register the user first
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      const userId = regRes.body.data.user.id;
      testUserIds.add(userId);

      // Call verification endpoint
      const response = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token: validToken });

      // 1. Assert HTTP Response
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe("Email verified successfully.");

      // 2. Assert User is now verified in DB
      const updatedUser = await prisma.user.findUnique({
        where: { id: userId },
      });
      expect(updatedUser.emailVerified).toBe(true);

      // 3. Assert Verification record has usedAt populated
      const verificationRecord = await prisma.emailVerification.findFirst({
        where: { userId },
      });
      expect(verificationRecord.usedAt).not.toBeNull();

      // 4. Assert AuditLog entry was created
      const auditLog = await prisma.auditLog.findFirst({
        where: { userId, action: "EMAIL_VERIFIED" },
      });
      expect(auditLog).not.toBeNull();
      expect(auditLog.action).toBe("EMAIL_VERIFIED");
    });

    it("should reject with 400 Bad Request when an invalid token code is provided", async () => {
      const response = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token: "999999" }); // Non-existent token

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe("TOKEN_INVALID");
      expect(response.body.error.message).toMatch(/invalid.*expired/i);
    });

    it("should reject with 400 Bad Request when the token has expired", async () => {
      const userData = generateTestUser("_expired_token");
      const expiredToken = "445566";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(expiredToken);

      // Register the user
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      const userId = regRes.body.data.user.id;
      testUserIds.add(userId);

      // Simulate token expiration by updating the DB row to a past timestamp
      const tokenHash = tokenUtils.hashToken(expiredToken);
      await prisma.emailVerification.update({
        where: { tokenHash },
        data: { expiresAt: new Date(Date.now() - 1000 * 60 * 10) }, // Expired 10 minutes ago
      });

      // Submit expired token
      const response = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token: expiredToken });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe("TOKEN_INVALID");

      // Verify user remains unverified
      const dbUser = await prisma.user.findUnique({ where: { id: userId } });
      expect(dbUser.emailVerified).toBe(false);
    });

    it("should reject with 400 Bad Request when attempting to reuse an already claimed token (Replay Protection)", async () => {
      const userData = generateTestUser("_replay_protection");
      const singleUseToken = "778899";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(singleUseToken);

      // Register the user
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      const userId = regRes.body.data.user.id;
      testUserIds.add(userId);

      // First verification: Must succeed
      const firstAttempt = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token: singleUseToken });
      expect(firstAttempt.status).toBe(200);

      // Second verification with identical token: Must be rejected
      const secondAttempt = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token: singleUseToken });

      expect(secondAttempt.status).toBe(400);
      expect(secondAttempt.body.success).toBe(false);
      expect(secondAttempt.body.error.code).toBe("TOKEN_INVALID");
    });

    it("should reject with 400 Bad Request when token is malformed (fails Zod schema)", async () => {
      const response = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token: "123" }); // Less than 6 characters

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
      expect(response.body.error.errors[0].field).toBe("token");
    });
  });

  // =========================================================================
  // 3. POST /api/v1/auth/resend-verification
  // =========================================================================
  describe("POST /api/v1/auth/resend-verification", () => {
    it("should successfully issue a new verification token for an unverified user", async () => {
      const userData = generateTestUser("_resend_ok");
      const initialToken = "111222";
      const newToken = "333444";

      // 1. Register with initial token
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(initialToken);
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      const userId = regRes.body.data.user.id;
      testUserIds.add(userId);

      // 2. Request resend with new token
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(newToken);
      const response = await request(app)
        .post("/api/v1/auth/resend-verification")
        .send({ email: userData.email });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe(
        "Email resent successfully. Please check your email to verify your account.",
      );

      // 3. Database check: Old token must be deleted, only new token exists
      const verifications = await prisma.emailVerification.findMany({
        where: { userId },
      });
      expect(verifications).toHaveLength(1);
      expect(verifications[0].tokenHash).toBe(tokenUtils.hashToken(newToken));

      // 4. Verify account using the newly issued token
      const verifyRes = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token: newToken });
      expect(verifyRes.status).toBe(200);

      const dbUser = await prisma.user.findUnique({ where: { id: userId } });
      expect(dbUser.emailVerified).toBe(true);
    });

    it("should return 200 OK silently without creating new tokens when user is already verified (Anti-Enumeration)", async () => {
      const userData = generateTestUser("_already_verified");
      const token = "555666";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(token);

      // Register and verify
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      const userId = regRes.body.data.user.id;
      testUserIds.add(userId);

      await request(app).post("/api/v1/auth/verify-email").send({ token });

      // Request resend for already-verified email
      const response = await request(app)
        .post("/api/v1/auth/resend-verification")
        .send({ email: userData.email });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);

      // Ensure no new verification records were added
      const verifications = await prisma.emailVerification.findMany({
        where: { userId, usedAt: null },
      });
      expect(verifications).toHaveLength(0);
    });

    it("should return 200 OK silently when email does not exist (Anti-Enumeration Protection)", async () => {
      const response = await request(app)
        .post("/api/v1/auth/resend-verification")
        .send({ email: "nonexistent_email_12345@example.com" });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain("Email resent successfully");
    });

    it("should enforce rate limiting with 429 Too Many Requests when exceeding max attempts in production mode", async () => {
      // Temporarily enable production mode to activate rate limiters
      finalConfig.env = "production";

      const testIp = "203.0.113.195"; // Dedicated IP address to prevent collision
      const targetEmail = "ratelimit_test@example.com";

      // The emailVerificationRateLimiter is configured with max: 3
      // Requests 1, 2, and 3 should be permitted (200 OK)
      for (let attempt = 1; attempt <= 3; attempt++) {
        const res = await request(app)
          .post("/api/v1/auth/resend-verification")
          .set("X-Forwarded-For", testIp)
          .send({ email: targetEmail });
        expect(res.status).toBe(200);
      }

      // Request 4 from the same IP must be rate-limited (429 Too Many Requests)
      const blockedRes = await request(app)
        .post("/api/v1/auth/resend-verification")
        .set("X-Forwarded-For", testIp)
        .send({ email: targetEmail });

      expect(blockedRes.status).toBe(429);
      expect(blockedRes.body.success).toBe(false);
      expect(blockedRes.body.error.code).toBe("RATE_LIMITED");
      expect(blockedRes.body.error.message).toBe(
        "Too many verification email requests, please try again later.",
      );
    });
  });
});
