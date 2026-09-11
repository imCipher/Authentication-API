import request from "supertest";

import app from "../../src/app.js";
import prisma from "../../src/config/db.js";
import finalConfig from "../../src/config/keys.js";
import tokenUtils from "../../src/utils/token.utils.js";
import Email from "../../src/utils/email.utils.js";
import jwt from "jsonwebtoken";
import redisService from "../../src/config/redis.js";

// Mock the Email utility so real SMTP network calls are never dispatched
vi.mock("../../src/utils/email.utils.js", () => {
  return {
    default: vi.fn().mockImplementation(function () {
      return {
        sendEmailConfirmation: vi.fn().mockResolvedValue(undefined),
        sendWelcomeEmail: vi.fn().mockResolvedValue(undefined),
        sendPasswordResetEmail: vi.fn().mockResolvedValue(undefined),
      };
    }),
  };
});

describe("Auth Routes Integration - Registration & Verification Lifecycle", () => {
  const testUserIds = new Set();
  let originalEnv;

  // Helper function to generate unique credentials adhering strictly to Zod schemas
  const generateTestUser = (suffix = "") => {
    const randomPart = Math.random().toString(36).substring(2, 8);
    const timestamp = Date.now().toString().slice(-6);
    const cleanSuffix = suffix.replace(/[^a-z0-9]/gi, "").toLowerCase();
    const uniqueSuffix = `${timestamp}${randomPart}${cleanSuffix}`;
    const password = "StrongP@ssw0rd123!";

    return {
      // fullName ONLY allows letters, spaces, hyphens, and apostrophes (NO digits or underscores)
      fullName: "Integration Test User",
      username: `usr_${uniqueSuffix}`.substring(0, 30),
      email: `test_${uniqueSuffix}@example.com`,
      password,
      confirmPassword: password,
    };
  };

  beforeAll(async () => {
    // Connect Redis for token denylist assertions
    await redisService.connect();
    // Proactive cleanup: purge any orphaned test accounts from previously interrupted runs
    await prisma.user.deleteMany({
      where: {
        OR: [
          { email: { startsWith: "test_" } },
          { username: { startsWith: "usr_" } },
        ],
      },
    });
  });

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

    // Disconnect clients to release connection handles
    await redisService.disconnect();
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
      const existingUser = generateTestUser("dupusr");

      // Seed first user
      const firstRes = await request(app)
        .post("/api/v1/auth/register")
        .send(existingUser);
      expect(firstRes.status).toBe(201);
      testUserIds.add(firstRes.body.data.user.id);

      // Attempt second registration with same username but different email
      const conflictingPayload = {
        ...generateTestUser("diffemail"),
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
      const existingUser = generateTestUser("dupeml");

      // Seed first user
      const firstRes = await request(app)
        .post("/api/v1/auth/register")
        .send(existingUser);
      expect(firstRes.status).toBe(201);
      testUserIds.add(firstRes.body.data.user.id);

      // Attempt second registration with same email but different username
      const conflictingPayload = {
        ...generateTestUser("diffusr"),
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
      const userData = generateTestUser("verok");
      const validToken = "112233";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(validToken);

      // Register the user first
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      expect(regRes.status).toBe(201);
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
      const userData = generateTestUser("exptkn");
      const expiredToken = "445566";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(expiredToken);

      // Register the user
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      expect(regRes.status).toBe(201);
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
      const userData = generateTestUser("rply");
      const singleUseToken = "778899";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(singleUseToken);

      // Register the user
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      expect(regRes.status).toBe(201);
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
      const userData = generateTestUser("rsndok");
      const initialToken = "111222";
      const newToken = "333444";

      // 1. Register with initial token
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(initialToken);
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      expect(regRes.status).toBe(201);
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
      const userData = generateTestUser("alrver");
      const token = "555666";
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(token);

      // Register and verify
      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      expect(regRes.status).toBe(201);
      const userId = regRes.body.data.user.id;
      testUserIds.add(userId);

      const verifyRes = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token });
      expect(verifyRes.status).toBe(200);

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

  // =========================================================================
  // 4. LOGIN, LOCKOUT & TOKEN MANAGEMENT
  // =========================================================================
  describe("Auth Routes Integration - Login, Lockout & Token Management", () => {
    // Helper to register and immediately verify a user for login tests
    const createVerifiedTestUser = async (suffix = "login") => {
      const userData = generateTestUser(suffix);
      // Generate a unique 6-digit code for every user to avoid DB unique constraint collisions
      const mockToken = String(Math.floor(100000 + Math.random() * 900000));
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(mockToken);

      const regRes = await request(app)
        .post("/api/v1/auth/register")
        .send(userData);
      expect(regRes.status).toBe(201);
      const userId = regRes.body.data.user.id;
      testUserIds.add(userId);

      // Verify the user email so they can log in
      const verifyRes = await request(app)
        .post("/api/v1/auth/verify-email")
        .send({ token: mockToken });
      expect(verifyRes.status).toBe(200);

      return { ...userData, id: userId };
    };

    // -----------------------------------------------------------------------
    // POST /api/v1/auth/login
    // -----------------------------------------------------------------------
    describe("POST /api/v1/auth/login", () => {
      it("should successfully log in with email and return token pair (200 OK)", async () => {
        const user = await createVerifiedTestUser("emlogin");

        const response = await request(app).post("/api/v1/auth/login").send({
          loginIdentifier: user.email,
          password: user.password,
        });

        // 1. Assert HTTP Response
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe("Login Successful.");
        expect(response.body.data.tokens.accessToken).toBeDefined();
        expect(response.body.data.tokens.refreshToken).toBeDefined();

        const { accessToken, refreshToken } = response.body.data.tokens;

        // 2. Assert User DB State (failedAttempts reset, lastLoginAt updated)
        const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
        expect(dbUser.failedAttempts).toBe(0);
        expect(dbUser.lastLoginAt).not.toBeNull();

        // 3. Assert LoginHistory record created
        const loginHistory = await prisma.loginHistory.findFirst({
          where: { userId: user.id, success: true },
        });
        expect(loginHistory).not.toBeNull();
        expect(loginHistory.reason).toBe("Login successful");

        // 4. Assert RefreshToken record persisted in DB
        const hashedRefreshToken = tokenUtils.hashToken(refreshToken);
        const dbRefreshToken = await prisma.refreshToken.findFirst({
          where: { userId: user.id, tokenHash: hashedRefreshToken },
        });
        expect(dbRefreshToken).not.toBeNull();
        expect(dbRefreshToken.revokedAt).toBeNull();
      });

      it("should successfully log in using username as the loginIdentifier (200 OK)", async () => {
        const user = await createVerifiedTestUser("usrlogin");

        const response = await request(app).post("/api/v1/auth/login").send({
          loginIdentifier: user.username,
          password: user.password,
        });

        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.data.tokens.accessToken).toBeDefined();
        expect(response.body.data.tokens.refreshToken).toBeDefined();
      });

      it("should reject login with 401 Unauthorized if the email is not verified", async () => {
        // Register user WITHOUT verifying email
        const unverifiedUser = generateTestUser("unverlogin");
        const regRes = await request(app)
          .post("/api/v1/auth/register")
          .send(unverifiedUser);
        expect(regRes.status).toBe(201);
        testUserIds.add(regRes.body.data.user.id);

        const response = await request(app).post("/api/v1/auth/login").send({
          loginIdentifier: unverifiedUser.email,
          password: unverifiedUser.password,
        });

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error.message).toContain("Email is not verified");

        // Assert failed attempt recorded in LoginHistory
        const history = await prisma.loginHistory.findFirst({
          where: { userId: regRes.body.data.user.id, success: false },
        });
        expect(history.reason).toBe("Email not verified.");
      });

      it("should reject login with 401 Unauthorized on invalid password and increment failedAttempts", async () => {
        const user = await createVerifiedTestUser("badpass");

        const response = await request(app).post("/api/v1/auth/login").send({
          loginIdentifier: user.email,
          password: "WrongPassword999!",
        });

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error.message).toBe("Invalid login credentials");

        // Assert failedAttempts incremented in DB
        const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
        expect(dbUser.failedAttempts).toBe(1);

        // Assert LoginHistory entry
        const history = await prisma.loginHistory.findFirst({
          where: { userId: user.id, success: false },
        });
        expect(history.reason).toBe("Incorrect password.");
      });

      it("should reject with 401 Unauthorized for non-existent users without timing leaks", async () => {
        const response = await request(app).post("/api/v1/auth/login").send({
          loginIdentifier: "non_existent_user_9999@example.com",
          password: "SomePassword123!",
        });

        expect(response.status).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error.message).toBe("Invalid login credentials");
      });

      it("should lock the user account after 5 consecutive failed login attempts (Account Lockout)", async () => {
        const user = await createVerifiedTestUser("lockout");

        // Perform 4 failed attempts (failedAttempts reaches 4)
        for (let i = 1; i <= 4; i++) {
          const res = await request(app).post("/api/v1/auth/login").send({
            loginIdentifier: user.email,
            password: "WrongPassword!",
          });
          expect(res.status).toBe(401);
        }

        const midCheck = await prisma.user.findUnique({
          where: { id: user.id },
        });
        expect(midCheck.failedAttempts).toBe(4);
        expect(midCheck.lockedUntil).toBeNull();

        // 5th failed attempt triggers the lockout threshold
        const lockoutRes = await request(app).post("/api/v1/auth/login").send({
          loginIdentifier: user.email,
          password: "WrongPassword!",
        });

        expect(lockoutRes.status).toBe(401);
        expect(lockoutRes.body.error.message).toContain("temporarily locked");

        // Assert DB state after lockout
        const lockedUser = await prisma.user.findUnique({
          where: { id: user.id },
        });
        expect(lockedUser.lockedUntil).not.toBeNull();
        expect(new Date(lockedUser.lockedUntil).getTime()).toBeGreaterThan(
          Date.now(),
        );
        expect(lockedUser.failedAttempts).toBe(0); // Reset upon locking

        // Assert AuditLog entry for ACCOUNT_LOCKED
        const audit = await prisma.auditLog.findFirst({
          where: { userId: user.id, action: "ACCOUNT_LOCKED" },
        });
        expect(audit).not.toBeNull();

        // 6th attempt with the CORRECT password must still be rejected while locked
        const subsequentRes = await request(app)
          .post("/api/v1/auth/login")
          .send({
            loginIdentifier: user.email,
            password: user.password,
          });

        expect(subsequentRes.status).toBe(401);
        expect(subsequentRes.body.error.message).toContain(
          "Account is temporarily locked",
        );
      });
    });

    // -----------------------------------------------------------------------
    // POST /api/v1/auth/refresh-token
    // -----------------------------------------------------------------------
    describe("POST /api/v1/auth/refresh-token", () => {
      it("should rotate refresh token, return new token pair, and link grace token (200 OK)", async () => {
        const user = await createVerifiedTestUser("rotok");

        // Login to get initial token pair
        const loginRes = await request(app)
          .post("/api/v1/auth/login")
          .send({ loginIdentifier: user.email, password: user.password });
        const initialRefreshToken = loginRes.body.data.tokens.refreshToken;

        // Rotate token
        const rotateRes = await request(app)
          .post("/api/v1/auth/refresh-token")
          .send({ refreshToken: initialRefreshToken });

        expect(rotateRes.status).toBe(200);
        expect(rotateRes.body.success).toBe(true);
        expect(rotateRes.body.message).toBe("Token refreshed successfully.");

        const { accessToken: newAccess, refreshToken: newRefresh } =
          rotateRes.body.data.tokens;
        expect(newRefresh).not.toBe(initialRefreshToken);

        // Assert DB states: Initial token revoked & grace copy stored
        const initialDbRecord = await prisma.refreshToken.findFirst({
          where: { tokenHash: tokenUtils.hashToken(initialRefreshToken) },
        });
        expect(initialDbRecord.revokedAt).not.toBeNull();
        expect(initialDbRecord.graceToken).toBe(newRefresh);

        // Assert DB states: New token is active
        const newDbRecord = await prisma.refreshToken.findFirst({
          where: { tokenHash: tokenUtils.hashToken(newRefresh) },
        });
        expect(newDbRecord.revokedAt).toBeNull();
      });

      it("should handle concurrency grace-window replay by serving the successor token once (200 OK)", async () => {
        const user = await createVerifiedTestUser("gracerep");

        const loginRes = await request(app)
          .post("/api/v1/auth/login")
          .send({ loginIdentifier: user.email, password: user.password });
        const originalRefreshToken = loginRes.body.data.tokens.refreshToken;

        // 1. First rotation (Normal)
        const firstRotate = await request(app)
          .post("/api/v1/auth/refresh-token")
          .send({ refreshToken: originalRefreshToken });
        expect(firstRotate.status).toBe(200);
        const expectedSuccessorToken =
          firstRotate.body.data.tokens.refreshToken;

        // 2. Second request re-presenting originalRefreshToken within grace window (e.g. parallel tab)
        const replayRotate = await request(app)
          .post("/api/v1/auth/refresh-token")
          .send({ refreshToken: originalRefreshToken });

        expect(replayRotate.status).toBe(200);
        expect(replayRotate.body.success).toBe(true);
        // Receives the EXACT SAME replacement token!
        expect(replayRotate.body.data.tokens.refreshToken).toBe(
          expectedSuccessorToken,
        );

        // Assert graceToken was consumed in DB (one-shot protection)
        const originalDbRecord = await prisma.refreshToken.findFirst({
          where: { tokenHash: tokenUtils.hashToken(originalRefreshToken) },
        });
        expect(originalDbRecord.graceToken).toBeNull();
      });

      it("should detect reuse on 3rd replay attempt, nuke all user sessions, and emit TOKEN_REUSE_DETECTED audit log (401 Unauthorized)", async () => {
        const user = await createVerifiedTestUser("reuse");

        const loginRes = await request(app)
          .post("/api/v1/auth/login")
          .send({ loginIdentifier: user.email, password: user.password });
        const stolenToken = loginRes.body.data.tokens.refreshToken;

        // 1st request: rotates legitimately
        await request(app)
          .post("/api/v1/auth/refresh-token")
          .send({ refreshToken: stolenToken });

        // 2nd request: consumes grace-window allowance
        await request(app)
          .post("/api/v1/auth/refresh-token")
          .send({ refreshToken: stolenToken });

        // 3rd request: grace copy is exhausted -> ATTACK DETECTED!
        const attackRes = await request(app)
          .post("/api/v1/auth/refresh-token")
          .send({ refreshToken: stolenToken });

        expect(attackRes.status).toBe(401);
        expect(attackRes.body.success).toBe(false);
        expect(attackRes.body.error.code).toBe("TOKEN_REVOKED");
        expect(attackRes.body.error.message).toContain(
          "Refresh token reuse detected",
        );

        // Assert "Family Nuke": ALL refresh tokens for this user must be revoked
        const activeTokens = await prisma.refreshToken.findMany({
          where: { userId: user.id, revokedAt: null },
        });
        expect(activeTokens).toHaveLength(0);

        // Assert AuditLog entry
        const audit = await prisma.auditLog.findFirst({
          where: { userId: user.id, action: "TOKEN_REUSE_DETECTED" },
        });
        expect(audit).not.toBeNull();
      });

      it("should reject with 401 Unauthorized when refresh token has expired", async () => {
        const user = await createVerifiedTestUser("exp_refresh");

        const loginRes = await request(app)
          .post("/api/v1/auth/login")
          .send({ loginIdentifier: user.email, password: user.password });
        const refreshToken = loginRes.body.data.tokens.refreshToken;

        // Backdate expiresAt in DB to 10 minutes ago
        await prisma.refreshToken.update({
          where: { tokenHash: tokenUtils.hashToken(refreshToken) },
          data: { expiresAt: new Date(Date.now() - 1000 * 60 * 10) },
        });

        const response = await request(app)
          .post("/api/v1/auth/refresh-token")
          .send({ refreshToken });

        expect(response.status).toBe(401);
        expect(response.body.error.code).toBe("TOKEN_EXPIRED");
      });
    });

    // -----------------------------------------------------------------------
    // POST /api/v1/auth/logout
    // -----------------------------------------------------------------------
    describe("POST /api/v1/auth/logout", () => {
      it("should revoke the specific session's refresh token and denylist access token in Redis (200 OK)", async () => {
        const user = await createVerifiedTestUser("logout_single");

        // Simulate login on Device A
        const loginResA = await request(app)
          .post("/api/v1/auth/login")
          .send({ loginIdentifier: user.email, password: user.password });
        const tokensA = loginResA.body.data.tokens;

        // Simulate login on Device B
        const loginResB = await request(app)
          .post("/api/v1/auth/login")
          .send({ loginIdentifier: user.email, password: user.password });
        const tokensB = loginResB.body.data.tokens;

        // Logout from Device A
        const logoutRes = await request(app)
          .post("/api/v1/auth/logout")
          .set("Authorization", `Bearer ${tokensA.accessToken}`)
          .send({ refreshToken: tokensA.refreshToken });

        expect(logoutRes.status).toBe(200);
        expect(logoutRes.body.success).toBe(true);
        expect(logoutRes.body.message).toBe("Logout successful.");

        // 1. Assert Device A's refresh token is revoked in DB
        const recordA = await prisma.refreshToken.findFirst({
          where: { tokenHash: tokenUtils.hashToken(tokensA.refreshToken) },
        });
        expect(recordA.revokedAt).not.toBeNull();

        // 2. Assert Device B's refresh token remains ACTIVE (unaffected)
        const recordB = await prisma.refreshToken.findFirst({
          where: { tokenHash: tokenUtils.hashToken(tokensB.refreshToken) },
        });
        expect(recordB.revokedAt).toBeNull();

        // 3. Assert Access Token JTI added to Redis denylist
        const decoded = jwt.decode(tokensA.accessToken);
        const isRevokedInRedis = await redisService.exists(
          `denylist:${decoded.jti}`,
        );
        expect(isRevokedInRedis).toBe(true);

        // 4. Consequence: Presenting revoked token A in protect middleware is immediately denied
        const meRes = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", `Bearer ${tokensA.accessToken}`);
        expect(meRes.status).toBe(401);
        expect(meRes.body.error.code).toBe("TOKEN_REVOKED");
      });

      it("should reject logout with 401 Unauthorized if Authorization header is missing", async () => {
        const response = await request(app)
          .post("/api/v1/auth/logout")
          .send({ refreshToken: "some-dummy-token" });

        expect(response.status).toBe(401);
        expect(response.body.error.code).toBe("UNAUTHORIZED");
      });
    });

    // -----------------------------------------------------------------------
    // POST /api/v1/auth/logout-all
    // -----------------------------------------------------------------------
    describe("POST /api/v1/auth/logout-all", () => {
      it("should invalidate all sessions, revoke all refresh tokens, and update sessionsRevokedAt (200 OK)", async () => {
        const user = await createVerifiedTestUser("logout_all");

        // Login on Device A
        const loginA = await request(app)
          .post("/api/v1/auth/login")
          .send({ loginIdentifier: user.email, password: user.password });
        const tokensA = loginA.body.data.tokens;

        // Login on Device B
        const loginB = await request(app)
          .post("/api/v1/auth/login")
          .send({ loginIdentifier: user.email, password: user.password });
        const tokensB = loginB.body.data.tokens;

        // Call logout-all using Device A
        const logoutAllRes = await request(app)
          .post("/api/v1/auth/logout-all")
          .set("Authorization", `Bearer ${tokensA.accessToken}`);

        expect(logoutAllRes.status).toBe(200);
        expect(logoutAllRes.body.success).toBe(true);
        expect(logoutAllRes.body.message).toBe(
          "Logged out from all sessions successfully.",
        );

        // 1. Assert ALL refresh tokens for this user are revoked in DB
        const activeTokens = await prisma.refreshToken.findMany({
          where: { userId: user.id, revokedAt: null },
        });
        expect(activeTokens).toHaveLength(0);

        // 2. Assert User.sessionsRevokedAt timestamp is set in DB
        const updatedUser = await prisma.user.findUnique({
          where: { id: user.id },
        });
        expect(updatedUser.sessionsRevokedAt).not.toBeNull();

        // 3. Assert AuditLog entry created for LOGOUT_ALL
        const audit = await prisma.auditLog.findFirst({
          where: { userId: user.id, action: "LOGOUT_ALL" },
        });
        expect(audit).not.toBeNull();

        // 4. Assert Device B's access token is rejected on subsequent calls
        //    because it was issued BEFORE sessionsRevokedAt
        const deviceBRes = await request(app)
          .get("/api/v1/auth/me")
          .set("Authorization", `Bearer ${tokensB.accessToken}`);

        expect(deviceBRes.status).toBe(401);
        expect(deviceBRes.body.error.message).toContain(
          "You have logged out from all sessions. Please log in again.",
        );
      });
    });
  });
});
