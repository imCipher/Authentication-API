import crypto from "crypto";

import prisma from "../../config/db.js";
import logger from "../../config/logger.js";
import ApiError from "../../utils/ApiError.js";
import hashUtils from "../../utils/hash.utils.js";
import tokenUtils from "../../utils/token.utils.js";
import Email from "../../utils/email.utils.js";
import finalConfig from "../../config/keys.js";

/**
 * Service class for handling user-related business logic.
 */
class AuthService {
  /**
   * Registers a new user in the system.
   *
   * @param {Object} userdata - The user data for registration.
   * @param {string} userdata.fullName - The full name of the user.
   * @param {string} userdata.username - The desired username of the user.
   * @param {string} userdata.email - The email address of the user.
   * @param {string} userdata.password - The plaintext password of the user.
   * @returns {Promise<Object>} - The newly created user object (excluding sensitive data like passwordHash).
   * @throws {ApiError} - Throws a 409 conflict error if the username or email is already taken.
   */
  async register(userdata) {
    const { fullName, username, email, password } = userdata;

    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
      },
    });

    if (existingUser) {
      if (existingUser.username === username) {
        throw ApiError.conflict("Username is already taken");
      }
      if (existingUser.email === email) {
        throw ApiError.conflict("Email is already registered");
      }
    }

    const start2Db = performance.now();
    const hashedPassword = await hashUtils.hashPassword(password);
    const end2Db = performance.now();
    logger.info("Password hashing time: %d ms", end2Db - start2Db);

    const token = tokenUtils.verificationToken(6);
    let hashToken = tokenUtils.hashToken(token);
    let expiryTime = tokenUtils.expiresAt(5);

    const user = await prisma.$transaction(async tx => {
      const newUser = await tx.user.create({
        data: {
          email,
          fullName,
          username,
          passwordHash: hashedPassword,
        },
        select: {
          id: true,
          fullName: true,
          username: true,
          email: true,
          role: true,
          emailVerified: true,
          createdAt: true,
        },
      });

      if (!newUser.emailVerified) {
        await tx.emailVerification.create({
          data: {
            userId: newUser.id,
            tokenHash: hashToken,
            expiresAt: expiryTime,
          },
        });
      }
      return newUser;
    });

    new Email(userdata, token).sendEmailConfirmation().catch(error => {
      logger.warn("Email sending failed", { email, error });
    });

    return user;
  }

  /**
   * Logs in a user by verifying their credentials and generating access and refresh tokens.
   *
   * @param {Object} loginData - The login data containing the login identifier and password.
   * @param {string} loginData.loginIdentifier - The email or username of the user.
   * @param {string} loginData.password - The plaintext password of the user.
   * @param {Object} metadata - Metadata containing user IP and user agent.
   * @param {string} metadata.userIp - The IP address of the user.
   * @param {string} metadata.userAgent - The user agent string of the user's device.
   * @returns {Promise<Object>} - An object containing the access token and refresh token.
   * @throws {ApiError} - Throws an error if the login credentials are invalid or if the account is locked or deactivated.
   */
  async login(loginData, metadata) {
    const { loginIdentifier, password } = loginData;
    const user = await prisma.user.findFirst({
      where: {
        OR: [{ email: loginIdentifier }, { username: loginIdentifier }],
      },
      select: {
        passwordHash: true,
        id: true,
        role: true,
        status: true,
        lockedUntil: true,
        failedAttempts: true,
        emailVerified: true,
      },
    });

    let failedAttemptsCount = user ? user.failedAttempts : 0;

    if (!user) {
      await hashUtils.fakeComparePassword(); // Prevent timing attacks
      throw ApiError.unauthorized("Invalid login credentials");
    }

    if (user.status !== "ACTIVE") {
      await prisma.loginHistory.create({
        data: {
          userId: user.id,
          ipAddress: metadata.userIp,
          userAgent: metadata.userAgent,
          success: false,
          reason: "Account has been deactivated.",
        },
      });
      throw ApiError.unauthorized(
        "User account has been deactivated. Please contact support for assistance.",
      );
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      await prisma.loginHistory.create({
        data: {
          userId: user.id,
          ipAddress: metadata.userIp,
          userAgent: metadata.userAgent,
          success: false,
          reason: "Account locked due to multiple failed login attempts",
        },
      });
      throw ApiError.unauthorized(
        "Account is temporarily locked due to multiple failed login attempts.",
      );
    }

    if (!user.emailVerified) {
      await prisma.loginHistory.create({
        data: {
          userId: user.id,
          ipAddress: metadata.userIp,
          userAgent: metadata.userAgent,
          success: false,
          reason: "Email not verified.",
        },
      });
      throw ApiError.unauthorized(
        "Email is not verified. Please verify your email before logging in.",
      );
    }

    if (!(await hashUtils.comparePassword(user.passwordHash, password))) {
      failedAttemptsCount++;

      if (failedAttemptsCount >= 5 && user.role !== "ADMIN") {
        const lockDuration = 15 * 60 * 1000; // 15 minutes
        const lockedUntil = new Date(Date.now() + lockDuration);
        await prisma.user.update({
          where: { id: user.id },
          data: { lockedUntil, failedAttempts: 0 },
        });
        throw ApiError.unauthorized(
          "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
        );
      }
      await prisma.user.update({
        where: { id: user.id },
        data: { failedAttempts: failedAttemptsCount },
      });

      await prisma.loginHistory.create({
        data: {
          userId: user.id,
          ipAddress: metadata.userIp,
          userAgent: metadata.userAgent,
          success: false,
          reason: "Incorrect password.",
        },
      });
      throw ApiError.unauthorized("Invalid login credentials");
    }

    const accessToken = await this.generateAccessToken(user);
    const { refreshToken } = await this.generateRefreshToken(user.id, metadata);

    await prisma.$transaction(async tx => {
      await tx.loginHistory.create({
        data: {
          userId: user.id,
          ipAddress: metadata.userIp,
          userAgent: metadata.userAgent,
          success: true,
          reason: "Login successful",
        },
      });

      await tx.user.update({
        where: { id: user.id },
        data: {
          failedAttempts: 0,
          lockedUntil: null,
          lastLoginAt: new Date(),
          lastLoginIp: metadata.userIp,
        },
      });
    });

    return { accessToken, refreshToken };
  }

  /**
   * Revokes the current refresh token and issues a new access token and refresh token.
   *
   * Rotation is atomic: claim, successor provisioning, and grace-token linkage
   * commit in one transaction, so a crash can never strand a revoked row without
   * its replacement (which would escalate an infra blip into a family nuke).
   *
   * A rotated-away token re-presented within the grace window
   * (finalConfig.jwt.refreshGraceWindowSeconds) is treated as benign concurrency
   * — second tab, parallel mobile requests — and receives the same replacement
   * pair once; see handleReplay.
   *
   * The row is matched on tokenHash alone: possession of a 512-bit random token
   * IS the authentication. IP/UA are soft signals only — hard-matching them
   * logs mobile users out whenever their network changes (Wi-Fi <-> cellular).
   *
   * @param {string} refreshToken - The current refresh token to be rotated.
   * @param {Object} metadata - Metadata containing user IP and user agent.
   * @param {string} metadata.userIp - The IP address of the user.
   * @param {string} metadata.userAgent - The user agent string of the user's device.
   * @returns {Promise<Object>} - An object containing the new access token and refresh token.
   * @throws {ApiError} - Throws a 401 unauthorized error if the refresh token is invalid, expired, or has been revoked.
   */
  async rotateRefreshToken(refreshToken, { userIp, userAgent }) {
    const hashedToken = tokenUtils.hashToken(refreshToken);
    const tokenInfo = await prisma.refreshToken.findFirst({
      where: {
        tokenHash: hashedToken,
      },
      select: {
        id: true,
        userId: true,
        createdAt: true,
        expiresAt: true,
        revokedAt: true,
        ipAddress: true,
        userAgent: true,
        graceToken: true,
        user: {
          select: {
            id: true,
            role: true,
            passwordChangedAt: true,
          },
        },
      },
    });

    if (!tokenInfo) {
      throw ApiError.unauthorized("Invalid refresh token", {
        code: "TOKEN_INVALID",
      });
    }

    if (tokenInfo.expiresAt < new Date()) {
      throw ApiError.unauthorized("Refresh token expired", {
        code: "TOKEN_EXPIRED",
      });
    }

    // A credential change kills every family minted before it. Rejecting rows
    // older than passwordChangedAt closes the window where a rotation racing a
    // password reset could provision a successor that escapes the reset's
    // revoke-all.
    if (
      tokenInfo.user.passwordChangedAt &&
      tokenInfo.createdAt < tokenInfo.user.passwordChangedAt
    ) {
      throw ApiError.unauthorized("Invalid refresh token", {
        code: "TOKEN_INVALID",
      });
    }

    // Possession authenticates, but a different device fingerprint on a live
    // token is worth surfacing (soft binding — never a rejection).
    if (
      !tokenInfo.revokedAt &&
      (tokenInfo.userAgent !== userAgent || tokenInfo.ipAddress !== userIp)
    ) {
      logger.warn("Refresh token used from unexpected device", {
        userId: tokenInfo.userId,
        tokenId: tokenInfo.id,
        expectedUserAgent: tokenInfo.userAgent,
        actualUserAgent: userAgent,
        expectedIp: tokenInfo.ipAddress,
        actualIp: userIp,
      });
    }

    const accessToken = await this.generateAccessToken(tokenInfo.user);

    // Claim + provision + link in ONE transaction. Concurrent losers block on
    // the parent row until commit, then see both revokedAt AND graceToken —
    // no window where a replay can observe one without the other.
    const successor = await prisma.$transaction(async tx => {
      const claimed = await tx.refreshToken.updateMany({
        where: { id: tokenInfo.id, revokedAt: null },
        data: { revokedAt: new Date() },
      });

      if (claimed.count === 0) {
        return null; // Lost the race — handled below.
      }

      const newRefreshToken = await this.generateRefreshToken(
        tokenInfo.userId,
        { userIp, userAgent },
        tx,
      );

      await tx.refreshToken.update({
        where: { id: tokenInfo.id },
        data: {
          replacedBy: newRefreshToken.id,
          graceToken: newRefreshToken.refreshToken,
        },
      });

      // The grandparent's grace copy points at the row we just rotated away —
      // it can no longer be served safely, so retire it here.
      await tx.refreshToken.updateMany({
        where: { replacedBy: tokenInfo.id, graceToken: { not: null } },
        data: { graceToken: null },
      });

      return newRefreshToken;
    });

    if (!successor) {
      return this.handleReplay(tokenInfo);
    }

    return { accessToken, refreshToken: successor.refreshToken };
  }

  /**
   * Handles presentation of a refresh token that lost the rotation race or was
   * already rotated away.
   *
   * Within the grace window this is legitimate concurrent use, so the caller
   * receives the exact replacement pair the winner got — ONCE. The grant is
   * consumed atomically when served, so repeat presentations of the same stale
   * token are treated as reuse (a thief re-syncing onto the victim's chain is
   * precisely what reuse detection exists for). Outside the window — or after
   * the grant is consumed — every active session is revoked.
   *
   * @param {Object} tokenInfo - Pre-claim snapshot of the refresh token row.
   * @returns {Promise<Object>} - An object containing a fresh access token and the surviving refresh token.
   * @throws {ApiError} - Throws a 401 TOKEN_REVOKED when reuse is detected, TOKEN_INVALID when the successor is dead.
   */
  async handleReplay(tokenInfo) {
    const graceMs = finalConfig.jwt.refreshGraceWindowSeconds * 1000;

    let info = tokenInfo;

    // Normally zero iterations: rotation commits claim and graceToken together,
    // so replays see both or neither. Kept as belt-and-braces for the case
    // where the winner's transaction is somehow still open.
    for (let attempt = 0; attempt < 3 && !info.graceToken; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 100));
      const fresh = await prisma.refreshToken.findUnique({
        where: { id: info.id },
        select: {
          userId: true,
          expiresAt: true,
          revokedAt: true,
          replacedBy: true,
          graceToken: true,
          user: {
            select: {
              id: true,
              role: true,
            },
          },
        },
      });
      if (!fresh) break;
      info = fresh;
    }

    const revokedAtMs = info.revokedAt ? info.revokedAt.getTime() : Date.now();
    const withinWindow = Date.now() - revokedAtMs <= graceMs;

    if (withinWindow && info.graceToken && info.replacedBy) {
      // Serve the raw replacement only while the successor itself is alive —
      // otherwise a chain rotation or security revoke would hand out a
      // dead-on-arrival token whose only future is another family nuke.
      const successor = await prisma.refreshToken.findUnique({
        where: { id: info.replacedBy },
        select: { revokedAt: true, expiresAt: true },
      });

      const successorLive =
        successor && !successor.revokedAt && successor.expiresAt > new Date();

      if (successorLive) {
        // One-shot consumption: two tabs passing liveness simultaneously race
        // here; exactly one wins, the other falls through to reuse handling.
        const consumed = await prisma.refreshToken.updateMany({
          where: { id: info.id, graceToken: { not: null } },
          data: { graceToken: null },
        });

        if (consumed.count > 0) {
          logger.info("Served grace-window replay", {
            userId: info.userId,
            tokenId: info.id,
          });
          const accessToken = await this.generateAccessToken(info.user);
          return { accessToken, refreshToken: info.graceToken };
        }
      } else {
        // Successor is gone — refuse WITHOUT declaring theft: the presenter may
        // be a straggler that the grace mechanism itself served moments ago.
        throw ApiError.unauthorized("Invalid refresh token", {
          code: "TOKEN_INVALID",
        });
      }
    }

    // Outside the window, or the grant was already consumed: genuine reuse —
    // revoke everything, and retire any remaining grace copies so nothing can
    // be resurrected from a dead family.
    await prisma.$transaction([
      prisma.refreshToken.updateMany({
        where: { userId: info.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
      prisma.refreshToken.updateMany({
        where: { userId: info.userId, graceToken: { not: null } },
        data: { graceToken: null },
      }),
    ]);
    logger.warn("Refresh token reuse detected — all sessions revoked", {
      userId: info.userId,
      tokenId: info.id,
    });
    throw ApiError.unauthorized(
      "Refresh token reuse detected. All sessions have been revoked.",
      {
        code: "TOKEN_REVOKED",
      },
    );
  }

  /**
   * Retrieves a user by their ID, optionally verifying their role.
   *
   * @param {string} userId - The ID of the user to retrieve.
   * @param {string} [role] - The role of the user to retrieve.
   * @returns {Promise<Object|null>} - The user object if found, otherwise null.
   */
  async getUserById(userId, role = null) {
    if (!userId || typeof userId !== "string") {
      return null; // Return null if userId is not provided or not a string
    }

    const where = { id: userId };
    if (role) {
      where.role = role;
    }

    const user = await prisma.user.findFirst({
      where,
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        role: true,
        status: true,
        emailVerified: true,
        lastLoginAt: true,
        passwordChangedAt: true,
        createdAt: true,
      },
    });
    return user;
  }

  /**
   * Generates an access token for a user based on their ID and role.
   *
   * @param {Object} user - The user object containing the user's ID and role.
   * @param {string} user.id - The ID of the user.
   * @param {string} user.role - The role of the user.
   * @returns {Promise<string>} - The generated access token.
   */
  async generateAccessToken({ id, role }) {
    const accessToken = await tokenUtils.signAccessToken({ id, role });
    return accessToken;
  }

  /**
   * Generates a refresh token for a user and stores it in the database.
   *
   * @param {string} userId - The ID of the user for whom the refresh token is generated.
   * @param {Object} metadata - Metadata containing user IP and user agent.
   * @param {string} metadata.userIp - The IP address of the user.
   * @param {string} metadata.userAgent - The user agent string of the user's device.
   * @param {Object} [client=prisma] - Prisma client or transaction object used to
   *   create the row, so callers can bundle it atomically with other writes.
   * @returns {Promise<{refreshToken: string, id: string}>} - The generated refresh token string and id.
   * @throws {ApiError} - Throws an error if the refresh token cannot be generated or stored.
   */
  async generateRefreshToken(userId, metadata, client = prisma) {
    const daysUntilExpiry = finalConfig.jwt.refreshExpiresIn;
    const refreshToken = await tokenUtils.signRefreshToken();
    const hashedRefreshToken = tokenUtils.hashToken(refreshToken);
    const expiryTime = tokenUtils.expiresAt(daysUntilExpiry * 24 * 60);

    const newRefreshToken = await client.refreshToken.create({
      data: {
        userId,
        tokenHash: hashedRefreshToken,
        expiresAt: expiryTime,
        userAgent: metadata.userAgent,
        ipAddress: metadata.userIp,
      },
    });
    return { refreshToken, id: newRefreshToken.id };
  }

  /**
   * Verifies an email verification token and marks the user's email as verified.
   *
   * @param {string} token - The email verification token to verify.
   * @returns {Promise<boolean>} - Returns true if the email verification is successful.
   * @throws {ApiError} - Throws a 400 bad request error if the token is invalid or has expired.
   */
  async verifyEmail(token) {
    const hashedToken = tokenUtils.hashToken(token);
    const verificationRecord = await prisma.emailVerification.findFirst({
      where: {
        tokenHash: hashedToken,
        expiresAt: { gte: new Date() },
      },
    });

    if (!verificationRecord) {
      throw ApiError.badRequest("Token is invalid or  has expired", undefined, {
        code: "TOKEN_INVALID",
      });
    }

    await prisma.$transaction(async tx => {
      await tx.emailVerification.update({
        where: { id: verificationRecord.id },
        data: {
          usedAt: new Date(),
        },
      });

      await tx.user.update({
        where: { id: verificationRecord.userId },
        data: {
          emailVerified: true,
        },
      });
    });

    return true;
  }

  /**
   * Resends the email verification token to a user who has not yet verified their email.
   *
   * @param {string} email - The email address of the user.
   * @returns {Promise<void>} - A promise that resolves when the email is sent.
   */
  async resendVerificationEmail(email) {
    const token = tokenUtils.verificationToken(6);
    const hashedToken = tokenUtils.hashToken(token);
    const expiryTime = tokenUtils.expiresAt(5);

    const user = await prisma.user.findFirst({
      where: {
        email,
        emailVerified: false,
      },
      select: {
        id: true,
        fullName: true,
        email: true,
      },
    });

    if (!user) {
      return; // If user is not found or already verified, do nothing
    }

    await prisma.$transaction(async tx => {
      await tx.emailVerification.deleteMany({
        where: { userId: user.id },
      });
      await tx.emailVerification.create({
        data: {
          userId: user.id,
          tokenHash: hashedToken,
          expiresAt: expiryTime,
        },
      });
    });

    new Email(user, token).sendEmailConfirmation().catch(error => {
      logger.warn("Email sending failed", { email, error });
    });
  }

  /**
   * Sends a password reset email to a user who has requested to reset their password.
   *
   * @param {string} email - The email address of the user requesting a password reset.
   * @returns {Promise<void>} - A promise that resolves when the password reset email is sent.
   */
  async sendPasswordResetEmail(email) {
    const token = tokenUtils.secureToken();
    const hashedToken = tokenUtils.hashToken(token);
    const expiryTime = tokenUtils.expiresAt(5);

    const user = await prisma.user.findFirst({
      where: {
        email,
      },
      select: {
        id: true,
        fullName: true,
        email: true,
      },
    });

    if (!user) {
      return; // Silently return if the user does not exist to prevent email enumeration
    }

    await prisma.$transaction(async tx => {
      await tx.passwordReset.deleteMany({
        where: { userId: user.id },
      });
      await tx.passwordReset.create({
        data: {
          userId: user.id,
          tokenHash: hashedToken,
          expiresAt: expiryTime,
        },
      });
    });

    new Email(user).sendPasswordReset(token).catch(error => {
      logger.warn("Password reset email sending failed", { email, error });
    });
  }

  /**
   * Resets a user's password using a verification token.
   *
   * @param {string} token - The verification token for the password reset.
   * @param {string} newPassword - The new password for the user.
   * @returns {Promise<void>} - A promise that resolves when the password is reset.
   */
  async resetPassword(token, newPassword) {
    const hashedToken = tokenUtils.hashToken(token);
    const resetRecord = await prisma.passwordReset.findFirst({
      where: {
        tokenHash: hashedToken,
        expiresAt: { gte: new Date() },
      },
      select: {
        id: true,
        userId: true,
        usedAt: true,
      },
    });

    if (!resetRecord || resetRecord.usedAt) {
      throw ApiError.badRequest("Token is invalid or has expired", undefined, {
        code: "TOKEN_INVALID",
      });
    }

    const hashedPassword = await hashUtils.hashPassword(newPassword);

    try {
      await prisma.$transaction(async tx => {
        // Read the clock from the DB so passwordChangedAt shares a time domain
        // with refreshToken.createdAt (DB DEFAULT CURRENT_TIMESTAMP) — the
        // stale-family guard in rotateRefreshToken compares the two directly.
        const [{ now: dbNow }] = await tx.$queryRaw`SELECT NOW() AS now`;

        await tx.user.update({
          where: {
            id: resetRecord.userId,
            status: { not: "DEACTIVATED" },
          },
          data: {
            passwordHash: hashedPassword,
            passwordChangedAt: dbNow,
          },
        });

        const claimed = await tx.passwordReset.updateMany({
          where: { id: resetRecord.id, usedAt: null },
          data: {
            usedAt: dbNow,
          },
        });

        if (claimed.count === 0) {
          throw ApiError.badRequest(
            "Token is invalid or has expired",
            undefined,
            {
              code: "TOKEN_INVALID",
            },
          );
        }

        const revokeAllSessions = () =>
          tx.refreshToken.updateMany({
            where: { userId: resetRecord.userId, revokedAt: null },
            data: { revokedAt: dbNow },
          });

        // Grace copies point at successors that just died — clear them so a
        // replay can't resurrect a session after a credential invalidation.
        const clearGraceCopies = () =>
          tx.refreshToken.updateMany({
            where: { userId: resetRecord.userId, graceToken: { not: null } },
            data: { graceToken: null },
          });

        await revokeAllSessions();
        await clearGraceCopies();

        // Repeat both sweeps as the FINAL statements. A rotation transaction
        // that held the parent row's lock commits a successor invisible to our
        // earlier statement snapshots — under READ COMMITTED, UPDATE ... WHERE
        // re-checks only locked rows and never sees concurrent INSERTs. A
        // fresh snapshot here is what catches that late-committed successor.
        await revokeAllSessions();
        await clearGraceCopies();
      });
    } catch (error) {
      if (error instanceof ApiError) throw error; // Re-throw if it's an ApiError
      logger.error("Error resetting password", error);
      if (error?.code === "P2025") {
        throw ApiError.unauthorized("User not found or deactivated", {
          code: "USER_NOT_FOUND",
          cause: error,
        });
      }
      throw error; // Re-throw other unexpected errors
    }
  }

  /**
   * Logs out a user by revoking their refresh token and clearing any associated grace tokens.
   *
   * This method ensures that the user's session is terminated and prevents further use of the refresh token for obtaining new access tokens.
   * @param {string} userId - The ID of the user to log out.
   * @param {string} refreshToken - The refresh token to be revoked.
   * @returns {Promise<void>} - A promise that resolves when the logout process is complete.
   * @throws {ApiError} - Throws an error if the logout process fails due to database issues or other unexpected errors.
   */
  async logout(userId, refreshToken) {
    const hashedToken = tokenUtils.hashToken(refreshToken);

    try {
      await prisma.$transaction(async tx => {
        // Locate the specific refresh token record for the user
        const tokenRecord = await tx.refreshToken.findFirst({
          where: {
            userId,
            tokenHash: hashedToken,
          },
          select: {
            id: true,
          },
        });

        // If the token does not exist or was already purged, exit safely (idempotent logout)
        if (!tokenRecord) {
          logger.warn("Logout attempted with unrecognized or deleted token", {
            userId,
          });
          return; // Exit if the token is not found
        }

        // 2. Revoke the token and clear its grace token in ONE atomic update
        await tx.refreshToken.update({
          where: {
            id: tokenRecord?.id,
          },
          data: {
            revokedAt: new Date(),
            graceToken: null,
          },
        });

        // 3. Clean up any predecessor grace copies pointing to this revoked token
        await tx.refreshToken.updateMany({
          where: {
            replacedBy: tokenRecord.id,
            graceToken: { not: null },
          },
          data: {
            graceToken: null,
          },
        });
      });
      logger.info("User logged out successfully", { userId });
    } catch (error) {
      if (error instanceof ApiError) throw error; // Re-throw if it's an ApiError
      logger.error("Error during logout process", error);
      throw ApiError.internal("An error occurred during logout", {
        cause: error,
      });
    }
  }

  /**
   * Logs out a user from all sessions by revoking all their refresh tokens and clearing any associated grace tokens.
   *
   * This method ensures that the user's sessions are terminated across all devices and prevents further use of any refresh tokens for obtaining new access tokens.
   * @param {string} userId - The ID of the user to log out from all sessions.
   * @param {Object} metadata - Metadata about the request, including user IP and user agent.
   * @returns {Promise<void>} - A promise that resolves when the logout process is complete.
   * @throws {ApiError} - Throws an error if the userId is invalid or if the logout process fails due to database issues or other unexpected errors.
   */
  async logoutAll(userId, metadata = {}) {
    if (!userId || typeof userId !== "string") {
      throw ApiError.badRequest("Invalid user ID provided.");
    }

    try {
      await prisma.$transaction(async tx => {
        // Find all active refresh tokens for the user
        await tx.refreshToken.updateMany({
          where: {
            userId,
            revokedAt: null,
          },
          data: {
            revokedAt: new Date(),
            graceToken: null,
          },
        });

        // Clean up any grace copies pointing to the revoked tokens
        await tx.refreshToken.updateMany({
          where: {
            userId,
            graceToken: { not: null },
          },
          data: {
            graceToken: null,
          },
        });

        await tx.auditLog.create({
          data: {
            userId,
            action: "LOGOUT_ALL",
            resource: "auth",
            message: "User logged out from all sessions",
            ipAddress: metadata.userIp || null,
            userAgent: metadata.userAgent || null,
          },
        });
      });
    } catch (error) {
      if (error instanceof ApiError) throw error; // Re-throw if it's an ApiError
      logger.error("Error during logoutAll process", error);
      throw ApiError.internal("An error occurred during logoutAll", {
        cause: error,
      });
    }
  }

  /**
   * Changes a user's password after verifying the current password.
   *
   * @param {string} userId - The ID of the user whose password is to be changed.
   * @param {string} currentPassword - The current password of the user.
   * @param {string} newPassword - The new password to be set for the user.
   * @param {Object} [metadata] - Metadata about the user Ip and  user agent.
   * @returns {Promise<void>} - A promise that resolves when the password is successfully changed.
   */
  async changePassword(userId, currentPassword, newPassword, metadata = {}) {
    if (currentPassword === newPassword) {
      throw ApiError.badRequest(
        "New password cannot be the same as the current password.",
      );
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { passwordHash: true, status: true },
    });

    if (user.status !== "ACTIVE") {
      throw ApiError.badRequest("User account is inactive or not found.");
    }

    if (!user.passwordHash) {
      throw ApiError.badRequest(
        "This account was created via social login and does not have a password set.",
      );
    }

    if (
      !(await hashUtils.comparePassword(user.passwordHash, currentPassword))
    ) {
      throw ApiError.badRequest("Current password is incorrect.");
    }

    const newPasswordHash = await hashUtils.hashPassword(newPassword);

    try {
      await prisma.$transaction(async tx => {
        // Use Db clock so passwordChangedAt shares a time domain with refreshToken.createdAt
        const [{ now: dbNow }] = await tx.$queryRaw`SELECT NOW() AS now`;

        await tx.user.update({
          where: { id: userId },
          data: {
            passwordHash: newPasswordHash,
            passwordChangedAt: dbNow,
          },
        });
        await tx.refreshToken.updateMany({
          where: { userId, revokedAt: null },
          data: { revokedAt: dbNow, graceToken: null },
        });
        await tx.refreshToken.updateMany({
          where: { userId, graceToken: { not: null } },
          data: { graceToken: null },
        });
        await tx.auditLog.create({
          data: {
            userId,
            action: "PASSWORD_CHANGE",
            resource: "auth",
            details: "User changed their password",
            ipAddress: metadata?.userIp || null,
            userAgent: metadata?.userAgent || null,
          },
        });
      });
      logger.info("Password changed successfully", { userId });
    } catch (error) {
      if (error instanceof ApiError) throw error;
      logger.error("Error during password change process", { userId, error });
      throw ApiError.internal("An error occurred while changing the password", {
        cause: error,
      });
    }
  }

  /**
   * Updates a user's profile information, including full name, username, and email.
   *
   * @param {string} userId - The ID of the user whose profile is to be updated.
   * @param {Object} profileData - An object containing the new profile data.
   * @param {string} [profileData.fullName] - The new full name of the user.
   * @param {string} [profileData.username] - The new username of the user.
   * @param {string} [profileData.email] - The new email address of the user.
   * @returns {Promise<Object>} - The updated sanitized user object.
   */
  async updateUserProfile(userId, profileData, metadata = {}) {
    if (!userId || typeof userId !== "string") {
      throw ApiError.badRequest("Invalid user ID provided.");
    }
    const { fullName, username, email } = profileData;

    const currentUser = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        username: true,
        fullName: true,
        status: true,
      },
    });

    if (!currentUser || currentUser.status !== "ACTIVE") {
      throw ApiError.notFound("User not found or account is inactive.");
    }

    const updateData = {};
    let emailChanged = false;

    if (fullName !== undefined && fullName.trim() !== currentUser.fullName) {
      updateData.fullName = fullName.trim();
    }

    if (
      username !== undefined &&
      username.toLowerCase().trim() !== currentUser.username
    ) {
      updateData.username = username.toLowerCase().trim();
    }

    if (
      email !== undefined &&
      email.toLowerCase().trim() !== currentUser.email
    ) {
      updateData.email = email.toLowerCase().trim();
      updateData.emailVerified = false; // Mark email as unverified if changed
      emailChanged = true;
    }

    if (Object.keys(updateData).length === 0) {
      return currentUser; // No changes to update
    }
    const uniqueChecks = [];
    if (updateData.username)
      uniqueChecks.push({ username: updateData.username });
    if (updateData.email) uniqueChecks.push({ email: updateData.email });

    if (uniqueChecks.length > 0) {
      const conflictUser = await prisma.user.findFirst({
        where: {
          OR: uniqueChecks,
          NOT: { id: userId },
        },
        select: { username: true, email: true },
      });
      if (conflictUser) {
        if (conflictUser.username === updateData.username) {
          throw ApiError.conflict("Username is already taken");
        }
        if (conflictUser.email === updateData.email) {
          throw ApiError.conflict(
            "Email is already registered by another user.",
          );
        }
      }
    }

    try {
      const updatedUser = await prisma.user.$transaction(async tx => {
        const user = await tx.user.update({
          where: { id: userId },
          data: updateData,
          select: {
            id: true,
            fullName: true,
            username: true,
            email: true,
            role: true,
            status: true,
            emailVerified: true,
            createdAt: true,
            updatedAt: true,
          },
        });

        if (emailChanged) {
          await tx.auditLog.create({
            data: {
              userId,
              action: "EMAIL_CHANGE",
              resource: "user",
              details: `User changed their email to ${updateData.email} from ${currentUser.email}`,
              ipAddress: metadata?.userIp || null,
              userAgent: metadata?.userAgent || null,
            },
          });
        }

        return user;
      });
      if (emailChanged) {
        await this.resendVerificationEmail(updatedUser.email);
      }
      logger.info("User profile updated successfully", { userId });
      return updatedUser;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if(error?.code === "P2002") {
        throw ApiError.conflict("Username or email is already in use.");
      }
      logger.error("Error updating user profile", { userId, error });
      throw ApiError.internal("An error occurred while updating the profile", {
        cause: error,
      });
    }
  }
}

export default new AuthService();
