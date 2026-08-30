import crypto from "crypto";

import prisma from "../../config/db.js";
import logger from "../../config/logger.js";
import ApiError from "../../utils/ApiError.js";
import hashUtils from "../../utils/hash.utils.js";
import tokenUtils from "../../utils/token.utils.js";
import Email from "../../utils/email.utils.js";
import finalConfig from "../../config/keys.js";
import redisService from "../../config/redis.js";

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

    // First, check if the username or email already exists in the database
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
      },
    });

    // If an existing user is found, throw a conflict error with a specific message
    if (existingUser) {
      if (existingUser.username === username) {
        throw ApiError.conflict("Username is already taken");
      }
      if (existingUser.email === email) {
        throw ApiError.conflict("Email is already registered");
      }
    }

    // Hash the user's password before storing it in the database
    const hashedPassword = await hashUtils.hashPassword(password);

    // Generate a verification token for email confirmation, hash it, and set an expiry time
    const token = tokenUtils.verificationToken(6);
    let hashToken = tokenUtils.hashToken(token);
    let expiryTime = tokenUtils.expiresAt(5);

    // Use a transaction to create the user and the email verification record atomically
    const user = await prisma.$transaction(async tx => {
      // Create the new user in the database
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

      // If the user's email is not verified, create an email verification record in the database
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

    // Send the email confirmation asynchronously, logging any errors without blocking the registration process
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

    // Find the user by email or username, selecting only the necessary fields for authentication
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

    // Initialize the failed attempts count based on the user's record, defaulting to 0 if the user is not found
    let failedAttemptsCount = user ? user.failedAttempts : 0;

    // If the user is not found, perform a fake password comparison to prevent timing attacks and throw an unauthorized error
    if (!user) {
      await hashUtils.fakeComparePassword(); // Prevent timing attacks
      throw ApiError.unauthorized("Invalid login credentials");
    }

    // Check the user's status and throw an unauthorized error if the account is deactivated
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

    // Check if the user's account is locked and throw an unauthorized error if it is
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

    // Check if the user's email is verified and throw an unauthorized error if it is not
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

    // If the password is incorrect, increment the failed attempts count and handle account locking if necessary
    if (!(await hashUtils.comparePassword(user.passwordHash, password))) {
      failedAttemptsCount++;

      // Lock the account if the failed attempts exceed the threshold and the user is not an admin
      if (failedAttemptsCount >= 5 && user.role !== "ADMIN") {
        const lockDuration = 15 * 60 * 1000; // 15 minutes
        const lockedUntil = new Date(Date.now() + lockDuration);
        await prisma.$transaction([
          await prisma.user.update({
            where: { id: user.id },
            data: { lockedUntil, failedAttempts: 0 },
          }),
          await prisma.auditLog.create({
            data: {
              userId: user.id,
              action: "ACCOUNT_LOCKED",
              resource: "auth",
              details: {
                message: `Account locked due to multiple failed login attempts.`,
              },
              ipAddress: metadata?.userIp || null,
              userAgent: metadata?.userAgent || null,
            },
          }),
        ]);
        throw ApiError.unauthorized(
          "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
        );
      }

      // Update the failed attempts count in the user's record and log the failed login attempt
      await prisma.user.update({
        where: { id: user.id },
        data: { failedAttempts: failedAttemptsCount },
      });

      // Log the failed login attempt in the login history
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

    // If the login is successful, reset the failed attempts count and update the user's last login information
    const accessToken = await this.generateAccessToken(user);
    const { refreshToken } = await this.generateRefreshToken(user.id, metadata);

    // Log the successful login attempt and update the user's last login information in a transaction
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

    // Look up the refresh token in the database, selecting relevant fields for validation and rotation
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
            sessionsRevokedAt: true,
          },
        },
      },
    });

    /*
    if (!tokenInfo) {
      throw ApiError.unauthorized("Invalid refresh token", {
        code: "TOKEN_INVALID",
      });
    } */

    // Check if the refresh token has expired and throw an unauthorized error if it has
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

    // A session revoke kills every family minted before it. Rejecting rows older than the session revoke time.
    if (
      tokenInfo.user.sessionsRevokedAt &&
      tokenInfo.createdAt < tokenInfo.user.sessionsRevokedAt
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
      return this.handleReplay(tokenInfo, { userIp, userAgent });
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
   * @param {Object} metadata - Metadata containing user IP and user agent.
   * @returns {Promise<Object>} - An object containing a fresh access token and the surviving refresh token.
   * @throws {ApiError} - Throws a 401 TOKEN_REVOKED when reuse is detected, TOKEN_INVALID when the successor is dead.
   */
  async handleReplay(tokenInfo, metadata = {}) {
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
          id: true,
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
      prisma.auditLog.create({
        data: {
          userId: info.userId,
          action: "TOKEN_REUSE_DETECTED",
          resource: "auth",
          details: {
            message: `Refresh token reuse detected. All sessions have been revoked.`,
          },
          ipAddress: metadata?.userIp || null,
          userAgent: metadata?.userAgent || null,
        },
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
    // Validate that userId is provided and is a string; return null if not
    if (!userId || typeof userId !== "string") {
      return null; // Return null if userId is not provided or not a string
    }

    // Build the query conditionally based on whether a role is provided, and retrieve the user from the database
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
        sessionsRevokedAt: true,
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
   * Verifies an email verification token, send welcome email, and marks the user's email as verified.
   *
   * @param {string} token - The email verification token to verify.
   * @param {Object} metadata - Metadata about the request.
   * @returns {Promise<boolean>} - Returns true if the email verification is successful.
   * @throws {ApiError} - Throws a 400 bad request error if the token is invalid or has expired.
   */
  async verifyEmail(token, metadata = {}) {
    // Hash the provided token
    const hashedToken = tokenUtils.hashToken(token);

    // Look up the email verification record in the database using the hashed token and check if it has expired
    const verificationRecord = await prisma.emailVerification.findFirst({
      where: {
        tokenHash: hashedToken,
        expiresAt: { gte: new Date() },
      },
    });

    // If no valid verification record is found, throw a bad request error indicating that the token is invalid or has expired
    if (!verificationRecord) {
      throw ApiError.badRequest("Token is invalid or  has expired", undefined, {
        code: "TOKEN_INVALID",
      });
    }

    // Use a transaction to update the email verification record, mark the user's email as verified, and create an audit log entry
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

      await tx.auditLog.create({
        data: {
          userId: verificationRecord.userId,
          action: "EMAIL_VERIFIED",
          resource: "auth",
          details: {
            message: `User verified their email.`,
          },
          ipAddress: metadata?.userIp || null,
          userAgent: metadata?.userAgent || null,
        },
      });
    });

    const user = prisma.user.find({
      where: { id: verificationRecord.userId },
      select: {
        id: true,
        fullName: true,
        email: true,
      },
    });

    // Send the welcome email asynchronously, logging any errors without blocking the process
    new Email(user).sendWelcomeEmail().catch(error => {
      logger.warn("Welcome email sending failed", { email: user.email, error });
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
    // Generate a new verification token, hash it, and set an expiry time
    const token = tokenUtils.verificationToken(6);
    const hashedToken = tokenUtils.hashToken(token);
    const expiryTime = tokenUtils.expiresAt(5);

    // Look up the user in the database by email, ensuring that the email is not already verified
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

    // If the user is not found or the email is already verified, do nothing and return
    if (!user) {
      return; // If user is not found or already verified, do nothing
    }

    // Use a transaction to delete any existing email verification records for the user and create a new one with the new token
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

    // Send the email confirmation asynchronously, logging any errors without blocking the process
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
    // Generate a new password reset token, hash it, and set an expiry time
    const token = tokenUtils.secureToken();
    const hashedToken = tokenUtils.hashToken(token);
    const expiryTime = tokenUtils.expiresAt(5);

    // Look up the user in the database by email, selecting only the necessary fields for sending the password reset email
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

    // Use a transaction to delete any existing password reset records for the user and create a new one with the new token
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

    // Send the password reset email asynchronously, logging any errors without blocking the process
    new Email(user).sendPasswordReset(token).catch(error => {
      logger.warn("Password reset email sending failed", { email, error });
    });
  }

  /**
   * Resets a user's password using a verification token.
   *
   * @param {string} token - The verification token for the password reset.
   * @param {string} newPassword - The new password for the user.
   * @param {Object} metadata - Metadata about the request.
   * @returns {Promise<void>} - A promise that resolves when the password is reset.
   */
  async resetPassword(token, newPassword, metadata = {}) {
    // Hash the provided token
    const hashedToken = tokenUtils.hashToken(token);

    // Look up the password reset record in the database using the hashed token and check if it has expired or has already been used
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

    // If no valid reset record is found or it has already been used, throw a bad request error indicating that the token is invalid or has expired
    if (!resetRecord || resetRecord.usedAt) {
      throw ApiError.badRequest("Token is invalid or has expired", undefined, {
        code: "TOKEN_INVALID",
      });
    }

    // Hash the new password before storing it in the database
    const hashedPassword = await hashUtils.hashPassword(newPassword);

    // Use a transaction to update the user's password, mark the password reset record as used, revoke all active sessions, clear any grace copies, and create an audit log entry
    try {
      await prisma.$transaction(async tx => {
        const dbNow = new Date(); // Use a single timestamp for all operations in this transaction

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

        // If the password reset record was not claimed (i.e., it was already used), throw an error indicating that the token is invalid or has expired
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

        await tx.auditLog.create({
          data: {
            userId: resetRecord.userId,
            action: "PASSWORD_RESET",
            resource: "auth",
            details: {
              message: `User reset their password`,
            },
            ipAddress: metadata?.userIp || null,
            userAgent: metadata?.userAgent || null,
          },
        });
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
   * @param {Object} decoded - The decoded JWT token info to be used for revocation.
   * @returns {Promise<void>} - A promise that resolves when the logout process is complete.
   * @throws {ApiError} - Throws an error if the logout process fails due to database issues or other unexpected errors.
   */
  async logout(userId, refreshToken, decoded) {
    // Hash the provided refresh token
    const hashedToken = tokenUtils.hashToken(refreshToken);

    // Calculate the remaining TTL (time-to-live) in seconds for the token based on its expiration time
    const remainingTtlSeconds = Math.max(
      0,
      decoded.exp - Math.floor(Date.now() / 1000),
    );

    // If the token has a valid remaining TTL and a unique identifier (jti), store it in the Redis denylist to prevent reuse of the same token
    if (remainingTtlSeconds > 0 && decoded.jti) {
      //Set key with auto-expiry equal to token's remaining TTL to prevent reuse of the same token
      await redisService.set(
        `denylist:${decoded.jti}`,
        "revoked",
        remainingTtlSeconds,
      );
    }

    // Use a transaction to locate the specific refresh token record for the user, revoke it, clear its grace token, and clean up any predecessor grace copies pointing to this revoked token
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
    // Validate that userId is provided and is a string; throw an error if not
    if (!userId || typeof userId !== "string") {
      throw ApiError.badRequest("Invalid user ID provided.");
    }

    // Use a transaction to revoke all active refresh tokens for the user, clear any grace copies, update the user's sessionRevokedAt timestamp, and create an audit log entry
    try {
      await prisma.$transaction(async tx => {
        // Find all active refresh tokens for the user and revoke them
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

        await tx.user.update({
          where: { id: userId },
          data: {
            sessionRevokedAt: new Date(),
          },
        });

        await tx.auditLog.create({
          data: {
            userId,
            action: "LOGOUT_ALL",
            resource: "auth",
            details: { message: "User logged out from all sessions" },
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
    // Validate the current password and new password inputs
    if (currentPassword === newPassword) {
      throw ApiError.badRequest(
        "New password cannot be the same as the current password.",
      );
    }

    // Look up the user in the database by their ID, selecting only the necessary fields for password verification and status check
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { passwordHash: true, status: true },
    });

    // If the user is not found or their account is inactive, throw a bad request error
    if (user.status !== "ACTIVE") {
      throw ApiError.badRequest("User account is inactive or not found.");
    }

    // If the user does not have a password set (e.g., account created via social login), throw a bad request error
    if (!user.passwordHash) {
      throw ApiError.badRequest(
        "This account was created via social login and does not have a password set.",
      );
    }

    // Verify that the provided current password matches the stored password hash; if not, throw a bad request error
    if (
      !(await hashUtils.comparePassword(user.passwordHash, currentPassword))
    ) {
      throw ApiError.badRequest("Current password is incorrect.");
    }

    // Hash the new password before storing it in the database
    const newPasswordHash = await hashUtils.hashPassword(newPassword);

    // Use a transaction to update the user's password, update the passwordChangedAt timestamp, revoke all active refresh tokens, clear any grace copies, and create an audit log entry
    try {
      await prisma.$transaction(async tx => {
        // Use Db clock so passwordChangedAt shares a time domain with refreshToken.createdAt
        const dbNow = new Date();

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
            details: { message: "User changed their password" },
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
    // Validate that userId is provided and is a string; throw an error if not
    if (!userId || typeof userId !== "string") {
      throw ApiError.badRequest("Invalid user ID provided.");
    }

    // Destructure the profileData object to extract the new full name, username, and email values
    const { fullName, username, email } = profileData;

    // Look up the current user in the database by their ID, selecting only the necessary fields for profile update and status check
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

    // If the user is not found or their account is inactive, throw a not found error
    if (!currentUser || currentUser.status !== "ACTIVE") {
      throw ApiError.notFound("User not found or account is inactive.");
    }

    // Prepare an object to hold the fields to be updated and a flag to track if the email has changed
    const updateData = {};
    let emailChanged = false;

    // Check if the new full name is provided and different from the current full name; if so, add it to the updateData object
    if (fullName !== undefined && fullName.trim() !== currentUser.fullName) {
      updateData.fullName = fullName.trim();
    }

    // Check if the new username is provided and different from the current username; if so, add it to the updateData object
    if (
      username !== undefined &&
      username.toLowerCase().trim() !== currentUser.username
    ) {
      updateData.username = username.toLowerCase().trim();
    }

    // Check if the new email is provided and different from the current email; if so, add it to the updateData object, mark the email as unverified, and revoke all sessions
    if (
      email !== undefined &&
      email.toLowerCase().trim() !== currentUser.email
    ) {
      updateData.email = email.toLowerCase().trim();
      updateData.emailVerified = false; // Mark email as unverified if changed
      updateData.sessionsRevokedAt = new Date(); // Revoke all sessions if email is changed
      emailChanged = true;
    }

    // If there are no changes to update, return the current user object
    if (Object.keys(updateData).length === 0) {
      return currentUser; // No changes to update
    }

    // Check for uniqueness of username and email if they are being updated, and throw a conflict error if either is already taken by another user
    const uniqueChecks = [];
    if (updateData.username)
      uniqueChecks.push({ username: updateData.username });
    if (updateData.email) uniqueChecks.push({ email: updateData.email });

    // Check for uniqueness of username and email if they are being updated
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

    // Use a transaction to update the user's profile, create an audit log entry if the email has changed, and resend the verification email if necessary
    try {
      const updatedUser = await prisma.$transaction(async tx => {
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
              details: {
                message: `User changed their email to ${updateData.email} from ${currentUser.email}`,
                previousEmail: currentUser.email,
                newEmail: updateData.email,
              },
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
      logger.error("Error updating user profile", { userId, error });
      if (error instanceof ApiError) throw error;
      if (error?.code === "P2002") {
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
