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
        ipAddress: userIp,
        userAgent,
      },
      select: {
        id: true,
        userId: true,
        expiresAt: true,
        revokedAt: true,
        user: {
          select: {
            id: true,
            role: true,
          },
        },
      },
    });

    if (!tokenInfo) {
      throw ApiError.unauthorized("Invalid refresh token", {
        code: "TOKEN_INVALID",
      });
    } else if (tokenInfo.expiresAt < new Date()) {
      throw ApiError.unauthorized("Refresh token expired", {
        code: "TOKEN_EXPIRED",
      });
    }

    if (tokenInfo.revokedAt) {
      await prisma.refreshToken.updateMany({
        where: { userId: tokenInfo.userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      throw ApiError.unauthorized(
        "Refresh token reuse detected. All sessions have been revoked.",
        {
          code: "TOKEN_REVOKED",
        },
      );
    }

    const accessToken = await this.generateAccessToken(tokenInfo.user);

    const newRefreshToken = await this.generateRefreshToken(tokenInfo.userId, {
      userIp,
      userAgent,
    });

    // Revoke the old refresh token
    await prisma.refreshToken.update({
      where: { id: tokenInfo.id },
      data: { revokedAt: new Date(), replacedBy: newRefreshToken.id },
    });

    return { accessToken, refreshToken: newRefreshToken.refreshToken };
  }

  /**
   * Retrieves a user by their ID and role.
   *
   * @param {string} userId - The ID of the user to retrieve.
   * @param {string} role - The role of the user to retrieve.
   * @returns {Promise<Object|null>} - The user object if found, otherwise null.
   */
  async getUserById(userId, role) {
    const user = await prisma.user.findFirst({
      where: {
        id: userId,
        role,
      },
      select: {
        id: true,
        fullName: true,
        username: true,
        email: true,
        role: true,
        emailVerified: true,
        createdAt: true,
        passwordChangedAt: true,
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
   * @returns {Promise<{refreshToken: string, id: string}>} - The generated refresh token string and id.
   * @throws {ApiError} - Throws an error if the refresh token cannot be generated or stored.
   */
  async generateRefreshToken(userId, metadata) {
    const daysUntilExpiry = finalConfig.jwt.refreshExpiresIn;
    const refreshToken = await tokenUtils.signRefreshToken();
    const hashedRefreshToken = tokenUtils.hashToken(refreshToken);
    const expiryTime = tokenUtils.expiresAt(daysUntilExpiry * 24 * 60);

    const newRefreshToken = await prisma.refreshToken.create({
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
        await tx.user.update({
          where: {
            id: resetRecord.userId,
            status: { not: "DEACTIVATED" },
          },
          data: {
            passwordHash: hashedPassword,
            passwordChangedAt: new Date(),
          },
        });

        const claimed = await tx.passwordReset.updateMany({
          where: { id: resetRecord.id, usedAt: null },
          data: {
            usedAt: new Date(),
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

        await tx.refreshToken.updateMany({
          where: { userId: resetRecord.userId, revokedAt: null },
          data: { revokedAt: new Date() },
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
}

export default new AuthService();
