import crypto from "crypto";

import prisma from "../../config/db.js";
import logger from "../../config/logger.js";
import ApiError from "../../utils/ApiError.js";
import hashUtils from "../../utils/hash.utils.js";
import tokenUtils from "../../utils/token.utils.js";
import Email from "../../Utils/email.utils.js";
import finalConfig from "../../config/keys.js";

/**
 * Service class for handling user-related business logic.
 */
class AuthService {
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

    if (!(await hashUtils.comparePassword(user.passwordHash, password))) {
      failedAttemptsCount++;
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
      failedAttemptsCount++;
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

    if (failedAttemptsCount >= 5 && user.role !== "admin") {
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

    const accessToken = await this.generateAccessToken(user);
    const refreshToken = await this.generateRefreshToken(user.id, metadata);

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

  async generateAccessToken({ id, role }) {
    const accessToken = await tokenUtils.signAccessToken({ id, role });
    return accessToken;
  }

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
    return newRefreshToken;
  }

  async verifyEmail(token) {
    const hashedToken = tokenUtils.hashToken(token);
    const verificationRecord = await prisma.emailVerification.findFirst({
      where: {
        tokenHash: hashedToken,
        expiresAt: { gte: new Date() },
      },
    });

    if (!verificationRecord) {
      throw ApiError.badRequest("Token is invalid or  has expired", {
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

  async resendVerificationEmail({ email }) {
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
      throw ApiError.badRequest("User is already verified or does not exist");
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
}

export default new AuthService();
