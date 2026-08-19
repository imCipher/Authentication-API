import crypto from "crypto";

import prisma from "../../config/db.js";
import logger from "../../config/logger.js";
import ApiError from "../../utils/ApiError.js";
import hashUtils from "../../utils/hash.utils.js";
import tokenUtils from "../../utils/token.utils.js";
import Email from "../../Utils/email.utils.js";
import finalConfig from "../../config/keys.js";
import { access } from "fs";

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
        throw ApiError.conflict("Username is already taken", {
          code: "USERNAME_TAKEN",
        });
      }
      if (existingUser.email === email) {
        throw ApiError.conflict("Email is already registered", {
          code: "EMAIL_REGISTERED",
        });
      }
    }

    const hashedPassword = await hashUtils.hashPassword(password);

    const token = tokenUtils.verificationToken(4);
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

      if (newUser.emailVerified !== "true") {
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

    // Revoke the old refresh token
    await prisma.refreshToken.update({
      where: { id: tokenInfo.id },
      data: { revokedAt: new Date(), replacedByToken: newHashedToken },
    });

    const accessToken = await this.generateAccessToken(tokenInfo.user);

    const newRefreshToken = await this.generateRefreshToken(tokenInfo.userId, {
      userIp,
      userAgent,
    });

    return { accessToken, refreshToken: newRefreshToken };
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

    await prisma.refreshToken.create({
      data: {
        userId,
        tokenHash: hashedRefreshToken,
        expiresAt: expiryTime,
        userAgent: metadata.userAgent,
        ipAddress: metadata.userIp,
      },
    });
    return refreshToken;
  }

  async resendVerificationEmail(user) {
    const email = user.email;
    const token = tokenUtils.verificationToken(4);
    const hashedToken = tokenUtils.hashToken(token);
    const expiryTime = tokenUtils.expiresAt(5);
    await prisma.$transaction(async tx => {
      await tx.user.findFirst({
        where: {
          id: user.id,
          emailVerified: false,
        },
      });

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
