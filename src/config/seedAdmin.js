import prisma from "./db.js";
import hashUtils from "../utils/hash.utils.js";
import finalConfig from "./keys.js";
import logger from "./logger.js";

/**
 * Seeds a default administrator into the database if one does not already exits.
 * This runs safely during server startup (idempotent).
 */
export const seedAdmin = async () => {
  const { fullName, email, username, password } = finalConfig.adminSeed;

  // Guard: check if a password was configured for the admin seed. If not, log a warning and skip seeding.
  if (!password || password === "12345") {
    logger.warn(
      "⚠️ No ADMIN_PASSWORD provided in environment. Skipping admin seed.",
    );
    return;
  }

  try {
    // Check if an admin account already exists in the database
    // We check both email and username because both have @unique constraints in schema.prisma
    const existingAdmin = await prisma.user.findFirst({
      where: {
        OR: [
          { email: email.toLowerCase() },
          { username: username.toLowerCase() },
          { role: "ADMIN" }, // or check if any user has the ADMIN role, to avoid creating multiple admins
        ],
      },
    });

    if (existingAdmin) {
      logger.info(
        `ℹ️ Admin account already exists (${existingAdmin.email}). Skipping seed.`,
      );
      return;
    }

    // Hash the admin password using Argon2 before storing it in the database
    const hashedPassword = await hashUtils.hashPassword(password);

    // Create the admin user in the database
    const newAdmin = await prisma.user.create({
      data: {
        fullName,
        username: username.toLowerCase(),
        email: email.toLowerCase(),
        passwordHash: hashedPassword,
        role: "ADMIN",
        status: "ACTIVE",
        emailVerified: true,
      },
    });
    logger.info(
      `🎉 Default admin seeded successfully: ${newAdmin.email} [${newAdmin.username}]`,
    );
  } catch (error) {
    logger.error(`❌ Error seeding default admin: ${error.message}`, {
      stack: error.stack,
    });
  }
};
