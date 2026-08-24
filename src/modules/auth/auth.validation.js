import * as z from "zod";

/**
 * Reserved usernames that cannot be used for registration.
 * These usernames are commonly associated with administrative or
 * system accounts and are therefore restricted to prevent confusion or misuse.
 */
const RESERVED_USERNAMES = new Set([
  "admin",
  "user",
  "test",
  "root",
  "api",
  "null",
  "undefined",
  "system",
  "support",
  "help",
  "contact",
]);

/**
 * Helper function to convert empty strings to undefined.
 * This is useful for preprocessing input values before validation,
 * ensuring that empty strings are treated as missing values rather than valid input.
 * @param {any} value - The input value to preprocess.
 * @returns {string|undefined} - Returns the trimmed string if it's not empty, otherwise returns undefined.
 */
const emptyToUndefined = value => {
  if (typeof value !== "string") return value;

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

/**
 * Validation schema for email addresses.
 * This schema ensures that the email is a valid string, normalized, trimmed,
 * converted to lowercase, and does not exceed 254 characters. It also checks
 * that the email format is correct.
 */
const emailSchema = z.preprocess(
  emptyToUndefined,
  z
    .string("Email is required")
    .normalize("NFC")
    .trim()
    .toLowerCase()
    .max(254)
    .pipe(z.email("Invalid email address")),
);

/**
 * Validation schema for login identifiers (username or email).
 * This schema ensures that the identifier is a valid string, normalized, trimmed,
 * converted to lowercase, and does not exceed 254 characters.
 */
const loginIdentifierSchema = z.preprocess(
  emptyToUndefined,
  z
    .string("Username or Email is required")
    .normalize("NFC")
    .trim()
    .toLowerCase()
    .min(3)
    .max(254),
);

/**
 * Validation schema for registration form data.
 * This schema ensures that all required fields are provided and meet the specified criteria.
 */
const registerSchema = {
  body: z
    .object({
      fullName: z
        .string("Full name is required")
        .trim()
        .min(2, "Full name must be at least 2 characters long")
        .max(100, "Full name must not exceed 100 characters")
        .regex(
          /^(?=.*\p{L})[\p{L}\p{M}'\-. ]+$/u,
          "Full name contains invalid characters",
        ),
      username: z
        .string("Username is required")
        .normalize("NFC")
        .trim()
        .toLowerCase()
        .regex(
          /^[a-z0-9_]+$/,
          "Username can only contain letters, numbers, and underscores",
        )
        .min(3)
        .max(30, "Username must be between 3 and 30 characters")
        .refine(
          username => !RESERVED_USERNAMES.has(username),
          "This username is not available. Please choose a different one.",
        ),
      email: emailSchema,
      password: z
        .string("Password is required")
        .normalize("NFC")
        .min(8, "Password must be at least 8 characters long")
        .max(72, "Password must not exceed 72 characters")
        .regex(
          /^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).*$/,
          "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
        ),
      confirmPassword: z
        .string("Confirm password is required")
        .normalize("NFC"),
    })
    .refine(data => data.password === data.confirmPassword, {
      message: "Passwords do not match",
    })
    .strict(),
};

/**
 * Validation schema for login form data.
 * This schema ensures that the login identifier and password are provided and meet the specified criteria.
 */
const loginSchema = {
  body: z
    .object({
      loginIdentifier: loginIdentifierSchema,
      password: z.string("Password is required").min(1).max(72),
    })
    .strict(),
};

/**
 * Validation schema for resending verification email.
 * This schema ensures that the email is provided and meets the specified criteria.
 */
const resendVerificationSchema = {
  body: z
    .object({
      email: emailSchema,
    })
    .strict(),
};

/**
 * Validation schema for refreshing authentication tokens.
 * This schema ensures that the refresh token is provided and meets the specified criteria.
 */
const refreshTokenSchema = {
  body: z
    .object({
      refreshToken: z.string("Refresh token is required").min(1),
    })
    .strict(),
};

/**
 * Validation schema for verifying email addresses.
 * This schema ensures that the verification token is provided and meets the specified criteria.
 */
const verifyEmailSchema = {
  body: z.object({
    token: z
      .string("Verification token is required")
      .min(6, "Verification token must be at least 6 characters long"),
  }),
};

/**
 * Validation schemas for resending verification email
 * This schema ensures that the email is provided and meets the specified criteria.
 */
const resendVerificationEmailSchema = {
  body: z.object({
    email: emailSchema,
  }),
};

/**
 * Validation schema for resetting passwords.
 * This schema ensures that the reset token, new password, and confirmation of the new password are provided and meet the specified criteria.
 */
const resetPasswordSchema = {
  params: z.object({
    token: z
      .string("Reset token is required")
      .min(8, "Reset token must be at least 8 characters long"),
  }),
  body: z
    .object({
      newPassword: z
        .string("Password is required")
        .normalize("NFC")
        .min(8, "Password must be at least 8 characters long")
        .max(72, "Password must not exceed 72 characters")
        .regex(
          /^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).*$/,
          "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
        ),
      confirmNewPassword: z
        .string("Confirm password is required")
        .normalize("NFC"),
    })
    .refine(data => data.newPassword === data.confirmNewPassword, {
      message: "Passwords do not match",
    })
    .strict(),
};

export default {
  registerSchema,
  loginSchema,
  resendVerificationSchema,
  resendVerificationEmailSchema,
  refreshTokenSchema,
  verifyEmailSchema,
  resetPasswordSchema,
};
