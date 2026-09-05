import * as z from "zod";

/**
 * Preprocessor to convert empty or whitespace-only string to undefined.
 */
const emptyToUndefined = value => {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

/**
 * Validate query parameter for identifying a user by ID. Ensures the ID is a valid UUID string.
 */
const userIdParam = z
  .string("User ID is required")
  .trim()
  .toLowerCase()
  .pipe(z.uuid("Invalid user ID format. Must be a valid UUID."));

/**
 * Reusable user role schema with case normalization and custom error messages.
 */
const userRoleSchema = z.preprocess(
  val => {
    const cleaned = emptyToUndefined(val);
    return typeof cleaned === "string" ? cleaned.toUpperCase() : cleaned;
  },
  z.enum(["USER", "ADMIN"], {
    errorMap: () => ({ message: "Role must be either 'USER' or 'ADMIN'" }),
  }),
);

/**
 * Reusable user status schema with case normalization and custom error messages.
 */
const userStatusSchema = z.preprocess(
  val => {
    const cleaned = emptyToUndefined(val);
    return typeof cleaned === "string" ? cleaned.toUpperCase() : cleaned;
  },
  z.enum(["ACTIVE", "SUSPENDED", "DEACTIVATED"], {
    errorMap: () => ({
      message: "Status must be 'ACTIVE', 'SUSPENDED', or 'DEACTIVATED'",
    }),
  }),
);

/**
 * Validation schema for admin user listing query parameters.
 * Enforces pagination, filtering, searching, and sorting rules.
 */
const getUsersSchema = {
  query: z.object({
    page: z.preprocess(
      emptyToUndefined,
      z.coerce.number().int().min(1, "Page must be at least 1").default(1),
    ),
    limit: z.preprocess(
      emptyToUndefined,
      z.coerce
        .number()
        .int()
        .min(1)
        .max(100, "Limit cannot exceed 100")
        .default(10),
    ),
    role: userRoleSchema.optional(),
    status: userStatusSchema.optional(),
    search: z.preprocess(
      emptyToUndefined,
      z
        .string()
        .trim()
        .max(100, "Search query cannot exceed 100 characters")
        .optional(),
    ),
    sortBy: z.preprocess(
      emptyToUndefined,
      z
        .enum(["createdAt", "fullName", "email", "username", "lastLoginAt"])
        .default("createdAt"),
    ),
    sortOrder: z.preprocess(
      val => {
        const cleaned = emptyToUndefined(val);
        return typeof cleaned === "string" ? cleaned.toLowerCase() : cleaned;
      },
      z.enum(["asc", "desc"]).default("desc"),
    ),
  }),
};

/**
 * Validation schema for retrieving a single user by ID.
 * Enforces that the ID is a valid UUID string.
 */
const userIdParamsSchema = {
  params: z
    .object({
      id: userIdParam,
    })
    .strict(),
};

/**
 * Validation schema for updating a user's role and/or status.
 * Enforces that at least one of 'role' or 'status' is provided, and validates their values.
 */
const patchUserSchema = {
  params: z
    .object({
      id: userIdParam,
    })
    .strict(),
  body: z
    .object({
      role: userRoleSchema.optional(),
      status: userStatusSchema.optional(),
    })
    .strict()
    .refine(data => data.role !== undefined || data.status !== undefined, {
      message:
        "At least one of 'role' or 'status' must be provided for update.",
    }),
};

/**
 * Validation schema for querying audit logs with optional filters and pagination.
 * Enforces that 'page' and 'limit' are positive integers, and validates optional filters.
 */
const getAuditLogsSchema = {
  query: z.object({
    page: z.preprocess(
      emptyToUndefined,
      z.coerce.number().int().min(1, "Page must be at least 1").default(1),
    ),
    limit: z.preprocess(
      emptyToUndefined,
      z.coerce
        .number()
        .int()
        .min(1)
        .max(100, "Limit cannot exceed 100")
        .default(10),
    ),
    search: z.preprocess(
      emptyToUndefined,
      z
        .string()
        .trim()
        .max(100, "Search query cannot exceed 100 characters")
        .optional(),
    ),
    sortBy: z.preprocess(
      emptyToUndefined,
      z
        .enum(["createdAt", "action", "adminId", "targetUserId"])
        .default("createdAt"),
    ),
    sortOrder: z.preprocess(
      val => {
        const cleaned = emptyToUndefined(val);
        return typeof cleaned === "string" ? cleaned.toLowerCase() : cleaned;
      },
      z.enum(["asc", "desc"]).default("desc"),
    ),
  }),
};
export default {
  getUsersSchema,
  userIdParamsSchema,
  patchUserSchema,
  getAuditLogsSchema,
};
