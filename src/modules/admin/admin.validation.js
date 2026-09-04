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
    role: z.preprocess(
      val => {
        const cleaned = emptyToUndefined(val);
        return typeof cleaned === "string" ? cleaned.toUpperCase() : cleaned;
      },
      z.enum(["USER", "ADMIN"]).optional(),
    ),
    status: z.preprocess(
      val => {
        const cleaned = emptyToUndefined(val);
        return typeof cleaned === "string" ? cleaned.toUpperCase() : cleaned;
      },
      z.enum(["ACTIVE", "SUSPENDED", "DEACTIVATED"]).optional(),
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

export default {
  getUsersSchema,
};
