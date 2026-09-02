import * as z from "zod";

const getUsersSchema = {
  query: z.object({
    page: z.coerce.number().int().min(1).optional(),
    limit: z.coerce.number().int().min(1).max(100).optional(),
    role: z.enum(["USER", "ADMIN"]).optional(),
    status: z.enum(["ACTIVE", "SUSPENDED", "DEACTIVATED"]).optional(),
    search: z.string().trim().optional(),
  }),
};

export default {
  getUsersSchema,
};
