import adminValidation from "../../../../src/modules/admin/admin.validation.js";

describe("Admin Validation Schemas", () => {
  const validUuid = "123e4567-e89b-12d3-a456-426614174000";

  describe("getUsersSchema.query", () => {
    it("should apply defaults when query is empty {}", () => {
      const result = adminValidation.getUsersSchema.query.safeParse({});

      expect(result.success).toBe(true);
      expect(result.data).toEqual({
        page: 1,
        limit: 10,
        sortBy: "createdAt",
        sortOrder: "desc",
      });
    });

    it("should coerce string numbers for page and limit and sanitize inputs", () => {
      const result = adminValidation.getUsersSchema.query.safeParse({
        page: "3",
        limit: "50",
        role: "admin", // should uppercase
        status: "active", // should uppercase
        search: "  John Doe  ", // should trim
        sortBy: "email",
        sortOrder: "ASC", // should lowercase
      });

      expect(result.success).toBe(true);
      expect(result.data).toEqual({
        page: 3,
        limit: 50,
        role: "ADMIN",
        status: "ACTIVE",
        search: "John Doe",
        sortBy: "email",
        sortOrder: "asc",
      });
    });

    it("should reject page < 1 or non-integer page", () => {
      const negativeResult = adminValidation.getUsersSchema.query.safeParse({
        page: "0",
      });
      const decimalResult = adminValidation.getUsersSchema.query.safeParse({
        page: "1.5",
      });

      expect(negativeResult.success).toBe(false);
      expect(decimalResult.success).toBe(false);
    });

    it("should reject limit < 1 or limit > 100", () => {
      const zeroResult = adminValidation.getUsersSchema.query.safeParse({
        limit: "0",
      });
      const tooLargeResult = adminValidation.getUsersSchema.query.safeParse({
        limit: "101",
      });

      expect(zeroResult.success).toBe(false);
      expect(tooLargeResult.success).toBe(false);
      expect(tooLargeResult.error.issues[0].message).toBe(
        "Limit cannot exceed 100",
      );
    });

    it("should reject invalid role or status values", () => {
      const invalidRole = adminValidation.getUsersSchema.query.safeParse({
        role: "SUPERADMIN",
      });
      const invalidStatus = adminValidation.getUsersSchema.query.safeParse({
        status: "BANNED",
      });

      expect(invalidRole.success).toBe(false);
      expect(invalidRole.error.issues[0].message).toBe(
        'Invalid option: expected one of "USER"|"ADMIN"',
      );
      expect(invalidStatus.success).toBe(false);
      expect(invalidStatus.error.issues[0].message).toBe(
        'Invalid option: expected one of "ACTIVE"|"SUSPENDED"|"DEACTIVATED"',
      );
    });

    it("should reject search query exceeding 100 characters", () => {
      const result = adminValidation.getUsersSchema.query.safeParse({
        search: "a".repeat(101),
      });

      expect(result.success).toBe(false);
      expect(result.error.issues[0].message).toBe(
        "Search query cannot exceed 100 characters",
      );
    });

    it("should reject unauthorized sortBy fields to prevent SQL/ORM injection", () => {
      const result = adminValidation.getUsersSchema.query.safeParse({
        sortBy: "passwordHash",
      });

      expect(result.success).toBe(false);
    });

    it("should reject unknown query parameters due to strict mode", () => {
      const result = adminValidation.getUsersSchema.query.safeParse({
        maliciousParam: "true",
      });

      expect(result.success).toBe(false);
    });
  });

  describe("userIdParamsSchema.params", () => {
    it("should accept a valid UUID and normalize to lowercase", () => {
      const upperUuid = "123E4567-E89B-12D3-A456-426614174000";
      const result = adminValidation.userIdParamsSchema.params.safeParse({
        id: upperUuid,
      });

      expect(result.success).toBe(true);
      expect(result.data.id).toBe(upperUuid.toLowerCase());
    });

    it("should reject non-UUID strings or empty IDs", () => {
      const invalidIdResult =
        adminValidation.userIdParamsSchema.params.safeParse({
          id: "invalid-user-123",
        });
      const emptyResult = adminValidation.userIdParamsSchema.params.safeParse({
        id: "",
      });

      expect(invalidIdResult.success).toBe(false);
      expect(invalidIdResult.error.issues[0].message).toContain(
        "Invalid user ID format. Must be a valid UUID.",
      );
      expect(emptyResult.success).toBe(false);
    });

    it("should reject extra params", () => {
      const result = adminValidation.userIdParamsSchema.params.safeParse({
        id: validUuid,
        extra: "unknown",
      });

      expect(result.success).toBe(false);
    });
  });

  describe("patchUserSchema", () => {
    it("should accept valid params and updating role only", () => {
      const paramsResult = adminValidation.patchUserSchema.params.safeParse({
        id: validUuid,
      });
      const bodyResult = adminValidation.patchUserSchema.body.safeParse({
        role: "admin",
      });

      expect(paramsResult.success).toBe(true);
      expect(bodyResult.success).toBe(true);
      expect(bodyResult.data.role).toBe("ADMIN");
    });

    it("should accept updating status only", () => {
      const bodyResult = adminValidation.patchUserSchema.body.safeParse({
        status: "suspended",
      });

      expect(bodyResult.success).toBe(true);
      expect(bodyResult.data.status).toBe("SUSPENDED");
    });

    it("should accept updating both role and status simultaneously", () => {
      const bodyResult = adminValidation.patchUserSchema.body.safeParse({
        role: "user",
        status: "deactivated",
      });

      expect(bodyResult.success).toBe(true);
      expect(bodyResult.data).toEqual({
        role: "USER",
        status: "DEACTIVATED",
      });
    });

    it("should reject when empty body {} is provided (refinement check)", () => {
      const bodyResult = adminValidation.patchUserSchema.body.safeParse({});

      expect(bodyResult.success).toBe(false);
      expect(bodyResult.error.issues[0].message).toBe(
        "At least one of 'role' or 'status' must be provided for update.",
      );
    });

    it("should reject unexpected fields in request body", () => {
      const bodyResult = adminValidation.patchUserSchema.body.safeParse({
        role: "ADMIN",
        emailVerified: true, // Forbidden extra field
      });

      expect(bodyResult.success).toBe(false);
    });
  });

  describe("getAuditLogsSchema.query", () => {
    it("should apply defaults for empty audit logs query", () => {
      const result = adminValidation.getAuditLogsSchema.query.safeParse({});

      expect(result.success).toBe(true);
      expect(result.data).toEqual({
        page: 1,
        limit: 10,
        sortBy: "createdAt",
        sortOrder: "desc",
      });
    });

    it.each([
      "PASSWORD_CHANGE",
      "PASSWORD_RESET",
      "EMAIL_CHANGE",
      "EMAIL_VERIFIED",
      "ROLE_CHANGE",
      "STATUS_CHANGE",
      "ACCOUNT_UNLOCKED",
      "OAUTH_ACCOUNT_LINKED",
      "TOKEN_REUSE_DETECTED",
      "LOGOUT_ALL",
      "ACCOUNT_DELETED",
      "ACCOUNT_LOCKED",
    ])(
      "should accept valid audit action '%s' with case insensitivity",
      action => {
        const result = adminValidation.getAuditLogsSchema.query.safeParse({
          action: action.toLowerCase(),
        });

        expect(result.success).toBe(true);
        expect(result.data.action).toBe(action);
      },
    );

    it("should reject invalid audit action names", () => {
      const result = adminValidation.getAuditLogsSchema.query.safeParse({
        action: "INVALID_ACTION",
      });

      expect(result.success).toBe(false);
    });

    it("should reject unauthorized sortBy column", () => {
      const result = adminValidation.getAuditLogsSchema.query.safeParse({
        sortBy: "ipAddress",
      });

      expect(result.success).toBe(false);
    });
  });

  describe("getLoginHistorySchema.query", () => {
    it("should apply defaults for empty login history query", () => {
      const result = adminValidation.getLoginHistorySchema.query.safeParse({});

      expect(result.success).toBe(true);
      expect(result.data).toEqual({
        page: 1,
        limit: 10,
        sortBy: "createdAt",
        sortOrder: "desc",
      });
    });

    it("should accept valid userId filter formatted as UUID", () => {
      const result = adminValidation.getLoginHistorySchema.query.safeParse({
        userId: validUuid,
      });

      expect(result.success).toBe(true);
      expect(result.data.userId).toBe(validUuid);
    });

    it("should reject invalid userId filter", () => {
      const result = adminValidation.getLoginHistorySchema.query.safeParse({
        userId: "not-a-valid-uuid",
      });

      expect(result.success).toBe(false);
    });

    it("should allow sorting by allowed columns ('createdAt', 'success', 'userId')", () => {
      for (const sortBy of ["createdAt", "success", "userId"]) {
        const result = adminValidation.getLoginHistorySchema.query.safeParse({
          sortBy,
        });
        expect(result.success).toBe(true);
        expect(result.data.sortBy).toBe(sortBy);
      }
    });
  });
});
