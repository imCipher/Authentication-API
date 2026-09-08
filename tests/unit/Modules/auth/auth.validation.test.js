import authValidation from "../../../../src/modules/auth/auth.validation.js";

describe("Auth Validation Schemas", () => {
  const validPassword = "Password123!";
  const validRegistrationPayload = {
    fullName: "Johnathan Doe",
    username: "johndoe_99",
    email: "john.doe@example.com",
    password: validPassword,
    confirmPassword: validPassword,
  };

  describe("registerSchema.body", () => {
    it("should succeed with a valid registration payload and normalize inputs", () => {
      const input = {
        fullName: "  Jane Doe  ",
        username: "  Jane_Doe99  ",
        email: "  JANE.DOE@EXAMPLE.COM  ",
        password: validPassword,
        confirmPassword: validPassword,
      };

      const result = authValidation.registerSchema.body.safeParse(input);

      expect(result.success).toBe(true);
      expect(result.data.fullName).toBe("Jane Doe");
      expect(result.data.username).toBe("jane_doe99");
      expect(result.data.email).toBe("jane.doe@example.com");
    });

    describe("fullName validation", () => {
      it("should reject full names shorter than 2 characters", () => {
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          fullName: "J",
        });

        expect(result.success).toBe(false);
        expect(result.error.issues[0].message).toContain(
          "at least 2 characters",
        );
      });

      it("should reject full names longer than 100 characters", () => {
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          fullName: "A".repeat(101),
        });

        expect(result.success).toBe(false);
        expect(result.error.issues[0].message).toContain(
          "not exceed 100 characters",
        );
      });

      it("should reject full names with numbers or invalid symbols", () => {
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          fullName: "John123",
        });

        expect(result.success).toBe(false);
        expect(result.error.issues[0].message).toContain("invalid characters");
      });

      it("should reject empty or whitespace-only full names", () => {
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          fullName: "   ",
        });

        expect(result.success).toBe(false);
        expect(result.error.issues[0].message).toContain(
          "Full name is required",
        );
      });
    });

    describe("username validation", () => {
      it("should reject usernames under 3 characters or over 30 characters", () => {
        const shortResult = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          username: "ab",
        });
        const longResult = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          username: "a".repeat(31),
        });

        expect(shortResult.success).toBe(false);
        expect(longResult.success).toBe(false);
      });

      it("should reject usernames with spaces or special characters other than underscore", () => {
        const invalidChars = [
          "user name",
          "user-name",
          "user@name",
          "user.name",
        ];

        for (const username of invalidChars) {
          const result = authValidation.registerSchema.body.safeParse({
            ...validRegistrationPayload,
            username,
          });
          expect(result.success).toBe(false);
          expect(result.error.issues[0].message).toContain(
            "can only contain letters, numbers, and underscores",
          );
        }
      });

      it.each([
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
      ])("should reject reserved username: '%s'", reserved => {
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          username: reserved,
        });

        expect(result.success).toBe(false);
        expect(result.error.issues[0].message).toContain(
          "This username is not available",
        );
      });
    });

    describe("email validation", () => {
      it.each([
        "not-an-email",
        "@example.com",
        "user@",
        "user@example",
        "user name@example.com",
      ])("should reject invalid email format: '%s'", invalidEmail => {
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          email: invalidEmail,
        });

        expect(result.success).toBe(false);
      });

      it("should reject whitespace-only emails", () => {
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          email: "   ",
        });

        expect(result.success).toBe(false);
        expect(result.error.issues[0].message).toContain("Email is required");
      });
    });

    describe("password & confirmPassword validation", () => {
      it.each([
        ["short", "Ab1!"], // Under 8 chars
        ["missing lowercase", "PASSWORD123!"],
        ["missing uppercase", "password123!"],
        ["missing number", "Password!!!!"],
        ["missing special char", "Password123"],
      ])(
        "should reject password that violates complexity: %s",
        (_, password) => {
          const result = authValidation.registerSchema.body.safeParse({
            ...validRegistrationPayload,
            password,
            confirmPassword: password,
          });

          expect(result.success).toBe(false);
        },
      );

      it("should reject passwords longer than 72 characters (bcrypt/argon2 safe limit)", () => {
        const longPassword = "A1!" + "a".repeat(70);
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          password: longPassword,
          confirmPassword: longPassword,
        });

        expect(result.success).toBe(false);
        expect(result.error.issues[0].message).toContain(
          "not exceed 72 characters",
        );
      });

      it("should reject when password and confirmPassword do not match", () => {
        const result = authValidation.registerSchema.body.safeParse({
          ...validRegistrationPayload,
          password: validPassword,
          confirmPassword: "DifferentPassword123!",
        });

        expect(result.success).toBe(false);
        expect(result.error.issues[0].message).toBe("Passwords do not match");
      });
    });

    it("should reject unexpected fields due to strict schema", () => {
      const result = authValidation.registerSchema.body.safeParse({
        ...validRegistrationPayload,
        role: "ADMIN", // Forbidden extra field
      });

      expect(result.success).toBe(false);
    });
  });

  describe("loginSchema.body", () => {
    it("should succeed with valid email and password", () => {
      const result = authValidation.loginSchema.body.safeParse({
        loginIdentifier: "user@example.com",
        password: "SecretPassword123!",
      });

      expect(result.success).toBe(true);
      expect(result.data.loginIdentifier).toBe("user@example.com");
    });

    it("should succeed with valid username and password", () => {
      const result = authValidation.loginSchema.body.safeParse({
        loginIdentifier: "john_doe",
        password: "SecretPassword123!",
      });

      expect(result.success).toBe(true);
      expect(result.data.loginIdentifier).toBe("john_doe");
    });

    it("should reject missing or empty credentials", () => {
      const emptyResult = authValidation.loginSchema.body.safeParse({
        loginIdentifier: "   ",
        password: "",
      });

      expect(emptyResult.success).toBe(false);
    });

    it("should reject payloads with unexpected fields", () => {
      const result = authValidation.loginSchema.body.safeParse({
        loginIdentifier: "validuser",
        password: "validPassword123",
        rememberMe: true, // Forbidden extra field
      });

      expect(result.success).toBe(false);
    });
  });

  describe("refreshTokenSchema.body", () => {
    it("should succeed with a valid non-empty refresh token", () => {
      const result = authValidation.refreshTokenSchema.body.safeParse({
        refreshToken: "a".repeat(64),
      });

      expect(result.success).toBe(true);
    });

    it("should reject an empty refresh token", () => {
      const result = authValidation.refreshTokenSchema.body.safeParse({
        refreshToken: "",
      });

      expect(result.success).toBe(false);
    });
  });

  describe("verifyEmailSchema.body", () => {
    it("should accept a verification token of at least 6 characters", () => {
      const result = authValidation.verifyEmailSchema.body.safeParse({
        token: "123456",
      });

      expect(result.success).toBe(true);
    });

    it("should reject tokens shorter than 6 characters", () => {
      const result = authValidation.verifyEmailSchema.body.safeParse({
        token: "12345",
      });

      expect(result.success).toBe(false);
      expect(result.error.issues[0].message).toContain(
        "at least 6 characters long",
      );
    });
  });

  describe("resendVerificationEmailSchema.body", () => {
    it("should accept a valid email address", () => {
      const result =
        authValidation.resendVerificationEmailSchema.body.safeParse({
          email: "user@example.com",
        });

      expect(result.success).toBe(true);
    });

    it("should reject an invalid email address", () => {
      const result =
        authValidation.resendVerificationEmailSchema.body.safeParse({
          email: "invalid-email",
        });

      expect(result.success).toBe(false);
    });
  });

  describe("resetPasswordSchema", () => {
    it("should accept valid params and matching new passwords", () => {
      const paramsResult = authValidation.resetPasswordSchema.params.safeParse({
        token: "reset-token-12345",
      });
      const bodyResult = authValidation.resetPasswordSchema.body.safeParse({
        newPassword: validPassword,
        confirmNewPassword: validPassword,
      });

      expect(paramsResult.success).toBe(true);
      expect(bodyResult.success).toBe(true);
    });

    it("should reject params token shorter than 8 characters", () => {
      const result = authValidation.resetPasswordSchema.params.safeParse({
        token: "short",
      });

      expect(result.success).toBe(false);
      expect(result.error.issues[0].message).toContain(
        "at least 8 characters long",
      );
    });

    it("should reject when newPassword and confirmNewPassword mismatch", () => {
      const result = authValidation.resetPasswordSchema.body.safeParse({
        newPassword: validPassword,
        confirmNewPassword: "DifferentPassword123!",
      });

      expect(result.success).toBe(false);
      expect(result.error.issues[0].message).toBe("Passwords do not match");
    });
  });

  describe("changePasswordSchema.body", () => {
    it("should accept valid current and matching new password", () => {
      const result = authValidation.changePasswordSchema.body.safeParse({
        currentPassword: "OldPassword123!",
        newPassword: "NewPassword123!",
        confirmNewPassword: "NewPassword123!",
      });

      expect(result.success).toBe(true);
    });

    it("should reject when newPassword and confirmNewPassword do not match", () => {
      const result = authValidation.changePasswordSchema.body.safeParse({
        currentPassword: "OldPassword123!",
        newPassword: "NewPassword123!",
        confirmNewPassword: "MismatchPassword123!",
      });

      expect(result.success).toBe(false);
      expect(result.error.issues[0].message).toBe("Passwords do not match");
    });
  });

  describe("updateProfileSchema.body", () => {
    it("should accept when at least one field is provided for update", () => {
      const usernameUpdate = authValidation.updateProfileSchema.body.safeParse({
        username: "new_username",
      });
      const emailUpdate = authValidation.updateProfileSchema.body.safeParse({
        email: "newemail@example.com",
      });
      const fullNameUpdate = authValidation.updateProfileSchema.body.safeParse({
        fullName: "New Name",
      });

      expect(usernameUpdate.success).toBe(true);
      expect(emailUpdate.success).toBe(true);
      expect(fullNameUpdate.success).toBe(true);
    });

    it("should reject when an empty payload {} is passed", () => {
      const result = authValidation.updateProfileSchema.body.safeParse({});

      expect(result.success).toBe(false);
      expect(result.error.issues[0].message).toContain(
        "At least one field (fullName, username, or email) must be provided",
      );
    });

    it("should reject unexpected fields", () => {
      const result = authValidation.updateProfileSchema.body.safeParse({
        username: "validuser",
        isAdmin: true, // Disallowed extra field
      });

      expect(result.success).toBe(false);
    });
  });
});
