import nodemailer from "nodemailer";
import pug from "pug";
import Email from "../../../src/utils/email.utils.js";
import finalConfig from "../../../src/config/keys.js";

// Mock Nodemailer transport to isolate network I/O
const mockSendMail = vi
  .fn()
  .mockResolvedValue({ messageId: "mock-message-id-123" });
const mockCreateTransport = vi.fn().mockReturnValue({
  sendMail: mockSendMail,
});

vi.mock("nodemailer", () => ({
  default: {
    createTransport: (...args) => mockCreateTransport(...args),
  },
}));

describe("Email Utility", () => {
  const mockUser = {
    email: "testuser@example.com",
    fullName: "Johnathan Doe",
  };

  // Clear mocks and set default mock behavior before each test
  beforeEach(() => {
    vi.clearAllMocks();
    mockSendMail.mockResolvedValue({ messageId: "mock-message-id-123" });
  });

  describe("Constructor & State Initialization", () => {
    it("should correctly initialize recipient, first name, code, and sender address", () => {
      const code = "987654";
      const email = new Email(mockUser, code);

      expect(email.to).toBe("testuser@example.com");
      expect(email.firstName).toBe("Johnathan");
      expect(email.code).toBe("987654");
      expect(email.from).toBe(`Test Auth < ${finalConfig.email.from}>`);
    });

    it("should extract first name correctly for single-token names", () => {
      const singleNameUser = { email: "single@example.com", fullName: "Cher" };
      const email = new Email(singleNameUser);

      expect(email.firstName).toBe("Cher");
      expect(email.code).toBeUndefined();
    });

    it("should default code to undefined when omitted", () => {
      const email = new Email(mockUser);

      expect(email.code).toBeUndefined();
    });
  });

  describe("Transport Configuration (newTransport)", () => {
    it("should configure nodemailer transport with STARTTLS and timeout settings", () => {
      const email = new Email(mockUser);
      email.newTransport();

      expect(mockCreateTransport).toHaveBeenCalledTimes(1);
      expect(mockCreateTransport).toHaveBeenCalledWith({
        host: finalConfig.email.host,
        port: finalConfig.email.port,
        secure: false, // Forces STARTTLS rather than direct SSL
        requireTLS: true,
        auth: {
          user: finalConfig.email.user,
          pass: finalConfig.email.pass,
        },
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 10000,
      });
    });
  });

  describe("Email Template Rendering & Dispatch (send)", () => {
    it("should render the pug template with correct locals and pass mailOptions to sendMail", async () => {
      // Spy on pug.renderFile to verify template rendering
      const renderSpy = vi.spyOn(pug, "renderFile");
      const email = new Email(mockUser, "123456");

      await email.send("register", "Confirm your email address");

      expect(renderSpy).toHaveBeenCalledTimes(1);
      expect(renderSpy).toHaveBeenCalledWith(
        expect.stringMatching(/views[/\\]register\.pug$/),
        expect.objectContaining({
          firstName: "Johnathan",
          code: "123456",
          subject: "Confirm your email address",
          url: "http://localhost:3000/reset-password/undefined",
        }),
      );

      expect(mockSendMail).toHaveBeenCalledTimes(1);
      expect(mockSendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: "testuser@example.com",
          from: email.from,
          subject: "Confirm your email address",
          html: expect.stringContaining("Confirm your email address"),
        }),
      );

      renderSpy.mockRestore();
    });

    it("should propagate error when SMTP dispatch fails", async () => {
      const smtpError = new Error("SMTP connection refused");
      mockSendMail.mockRejectedValueOnce(smtpError);

      const email = new Email(mockUser);

      await expect(email.send("welcome", "Welcome!")).rejects.toThrow(
        "SMTP connection refused",
      );
    });
  });

  describe("Domain Convenience Methods", () => {
    it("should send registration confirmation email via sendEmailConfirmation()", async () => {
      const email = new Email(mockUser, "654321");
      const sendSpy = vi.spyOn(email, "send").mockResolvedValue();

      await email.sendEmailConfirmation();

      expect(sendSpy).toHaveBeenCalledWith(
        "register",
        "Confirm your email address",
      );
      sendSpy.mockRestore();
    });

    it("should send welcome email via sendWelcomeEmail()", async () => {
      const email = new Email(mockUser);
      const sendSpy = vi.spyOn(email, "send").mockResolvedValue();

      await email.sendWelcomeEmail();

      expect(sendSpy).toHaveBeenCalledWith("welcome", "Welcome to Test Auth!");
      sendSpy.mockRestore();
    });

    it("should send password reset email with urlCode via sendPasswordReset()", async () => {
      const email = new Email(mockUser);
      const sendSpy = vi.spyOn(email, "send").mockResolvedValue();
      const resetToken = "reset-uuid-token-789";

      await email.sendPasswordReset(resetToken);

      expect(sendSpy).toHaveBeenCalledWith(
        "resetpassword",
        "Reset your password",
        resetToken,
      );
      sendSpy.mockRestore();
    });
  });

  describe("Template Compilation Smoke Tests", () => {
    it.each([
      ["register", "Confirm your email address", "123456", undefined],
      ["welcome", "Welcome to Test Auth!", undefined, undefined],
      ["resetpassword", "Reset your password", undefined, "token-abc-123"],
    ])(
      "should successfully compile '%s.pug' with baseEmail layout into HTML",
      async (template, subject, code, urlCode) => {
        const email = new Email(mockUser, code);

        // Ensure that the send method does not throw and that sendMail is called with expected parameters
        await expect(
          email.send(template, subject, urlCode),
        ).resolves.not.toThrow();

        expect(mockSendMail).toHaveBeenCalledWith(
          expect.objectContaining({
            subject,
            html: expect.stringContaining("Johnathan"),
          }),
        );
      },
    );
  });
});
