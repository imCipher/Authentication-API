import request from "supertest";
import passport from "passport";

import app from "../../src/app.js";
import prisma from "../../src/config/db.js";
import redisService from "../../src/config/redis.js";
import finalConfig from "../../src/config/keys.js";
import hashUtils from "../../src/utils/hash.utils.js";
import tokenUtils from "../../src/utils/token.utils.js";

// Never send real emails from tests
vi.mock("../../src/utils/email.utils.js", () => ({
  default: vi.fn().mockImplementation(function () {
    return {
      sendEmailConfirmation: vi.fn().mockResolvedValue(undefined),
      sendWelcomeEmail: vi.fn().mockResolvedValue(undefined),
      sendPasswordReset: vi.fn().mockResolvedValue(undefined),
    };
  }),
}));

// =========================================================================
// Helpers
// =========================================================================
const PASSWORD = "StrongP@ssw0rd123!";
const NEW_PASSWORD = "BrandNewP@ssw0rd456!";
const HTML = { Accept: "text/html" }; // what a browser sends when loading a page

// Every test user's email starts with "web_" so cleanup can find them all
const uniqueUser = (tag = "") => {
  const id = `${Date.now().toString().slice(-6)}${Math.random().toString(36).slice(2, 6)}${tag}`;
  return {
    fullName: "Web Test User",
    username: `webusr_${id}`.slice(0, 30).toLowerCase(),
    email: `web_${id}@example.com`.toLowerCase(),
    password: PASSWORD,
    confirmPassword: PASSWORD,
  };
};

// ARRANGE quickly: put a verified user straight into the DB.
// (Tests that are ABOUT registering use the real form instead.)
const createVerifiedUser = async tag => {
  const data = uniqueUser(tag);
  const user = await prisma.user.create({
    data: {
      fullName: data.fullName,
      username: data.username,
      email: data.email,
      passwordHash: await hashUtils.hashPassword(PASSWORD),
      emailVerified: true,
    },
  });
  return { ...data, id: user.id };
};

// Take the hidden CSRF token out of a rendered page
const csrfFrom = html => {
  const match = html.match(/name="_csrf" value="([^"]+)"/);
  if (!match) throw new Error("No CSRF token found in page");
  return match[1];
};

// GET a page with an agent (this sets the sid + csrf cookies) and return its token
const getToken = async (agent, path) => {
  const res = await agent.get(path).set(HTML);
  expect(res.status).toBe(200);
  return csrfFrom(res.text);
};

// Find one cookie in a response's Set-Cookie headers
const cookieLine = (res, name) =>
  (res.headers["set-cookie"] ?? []).find(c => c.startsWith(`${name}=`));
const cookieValue = (res, name) =>
  cookieLine(res, name)
    ?.split(";")[0]
    .slice(name.length + 1);

// Submit the real login form with an agent; returns the response (doesn't assert)
const submitLogin = async (agent, loginIdentifier, password = PASSWORD) => {
  const _csrf = await getToken(agent, "/login");
  return agent
    .post("/login")
    .type("form")
    .send({ _csrf, loginIdentifier, password });
};

// Log an agent in and assert it worked
const loginAs = async (agent, user, password = PASSWORD) => {
  const res = await submitLogin(agent, user.email, password);
  expect(res.status).toBe(303);
  expect(res.headers.location).toBe("/dashboard");
  return res;
};

// A random documentation-range IP, so rate-limit counters from earlier runs
// (stored in Redis for 15+ minutes) never collide with this run
const randomIp = () => `198.51.100.${Math.floor(1 + Math.random() * 250)}`;

// =========================================================================
// Tests
// =========================================================================
describe("Web pages (server-rendered)", () => {
  let originalEnv;

  beforeAll(async () => {
    await redisService.connect(); // protect() checks the Redis denylist
  });

  beforeEach(() => {
    vi.clearAllMocks();
    originalEnv = finalConfig.env;
  });

  afterEach(() => {
    finalConfig.env = originalEnv; // undo the rate-limit tests' "production" switch
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    const users = await prisma.user.findMany({
      where: { email: { startsWith: "web_" } },
      select: { id: true },
    });
    const ids = users.map(u => u.id);
    if (ids.length) {
      await prisma.auditLog.deleteMany({ where: { userId: { in: ids } } });
      await prisma.user.deleteMany({ where: { id: { in: ids } } });
    }
    await redisService.disconnect();
    await prisma.$disconnect();
  });

  // -----------------------------------------------------------------------
  describe("Rendering", () => {
    it.each([
      "/login",
      "/register",
      "/forgot-password",
      "/verify-email",
      `/reset-password/${"a".repeat(64)}`,
    ])("GET %s renders an HTML page with a CSRF token", async path => {
      const res = await request(app).get(path).set(HTML);

      expect(res.status).toBe(200);
      expect(res.headers["content-type"]).toMatch(/text\/html/);
      expect(() => csrfFrom(res.text)).not.toThrow();
    });

    it("GET / sends visitors on to /dashboard", async () => {
      const res = await request(app).get("/").set(HTML);

      expect(res.status).toBe(302);
      expect(res.headers.location).toBe("/dashboard");
    });

    it("gives every new visitor an httpOnly sid cookie", async () => {
      const res = await request(app).get("/login").set(HTML);

      expect(cookieLine(res, "sid")).toMatch(/HttpOnly/i);
    });

    it.each([
      ["password-changed", "Password changed"],
      ["logged-out", "logged out"],
      ["verified", "Email verified"],
      ["password-reset", "Your password has been reset"],
    ])("GET /login?reason=%s shows its notice", async (reason, text) => {
      const res = await request(app).get(`/login?reason=${reason}`).set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain(text);
    });

    it("ignores unknown ?reason= values instead of printing them", async () => {
      const res = await request(app)
        .get("/login?reason=Your account is suspended")
        .set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).not.toContain("Your account is suspended");
      expect(res.text).not.toContain('class="notice"');
    });
  });

  // -----------------------------------------------------------------------
  describe("CSRF protection", () => {
    it("rejects a form POST with no CSRF token (403 HTML page)", async () => {
      const agent = request.agent(app);
      await getToken(agent, "/login"); // gets the cookies, but we "forget" the token

      const res = await agent
        .post("/login")
        .type("form")
        .set(HTML)
        .send({ loginIdentifier: "someone@example.com", password: PASSWORD });

      expect(res.status).toBe(403);
      expect(res.headers["content-type"]).toMatch(/text\/html/); // friendly page, not JSON
      expect(res.text).toContain("Session expired");
    });

    it("rejects a tampered CSRF token (403)", async () => {
      const agent = request.agent(app);
      const token = await getToken(agent, "/login");
      const tampered = token.slice(0, -1) + (token.endsWith("a") ? "b" : "a");

      const res = await agent
        .post("/login")
        .type("form")
        .set(HTML)
        .send({
          _csrf: tampered,
          loginIdentifier: "someone@example.com",
          password: PASSWORD,
        });

      expect(res.status).toBe(403);
    });

    it("rejects a valid token used from a DIFFERENT browser session (403)", async () => {
      const alice = request.agent(app);
      const mallory = request.agent(app);
      const alicesToken = await getToken(alice, "/login");
      await getToken(mallory, "/login"); // mallory has her own sid cookie

      const res = await mallory
        .post("/login")
        .type("form")
        .set(HTML)
        .send({
          _csrf: alicesToken,
          loginIdentifier: "someone@example.com",
          password: PASSWORD,
        });

      expect(res.status).toBe(403); // tokens are tied to the sid → can't be reused elsewhere
    });

    it("rejects a POST from a client with no cookies at all (403)", async () => {
      const page = await request(app).get("/login").set(HTML);
      const token = csrfFrom(page.text);

      // send the token, but none of the cookies it belongs to
      const res = await request(app)
        .post("/login")
        .type("form")
        .set(HTML)
        .send({
          _csrf: token,
          loginIdentifier: "someone@example.com",
          password: PASSWORD,
        });

      expect(res.status).toBe(403);
    });
  });

  // -----------------------------------------------------------------------
  describe("Login", () => {
    it("wrong password re-renders the form with the error, keeps the identifier, never the password", async () => {
      const user = await createVerifiedUser("badpw");
      const agent = request.agent(app);

      const res = await submitLogin(agent, user.email, "WrongP@ssw0rd1!");

      expect(res.status).toBe(401);
      expect(res.text).toContain("Invalid login credentials");
      expect(res.text).toContain(`value="${user.email}"`);
      expect(res.text).not.toContain("WrongP@ssw0rd1!");
    });

    it("an empty form re-renders with a validation error (422)", async () => {
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/login");

      const res = await agent.post("/login").type("form").send({ _csrf });

      expect(res.status).toBe(422);
      expect(res.text).toContain('class="auth-error"');
    });

    it("escapes user input when re-rendering (no XSS)", async () => {
      const agent = request.agent(app);
      const evil = `<script>alert(1)</script>`;

      const res = await submitLogin(agent, evil);

      expect([401, 422]).toContain(res.status);
      expect(res.text).not.toContain(evil);
      expect(res.text).toContain("&lt;script&gt;");
    });

    it("an unverified account cannot log in", async () => {
      const data = uniqueUser("unver");
      await prisma.user.create({
        data: {
          fullName: data.fullName,
          username: data.username,
          email: data.email,
          passwordHash: await hashUtils.hashPassword(PASSWORD),
          emailVerified: false,
        },
      });

      const res = await submitLogin(request.agent(app), data.email);

      expect(res.status).toBe(401);
      expect(res.text).toMatch(/not verified/i);
    });

    it("can log in with the username as well as the email", async () => {
      const user = await createVerifiedUser("byname");

      const res = await submitLogin(request.agent(app), user.username);

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/dashboard");
    });

    it("successful login redirects to /dashboard and sets httpOnly cookies", async () => {
      const user = await createVerifiedUser("ok");
      const agent = request.agent(app);

      const res = await loginAs(agent, user);

      for (const name of ["accessToken", "refreshToken"]) {
        const line = cookieLine(res, name);
        expect(line).toBeDefined();
        expect(line).toMatch(/HttpOnly/i); // page JavaScript can't read it
        expect(line).toMatch(/SameSite=Lax/i);
      }

      // the agent kept the cookies → the dashboard now loads
      const dash = await agent.get("/dashboard").set(HTML);
      expect(dash.status).toBe(200);
      expect(dash.text).toContain(user.fullName);
      expect(dash.text).toContain(user.email);
      expect(dash.text).toContain("Verified");
    });
  });

  // -----------------------------------------------------------------------
  describe("Page protection", () => {
    it.each(["/dashboard", "/settings"])(
      "redirects guests from %s to /login",
      async path => {
        const res = await request(app).get(path).set(HTML);

        expect(res.status).toBe(303);
        expect(res.headers.location).toBe("/login");
      },
    );

    it.each(["/login", "/register", "/forgot-password"])(
      "redirects logged-in users away from %s",
      async path => {
        const user = await createVerifiedUser("guest");
        const agent = request.agent(app);
        await loginAs(agent, user);

        const res = await agent.get(path).set(HTML);

        expect(res.status).toBe(303);
        expect(res.headers.location).toBe("/dashboard");
      },
    );

    it("silently refreshes an expired access token using the refresh cookie", async () => {
      const user = await createVerifiedUser("refresh");
      const loginRes = await loginAs(request.agent(app), user);
      const oldRefresh = cookieValue(loginRes, "refreshToken");

      // Send ONLY the refresh cookie — as if the 15-minute access cookie had expired
      const res = await request(app)
        .get("/dashboard")
        .set(HTML)
        .set("Cookie", `refreshToken=${oldRefresh}`);

      expect(res.status).toBe(200);
      expect(cookieValue(res, "accessToken")).toBeTruthy(); // new access token issued
      expect(cookieValue(res, "refreshToken")).not.toBe(oldRefresh); // refresh token rotated
    });

    it("sends a garbage refresh cookie to /login and clears the cookies (not a 500)", async () => {
      const res = await request(app)
        .get("/dashboard")
        .set(HTML)
        .set("Cookie", "refreshToken=not-a-real-token");

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login");
      expect(cookieLine(res, "refreshToken")).toMatch(
        /Expires=Thu, 01 Jan 1970/,
      ); // cleared
    });

    it("sends a garbage access cookie (and no refresh cookie) to /login", async () => {
      const res = await request(app)
        .get("/dashboard")
        .set(HTML)
        .set("Cookie", "accessToken=not.a.jwt");

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login");
    });
  });

  // -----------------------------------------------------------------------
  describe("Register", () => {
    it("empty form shows an error under each field (422)", async () => {
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/register");

      const res = await agent.post("/register").type("form").send({ _csrf });

      expect(res.status).toBe(422);
      for (const field of ["fullName", "username", "email", "password"]) {
        expect(res.text).toContain(`id="${field}-error"`);
      }
    });

    it("mismatched passwords put the error under the confirm field", async () => {
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/register");
      const data = uniqueUser("mismatch");

      const res = await agent
        .post("/register")
        .type("form")
        .send({ _csrf, ...data, confirmPassword: "Different1!Pass" });

      expect(res.status).toBe(422);
      expect(res.text).toContain(`id="confirmPassword-error"`);
      expect(res.text).toContain("Passwords do not match");
    });

    it("keeps typed values after an error, but never the passwords", async () => {
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/register");
      const data = uniqueUser("keep");

      const res = await agent
        .post("/register")
        .type("form")
        .send({ _csrf, ...data, confirmPassword: "Different1!Pass" });

      expect(res.text).toContain(`value="${data.fullName}"`);
      expect(res.text).toContain(`value="${data.username}"`);
      expect(res.text).toContain(`value="${data.email}"`);
      expect(res.text).not.toContain(PASSWORD);
    });

    it("a username that is already taken shows an error (409)", async () => {
      const existing = await createVerifiedUser("taken");
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/register");
      const data = { ...uniqueUser("dup"), username: existing.username };

      const res = await agent
        .post("/register")
        .type("form")
        .send({ _csrf, ...data });

      expect(res.status).toBe(409);
      expect(res.text).toContain("Username is already taken");
    });

    it("an email that is already registered shows an error (409)", async () => {
      const existing = await createVerifiedUser("takenmail");
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/register");
      const data = { ...uniqueUser("dupmail"), email: existing.email };

      const res = await agent
        .post("/register")
        .type("form")
        .send({ _csrf, ...data });

      expect(res.status).toBe(409);
      expect(res.text).toContain("Email is already registered");
    });

    it("trims and lowercases the username, so case variants count as taken", async () => {
      const agent = request.agent(app);
      const data = uniqueUser("case");

      let _csrf = await getToken(agent, "/register");
      const first = await agent
        .post("/register")
        .type("form")
        .send({
          _csrf,
          ...data,
          username: `  ${data.username.toUpperCase()} `,
        });
      expect(first.status).toBe(303);

      const saved = await prisma.user.findUnique({
        where: { email: data.email },
      });
      expect(saved.username).toBe(data.username); // stored trimmed + lowercase

      _csrf = await getToken(agent, "/register");
      const second = await agent
        .post("/register")
        .type("form")
        .send({
          _csrf,
          ...uniqueUser("case2"),
          username: data.username.toUpperCase(),
        });
      expect(second.status).toBe(409);
    });

    it("valid registration redirects to /verify-email and creates an unverified user", async () => {
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/register");
      const data = uniqueUser("reg");

      const res = await agent
        .post("/register")
        .type("form")
        .send({ _csrf, ...data });

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe(
        `/verify-email?email=${encodeURIComponent(data.email)}`,
      );

      const dbUser = await prisma.user.findUnique({
        where: { email: data.email },
      });
      expect(dbUser).not.toBeNull();
      expect(dbUser.emailVerified).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  describe("Verify email", () => {
    // Register through the real form with a code we choose
    const registerThroughForm = async (agent, code) => {
      vi.spyOn(tokenUtils, "verificationToken").mockReturnValue(code);
      const data = uniqueUser("ver");
      const _csrf = await getToken(agent, "/register");
      const res = await agent
        .post("/register")
        .type("form")
        .send({ _csrf, ...data });
      expect(res.status).toBe(303);
      return data;
    };

    const verifyPage = email =>
      `/verify-email?email=${encodeURIComponent(email)}`;

    it("shows the email from the URL when it is valid", async () => {
      const res = await request(app)
        .get(verifyPage("someone@example.com"))
        .set(HTML);

      expect(res.text).toContain("someone@example.com");
      expect(res.text).not.toContain('id="verifyEmail"'); // no email box needed
    });

    it("ignores an invalid ?email= value and asks for the email instead", async () => {
      const res = await request(app)
        .get("/verify-email?email=hello world")
        .set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).not.toContain("hello world");
      expect(res.text).toContain('id="verifyEmail"');
    });

    it("the correct code verifies the account and redirects to login", async () => {
      const agent = request.agent(app);
      const data = await registerThroughForm(agent, "482913");
      const _csrf = await getToken(agent, verifyPage(data.email));

      const res = await agent
        .post("/verify-email")
        .type("form")
        .send({ _csrf, email: data.email, token: "482913" });

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?reason=verified");
      const dbUser = await prisma.user.findUnique({
        where: { email: data.email },
      });
      expect(dbUser.emailVerified).toBe(true);
    });

    it("accepts a code typed with spaces, like '482 913'", async () => {
      const agent = request.agent(app);
      const data = await registerThroughForm(agent, "135246");
      const _csrf = await getToken(agent, verifyPage(data.email));

      const res = await agent
        .post("/verify-email")
        .type("form")
        .send({ _csrf, email: data.email, token: "135 246" });

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?reason=verified");
    });

    it("a wrong code re-renders the page with an error and keeps the email", async () => {
      const agent = request.agent(app);
      const data = await registerThroughForm(agent, "111222");
      const _csrf = await getToken(agent, verifyPage(data.email));

      const res = await agent
        .post("/verify-email")
        .type("form")
        .send({ _csrf, email: data.email, token: "999999" });

      expect(res.status).toBe(400);
      expect(res.text).toMatch(/invalid or\s+has expired/i);
      expect(res.text).toContain(data.email);
    });

    it("a correct code with someone else's email does NOT verify the account", async () => {
      const agent = request.agent(app);
      const victim = await registerThroughForm(agent, "777888");
      const _csrf = await getToken(agent, verifyPage("attacker@example.com"));

      const res = await agent
        .post("/verify-email")
        .type("form")
        .send({ _csrf, email: "attacker@example.com", token: "777888" });

      expect(res.status).toBe(400);
      const dbUser = await prisma.user.findUnique({
        where: { email: victim.email },
      });
      expect(dbUser.emailVerified).toBe(false);
    });

    it("a code that is not 6 digits fails validation (422)", async () => {
      const agent = request.agent(app);
      const _csrf = await getToken(agent, verifyPage("someone@example.com"));

      const res = await agent
        .post("/verify-email")
        .type("form")
        .send({ _csrf, email: "someone@example.com", token: "12ab" });

      expect(res.status).toBe(422);
      expect(res.text).toContain('class="auth-error"');
    });

    it("resend redirects back with the 'sent' notice (same for any email)", async () => {
      const agent = request.agent(app);

      for (const email of [
        "nobody-here@example.com",
        "another-nobody@example.com",
      ]) {
        const _csrf = await getToken(agent, verifyPage(email));
        const res = await agent
          .post("/verify-email/resend")
          .type("form")
          .send({ _csrf, email });

        expect(res.status).toBe(303);
        expect(res.headers.location).toBe(`${verifyPage(email)}&sent=1`);
      }

      const page = await agent
        .get(`${verifyPage("nobody-here@example.com")}&sent=1`)
        .set(HTML);
      expect(page.text).toContain("a new code is on its way");
    });

    it("resend with an invalid email shows an error (422)", async () => {
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/verify-email");

      const res = await agent
        .post("/verify-email/resend")
        .type("form")
        .send({ _csrf, email: "not-an-email" });

      expect(res.status).toBe(422);
      expect(res.text).toContain("Please enter a valid email address.");
    });
  });

  // -----------------------------------------------------------------------
  describe("Forgot password", () => {
    it("gives the SAME response for a real and a made-up email (no account enumeration)", async () => {
      const user = await createVerifiedUser("forgot");
      const agent = request.agent(app);

      const responses = [];
      for (const email of [user.email, "no-such-account@example.com"]) {
        const _csrf = await getToken(agent, "/forgot-password");
        responses.push(
          await agent
            .post("/forgot-password")
            .type("form")
            .send({ _csrf, email }),
        );
      }

      for (const res of responses) {
        expect(res.status).toBe(303);
        expect(res.headers.location).toBe("/forgot-password?sent=1"); // email NOT in the URL
      }
    });

    it("shows the 'sent' notice after redirecting", async () => {
      const res = await request(app).get("/forgot-password?sent=1").set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain("If an account exists for that email");
    });

    it("an invalid email shows a field error and keeps the value (422)", async () => {
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/forgot-password");

      const res = await agent
        .post("/forgot-password")
        .type("form")
        .send({ _csrf, email: "not-an-email" });

      expect(res.status).toBe(422);
      expect(res.text).toContain('id="email-error"');
      expect(res.text).toContain('value="not-an-email"');
    });

    it("creates a reset record only for a real account", async () => {
      const user = await createVerifiedUser("forgotrec");
      const agent = request.agent(app);
      const _csrf = await getToken(agent, "/forgot-password");

      await agent
        .post("/forgot-password")
        .type("form")
        .send({ _csrf, email: user.email });

      const resets = await prisma.passwordReset.findMany({
        where: { userId: user.id },
      });
      expect(resets).toHaveLength(1);
    });
  });

  // -----------------------------------------------------------------------
  describe("Reset password", () => {
    // Request a reset for `user` with a token we choose, and return that token
    const requestReset = async (agent, user, token) => {
      vi.spyOn(tokenUtils, "secureToken").mockReturnValue(token);
      const _csrf = await getToken(agent, "/forgot-password");
      const res = await agent
        .post("/forgot-password")
        .type("form")
        .send({ _csrf, email: user.email });
      expect(res.status).toBe(303);
      return token;
    };

    const uniqueToken = () =>
      (Date.now().toString(16) + Math.random().toString(16).slice(2))
        .padEnd(64, "0")
        .slice(0, 64);

    const submitReset = async (
      agent,
      token,
      newPassword,
      confirmNewPassword = newPassword,
    ) => {
      const _csrf = await getToken(agent, `/reset-password/${token}`);
      return agent
        .post(`/reset-password/${token}`)
        .type("form")
        .send({ _csrf, newPassword, confirmNewPassword });
    };

    it("full flow: reset, then log in with the new password (old one stops working)", async () => {
      const user = await createVerifiedUser("reset");
      const agent = request.agent(app);
      const token = await requestReset(agent, user, uniqueToken());

      const res = await submitReset(agent, token, NEW_PASSWORD);

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?reason=password-reset");

      const oldPw = await submitLogin(request.agent(app), user.email, PASSWORD);
      expect(oldPw.status).toBe(401);

      const newPw = await submitLogin(
        request.agent(app),
        user.email,
        NEW_PASSWORD,
      );
      expect(newPw.status).toBe(303);
      expect(newPw.headers.location).toBe("/dashboard");
    });

    it("the same link cannot be used twice", async () => {
      const user = await createVerifiedUser("reuse");
      const agent = request.agent(app);
      const token = await requestReset(agent, user, uniqueToken());

      const first = await submitReset(agent, token, NEW_PASSWORD);
      expect(first.status).toBe(303);

      const second = await submitReset(agent, token, "YetAnotherP@ssw0rd789!");
      expect(second.status).toBe(400);
      expect(second.text).toContain(
        "This reset link is invalid or has expired.",
      );
      expect(second.text).not.toContain('action="/reset-password'); // no form for a dead link
      expect(second.text).toContain('href="/forgot-password"');
    });

    it("an unknown (well-formed) token shows the expired state, not the form", async () => {
      const res = await submitReset(
        request.agent(app),
        "f".repeat(64),
        NEW_PASSWORD,
      );

      expect(res.status).toBe(400);
      expect(res.text).toContain("This reset link is invalid or has expired.");
      expect(res.text).not.toContain('action="/reset-password');
    });

    it("a too-short token in the URL shows the expired state (400), not a 500", async () => {
      const res = await submitReset(request.agent(app), "abc", NEW_PASSWORD);

      expect(res.status).toBe(400);
      expect(res.text).toContain("This reset link is invalid or has expired.");
    });

    it("an expired link shows the expired state", async () => {
      const user = await createVerifiedUser("expired");
      const agent = request.agent(app);
      const token = await requestReset(agent, user, uniqueToken());
      await prisma.passwordReset.updateMany({
        where: { userId: user.id },
        data: { expiresAt: new Date(Date.now() - 60 * 1000) },
      });

      const res = await submitReset(agent, token, NEW_PASSWORD);

      expect(res.status).toBe(400);
      expect(res.text).toContain("This reset link is invalid or has expired.");
    });

    it("mismatched passwords put the error under the confirm field (422)", async () => {
      const user = await createVerifiedUser("resetmm");
      const agent = request.agent(app);
      const token = await requestReset(agent, user, uniqueToken());

      const res = await submitReset(
        agent,
        token,
        NEW_PASSWORD,
        "Different1!Pass",
      );

      expect(res.status).toBe(422);
      expect(res.text).toContain('id="confirmNewPassword-error"');
      expect(res.text).toContain("Passwords do not match");
      // the link is still good → the form is still shown
      expect(res.text).toContain(`action="/reset-password/${token}"`);
    });

    it("a weak new password shows an error under the new password field (422)", async () => {
      const user = await createVerifiedUser("resetweak");
      const agent = request.agent(app);
      const token = await requestReset(agent, user, uniqueToken());

      const res = await submitReset(agent, token, "weak");

      expect(res.status).toBe(422);
      expect(res.text).toContain('id="newPassword-error"');
    });

    it("resetting logs out sessions on other browsers", async () => {
      const user = await createVerifiedUser("resetout");
      const otherBrowser = request.agent(app);
      await loginAs(otherBrowser, user);

      const agent = request.agent(app);
      const token = await requestReset(agent, user, uniqueToken());
      await submitReset(agent, token, NEW_PASSWORD);

      const res = await otherBrowser.get("/dashboard").set(HTML);
      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login");
    });
  });

  // -----------------------------------------------------------------------
  describe("Settings", () => {
    const postSettings = async (agent, path, body) => {
      const _csrf = await getToken(agent, "/settings");
      return agent
        .post(path)
        .type("form")
        .send({ _csrf, ...body });
    };

    it("a user with a password sees the change-password form (not 'set a password')", async () => {
      const user = await createVerifiedUser("setform");
      const agent = request.agent(app);
      await loginAs(agent, user);

      const res = await agent.get("/settings").set(HTML);

      expect(res.text).toContain('action="/settings/password"');
      expect(res.text).toContain('name="currentPassword"');
      expect(res.text).not.toContain('action="/settings/password-link"');
    });

    it("shows the current profile values", async () => {
      const user = await createVerifiedUser("setshow");
      const agent = request.agent(app);
      await loginAs(agent, user);

      const res = await agent.get("/settings").set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain(`value="${user.fullName}"`);
      expect(res.text).toContain(`value="${user.username}"`);
      expect(res.text).toContain(`value="${user.email}"`);
    });

    it("updates the profile and shows a success notice", async () => {
      const user = await createVerifiedUser("setprof");
      const agent = request.agent(app);
      await loginAs(agent, user);

      const res = await postSettings(agent, "/settings/profile", {
        fullName: "Renamed Person",
        username: user.username,
      });

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/settings?updated=profile");

      const page = await agent.get("/settings?updated=profile").set(HTML);
      expect(page.text).toContain("Your profile has been updated.");
      expect(page.text).toContain('value="Renamed Person"');
    });

    it("rejects a username that another user already has (409)", async () => {
      const other = await createVerifiedUser("setother");
      const user = await createVerifiedUser("setme");
      const agent = request.agent(app);
      await loginAs(agent, user);

      const res = await postSettings(agent, "/settings/profile", {
        fullName: user.fullName,
        username: other.username,
      });

      expect(res.status).toBe(409);
      expect(res.text).toContain("Username is already taken");
      expect(res.text).toContain(`value="${other.username}"`); // typed value kept
    });

    it("ignores an email sent in the profile form (email is read-only for now)", async () => {
      const user = await createVerifiedUser("setmail");
      const agent = request.agent(app);
      await loginAs(agent, user);

      await postSettings(agent, "/settings/profile", {
        fullName: user.fullName,
        username: user.username,
        email: "hijack@example.com",
      });

      const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
      expect(dbUser.email).toBe(user.email);
    });

    it("a wrong current password shows an error and keeps you logged in", async () => {
      const user = await createVerifiedUser("setwrong");
      const agent = request.agent(app);
      await loginAs(agent, user);

      const res = await postSettings(agent, "/settings/password", {
        currentPassword: "NotMyP@ssw0rd99!",
        newPassword: NEW_PASSWORD,
        confirmNewPassword: NEW_PASSWORD,
      });

      expect(res.status).toBe(400);
      expect(res.text).toContain("Current password is incorrect.");
      expect(res.text).not.toContain(NEW_PASSWORD);

      const dash = await agent.get("/dashboard").set(HTML);
      expect(dash.status).toBe(200);
    });

    it("changing the password logs you out and the new password works", async () => {
      const user = await createVerifiedUser("setpw");
      const agent = request.agent(app);
      await loginAs(agent, user);

      const res = await postSettings(agent, "/settings/password", {
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
        confirmNewPassword: NEW_PASSWORD,
      });

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?reason=password-changed");

      const dash = await agent.get("/dashboard").set(HTML);
      expect(dash.status).toBe(303);
      expect(dash.headers.location).toBe("/login");

      const relogin = await submitLogin(
        request.agent(app),
        user.email,
        NEW_PASSWORD,
      );
      expect(relogin.status).toBe(303);
    });

    it("'log out of all devices' ends every session", async () => {
      const user = await createVerifiedUser("setall");
      const laptop = request.agent(app);
      const phone = request.agent(app);
      await loginAs(laptop, user);
      await loginAs(phone, user);

      const res = await postSettings(laptop, "/settings/logout-all", {});

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?reason=logged-out-all");

      for (const device of [laptop, phone]) {
        const dash = await device.get("/dashboard").set(HTML);
        expect(dash.status).toBe(303);
        expect(dash.headers.location).toBe("/login");
      }
    });

    it("logging in right after a password change works immediately (no same-second bug)", async () => {
      const user = await createVerifiedUser("samesec");
      const agent = request.agent(app);
      await loginAs(agent, user);
      await postSettings(agent, "/settings/password", {
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
        confirmNewPassword: NEW_PASSWORD,
      });

      const fresh = request.agent(app);
      await loginAs(fresh, user, NEW_PASSWORD);
      const dash = await fresh.get("/dashboard").set(HTML);

      expect(dash.status).toBe(200);
    });
  });

  // -----------------------------------------------------------------------
  describe("Logout", () => {
    it("POST /logout ends the session", async () => {
      const user = await createVerifiedUser("out");
      const agent = request.agent(app);
      await loginAs(agent, user);
      const _csrf = await getToken(agent, "/dashboard"); // the logout form lives in the nav

      const res = await agent.post("/logout").type("form").send({ _csrf });

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?reason=logged-out");
      expect(cookieLine(res, "accessToken")).toMatch(
        /Expires=Thu, 01 Jan 1970/,
      );

      const after = await agent.get("/dashboard").set(HTML);
      expect(after.status).toBe(303);
      expect(after.headers.location).toBe("/login");
    });

    it("the old refresh token cannot be used after logout", async () => {
      const user = await createVerifiedUser("outrt");
      const agent = request.agent(app);
      const loginRes = await loginAs(agent, user);
      const refresh = cookieValue(loginRes, "refreshToken");
      const _csrf = await getToken(agent, "/dashboard");
      await agent.post("/logout").type("form").send({ _csrf });

      // a "stolen" copy of the refresh cookie must not bring the session back
      const res = await request(app)
        .get("/dashboard")
        .set(HTML)
        .set("Cookie", `refreshToken=${refresh}`);

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login");
    });
  });

  // -----------------------------------------------------------------------
  describe("Continue with Google", () => {
    const strategy = () => passport._strategy("google-web");

    // Replace ONLY the two network calls to Google with fakes. Everything else —
    // the state check, finding/linking/creating the user, cookies, redirects — is real.
    const fakeGoogle = profile => {
      vi.spyOn(strategy()._oauth2, "getOAuthAccessToken").mockImplementation(
        (code, params, callback) =>
          callback(null, "fake-google-access", "fake-google-refresh", {}),
      );
      vi.spyOn(strategy(), "userProfile").mockImplementation(
        (accessToken, done) => done(null, profile),
      );
    };

    const googleProfile = ({
      email,
      verified = true,
      name = "Google Person",
    }) => ({
      provider: "google",
      id: `g-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      displayName: name,
      name: { givenName: name.split(" ")[0] },
      emails: [{ value: email, verified }],
      _json: { email_verified: verified },
    });

    // Start the flow like a browser and return the state Google would send back
    const startFlow = async agent => {
      const res = await agent.get("/auth/google").set(HTML);
      expect(res.status).toBe(302);
      return new URL(res.headers.location).searchParams.get("state");
    };

    const finishFlow = (agent, state) =>
      agent
        .get(`/auth/google/callback?code=fake-code&state=${state}`)
        .set(HTML);

    it.each(["/login", "/register"])(
      "%s shows the 'Continue with Google' button",
      async path => {
        const res = await request(app).get(path).set(HTML);

        expect(res.text).toContain('href="/auth/google"');
        expect(res.text).toContain("Continue with Google");
      },
    );

    it("GET /auth/google redirects to Google with our client, callback, scope and a state", async () => {
      const res = await request(app).get("/auth/google").set(HTML);

      expect(res.status).toBe(302);
      const url = new URL(res.headers.location);
      expect(url.hostname).toBe("accounts.google.com");
      expect(url.searchParams.get("client_id")).toBe(
        process.env.GOOGLE_CLIENT_ID,
      );
      expect(url.searchParams.get("redirect_uri")).toBe(
        `${process.env.APP_URL}/auth/google/callback`,
      );
      expect(url.searchParams.get("scope")).toContain("email");

      // the same random state is in the URL AND in an httpOnly cookie
      const state = url.searchParams.get("state");
      expect(state).toMatch(/^[a-f0-9]{48}$/);
      const stateCookie = cookieLine(res, "oauth_state");
      expect(stateCookie).toMatch(/HttpOnly/i);
      expect(stateCookie).toMatch(/Path=\/auth\/google/i);
      expect(cookieValue(res, "oauth_state")).toBe(state);
    });

    it("logged-in users are sent to the dashboard instead of Google", async () => {
      const user = await createVerifiedUser("gloggedin");
      const agent = request.agent(app);
      await loginAs(agent, user);

      const res = await agent.get("/auth/google").set(HTML);

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/dashboard");
    });

    it("a NEW Google user gets an account and lands on the dashboard", async () => {
      const email = uniqueUser("gnew").email;
      fakeGoogle(googleProfile({ email, name: "Google Person" }));
      const agent = request.agent(app);

      const state = await startFlow(agent);
      const res = await finishFlow(agent, state);

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/dashboard");
      expect(cookieLine(res, "accessToken")).toMatch(/HttpOnly/i);
      expect(cookieLine(res, "refreshToken")).toMatch(/HttpOnly/i);

      const dash = await agent.get("/dashboard").set(HTML);
      expect(dash.status).toBe(200);
      expect(dash.text).toContain("Google Person");

      const dbUser = await prisma.user.findUnique({ where: { email } });
      expect(dbUser.emailVerified).toBe(true);
      expect(dbUser.passwordHash).toBeNull(); // Google-only account has no password
    });

    it("signing in with the same Google account again reuses the same user", async () => {
      const email = uniqueUser("gagain").email;
      const profile = googleProfile({ email });

      for (let i = 0; i < 2; i++) {
        fakeGoogle(profile);
        const agent = request.agent(app);
        const res = await finishFlow(agent, await startFlow(agent));
        expect(res.headers.location).toBe("/dashboard");
        vi.restoreAllMocks();
      }

      const users = await prisma.user.findMany({ where: { email } });
      expect(users).toHaveLength(1);
    });

    it("links Google to an existing VERIFIED account and keeps its password", async () => {
      const user = await createVerifiedUser("glink");
      fakeGoogle(googleProfile({ email: user.email }));
      const agent = request.agent(app);

      const res = await finishFlow(agent, await startFlow(agent));

      expect(res.headers.location).toBe("/dashboard");
      const links = await prisma.oauthAccount.findMany({
        where: { userId: user.id },
      });
      expect(links).toHaveLength(1);

      const pwLogin = await submitLogin(
        request.agent(app),
        user.email,
        PASSWORD,
      );
      expect(pwLogin.status).toBe(303); // the owner's own password still works
    });

    it("pre-hijacking: linking an UNVERIFIED account wipes the unproven password", async () => {
      // An attacker registered the victim's email with the attacker's password
      // (never verified — the attacker can't read the victim's inbox)
      const data = uniqueUser("ghijack");
      const attackerPassword = "Attacker1!Password";
      await prisma.user.create({
        data: {
          fullName: data.fullName,
          username: data.username,
          email: data.email,
          passwordHash: await hashUtils.hashPassword(attackerPassword),
          emailVerified: false,
        },
      });

      // The real owner later signs in with Google (which proves they own the email)
      fakeGoogle(googleProfile({ email: data.email }));
      const agent = request.agent(app);
      const res = await finishFlow(agent, await startFlow(agent));
      expect(res.headers.location).toBe("/dashboard");

      const dbUser = await prisma.user.findUnique({
        where: { email: data.email },
      });
      expect(dbUser.emailVerified).toBe(true);
      expect(dbUser.passwordHash).toBeNull();

      // …so the attacker's password no longer opens the victim's account
      const attackerLogin = await submitLogin(
        request.agent(app),
        data.email,
        attackerPassword,
      );
      expect(attackerLogin.status).toBe(401);
    });

    it("refuses to link when Google says the email is NOT verified", async () => {
      const user = await createVerifiedUser("gunver");
      fakeGoogle(googleProfile({ email: user.email, verified: false }));
      const agent = request.agent(app);

      const res = await finishFlow(agent, await startFlow(agent));

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?error=oauth-failed");
      const links = await prisma.oauthAccount.findMany({
        where: { userId: user.id },
      });
      expect(links).toHaveLength(0);
    });

    it("a suspended account is turned away with its own message", async () => {
      const user = await createVerifiedUser("gsusp");
      await prisma.user.update({
        where: { id: user.id },
        data: { status: "SUSPENDED" },
      });
      fakeGoogle(googleProfile({ email: user.email }));
      const agent = request.agent(app);

      const res = await finishFlow(agent, await startFlow(agent));

      expect(res.headers.location).toBe("/login?error=oauth-suspended");
      expect(cookieLine(res, "accessToken")).toBeUndefined();

      const page = await request(app)
        .get("/login?error=oauth-suspended")
        .set(HTML);
      expect(page.text).toContain("suspended or deactivated");
    });

    it("rejects a callback whose state does not match the cookie (login CSRF)", async () => {
      const exchange = vi.spyOn(strategy()._oauth2, "getOAuthAccessToken");
      const agent = request.agent(app);
      await startFlow(agent); // agent holds the REAL state cookie

      const res = await finishFlow(agent, "attacker-supplied-state");

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?error=oauth-failed");
      expect(exchange).not.toHaveBeenCalled(); // stopped BEFORE talking to Google
    });

    it("rejects a callback when there is no state cookie at all", async () => {
      const exchange = vi.spyOn(strategy()._oauth2, "getOAuthAccessToken");

      // a fresh client that never started the flow (e.g. a link an attacker sent you)
      const res = await finishFlow(request(app), "a".repeat(48));

      expect(res.headers.location).toBe("/login?error=oauth-failed");
      expect(exchange).not.toHaveBeenCalled();
    });

    it("a state can only be used once", async () => {
      fakeGoogle(googleProfile({ email: uniqueUser("gonce").email }));
      const agent = request.agent(app);
      const state = await startFlow(agent);

      const first = await finishFlow(agent, state);
      expect(first.headers.location).toBe("/dashboard");
      expect(cookieLine(first, "oauth_state")).toMatch(
        /Expires=Thu, 01 Jan 1970/,
      ); // cleared

      // replaying the same callback URL from a cookie-less client fails
      const replay = await finishFlow(request(app), state);
      expect(replay.headers.location).toBe("/login?error=oauth-failed");
    });

    it("pressing Cancel on Google's screen shows a friendly message", async () => {
      const res = await request(app)
        .get("/auth/google/callback?error=access_denied")
        .set(HTML);

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login?error=oauth-cancelled");

      const page = await request(app)
        .get("/login?error=oauth-cancelled")
        .set(HTML);
      expect(page.text).toContain("Google sign-in was cancelled.");
    });

    it("ignores unknown ?error= values on the login page", async () => {
      const res = await request(app)
        .get("/login?error=Your account was hacked")
        .set(HTML);

      expect(res.text).not.toContain("Your account was hacked");
      expect(res.text).not.toContain('class="auth-error"');
    });

    it("a Google-only user sees 'set a password' instead of the change form", async () => {
      fakeGoogle(googleProfile({ email: uniqueUser("gnopw").email }));
      const agent = request.agent(app);
      await finishFlow(agent, await startFlow(agent));

      const res = await agent.get("/settings").set(HTML);

      expect(res.text).toContain('action="/settings/password-link"');
      expect(res.text).not.toContain('action="/settings/password"');
    });

    it("'email me a link' creates a reset link for a Google-only user", async () => {
      const email = uniqueUser("gsetpw").email;
      fakeGoogle(googleProfile({ email }));
      const agent = request.agent(app);
      await finishFlow(agent, await startFlow(agent));
      const _csrf = await getToken(agent, "/settings");

      const res = await agent
        .post("/settings/password-link")
        .type("form")
        .send({ _csrf });

      expect(res.headers.location).toBe("/settings?updated=password-link");
      const dbUser = await prisma.user.findUnique({ where: { email } });
      const resets = await prisma.passwordReset.findMany({
        where: { userId: dbUser.id },
      });
      expect(resets).toHaveLength(1);
    });
  });

  // -----------------------------------------------------------------------
  describe("Rate limiting (production mode)", () => {
    it("too many failed logins shows the login page with a 429 message, not JSON", async () => {
      finalConfig.env = "production"; // limiters are skipped in testing; switch them on
      const ip = randomIp();
      const agent = request.agent(app);

      let res;
      for (let attempt = 1; attempt <= 5; attempt++) {
        const _csrf = await getToken(agent, "/login");
        res = await agent
          .post("/login")
          .set("X-Forwarded-For", ip)
          .type("form")
          .send({
            _csrf,
            loginIdentifier: "nobody@example.com",
            password: "WrongP@ssw0rd1!",
          });
        if (res.status === 429) break;
      }

      expect(res.status).toBe(429);
      expect(res.headers["content-type"]).toMatch(/text\/html/);
      expect(res.text).toContain("Too many failed login attempts");
      expect(res.text).toContain('value="nobody@example.com"'); // still the login page
    });

    it("too many forgot-password requests shows the forgot page with a 429 message", async () => {
      finalConfig.env = "production";
      const ip = randomIp();
      const agent = request.agent(app);

      let res;
      for (let attempt = 1; attempt <= 7; attempt++) {
        const _csrf = await getToken(agent, "/forgot-password");
        res = await agent
          .post("/forgot-password")
          .set("X-Forwarded-For", ip)
          .type("form")
          .send({ _csrf, email: "nobody@example.com" });
        if (res.status === 429) break;
      }

      expect(res.status).toBe(429);
      expect(res.headers["content-type"]).toMatch(/text\/html/);
      expect(res.text).toContain("Too many password reset requests");
    });
  });

  // -----------------------------------------------------------------------
  describe("Error pages", () => {
    it("an unknown page returns the HTML 404 page", async () => {
      const res = await request(app).get("/this-page-does-not-exist").set(HTML);

      expect(res.status).toBe(404);
      expect(res.headers["content-type"]).toMatch(/text\/html/);
      expect(res.text).toContain("Page not found");
    });

    it("a missing image returns a small JSON 404, not a whole page", async () => {
      const res = await request(app)
        .get("/images/nope.png")
        .set("Accept", "image/*");

      expect(res.status).toBe(404);
      expect(res.headers["content-type"]).toMatch(/json/);
    });

    it("an unknown /api route still returns JSON, even for a browser", async () => {
      const res = await request(app).get("/api/v1/nope").set(HTML);

      expect(res.status).toBe(404);
      expect(res.headers["content-type"]).toMatch(/json/);
    });
  });
});
