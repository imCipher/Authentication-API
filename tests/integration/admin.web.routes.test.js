import request from "supertest";

import app from "../../src/app.js";
import prisma from "../../src/config/db.js";
import redisService from "../../src/config/redis.js";
import hashUtils from "../../src/utils/hash.utils.js";

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
const HTML = { Accept: "text/html" };
const RUN = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`; // unique per run

// Every user here has an email starting with "adm_" so cleanup can find them
const createUser = async (tag, { role = "USER", ...extra } = {}) => {
  const id = `${RUN}${tag}${Math.random().toString(36).slice(2, 5)}`.toLowerCase();
  const data = {
    fullName: "Admin Test User",
    username: `adm_${id}`.slice(0, 30),
    email: `adm_${id}@example.com`,
  };
  const user = await prisma.user.create({
    data: {
      ...data,
      passwordHash: await hashUtils.hashPassword(PASSWORD),
      emailVerified: true,
      role,
      ...extra,
    },
  });
  return user;
};

const csrfFrom = html => {
  const match = html.match(/name="_csrf" value="([^"]+)"/);
  if (!match) throw new Error("No CSRF token found in page");
  return match[1];
};

const getToken = async (agent, path) => {
  const res = await agent.get(path).set(HTML);
  expect(res.status).toBe(200);
  return csrfFrom(res.text);
};

const loginAs = async user => {
  const agent = request.agent(app);
  const _csrf = await getToken(agent, "/login");
  const res = await agent
    .post("/login")
    .type("form")
    .send({ _csrf, loginIdentifier: user.email, password: PASSWORD });
  expect(res.status).toBe(303);
  return agent;
};

// POST an admin form from the user's detail page (where the CSRF token comes from)
const adminPost = async (agent, targetId, action, body = {}) => {
  const _csrf = await getToken(agent, `/admin/users/${targetId}`);
  return agent
    .post(`/admin/users/${targetId}/${action}`)
    .type("form")
    .set(HTML)
    .send({ _csrf, ...body });
};

// =========================================================================
// Tests
// =========================================================================
describe("Admin pages (server-rendered)", () => {
  let admin;
  let adminAgent;

  beforeAll(async () => {
    await redisService.connect();
    admin = await createUser("boss", { role: "ADMIN" });
    adminAgent = await loginAs(admin);
  });

  afterAll(async () => {
    const users = await prisma.user.findMany({
      where: { email: { startsWith: "adm_" } },
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
  describe("Access control", () => {
    it.each(["/admin/users", "/admin/audit-logs", "/admin/login-history", "/admin/maintenance"])(
      "guests are sent to /login from %s",
      async path => {
        const res = await request(app).get(path).set(HTML);

        expect(res.status).toBe(303);
        expect(res.headers.location).toBe("/login");
      },
    );

    it.each(["/admin/users", "/admin/audit-logs", "/admin/login-history", "/admin/maintenance"])(
      "a normal user gets the 403 'Access denied' page at %s",
      async path => {
        const user = await createUser("plain");
        const agent = await loginAs(user);

        const res = await agent.get(path).set(HTML);

        expect(res.status).toBe(403);
        expect(res.headers["content-type"]).toMatch(/text\/html/);
        expect(res.text).toContain("Access denied");
        expect(res.text).not.toContain("Session expired"); // that's only for CSRF
      },
    );

    it("a normal user cannot run admin actions either (403)", async () => {
      const user = await createUser("sneaky");
      const victim = await createUser("victim");
      const agent = await loginAs(user);
      const _csrf = await getToken(agent, "/dashboard");

      const res = await agent
        .post(`/admin/users/${victim.id}/role`)
        .type("form")
        .set(HTML)
        .send({ _csrf, role: "ADMIN" });

      expect(res.status).toBe(403);
      const dbUser = await prisma.user.findUnique({ where: { id: victim.id } });
      expect(dbUser.role).toBe("USER");
    });

    it("only admins see the 'Admin' link in the nav", async () => {
      const user = await createUser("navuser");
      const userAgent = await loginAs(user);

      const forUser = await userAgent.get("/dashboard").set(HTML);
      const forAdmin = await adminAgent.get("/dashboard").set(HTML);

      expect(forUser.text).not.toContain('href="/admin/users"');
      expect(forAdmin.text).toContain('href="/admin/users"');
    });

    it("/admin redirects to the users list", async () => {
      const res = await adminAgent.get("/admin").set(HTML);

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/admin/users");
    });

    it("an admin POST without a CSRF token is rejected with the 'Session expired' page", async () => {
      const target = await createUser("nocsrf");

      const res = await adminAgent
        .post(`/admin/users/${target.id}/role`)
        .type("form")
        .set(HTML)
        .send({ role: "ADMIN" });

      expect(res.status).toBe(403);
      expect(res.text).toContain("Session expired");
      const dbUser = await prisma.user.findUnique({ where: { id: target.id } });
      expect(dbUser.role).toBe("USER");
    });

    it("a demoted admin loses access on their very next request", async () => {
      const second = await createUser("second", { role: "ADMIN" });
      const secondAgent = await loginAs(second);
      expect((await secondAgent.get("/admin/users").set(HTML)).status).toBe(200);

      await adminPost(adminAgent, second.id, "role", { role: "USER" });

      const res = await secondAgent.get("/admin/users").set(HTML);
      expect([303, 403]).toContain(res.status); // sessions revoked → /login, or 403 if still logged in
    });
  });

  // -----------------------------------------------------------------------
  describe("Users list", () => {
    it("lists users with their role and status", async () => {
      const user = await createUser("listed");

      const res = await adminAgent.get(`/admin/users?search=${user.username}`).set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain(user.email);
      expect(res.text).toContain(`href="/admin/users/${user.id}"`);
      expect(res.text).toContain("ACTIVE");
    });

    it("search narrows the list", async () => {
      const a = await createUser("findme");
      const b = await createUser("other");

      const res = await adminAgent.get(`/admin/users?search=${a.username}`).set(HTML);

      expect(res.text).toContain(a.email);
      expect(res.text).not.toContain(b.email);
    });

    it("filters by role and status", async () => {
      const suspended = await createUser("susp", { status: "SUSPENDED" });
      const active = await createUser("act");

      const res = await adminAgent
        .get(`/admin/users?search=adm_${RUN}&status=SUSPENDED&limit=100`)
        .set(HTML);

      expect(res.text).toContain(suspended.email);
      expect(res.text).not.toContain(active.email);
      expect(res.text).toMatch(/<option value="SUSPENDED"\s+selected/); // dropdown remembers it
    });

    it("filtering only by status works with the form's empty role (?role=&status=…)", async () => {
      const suspended = await createUser("formsusp", { status: "SUSPENDED" });
      const active = await createUser("formact");

      // exactly what the filter form submits when "Any role" is left selected
      const res = await adminAgent
        .get(`/admin/users?search=adm_${RUN}&role=&status=SUSPENDED&sortBy=createdAt&sortOrder=desc&limit=100`)
        .set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).not.toContain("Some filters were invalid");
      expect(res.text).toContain(suspended.email);
      expect(res.text).not.toContain(active.email);
    });

    it("filtering only by role works with the form's empty status", async () => {
      const promoted = await createUser("formadmin", { role: "ADMIN" });

      const res = await adminAgent
        .get(`/admin/users?search=${promoted.username}&role=ADMIN&status=`)
        .set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).not.toContain("Some filters were invalid");
      expect(res.text).toContain(promoted.email);
    });

    it("pagination links keep the current filters", async () => {
      await createUser("pagea");
      await createUser("pageb");

      const res = await adminAgent
        .get(`/admin/users?search=adm_${RUN}&limit=1`)
        .set(HTML);

      expect(res.status).toBe(200);
      // the "Next" link carries the search and limit along with page=2
      const next = res.text.match(/href="([^"]+)" rel="next"/);
      expect(next).not.toBeNull();
      const url = new URL(next[1].replaceAll("&amp;", "&"), "http://x");
      expect(url.searchParams.get("search")).toBe(`adm_${RUN}`);
      expect(url.searchParams.get("limit")).toBe("1");
      expect(url.searchParams.get("page")).toBe("2");
    });

    it("clicking a sorted column again reverses the order", async () => {
      const res = await adminAgent.get("/admin/users?sortBy=email&sortOrder=desc").set(HTML);

      const link = res.text.match(/<th aria-sort="descending"><a href="([^"]+)"/);
      expect(link).not.toBeNull();
      expect(link[1]).toContain("sortBy=email");
      expect(link[1]).toContain("sortOrder=asc");
    });

    it("invalid filters are reset with a message instead of an error page", async () => {
      const res = await adminAgent.get("/admin/users?page=-3&role=WIZARD").set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain("Some filters were invalid and have been reset.");
    });

    it("escapes the search text when showing it back (no XSS)", async () => {
      const res = await adminAgent
        .get(`/admin/users?search=${encodeURIComponent('"><script>alert(1)</script>')}`)
        .set(HTML);

      expect(res.text).not.toContain("<script>alert(1)</script>");
    });
  });

  // -----------------------------------------------------------------------
  describe("User detail", () => {
    it("shows the account details and the action forms", async () => {
      const target = await createUser("detail");

      const res = await adminAgent.get(`/admin/users/${target.id}`).set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain(target.email);
      for (const action of ["role", "status", "unlock", "logout-all", "delete"]) {
        expect(res.text).toContain(`action="/admin/users/${target.id}/${action}"`);
      }
    });

    it("on your own page the role, status and delete forms are hidden", async () => {
      const res = await adminAgent.get(`/admin/users/${admin.id}`).set(HTML);

      expect(res.text).toContain("This is your own account");
      expect(res.text).not.toContain(`action="/admin/users/${admin.id}/role"`);
      expect(res.text).not.toContain(`action="/admin/users/${admin.id}/status"`);
      expect(res.text).not.toContain(`action="/admin/users/${admin.id}/delete"`);
    });

    it.each(["not-a-uuid", "00000000-0000-4000-8000-000000000000"])(
      "an invalid or unknown id (%s) shows the 404 page",
      async id => {
        const res = await adminAgent.get(`/admin/users/${id}`).set(HTML);

        expect(res.status).toBe(404);
        expect(res.text).toContain("Page not found");
      },
    );
  });

  // -----------------------------------------------------------------------
  describe("User actions", () => {
    it("changing the role updates it, shows a notice and logs the user out", async () => {
      const target = await createUser("promote");
      const targetAgent = await loginAs(target);

      const res = await adminPost(adminAgent, target.id, "role", { role: "ADMIN" });

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe(`/admin/users/${target.id}?done=role`);
      const dbUser = await prisma.user.findUnique({ where: { id: target.id } });
      expect(dbUser.role).toBe("ADMIN");

      const page = await adminAgent.get(res.headers.location).set(HTML);
      expect(page.text).toContain("Role updated.");

      const after = await targetAgent.get("/dashboard").set(HTML);
      expect(after.headers.location).toBe("/login"); // their session was revoked
    });

    it("an invalid role is rejected with a message", async () => {
      const target = await createUser("badrole");

      const res = await adminPost(adminAgent, target.id, "role", { role: "WIZARD" });

      expect(res.status).toBe(400);
      expect(res.text).toContain("Choose a valid role.");
    });

    it("an admin cannot change their own role (the service refuses)", async () => {
      // the form is hidden, but a hand-made POST must still be refused
      const res = await adminPost(adminAgent, admin.id, "role", { role: "USER" });

      expect(res.status).toBe(403);
      expect(res.text).toContain("cannot change their own role");
      const dbUser = await prisma.user.findUnique({ where: { id: admin.id } });
      expect(dbUser.role).toBe("ADMIN");
    });

    it("suspending a user ends their session and blocks login", async () => {
      const target = await createUser("suspend");
      const targetAgent = await loginAs(target);

      const res = await adminPost(adminAgent, target.id, "status", { status: "SUSPENDED" });

      expect(res.status).toBe(303);
      const dbUser = await prisma.user.findUnique({ where: { id: target.id } });
      expect(dbUser.status).toBe("SUSPENDED");

      const after = await targetAgent.get("/dashboard").set(HTML);
      expect(after.headers.location).toBe("/login");

      const relogin = request.agent(app);
      const _csrf = await getToken(relogin, "/login");
      const attempt = await relogin
        .post("/login")
        .type("form")
        .send({ _csrf, loginIdentifier: target.email, password: PASSWORD });
      expect(attempt.status).toBe(401);
    });

    it("unlock is refused when the account isn't locked", async () => {
      const target = await createUser("notlocked");

      const res = await adminPost(adminAgent, target.id, "unlock");

      expect(res.status).toBe(400);
      expect(res.text).toContain("not currently locked");
    });

    it("unlock clears failed attempts and the lockout", async () => {
      const target = await createUser("locked", {
        failedAttempts: 5,
        lockedUntil: new Date(Date.now() + 15 * 60 * 1000),
      });

      const res = await adminPost(adminAgent, target.id, "unlock");

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe(`/admin/users/${target.id}?done=unlocked`);
      const dbUser = await prisma.user.findUnique({ where: { id: target.id } });
      expect(dbUser.failedAttempts).toBe(0);
      expect(dbUser.lockedUntil).toBeNull();
    });

    it("'log out everywhere' ends the user's sessions", async () => {
      const target = await createUser("kick");
      const targetAgent = await loginAs(target);

      const res = await adminPost(adminAgent, target.id, "logout-all");

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe(`/admin/users/${target.id}?done=logged-out`);
      const after = await targetAgent.get("/dashboard").set(HTML);
      expect(after.headers.location).toBe("/login");
    });

    it("delete requires typing the exact username", async () => {
      const target = await createUser("keepme");

      const res = await adminPost(adminAgent, target.id, "delete", { confirmUsername: "wrong" });

      expect(res.status).toBe(422);
      expect(res.text).toContain(`type their username (${target.username}) exactly`);
      expect(await prisma.user.findUnique({ where: { id: target.id } })).not.toBeNull();
    });

    it("delete with the right username removes the user", async () => {
      const target = await createUser("byebye");

      const res = await adminPost(adminAgent, target.id, "delete", {
        confirmUsername: target.username,
      });

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/admin/users?done=deleted");
      expect(await prisma.user.findUnique({ where: { id: target.id } })).toBeNull();

      const list = await adminAgent.get("/admin/users?done=deleted").set(HTML);
      expect(list.text).toContain("User permanently deleted.");
    });

    it("an admin cannot delete themselves (the service refuses)", async () => {
      const res = await adminPost(adminAgent, admin.id, "delete", {
        confirmUsername: admin.username,
      });

      expect(res.status).toBe(403);
      expect(res.text).toContain("cannot delete their own account");
      expect(await prisma.user.findUnique({ where: { id: admin.id } })).not.toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  describe("Audit log", () => {
    it("shows admin actions, filterable by action", async () => {
      const target = await createUser("audited");
      await adminPost(adminAgent, target.id, "status", { status: "SUSPENDED" });

      const res = await adminAgent
        .get(`/admin/audit-logs?action=STATUS_CHANGE&search=${admin.id}`)
        .set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain("STATUS_CHANGE");
      expect(res.text).toContain("Status ACTIVE → SUSPENDED");
      expect(res.text).toContain(`href="/admin/users/${target.id}"`); // link to the target user
    });

    it("an unknown action filter is reset with a message", async () => {
      const res = await adminAgent.get("/admin/audit-logs?action=NOT_A_THING").set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain("Some filters were invalid and have been reset.");
    });
  });

  // -----------------------------------------------------------------------
  describe("Login history", () => {
    it("shows logins, and can be filtered to one user", async () => {
      const user = await createUser("logins");
      await loginAs(user);

      const res = await adminAgent.get(`/admin/login-history?userId=${user.id}`).set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain("Showing logins for one user only.");
      expect(res.text).toContain(`href="/admin/users/${user.id}"`);
      expect(res.text).toContain("Success");
    });

    it("the user detail page shows their recent logins", async () => {
      const user = await createUser("recent");
      await loginAs(user);

      const res = await adminAgent.get(`/admin/users/${user.id}`).set(HTML);

      expect(res.text).toContain("Recent logins");
      expect(res.text).toContain(`href="/admin/login-history?userId=${user.id}"`);
    });
  });

  // -----------------------------------------------------------------------
  describe("Maintenance", () => {
    it("shows the cleanup form with sensible defaults", async () => {
      const res = await adminAgent.get("/admin/maintenance").set(HTML);

      expect(res.status).toBe(200);
      expect(res.text).toContain('action="/admin/maintenance/cleanup"');
      expect(res.text).toContain('name="retentionDays" min="1" max="365" value="7"');
    });

    it("running the cleanup shows a summary", async () => {
      const _csrf = await getToken(adminAgent, "/admin/maintenance");

      const res = await adminAgent
        .post("/admin/maintenance/cleanup")
        .type("form")
        .send({ _csrf, retentionDays: "30", loginHistoryRetentionDays: "730" });

      expect(res.status).toBe(200);
      expect(res.text).toContain("Cleanup finished");
      expect(res.text).toContain("Refresh tokens");
    });

    it("the 'also delete login history' checkbox is turned into a real boolean", async () => {
      const _csrf = await getToken(adminAgent, "/admin/maintenance");

      const res = await adminAgent
        .post("/admin/maintenance/cleanup")
        .type("form")
        // 730 days keeps everything newer than two years, so this is harmless on a dev DB
        .send({ _csrf, retentionDays: "30", cleanLoginHistory: "on", loginHistoryRetentionDays: "730" });

      expect(res.status).toBe(200);
      expect(res.text).toMatch(/name="cleanLoginHistory"\s+checked/); // stays ticked
    });

    it("invalid numbers are rejected with a message (422)", async () => {
      const _csrf = await getToken(adminAgent, "/admin/maintenance");

      const res = await adminAgent
        .post("/admin/maintenance/cleanup")
        .type("form")
        .send({ _csrf, retentionDays: "0", loginHistoryRetentionDays: "90" });

      expect(res.status).toBe(422);
      expect(res.text).toContain("Retention days must be at least 1");
    });
  });
});
