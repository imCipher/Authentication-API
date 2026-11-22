# Authentication with Prisma
[![Tests](https://github.com/imCipher/Authentication-API/actions/workflows/tests.yml/badge.svg)](https://github.com/imCipher/Authentication-API/actions/workflows/tests.yml)

A production-style authentication system built with **Node.js, Express 5, Prisma 7, PostgreSQL and Redis**: a JSON REST API **and** a server-rendered website (EJS) on top of the same service layer, deployed with Docker.

**🔗 Live demo:** https://auth.primedev.dedyn.io
**Demo login:** `john_lee3 or john.lee3@example.com` / `SecureP@ss1` _(a seeded demo account — feel free to try it)_

> Built as a learning and portfolio project, with a focus on getting the security details right rather than just "making login work".

---

## Screenshots

| Log in                                | Create an account                          | Verification code                            |
| ------------------------------------- | ------------------------------------------ | -------------------------------------------- |
| ![Log in](docs/screenshots/login.png) | ![Register](docs/screenshots/register.png) | ![Verify email](docs/screenshots/verify.png) |

| Dashboard                                    | Admin: users                                     | Admin: user detail                             |
| -------------------------------------------- | ------------------------------------------------ | ---------------------------------------------- |
| ![Dashboard](docs/screenshots/dashboard.png) | ![Admin users](docs/screenshots/admin-users.png) | ![Admin user](docs/screenshots/admin-user.png) |

---

## Features

**For users**

- Register with email + password, verified by a **6-digit email code** (paste-friendly digit boxes, resend with cooldown)
- Log in with **email or username**, or **Continue with Google**
- Forgot / reset password by email link
- Dashboard and settings: edit profile, change password, **log out of all devices**
- Google-only accounts can set a password later by email link

**For admins**

- Users list with **search, filters, sortable columns and pagination** (filters live in the URL, so views can be bookmarked)
- User detail: change role or status, unlock a locked account, force log-out everywhere, delete (type-the-username confirmation)
- **Audit log** and **login history** viewers
- Database maintenance: clean up expired and used tokens

**Two front doors, one core**

- A versioned **JSON API** (`/api/v1/...`) with Swagger docs
- A **server-rendered website** with EJS
- Both call the same service layer, so every business rule lives in exactly one place

---

## Security highlights

| Area                   | What's implemented                                                                                                                                                                      |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Passwords              | **argon2id** hashing; constant-time dummy check for unknown users (no timing-based account discovery)                                                                                   |
| Sessions               | Short-lived **JWT access tokens** (15 min) + opaque **refresh tokens stored only as SHA-256 hashes**                                                                                    |
| Refresh token rotation | Every refresh issues a new token; **reuse of an old token revokes all of that user's sessions**; a short grace window handles legitimate parallel requests                              |
| Logout                 | Access tokens are **denylisted in Redis** until they expire; password change, reset and "log out everywhere" invalidate all sessions                                                    |
| Cookies                | `httpOnly`, `SameSite=Lax`, `Secure` in production, `__Host-` prefix                                                                                                                    |
| CSRF                   | Double-submit CSRF tokens (`csrf-csrf`) **tied to a per-visitor session id**                                                                                                            |
| Email codes            | 6-digit codes **scoped to the email**, expire in 5 minutes, **locked after 5 wrong attempts** (atomic counter, safe under parallel requests)                                            |
| Password reset         | 256-bit single-use tokens, expiring, all sessions revoked after reset                                                                                                                   |
| Brute force            | Account lockout after 5 failures + **per-route rate limits in Redis** (falls back to memory if Redis is down)                                                                           |
| Account enumeration    | Forgot-password and resend-code always give the same response                                                                                                                           |
| Google sign-in         | OAuth `state` checked against a short-lived cookie (**login-CSRF protection**); **pre-hijacking protection** (linking Google to a never-verified account removes the unproven password) |
| Access control         | Role-based access (USER / ADMIN), role re-checked from the database on every request, **last-admin protection**, no self-demotion or self-deletion                                      |
| Input & output         | **Zod** validation on every input; all user content escaped in templates; Helmet security headers                                                                                       |
| Logging                | Secrets (reset tokens, OAuth codes, emails) **redacted from access logs**                                                                                                               |
| Configuration          | The server **refuses to start in production** with missing or unsafe settings (default secrets, non-HTTPS URL, `*` CORS)                                                                |

---

## Tech stack

| Layer                          | Tools                                                        |
| ------------------------------ | ------------------------------------------------------------ |
| Runtime                        | Node.js 26, Express 5                                        |
| Database                       | PostgreSQL 18, Prisma 7 (with the `pg` driver adapter)       |
| Cache / rate limits / denylist | Redis (ioredis)                                              |
| Auth                           | jsonwebtoken, argon2, Passport (Google OAuth 2.0), csrf-csrf |
| Validation                     | Zod 4                                                        |
| Views                          | EJS, plain CSS, vanilla JavaScript                           |
| Email                          | Nodemailer + Pug templates                                   |
| Logging                        | Winston + Morgan                                             |
| Testing                        | Vitest + Supertest (unit and integration)                    |
| Deployment                     | Docker, Dokploy, Traefik (HTTPS via Let's Encrypt)           |

---

## Architecture

```mermaid
flowchart LR
  Browser["Browser (EJS pages)"] --> Web["Web routes + controllers<br/>cookies, CSRF, redirects"]
  Client["API client / mobile"] --> API["API routes + controllers<br/>JSON, Bearer tokens"]
  Web --> Services["Services<br/>AuthService · AdminService<br/>(all business rules)"]
  API --> Services
  Services --> Prisma["Prisma ORM"] --> PG[("PostgreSQL")]
  Services --> Redis[("Redis<br/>rate limits · denylist")]
```

The routes and controllers only translate HTTP. The JSON API returns JSON, and the website sets cookies, renders pages and redirects. **All rules live in the services**, so a fix in one place applies to both.

```
src/
├── config/        # env config, Prisma, Redis, Passport, CSRF, logger
├── middlewares/   # auth, page auth, RBAC, rate limiters, validation, errors
├── modules/
│   ├── auth/      # API: routes, controller, service, Zod schemas
│   ├── admin/     # API: routes, controller, service, Zod schemas
│   ├── health/    # liveness + readiness (DB check)
│   └── web/       # website: page routes + controllers (incl. admin pages)
├── utils/         # tokens, hashing, cookies, email, errors
└── views/         # EJS pages + partials, Pug email templates
prisma/            # schema + migrations
public/            # CSS, JS, images
tests/             # unit + integration tests
```

---

## API overview

Interactive docs: **`/api-docs`** (Swagger, available in development).

| Method               | Endpoint                                         | Description                                    |
| -------------------- | ------------------------------------------------ | ---------------------------------------------- |
| POST                 | `/api/v1/auth/register`                          | Create an account and send a verification code |
| POST                 | `/api/v1/auth/verify-email`                      | Verify the email with the 6-digit code         |
| POST                 | `/api/v1/auth/resend-verification`               | Send a new code                                |
| POST                 | `/api/v1/auth/login`                             | Log in, returns an access + refresh token pair |
| POST                 | `/api/v1/auth/refresh-token`                     | Rotate the refresh token                       |
| POST                 | `/api/v1/auth/logout` · `/logout-all`            | End this session · all sessions                |
| POST                 | `/api/v1/auth/forgot-password`                   | Email a reset link                             |
| POST                 | `/api/v1/auth/reset-password/:token`             | Set a new password                             |
| POST                 | `/api/v1/auth/change-password`                   | Change password (logged in)                    |
| GET · PATCH          | `/api/v1/auth/me`                                | Read · update your profile                     |
| GET                  | `/api/v1/auth/google`                            | Sign in with Google                            |
| GET                  | `/api/v1/admin/users`                            | List users (search, filter, sort, paginate)    |
| GET · PATCH · DELETE | `/api/v1/admin/users/:id`                        | View · change role/status · delete             |
| POST                 | `/api/v1/admin/users/:id/unlock` · `/logout-all` | Unlock · force log-out                         |
| GET                  | `/api/v1/admin/audit-logs` · `/login-history`    | Audit trail · login attempts                   |
| POST                 | `/api/v1/admin/maintenance/cleanup`              | Purge expired tokens                           |
| GET                  | `/api/v1/health` · `/health/ready`               | Liveness · readiness (database check)          |

---

## Testing

**476 tests** across unit and integration suites. Integration tests run the real app with Supertest against a real PostgreSQL and Redis. Only outgoing email and Google's network calls are faked.

Highlights include CSRF rejection (missing, tampered or cross-session tokens), refresh-token reuse detection, XSS escaping, account enumeration checks, the Google sign-in `state` check, pre-hijacking protection, and the admin last-admin and self-action rules.

```bash
npm test               # run everything
npm run test:coverage  # with a coverage report
```

---

## Running locally

**Requirements:** Node.js 26+, PostgreSQL 18, Redis.

```bash
git clone https://github.com/imCipher/Authentication-API.git
cd Authentication-API
npm install
```

Create a `.env` file in the project root:

```env
NODE_ENV=development
PORT=3000
APP_URL=http://localhost:3000
DATABASE_URL=postgresql://postgres:password@localhost:5432/auth_db?schema=public
REDIS_HOST=127.0.0.1
REDIS_PORT=6379

JWT_ACCESS_SECRET=<random 64 chars>
JWT_REFRESH_SECRET=<random 64 chars>
CSRF_SECRET=<random 64 chars>
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7

ADMIN_EMAIL=admin@example.com
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<at least 8 characters>

EMAIL_HOST=<smtp host>
EMAIL_PORT=587
EMAIL_USER=<smtp user>
EMAIL_PASS=<smtp password>
EMAIL_FROM=Auth <no-reply@example.com>

# optional: enables "Continue with Google"
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_CALLBACK_URL=http://localhost:3000/api/v1/auth/google/callback
```

Generate secrets with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.

```bash
npx prisma migrate deploy   # create the tables
npx prisma generate         # build the Prisma client
npm run dev                 # http://localhost:3000/login
npm run db:seed             # optional: 50 demo users (password: SecureP@ss1)
```

The admin account in `ADMIN_*` is created automatically on first start.

---

## Deployment

Shipped as a **Docker** image (`node:26-slim`, runs as a non-root user, health check on `/api/v1/health/ready`). On every start the container runs `prisma migrate deploy` before the server, so the database schema is always up to date.

It runs on a VPS with **Dokploy**. Traefik handles HTTPS with Let's Encrypt, PostgreSQL and Redis run as internal services, and every merge to `main` deploys automatically.

---

## What I learned

- Designing a **refresh-token rotation** scheme with reuse detection, and handling the race conditions in it
- Protecting cookie-based sessions with **CSRF tokens**, and why `SameSite` alone isn't enough
- OAuth's `state` parameter and **account pre-hijacking**, which are easy to miss
- Keeping **one service layer** behind two different interfaces (JSON API and server-rendered pages)
- Writing integration tests that prove **security properties**, not just happy paths
- Prisma migrations in production, and deploying with Docker

---

## Author

**Cipher**: [GitHub](https://github.com/imCipher) · [LinkedIn](https://www.linkedin.com/in/umar-ekerin)
