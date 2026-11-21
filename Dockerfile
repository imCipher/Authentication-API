# 1. Start from the official Node 26 image (Debian "slim" — argon2 has ready-made binaries for it)
FROM node:26-slim

# 2. All following commands run inside /app
WORKDIR /app

# 3. Production mode for npm and for the app
ENV NODE_ENV=production

# 4. Install dependencies first: this slow step is cached until package*.json changes
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# 5. Copy the app (everything not listed in .dockerignore)
COPY . .

# 6. Build the Prisma client into ./generated (reads schema.prisma, no database needed)
RUN npx prisma generate

# 7. Run as the unprivileged "node" user, not root
USER node

# 8. The port server.js listens on (PORT=3000)
EXPOSE 3000

# 9. Docker/Dokploy checks the app + database are healthy every 30s
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/v1/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# 10. On every start: apply new migrations, then run the app (stops if a migration fails)
CMD ["sh", "-c", "npx prisma migrate deploy && node server.js"]