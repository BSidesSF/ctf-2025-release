FROM node:18-alpine AS base

# Setup node modules
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY nextpm/package.json nextpm/package-lock.json .
RUN npm ci

# Build the app itself
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY nextpm/ .
RUN npm run build

FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER 1001

EXPOSE 3000

ENV PORT=3000

ENV HOSTNAME="0.0.0.0"
CMD ["node", "server.js"]
