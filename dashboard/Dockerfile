# The dashboard, built and served with next start on 3000. docker-compose.yml runs it in the
# gateway service's network, so http://127.0.0.1:8766, the admin API URL baked in at build time,
# reaches the gateway both from the server and from the browser.
FROM node:22-slim AS build
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev && rm -rf .next/cache

# Only what next start needs: the build output and the runtime dependencies.
FROM node:22-slim
ENV NEXT_TELEMETRY_DISABLED=1 NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json /app/next.config.ts ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
EXPOSE 3000
CMD ["node_modules/.bin/next", "start", "--hostname", "0.0.0.0", "--port", "3000"]
