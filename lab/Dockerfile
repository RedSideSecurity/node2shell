# The Node.js version is the ONLY difference between a vulnerable and a
# patched lab target. 24.22.0 bundles the vulnerable Brotli decoder;
# 24.22.1 bundles the fix. The app layer is identical.
ARG NODE_VERSION=24.22.0
FROM node:${NODE_VERSION}-bookworm-slim

WORKDIR /app
COPY app/package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY app/server.js ./

EXPOSE 3000
CMD ["node", "server.js"]
