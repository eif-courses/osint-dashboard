# ---- build stage ----
FROM node:20-bookworm AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ---- runtime stage ----
FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl unzip nmap \
  && rm -rf /var/lib/apt/lists/*

# Install Amass v3 (pinned — v4 has breaking CLI changes that break passive enum)
RUN set -eux; \
  curl -fsSL -o /tmp/amass.zip \
    https://github.com/owasp-amass/amass/releases/download/v3.23.3/amass_Linux_amd64.zip \
  && mkdir -p /opt/amass \
  && unzip -q /tmp/amass.zip -d /opt/amass \
  && ln -sf /opt/amass/amass_Linux_amd64/amass /usr/local/bin/amass \
  && rm -f /tmp/amass.zip

COPY --from=build /app/.output ./.output
COPY --from=build /app/package*.json ./

EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
