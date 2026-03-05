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

# Install Amass (binary release)
# Install Amass (binary release)
RUN set -eux; \
  curl -fsSL -o /tmp/amass.tar.gz \
    https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.tar.gz \
  && mkdir -p /opt/amass \
  && tar -xzf /tmp/amass.tar.gz -C /opt/amass \
  && ln -sf /opt/amass/amass_linux_amd64/amass /usr/local/bin/amass \
  && rm -f /tmp/amass.tar.gz

COPY --from=build /app/.output ./.output
COPY --from=build /app/package*.json ./

EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
