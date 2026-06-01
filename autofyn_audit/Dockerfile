# autofyn_audit/Dockerfile
#
# Pinned base image digest resolved via:
#   docker pull oven/bun:1.3.6 && \
#   docker inspect --format='{{index .RepoDigests 0}}' oven/bun:1.3.6
# Result: oven/bun@sha256:f20d9cf365ab35529384f1717687c739c92e6f39157a35a95ef06f4049a10e4a
#
# Build context: repo root (pass EXPECTED_COMMIT as ARG; host checks git rev first)
#
FROM oven/bun:1.3.6@sha256:f20d9cf365ab35529384f1717687c739c92e6f39157a35a95ef06f4049a10e4a

ARG EXPECTED_COMMIT=268499068810586495ba5bd4773f8c5786d9fc97

# Install a REAL Node.js (>= 20) + curl.
#
# IMPORTANT: the oven/bun image ships a `node` that is merely a symlink to `bun`
# (/usr/local/bun-node-fallback-bin/node -> /usr/local/bin/bun). Wrangler's
# `wrangler dev` opens a websocket to its local workerd runtime and that
# handshake FAILS under Bun ("Unexpected server response: 101" / "Wrangler does
# not support the Bun runtime"). We therefore install genuine Node.js from
# NodeSource so `wrangler dev` (apps/mcp) runs under Node. `next dev` (apps/web)
# is unaffected and continues to run under bun via `bun run dev:app`.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends curl ca-certificates gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    # Ensure the real node shadows the bun-node fallback shim on PATH.
    ln -sf /usr/bin/node /usr/local/bin/node && \
    /usr/bin/node --version

WORKDIR /app

# Copy the full repo (minus what .dockerignore excludes: node_modules, .git, .next, dist, .open-next).
COPY . .

# Install all workspace dependencies using the lock file.
# First build may take 2-4 minutes on a cold cache.
RUN bun install --frozen-lockfile

# Disable wrangler telemetry and update checks; use error-level logging only.
ENV WRANGLER_SEND_METRICS=false \
    CI=1 \
    WRANGLER_LOG=error \
    NODE_ENV=development

# Default CMD is overridden per-container in setup.sh.
CMD ["echo", "Specify a CMD when running this image."]
