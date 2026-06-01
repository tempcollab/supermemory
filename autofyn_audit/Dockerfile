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

# Install Node.js >= 20 (bun image ships node too, but confirm version) and curl for health-checks.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

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
