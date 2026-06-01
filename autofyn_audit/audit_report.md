# Security Audit Report — Supermemory Monorepo

**Audit Firm:** AutoFyn Security  
**Date:** 2026-06-01  
**Pinned Commit:** `268499068810586495ba5bd4773f8c5786d9fc97`  
**Pinned Base Image:** `oven/bun:1.3.6@sha256:f20d9cf365ab35529384f1717687c739c92e6f39157a35a95ef06f4049a10e4a`  
**Methodology:** Static code analysis + live local instance (`next dev` / `wrangler dev`) in Docker, no external API access.  

---

## Scope & Architecture

**In scope:** `apps/web` (Next.js, port 3000) and `apps/mcp` (Hono MCP server on Cloudflare Workers, port 8788).

**Out of scope — explicitly:** `api.supermemory.ai` and any external hosted endpoint. The web application is a **thin UI proxy**: it has no in-repo database, no persistent server-side data boundary, and no business logic of its own beyond routing to the external API. This architectural fact caps the realistic severity of all findings. A finding that would be CRITICAL in a monolithic app is often MEDIUM here because there is no direct path to exfiltrate user data stored in-repo.

**Impact ceiling:** The most critical server-side attack surface (data store, auth server, API business logic) lives in `api.supermemory.ai` which is out of scope and was not targeted.

---

## Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0     |
| HIGH     | 0     |
| MEDIUM   | 2     |
| LOW/INFO | 1     |

**0 CRITICAL, 0 HIGH findings.** The thin-proxy architecture means there is no in-repo data to exfiltrate. Two previously reported HIGH/MEDIUM findings (C2 and C3) were **refuted by live testing** — those routes are auth-gated and return 401 without a session cookie. See the Dropped/Refuted Candidates appendix.

**2 MEDIUM (C1, C4):** SSRF in the OG-scraper route (mitigated in production by Cloudflare's `global_fetch_strictly_public`), and unvalidated host-header reflection in MCP OAuth metadata.

**1 LOW/INFO (L1):** Presence-only cookie validation on `/api/*` — any non-empty `better-auth-dev.session_token` value satisfies the middleware auth check (no signature verification at the edge). This is the real enabler that lets C1 be reached with `Cookie: better-auth-dev.session_token=x`.

---

## Findings

---

### C1 — SSRF in `/api/og`

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Affected file** | `apps/web/app/api/og/route.ts:16-36` (`isPrivateHost`), `:182` (fetch call) |
| **Authentication** | Session cookie required (presence-only check — any non-empty value works) |

#### Description

The `/api/og` route fetches a user-supplied URL server-side and returns parsed `<title>` / `<meta>` / `og:*` content as JSON. `isPrivateHost()` (line 16-36) attempts to block internal targets, but its check is a literal string/prefix match against the URL's `hostname` property. It misses:

1. **DNS names that resolve to internal IPs** — `new URL("http://audit-mock/").hostname` returns the string `"audit-mock"`, which matches no blocked pattern. Node.js `fetch()` then resolves it to the Docker network internal IP and makes the request. This is the primary bypass demonstrated live.
2. **Link-local `169.254.0.0/16`** — No rule blocks `169.254.*`. On cloud VMs this exposes the Instance Metadata Service (IMDS) endpoint `169.254.169.254`. Live: 504 timeout proves fetch was attempted (no IMDS locally).

> **Withdrawn sub-claim:** The decimal-IP bypass (`http://2130706433/`) was claimed in the initial analysis but is **BLOCKED live**. Bun/Node normalises `new URL("http://2130706433/").hostname` to `127.0.0.1`, which matches `isPrivateHost()`'s `startsWith("127.")` check, returning 400. This sub-claim is withdrawn.

The route is matched by the Next.js middleware (the matcher at `middleware.ts:82` does not exclude `og`), so a session cookie is required — but the check is `if (!sessionCookie)` with no cryptographic validation, satisfied by `Cookie: better-auth-dev.session_token=x` (see also L1).

#### Reproduction

```bash
# Ensure setup.sh and mock_server.py are running
bash autofyn_audit/setup.sh

# Run the exploit directly:
bash autofyn_audit/exploits/exploit_01_og_ssrf.sh

# Or via run_exploits.sh:
bash autofyn_audit/run_exploits.sh
```

Exact request (primary proof):
```
GET http://autofyn-web:3000/api/og?url=http%3A%2F%2Faudit-mock%3A9099%2Fssrf-target
Cookie: better-auth-dev.session_token=x
```

Expected result: HTTP 200 with `title`/`description` containing the canary token; mock `/__hits` records a server-side fetch to `/ssrf-target`.

#### Evidence

**C1 PRIMARY — DNS-name SSRF (confirmed live):**
```
Request:  GET http://autofyn-web:3000/api/og?url=http://audit-mock:9099/ssrf-target
Cookie:   better-auth-dev.session_token=x
Status:   200
Body:     {"title":"SSRF-CANARY-e9435e4e-...-og-title","description":"SSRF-CANARY-e9435e4e-...-og-desc"}
Mock hit recorded (server-side fetch from the web container):
  {"method":"GET","path":"/ssrf-target","headers":{"host":"audit-mock:9099",
   "User-Agent":"Mozilla/5.0 (compatible; SuperMemory/1.0; +https://supermemory.ai)", ...}}
```
The web server fetched an internal-network host addressed by bare DNS name. Canary reflected in JSON response confirms content exfiltration of the internal response.

**C1 SECONDARY — link-local bypass (confirmed live):**
```
Request:  GET http://autofyn-web:3000/api/og?url=http://169.254.169.254/latest/meta-data/
Cookie:   better-auth-dev.session_token=x
Status:   504
```
504 timeout = validation passed, fetch was attempted. isPrivateHost() has no `169.254.*` rule.

**C1 WITHDRAWN — decimal-IP (BLOCKED live):**
```
Request:  GET http://autofyn-web:3000/api/og?url=http://2130706433/
Status:   400  {"error":"Private/localhost URLs are not allowed"}
```
Bun/Node normalises `2130706433` → `127.0.0.1` → blocked. Sub-claim withdrawn.

Proof file: `autofyn_audit/.audit_state/exploit_01.proof`

#### Impact

- **Dev/Node deployments:** Server-side fetch to arbitrary internal DNS names and non-RFC1918 IP ranges (IMDS, link-local). On cloud infrastructure this could expose instance metadata credentials.
- **Production (Cloudflare Workers):** The `global_fetch_strictly_public` compatibility flag (`apps/web/wrangler.jsonc:12`) blocks private/link-local egress at the Workers runtime level. **Production impact is largely mitigated.**

#### Mitigating Factors

- `global_fetch_strictly_public` in `wrangler.jsonc` makes this a dev-only risk in the current deployment.
- Content is reflected (title/meta) not raw response bodies — partial mitigation against blind SSRF.

#### Recommendation

1. Add `169.254.0.0/16` (link-local), `100.64.0.0/10` (CGNAT), and `fd00::/8` (IPv6 ULA) to `isPrivateHost()`.
2. Resolve the URL hostname via DNS before the allowlist check (or block non-routable DNS names at the application layer).
3. Alternatively, add a server-side HTTP proxy with an explicit allowlist for external-only URLs.

---

### C4 — MCP Host-Header Injection in OAuth Metadata

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Affected file** | `apps/mcp/src/index.ts:28-33` (`mcpBaseUrl`), `:69-78` (well-known JSON), `:125-131` (WWW-Authenticate) |
| **Authentication** | None required (public endpoints) |

#### Description

`mcpBaseUrl()` (`index.ts:28-33`) constructs the server base URL from the `x-forwarded-host` (then `host`) header with no validation or allowlist when `MCP_URL` env is unset:

```typescript
const mcpBaseUrl = (c: Context<{ Bindings: Bindings }>) => {
    if (c.env.MCP_URL) return c.env.MCP_URL.replace(/\/$/, "")
    const host = c.req.header("x-forwarded-host") || c.req.header("host")
    const proto = c.req.header("x-forwarded-proto") || "https"
    return host ? `${proto}://${host}` : DEFAULT_MCP_URL
}
```

This value is reflected verbatim into:

1. **`WWW-Authenticate` header** on 401 from `GET /mcp` (no token):
   ```
   WWW-Authenticate: Bearer resource_metadata="https://attacker.example/.well-known/oauth-protected-resource/mcp"
   ```
2. **`resource` field** in `GET /.well-known/oauth-protected-resource` JSON:
   ```json
   {"resource": "https://attacker.example/mcp", ...}
   ```

A spec-compliant MCP client that auto-follows `resource_metadata` would be redirected to an attacker-designated OAuth authorization server — OAuth metadata poisoning / phishing redirect.

**Precondition:** `apps/mcp/wrangler.jsonc` sets only `API_URL`, not `MCP_URL`. So `wrangler dev` (local mode) starts with `MCP_URL` unset, making this live-reproducible in the audit environment.

**CRLF injection is NOT claimed.** Workers/Hono normalize header values; only the URL-value injection is confirmed.

#### Reproduction

```bash
bash autofyn_audit/exploits/exploit_04_mcp_host_header_injection.sh
```

**Proof A:**
```bash
curl -s -D - http://autofyn-mcp:8788/mcp \
  -H "x-forwarded-host: attacker.example"
# Expected: 401 with:
# WWW-Authenticate: Bearer resource_metadata="https://attacker.example/.well-known/oauth-protected-resource/mcp"
```

**Proof B:**
```bash
curl -s http://autofyn-mcp:8788/.well-known/oauth-protected-resource \
  -H "x-forwarded-host: attacker.example"
# Expected: {"resource":"https://attacker.example/mcp", ...}
```

#### Evidence

**C4 Proof A (confirmed live):**
```
Request: GET http://autofyn-mcp:8788/mcp   -H "x-forwarded-host: attacker.example"
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Bearer resource_metadata="https://attacker.example/.well-known/oauth-protected-resource/mcp"
```

**C4 Proof B (confirmed live):**
```
Request: GET http://autofyn-mcp:8788/.well-known/oauth-protected-resource   -H "x-forwarded-host: attacker.example"
  200 {"resource":"https://attacker.example/mcp","authorization_servers":["https://api.supermemory.ai"],...}
```

**Baseline (no header):**
```
GET http://autofyn-mcp:8788/.well-known/oauth-protected-resource
  200 {"resource":"https://mcp.supermemory.ai/mcp",...}
```

Attacker-controlled `x-forwarded-host` is reflected verbatim into both the OAuth resource-metadata URL and the `WWW-Authenticate` discovery header.

Proof file: `autofyn_audit/.audit_state/exploit_04.proof`

#### Impact

- MCP clients that auto-follow `resource_metadata` per the OAuth spec would fetch OAuth metadata from an attacker-controlled server. This could facilitate phishing / credential harvesting of OAuth tokens.
- Requires attacker to be a MITM or to control the HTTP layer supplying `x-forwarded-host`.

#### Mitigating Factors

- Exploitable only when `MCP_URL` env is unset. In production deployments that set `MCP_URL`, the header is ignored.
- Requires a client that auto-follows `resource_metadata` links without user confirmation.
- CRLF/header-splitting is NOT exploitable here.

#### Recommendation

1. Set `MCP_URL` in all deployment environments (including local dev via `.env` / wrangler vars).
2. Validate `x-forwarded-host` against an allowlist of known deployment hostnames if dynamic resolution is required.
3. Remove `x-forwarded-host` trust when behind a load balancer that doesn't set it, or configure trusted proxy IPs explicitly.

---

### L1 — Presence-Only Cookie Validation on `/api/*` (LOW/INFO)

| Field | Value |
|-------|-------|
| **Severity** | LOW/INFO |
| **Affected file** | `apps/web/middleware.ts:35` |
| **Authentication** | Any non-empty cookie value accepted |

#### Description

The Next.js middleware reads the session cookie via better-auth's `getSessionCookie` (`middleware.ts:5-10`, `:19`) and gates `/api/*` routes on its mere presence (`middleware.ts:34-44`):

```typescript
function getAuthSessionCookie(request: Request): string | null {
    return (
        getSessionCookie(request) ??
        getSessionCookie(request, { cookiePrefix: "better-auth-dev" })
    )
}
// ...
const sessionCookie = getAuthSessionCookie(request)
// ...
if (url.pathname.startsWith("/api/")) {
    if (!sessionCookie) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
        })
    }
    return NextResponse.next()
}
```

`getSessionCookie` only reads and decodes the cookie value; it performs no server-side session lookup or signature verification. The gate is `if (!sessionCookie)` — presence only. **Any non-empty value** (e.g. `Cookie: better-auth-dev.session_token=x`) satisfies it. Real session validation happens downstream at `api.supermemory.ai` (out of scope).

This is the enabler that allows C1 (`/api/og` SSRF) to be demonstrated with a fake cookie. Without this, the SSRF would require a valid session.

#### Impact

- A forged cookie bypasses the Next.js edge auth check and reaches any `/api/*` route handler.
- The most sensitive handlers (e.g., `/api/og` SSRF) are reachable with zero credentials.
- In practice, actual business-logic enforcement (real auth validation, data access control) is at `api.supermemory.ai` — out of scope. This is therefore LOW at the web-layer level.

#### Mitigating Factors

- All meaningful auth enforcement is upstream at `api.supermemory.ai`.
- The web app is a thin proxy; no sensitive data is stored or accessible purely at the Next.js layer.

#### Recommendation

1. If the intent is to gate routes at the edge, validate the session token cryptographically (e.g., verify a signed JWT) rather than checking presence only.
2. Alternatively, document that the Next.js middleware gate is a soft/cosmetic layer and that real auth is enforced by the API backend — so maintainers are not surprised when a fake cookie reaches route handlers.

---

## Appendix — Dropped/Refuted Candidates

These were evaluated (including live testing) and explicitly excluded from the confirmed exploit set.

---

### REFUTED: C2 — `/api/onboarding/research` (previously HIGH)

**Original claim:** The Next.js middleware matcher negative-lookahead EXCLUDES the `onboarding` path segment, so the middleware NEVER runs for `/api/onboarding/*` routes. Zero authentication required.

**Live result:** REFUTED. The route returns **401 `{"error":"Unauthorized"}`** without a session cookie — middleware IS running and enforcing auth.

**Evidence:**
```
Request:  POST http://autofyn-web:3000/api/onboarding/research   (no cookie)
Body:     {"xUrl":"!!!invalid handle!!!"}
Status:   401
Body:     {"error":"Unauthorized"}      <-- middleware auth gate; route is NOT unauthenticated

With cookie better-auth-dev.session_token=x:
Status:   400  {"error":"Could not parse a valid X/Twitter handle from the input"}
```

**Why the static analysis was wrong:** The matcher regex `"/((?!_next/static|…|onboarding|ingest|login|…).*)"` anchors the negative-lookahead at the **start of the path-after-leading-slash**. For `/api/onboarding/research` that string is `api/onboarding/research`, which starts with `api`, not `onboarding` — the lookahead does **not** exclude it. The middleware runs and enforces the `/api/*` 401 gate (`middleware.ts:34-44`). The `onboarding` token in the exclusion list matches only the **top-level** `/onboarding` page (which returns 200, confirmed). Compare: `api/emails` appears in the list WITH its `api/` prefix, proving API subpaths require the prefix to be excluded.

**Status:** Investigated, REFUTED against live instance — route is auth-gated (401 without session cookie). The static-analysis claim was incorrect.

---

### REFUTED: C3 — `/api/onboarding/extract-content` (previously MEDIUM)

**Original claim:** Same middleware exclusion as C2. Unauthenticated access to `/api/onboarding/extract-content` enables SSRF-by-proxy through Exa API.

**Live result:** REFUTED. The route returns **401 `{"error":"Unauthorized"}`** without a session cookie.

**Evidence:**
```
Request:  POST http://autofyn-web:3000/api/onboarding/extract-content   (no cookie)
Body:     {}
Status:   401
Body:     {"error":"Unauthorized"}      <-- auth-gated, not 503
```

**Why the static analysis was wrong:** Same root cause as C2. The `onboarding` exclusion in the matcher does not apply to `/api/onboarding/*` paths.

**Status:** Investigated, REFUTED against live instance — route is auth-gated (401 without session cookie). The static-analysis claim was incorrect.

---

### Other Dropped Candidates

| Candidate | Reason Dropped |
|-----------|----------------|
| Middleware "dev-cookie auth bypass" as standalone CRITICAL | Web app is a thin proxy with no in-repo data boundary. Cookie presence-only check is real but its only effect is gating the OG route (already covered by C1). No backend data to bypass. Documented as L1. |
| `account-status` SSRF / arbitrary URL fetch | `parseXAccount` and `parseLinkedInAccount` always reconstruct the fetched URL as `https://x.com/<handle>` or `https://www.linkedin.com/...` with handles constrained by strict regex. Host is never attacker-controlled. |
| Cross-tenant `containerTag` access (MCP) | Enforcement at `api.supermemory.ai` (`validateApiKey`/`validateOAuthToken`). Not confirmable live without real API key + second tenant; must not attack external API. |
| Better-auth CVE-2025-61928 | Affects external auth server (`api.supermemory.ai`), not in this repo. Web app is auth client only. Out of scope. |
| MCP CORS wildcard | LOW/INFO — CORS `*` on a resource server is standard for MCP; risk depends on browser context and auth token storage. Not directly exploitable in-repo. |
| Unbounded `fetch-graph-data` limit, browser-extension postMessage/token storage | Require external backend with valid API key, or are client-side LOW findings. Not live-confirmable in this repo scope. |
| Workers-oauth-provider issues | Third-party library; in-scope only if a CVE is attributable to the repo's usage, which was not established. |
| C1 decimal-IP bypass (`http://2130706433/`) | BLOCKED live — Bun/Node normalises hostname to 127.0.0.1, which is caught by `isPrivateHost()`'s `startsWith("127.")` check. Returns 400. Sub-claim withdrawn. |

---

## Methodology Notes

- All exploit scripts run without external network access (no calls to `api.supermemory.ai` or any production endpoint).
- The mock server (`mock_server.py`) runs as a Docker container on the shared audit network and acts as both an internal SSRF target and an outbound-fetch collector.
- Containers run in local mode only (`wrangler dev` without `--remote`; `next dev` for Next.js).
- `XAI_API_KEY` and `EXA_API_KEY` are optional; all confirmed PASS conditions work without them.
- File sharing between containers uses `docker cp` (portable across host bind-mount and named-volume backed driver topologies).

---

*End of report.*
