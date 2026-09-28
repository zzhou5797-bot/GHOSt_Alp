import http from "node:http";
import { spawn } from "node:child_process";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod/v4";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const REPO = resolve(process.env.GHOST_PLUGIN_REPO || resolve(__dirname, ".."));
const HOST = process.env.GHOST_PLUGIN_HOST || "127.0.0.1";
const PORT = Number(process.env.GHOST_PLUGIN_PORT || "8787");
const PUBLIC_ORIGIN = (process.env.GHOST_PLUGIN_PUBLIC_ORIGIN || "").replace(/\/+$/, "");
const PASSWORD_FILE =
  process.env.GHOST_PLUGIN_PASSWORD_FILE || resolve(REPO, "target/.ghost-plugin-password");
const SIGNING_KEY_FILE =
  process.env.GHOST_PLUGIN_SIGNING_KEY_FILE || resolve(REPO, "target/.ghost-plugin-signing-key");
const PROXY =
  process.env.GHOST_SHELL_PROXY || resolve(REPO, "target/debug/ghost-shell-proxy");
const SCOPE = "shell:execute";
const MAX_BODY = 1024 * 1024;

const ownerPassword = readFileSync(PASSWORD_FILE, "utf8").trim();
const signingKey = Buffer.from(readFileSync(SIGNING_KEY_FILE, "utf8").trim(), "hex");
if (ownerPassword.length < 20) throw new Error("Ghost plugin password is too short");
if (signingKey.length < 32) throw new Error("Ghost plugin signing key is too short");

const authCodes = new Map();

function originFor(req) {
  if (PUBLIC_ORIGIN) return PUBLIC_ORIGIN;
  const proto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
  const host = String(req.headers["x-forwarded-host"] || req.headers.host || `${HOST}:${PORT}`)
    .split(",")[0]
    .trim();
  return `${proto}://${host}`;
}

function resourceFor(req) {
  return `${originFor(req)}/mcp`;
}

function json(res, status, value, headers = {}) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  res.end(JSON.stringify(value));
}

function html(res, status, body) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
  res.end(body);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signToken(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = createHmac("sha256", signingKey).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifyToken(token, expectedResource) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;

  const expected = createHmac("sha256", signingKey).update(body).digest();
  let actual;
  try {
    actual = Buffer.from(sig, "base64url");
  } catch {
    return null;
  }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now || payload.nbf > now + 30) return null;
  if (payload.aud !== expectedResource) return null;
  if (!String(payload.scope || "").split(/\s+/).includes(SCOPE)) return null;
  return payload;
}

function challenge(req) {
  return `Bearer resource_metadata="${originFor(req)}/.well-known/oauth-protected-resource", scope="${SCOPE}"`;
}

function requireAccess(req, res) {
  const auth = String(req.headers.authorization || "");
  const match = /^Bearer\s+(.+)$/i.exec(auth);
  const payload = match ? verifyToken(match[1], resourceFor(req)) : null;
  if (!payload) {
    json(
      res,
      401,
      { error: "unauthorized", error_description: "Link the Ghost plugin before using shell." },
      { "www-authenticate": challenge(req) },
    );
    return null;
  }
  return payload;
}

function validChatGptClient(clientId, redirectUri) {
  try {
    const client = new URL(clientId);
    const redirect = new URL(redirectUri);
    if (client.protocol !== "https:" || client.hostname !== "chatgpt.com") return false;
    if (!client.pathname.startsWith("/oauth/")) return false;
    if (redirect.protocol !== "https:" || redirect.hostname !== "chatgpt.com") return false;
    return (
      redirect.pathname === "/connector_platform_oauth_redirect" ||
      redirect.pathname.startsWith("/connector/oauth/")
    );
  } catch {
    return false;
  }
}

function authorizeParams(input) {
  return {
    response_type: input.get("response_type") || "",
    client_id: input.get("client_id") || "",
    redirect_uri: input.get("redirect_uri") || "",
    state: input.get("state") || "",
    code_challenge: input.get("code_challenge") || "",
    code_challenge_method: input.get("code_challenge_method") || "",
    resource: input.get("resource") || "",
    scope: input.get("scope") || SCOPE,
  };
}

function validateAuthorize(req, p) {
  if (p.response_type !== "code") return "unsupported response_type";
  if (p.code_challenge_method !== "S256" || !p.code_challenge) return "PKCE S256 is required";
  if (!validChatGptClient(p.client_id, p.redirect_uri)) return "unrecognized ChatGPT OAuth client";
  if (p.resource !== resourceFor(req)) return "resource mismatch";
  if (!p.scope.split(/\s+/).includes(SCOPE)) return "missing shell:execute scope";
  return null;
}

function authorizationForm(p, error = "") {
  const hidden = Object.entries(p)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join("\n");
  const err = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Authorize Ghost Shell</title>
<style>
body{font:16px system-ui;max-width:560px;margin:8vh auto;padding:0 24px;background:#111;color:#eee}
.card{border:1px solid #444;border-radius:16px;padding:24px;background:#181818}
input[type=password]{width:100%;box-sizing:border-box;padding:12px;margin:8px 0 16px;background:#0d0d0d;color:#fff;border:1px solid #555;border-radius:8px}
button{padding:12px 18px;border:0;border-radius:8px;font-weight:700}
.error{color:#ff8a8a}.warn{color:#ffd27a}
code{background:#252525;padding:2px 5px;border-radius:5px}
</style></head>
<body><div class="card">
<h1>Ghost Shell</h1>
<p class="warn">This grants ChatGPT command execution with the OS privileges of the Ghost host process.</p>
<p>Requested scope: <code>${escapeHtml(p.scope)}</code></p>
${err}
<form method="post" action="/authorize">
${hidden}
<label>Owner password</label>
<input type="password" name="password" autocomplete="current-password" autofocus required>
<button type="submit">Authorize ChatGPT</button>
</form>
</div></body></html>`;
}

async function runGhostShell({ command, cwd, timeout_ms }) {
  const args = ["-lc", command];
  const timeout = Math.max(100, Math.min(Number(timeout_ms || 30000), 300000));
  return await new Promise((resolvePromise, reject) => {
    const child = spawn(PROXY, args, {
      cwd: cwd || REPO,
      env: { ...process.env, GHOST_SHELL_HOME: REPO },
      stdio: ["ignore", "pipe", "pipe"],
    });

    const stdout = [];
    const stderr = [];
    let outBytes = 0;
    let errBytes = 0;
    const cap = 1024 * 1024;

    child.stdout.on("data", (chunk) => {
      if (outBytes < cap) stdout.push(chunk.subarray(0, cap - outBytes));
      outBytes += chunk.length;
    });
    child.stderr.on("data", (chunk) => {
      if (errBytes < cap) stderr.push(chunk.subarray(0, cap - errBytes));
      errBytes += chunk.length;
    });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`shell command timed out after ${timeout}ms`));
    }, timeout);

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const out = Buffer.concat(stdout).toString("utf8");
      const err = Buffer.concat(stderr).toString("utf8");
      resolvePromise({
        command,
        cwd: cwd || REPO,
        exit_code: code,
        signal,
        success: code === 0,
        stdout: out + (outBytes > cap ? "\n[stdout truncated]" : ""),
        stderr: err + (errBytes > cap ? "\n[stderr truncated]" : ""),
      });
    });
  });
}

function createMcpServer() {
  const server = new McpServer({ name: "ghost-shell", version: "0.1.0" });

  server.registerTool(
    "shell",
    {
      title: "Ghost Shell",
      description:
        "Execute a shell command on the owner's Ghost-controlled host. Use for terminal, files, git, build tools, processes, and system inspection.",
      inputSchema: {
        command: z.string().min(1).max(20000),
        cwd: z.string().min(1).max(4096).optional(),
        timeout_ms: z.number().int().min(100).max(300000).optional(),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
      _meta: {
        securitySchemes: [{ type: "oauth2", scopes: [SCOPE] }],
      },
    },
    async ({ command, cwd, timeout_ms }) => {
      try {
        const result = await runGhostShell({ command, cwd, timeout_ms });
        return {
          content: [{ type: "text", text: result.stdout || result.stderr || "(no output)" }],
          structuredContent: result,
          isError: !result.success,
        };
      } catch (error) {
        return {
          content: [{ type: "text", text: String(error?.message || error) }],
          isError: true,
        };
      }
    },
  );

  return server;
}

const httpServer = http.createServer(async (req, res) => {
  try {
    const origin = originFor(req);
    const resource = resourceFor(req);
    const url = new URL(req.url || "/", origin);

    if (req.method === "GET" && url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end("Ghost Shell MCP\n");
      return;
    }

    if (req.method === "GET" && url.pathname === "/healthz") {
      json(res, 200, { ok: true, mcp: `${origin}/mcp` });
      return;
    }

    if (
      req.method === "GET" &&
      (url.pathname === "/.well-known/oauth-authorization-server" ||
        url.pathname === "/.well-known/openid-configuration")
    ) {
      json(res, 200, {
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        client_id_metadata_document_supported: true,
        authorization_response_iss_parameter_supported: true,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: [SCOPE],
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/.well-known/oauth-protected-resource") {
      json(res, 200, {
        resource,
        authorization_servers: [origin],
        scopes_supported: [SCOPE],
        resource_documentation: `${origin}/`,
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/authorize") {
      const p = authorizeParams(url.searchParams);
      const error = validateAuthorize(req, p);
      html(res, error ? 400 : 200, authorizationForm(p, error || ""));
      return;
    }

    if (req.method === "POST" && url.pathname === "/authorize") {
      const body = await readBody(req);
      const form = new URLSearchParams(body.toString("utf8"));
      const p = authorizeParams(form);
      const error = validateAuthorize(req, p);
      const password = form.get("password") || "";

      if (error) {
        html(res, 400, authorizationForm(p, error));
        return;
      }
      const a = Buffer.from(password);
      const b = Buffer.from(ownerPassword);
      if (a.length !== b.length || !timingSafeEqual(a, b)) {
        html(res, 401, authorizationForm(p, "Incorrect owner password"));
        return;
      }

      const code = randomBytes(32).toString("base64url");
      authCodes.set(code, { ...p, expires: Date.now() + 5 * 60_000 });

      const redirect = new URL(p.redirect_uri);
      redirect.searchParams.set("code", code);
      if (p.state) redirect.searchParams.set("state", p.state);
      redirect.searchParams.set("iss", origin);
      res.writeHead(302, { location: redirect.toString(), "cache-control": "no-store" });
      res.end();
      return;
    }

    if (req.method === "POST" && url.pathname === "/token") {
      const body = await readBody(req);
      const form = new URLSearchParams(body.toString("utf8"));
      const grantType = form.get("grant_type") || "";
      const code = form.get("code") || "";
      const clientId = form.get("client_id") || "";
      const redirectUri = form.get("redirect_uri") || "";
      const verifier = form.get("code_verifier") || "";
      const resourceParam = form.get("resource") || "";
      const record = authCodes.get(code);

      if (grantType !== "authorization_code" || !record) {
        json(res, 400, { error: "invalid_grant" });
        return;
      }
      authCodes.delete(code);

      if (
        record.expires < Date.now() ||
        record.client_id !== clientId ||
        record.redirect_uri !== redirectUri ||
        record.resource !== resourceParam ||
        resourceParam !== resource
      ) {
        json(res, 400, { error: "invalid_grant" });
        return;
      }

      const actualChallenge = createHash("sha256").update(verifier).digest("base64url");
      if (actualChallenge !== record.code_challenge) {
        json(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      const accessToken = signToken({
        iss: origin,
        sub: "ghost-owner",
        aud: resource,
        scope: record.scope,
        iat: now,
        nbf: now - 5,
        exp: now + 7 * 24 * 60 * 60,
      });

      json(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 7 * 24 * 60 * 60,
        scope: record.scope,
      });
      return;
    }

    if (req.method === "OPTIONS" && url.pathname === "/mcp") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "POST, GET, DELETE, OPTIONS",
        "access-control-allow-headers":
          "content-type, authorization, mcp-session-id, mcp-protocol-version",
        "access-control-expose-headers": "Mcp-Session-Id",
      });
      res.end();
      return;
    }

    if (url.pathname === "/mcp" && ["POST", "GET", "DELETE"].includes(req.method || "")) {
      if (!requireAccess(req, res)) return;

      res.setHeader("access-control-allow-origin", "*");
      res.setHeader("access-control-expose-headers", "Mcp-Session-Id");

      const mcp = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });

      res.on("close", () => {
        transport.close().catch(() => {});
        mcp.close().catch(() => {});
      });

      await mcp.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not Found");
  } catch (error) {
    console.error("request failed:", error);
    if (!res.headersSent) json(res, 500, { error: "server_error" });
    else res.end();
  }
});

httpServer.listen(PORT, HOST, () => {
  console.log(`Ghost Shell MCP listening on http://${HOST}:${PORT}/mcp`);
  if (PUBLIC_ORIGIN) console.log(`Public MCP URL: ${PUBLIC_ORIGIN}/mcp`);
});
