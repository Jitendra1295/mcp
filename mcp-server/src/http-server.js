import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { Readable } from "node:stream";
import path from "node:path";
import { fileURLToPath } from "node:url";
import bcrypt from "bcryptjs";
import express from "express";
import session from "express-session";
import rateLimit from "express-rate-limit";
import Provider, { errors as oidcErrors } from "oidc-provider";
import {
    buildOAuthProtectedResourceMetadata,
    createMcpHandler,
    getOAuthProtectedResourceMetadataUrl,
    OAuthError,
    OAuthErrorCode,
    originValidationResponse,
    requireBearerAuth,
} from "@modelcontextprotocol/server";

const here = path.dirname(fileURLToPath(import.meta.url));
const frontendDist = path.resolve(here, "../../frontend/dist");
const port = Number(process.env.MCP_PORT || 3001);
const host = process.env.MCP_HOST || "127.0.0.1";
const isProduction = process.env.NODE_ENV === "production";
const isTest = process.env.NODE_ENV === "test";
const issuerValue = process.env.OAUTH_ISSUER || (isProduction ? "" : "http://localhost:5173");
const issuer = issuerValue.replace(/\/$/, "");
const resourceUrl = issuer ? new URL(`${issuer}/mcp`) : undefined;
const cookieSecret = process.env.OIDC_COOKIE_SECRET;
const webSessionSecret = process.env.WEB_SESSION_SECRET;
const userEmail = (isTest || isProduction ? process.env.DEFAULT_USER_EMAIL || "Test@example.com" : "Test@example.com").trim().toLowerCase();
let passwordHash = process.env.DEFAULT_USER_PASSWORD_HASH;
const developmentPassword = "Test@123";
const userId = "mini-sherlocq-default-user";
const mcpScope = "mcp";

function required(value, name) {
    if (!value) throw new Error(`${name} is required for the remote HTTP server`);
    return value;
}

function strongSecret(value, name) {
    required(value, name);
    if (Buffer.byteLength(value) < 32) throw new Error(`${name} must be at least 32 bytes`);
    return value;
}

function parseJwks() {
    if (!process.env.OAUTH_JWKS) {
        if (isProduction) throw new Error("OAUTH_JWKS must be configured in production");
        return undefined;
    }
    try {
        const jwks = JSON.parse(process.env.OAUTH_JWKS);
        if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) throw new Error("keys array is missing");
        return jwks;
    } catch (error) {
        throw new Error(`OAUTH_JWKS must contain a valid JWKS JSON value: ${error.message}`);
    }
}

async function configuredAccount() {
    if (isTest || isProduction) {
        required(passwordHash, "DEFAULT_USER_PASSWORD_HASH");
        if (!/^\$2[aby]\$\d\d\$/.test(passwordHash)) throw new Error("DEFAULT_USER_PASSWORD_HASH must be a bcrypt hash");
    } else {
        passwordHash = await bcrypt.hash(developmentPassword, 12);
    }
    if (isProduction && (userEmail === "test@example.com" || await bcrypt.compare(developmentPassword, passwordHash))) {
        throw new Error("Production cannot use the documented development email or password");
    }
}

function safeEqual(left, right) {
    if (!left || !right) return false;
    const a = Buffer.from(String(left));
    const b = Buffer.from(String(right));
    return a.length === b.length && timingSafeEqual(a, b);
}

function csrfToken(req) {
    if (!req.session.csrfToken) req.session.csrfToken = randomBytes(32).toString("base64url");
    return req.session.csrfToken;
}

function checkBrowserPost(req, res, { allowOriginMismatchWithCsrf = false } = {}) {
    const origin = req.get("origin");
    const localDevelopmentOrigins = !isProduction
        ? ["http://localhost:5173", "http://127.0.0.1:5173", `http://localhost:${port}`, `http://127.0.0.1:${port}`]
        : [];
    // The browser origin must match the configured issuer or the host that
    // actually served this request through our trusted local/tunnel proxy.
    // Restrict the host before deriving this value so an arbitrary Host header
    // cannot make an arbitrary Origin acceptable. The CSRF token is still
    // mandatory below for every browser POST.
    const requestHost = (req.get("host") || "").toLowerCase();
    const issuerHost = new URL(issuer).host.toLowerCase();
    const localHosts = new Set(["localhost", "localhost:" + port, "127.0.0.1", "127.0.0.1:" + port]);
    const originForThisRequest = requestHost === issuerHost || localHosts.has(requestHost)
        ? `${req.protocol}://${requestHost}`
        : undefined;
    let normalizedOrigin;
    if (origin && origin !== "null") {
        try {
            normalizedOrigin = new URL(origin).origin;
        } catch {
            normalizedOrigin = undefined;
        }
    }
    const allowedOrigins = [issuer, ...localDevelopmentOrigins, originForThisRequest].filter(Boolean);
    const originIsAllowed = Boolean(normalizedOrigin && allowedOrigins.includes(normalizedOrigin));
    const csrfIsValid = safeEqual(req.get("x-csrf-token") || req.body?._csrf, req.session.csrfToken);
    // OAuth interaction pages may be hosted inside a client's browser/webview.
    // Their per-session token plus the same-site session cookie is the CSRF
    // boundary; accept a different/missing Origin there only when that token
    // matches. The app's ordinary login/logout endpoints remain origin-bound.
    if (!originIsAllowed && !(allowOriginMismatchWithCsrf && csrfIsValid)) {
        if (!isProduction) {
            const receivedHost = (() => {
                if (origin === "null") return "<null>";
                try { return origin ? new URL(origin).host : "<missing>"; } catch { return "<invalid>"; }
            })();
            console.warn("Rejected browser POST origin", {
                receivedHost,
                requestHost,
                forwardedProto: req.protocol,
            });
        }
        res.status(403).json({ error: { code: "INVALID_ORIGIN", message: "Request origin is not allowed" } });
        return false;
    }
    if (!csrfIsValid) {
        res.status(403).json({ error: { code: "CSRF_FAILED", message: "Please refresh the page and try again" } });
        return false;
    }
    return true;
}

export async function startHttpServer(createMcpServer) {
    if (!issuer || !resourceUrl) throw new Error("OAUTH_ISSUER must be set to the public HTTPS origin in production");
    const issuerUrl = new URL(issuer);
    if (issuerUrl.origin !== issuer || issuerUrl.username || issuerUrl.password) throw new Error("OAUTH_ISSUER must be an origin URL without a path or credentials");
    if (isProduction && issuerUrl.protocol !== "https:") throw new Error("OAUTH_ISSUER must use HTTPS in production");
    // Claude's OAuth browser can submit the interaction form in a cross-site
    // context. HTTPS cookies need SameSite=None so the session carrying the
    // CSRF token accompanies that POST; local HTTP development stays Lax.
    const secureCookies = issuerUrl.protocol === "https:";
    const cookieSameSite = secureCookies ? "none" : "lax";
    strongSecret(cookieSecret, "OIDC_COOKIE_SECRET");
    strongSecret(webSessionSecret, "WEB_SESSION_SECRET");
    await configuredAccount();
    if (cookieSecret === webSessionSecret) throw new Error("OIDC_COOKIE_SECRET and WEB_SESSION_SECRET must be different values");

    const mcpResource = resourceUrl.href;
    const allowedHostnames = [...new Set([new URL(issuer).hostname, "127.0.0.1", "localhost"])];
    const oidcConfiguration = {
        cookies: {
            keys: [cookieSecret],
            // oidc-provider derives Secure from its trusted proxy context; do
            // not force secure:true here or HTTP-origin callbacks will throw.
            long: { httpOnly: true, sameSite: cookieSameSite },
            short: { httpOnly: true, sameSite: cookieSameSite },
        },
        ...(parseJwks() ? { jwks: parseJwks() } : {}),
        scopes: [mcpScope],
        findAccount: async (_ctx, accountId) => accountId === userId
            ? { accountId: userId, claims: async () => ({ sub: userId, email: userEmail, email_verified: true }) }
            : undefined,
        routes: {
            authorization: "/oauth/authorize",
            token: "/oauth/token",
            registration: "/oauth/register",
            jwks: "/oauth/jwks",
            revocation: "/oauth/revoke",
        },
        interactions: {
            url: async (_ctx, interaction) => `/oauth/interaction/${encodeURIComponent(interaction.uid)}`,
        },
        issueRefreshToken: async (_ctx, client, source) => client.grantTypeAllowed("refresh_token") && source.scopes.has(mcpScope),
        expiresWithSession: async () => false,
        ttl: { AccessToken: 900, AuthorizationCode: 60, Interaction: 600, RefreshToken: 14 * 24 * 60 * 60, Session: 30 * 24 * 60 * 60, Grant: 30 * 24 * 60 * 60 },
        features: {
            devInteractions: { enabled: false },
            registration: { enabled: true },
            revocation: {
                enabled: true,
                allowedPolicy: async (_ctx, client, token) => token.clientId === client.clientId,
            },
            resourceIndicators: {
                enabled: true,
                getResourceServerInfo: async (_ctx, requestedResource) => {
                    if (requestedResource !== mcpResource) throw new oidcErrors.InvalidTarget();
                    return {
                        audience: mcpResource,
                        scope: mcpScope,
                        accessTokenTTL: 900,
                        accessTokenFormat: "opaque",
                    };
                },
                useGrantedResource: async (_ctx, source) => source.resource !== undefined,
            },
        },
        extraTokenClaims: async (_ctx, token) => token.accountId === userId ? { sub: userId } : {},
    };

    const provider = new Provider(issuer, oidcConfiguration);
    // oidc-provider is mounted on Express, so trust the one Cloudflare TLS
    // offload hop on the provider instance itself. The config object's `proxy`
    // field does not set Koa's request protocol and left cookies non-Secure.
    provider.proxy = true;
    provider.on("server_error", (_ctx, error) => console.error("OAuth provider internal error:", error.name));
    const oauthMetadata = {
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        registration_endpoint: `${issuer}/oauth/register`,
        revocation_endpoint: `${issuer}/oauth/revoke`,
        jwks_uri: `${issuer}/oauth/jwks`,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: [mcpScope],
    };
    const protectedResourceMetadata = buildOAuthProtectedResourceMetadata({
        oauthMetadata,
        resourceServerUrl: resourceUrl,
        scopesSupported: [mcpScope],
    });

    const verifier = {
        async verifyAccessToken(token) {
            let stored;
            try {
                stored = await provider.AccessToken.find(token);
            } catch {
                stored = undefined;
            }
            if (!stored || stored.isExpired || stored.aud !== mcpResource) {
                throw new OAuthError(OAuthErrorCode.InvalidToken, "The access token is invalid or expired");
            }
            return {
                token,
                clientId: stored.clientId,
                scopes: [...stored.scopes],
                expiresAt: Math.floor(Date.now() / 1000) + Math.max(1, stored.remainingTTL),
                resource: new URL(stored.aud),
            };
        },
    };
    const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceUrl);
    const authGate = requireBearerAuth({
        verifier,
        requiredScopes: [mcpScope],
        resourceMetadataUrl,
        expectedResource: resourceUrl,
    });
    const mcpHandler = createMcpHandler(createMcpServer);

    const app = express();
    app.disable("x-powered-by");
    // MCP binds to loopback and may receive one forwarded client through Vite or cloudflared.
    app.set("trust proxy", 1);
    app.use((_req, res, next) => {
        res.set({
            // OAuth interactions must be allowed to redirect to external client redirect URIs (e.g. claude.ai).
            // Restricting form-action to 'self' breaks form post redirects to OAuth client callback URLs.
            "Content-Security-Policy": `default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; script-src 'self'; style-src 'self'`,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        });
        if (isProduction) res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        next();
    });
    app.use("/api", express.json({ limit: "32kb" }));
    app.use("/api", express.urlencoded({ extended: false, limit: "16kb" }));
    // OAuth interaction forms submit URL-encoded data under /oauth/interaction.
    app.use("/oauth/interaction", express.urlencoded({ extended: false, limit: "16kb" }));
    app.use(session({
        name: "mini-sherlocq.sid",
        secret: webSessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, secure: secureCookies, sameSite: cookieSameSite, maxAge: 30 * 60 * 1000, path: "/" },
    }));

    const loginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 5,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: { error: { code: "LOGIN_RATE_LIMITED", message: "Too many attempts. Please wait before trying again." } },
    });
    const registrationLimiter = rateLimit({
        windowMs: 60 * 60 * 1000,
        limit: 30,
        standardHeaders: "draft-8",
        legacyHeaders: false,
    });

    app.get("/health", (_req, res) => res.json({ success: true, service: "Mini Sherlocq MCP OAuth and Streamable HTTP endpoint" }));
    app.get("/api/session", (req, res) => {
        res.set("Cache-Control", "no-store");
        res.json({ csrfToken: csrfToken(req), authenticated: req.session.userId === userId, email: req.session.userId === userId ? userEmail : undefined });
    });
    app.get("/api/config", (_req, res) => res.json({ issuer, mcpUrl: mcpResource }));
    app.post("/api/login", loginLimiter, async (req, res) => {
        if (!checkBrowserPost(req, res)) return;
        const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
        const password = typeof req.body?.password === "string" ? req.body.password : "";
        const valid = email === userEmail && await bcrypt.compare(password, passwordHash);
        if (!valid) return res.status(401).json({ error: { code: "INVALID_CREDENTIALS", message: "Email or password is incorrect" } });
        req.session.regenerate((error) => {
            if (error) return res.status(500).json({ error: { code: "SESSION_ERROR", message: "Unable to start a session" } });
            req.session.userId = userId;
            req.session.csrfToken = randomBytes(32).toString("base64url");
            return req.session.save((saveError) => {
                if (saveError) return res.status(500).json({ error: { code: "SESSION_ERROR", message: "Unable to start a session" } });
                return res.json({ authenticated: true, email: userEmail, csrfToken: req.session.csrfToken });
            });
        });
    });
    app.post("/api/logout", (req, res) => {
        if (!checkBrowserPost(req, res)) return;
        req.session.destroy((error) => {
            if (error) return res.status(500).json({ error: { code: "LOGOUT_FAILED", message: "Unable to end the session" } });
            res.clearCookie("mini-sherlocq.sid", { httpOnly: true, secure: secureCookies, sameSite: cookieSameSite, path: "/" });
            return res.status(204).end();
        });
    });

    const sendInteractionDetails = async (req, res, next) => {
        try {
            const details = await provider.interactionDetails(req, res);
            const client = details?.params?.client_id ? await provider.Client.find(details.params.client_id) : undefined;
            res.set("Cache-Control", "no-store");
            return res.json({
                prompt: details.prompt?.name,
                authenticated: req.session.userId === userId,
                email: req.session.userId === userId ? userEmail : undefined,
                clientName: client?.clientName || "An MCP client",
                scopes: typeof details.params?.scope === "string" ? details.params.scope.split(/\s+/).filter(Boolean) : [],
                csrfToken: csrfToken(req),
            });
        } catch (error) {
            if (!isProduction) console.error("OAuth interaction lookup failed:", error.name, error.error, error.message);
            res.set("Cache-Control", "no-store");
            return res.status(400).json({
                error: {
                    code: "INTERACTION_UNAVAILABLE",
                    message: "This sign-in request is no longer available. Return to Claude and start connecting again.",
                },
            });
        }
    };
    app.get("/api/oauth/interaction/:uid", sendInteractionDetails);

    app.post(["/api/oauth/interaction/:uid/login", "/oauth/interaction/:uid/login"], loginLimiter, async (req, res, next) => {
        if (!checkBrowserPost(req, res, { allowOriginMismatchWithCsrf: true })) return;
        try {
            const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
            const password = typeof req.body?.password === "string" ? req.body.password : "";
            if (email !== userEmail || !(await bcrypt.compare(password, passwordHash))) {
                return res.redirect(303, `/oauth/interaction/${encodeURIComponent(req.params.uid)}?error=login`);
            }
            const details = await provider.interactionDetails(req, res);
            if (details.prompt?.name !== "login") return res.status(400).json({ error: { code: "INVALID_INTERACTION", message: "This authorization step is no longer current" } });
            await new Promise((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
            req.session.userId = userId;
            req.session.csrfToken = randomBytes(32).toString("base64url");
            await new Promise((resolve, reject) => req.session.save((error) => error ? reject(error) : resolve()));
            const result = { login: { accountId: userId, remember: false, ts: Math.floor(Date.now() / 1000) } };
            return provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
        } catch (error) {
            return next(error);
        }
    });

    app.post(["/api/oauth/interaction/:uid/continue", "/oauth/interaction/:uid/continue"], async (req, res, next) => {
        if (!checkBrowserPost(req, res, { allowOriginMismatchWithCsrf: true })) return;
        try {
            if (req.session.userId !== userId) return res.status(401).json({ error: { code: "LOGIN_REQUIRED", message: "Please sign in to continue" } });
            const details = await provider.interactionDetails(req, res);
            if (details.prompt?.name !== "login") return res.status(400).json({ error: { code: "INVALID_INTERACTION", message: "This authorization step is no longer current" } });
            return provider.interactionFinished(req, res, {
                login: { accountId: userId, remember: false, ts: Math.floor(Date.now() / 1000) },
            }, { mergeWithLastSubmission: false });
        } catch (error) {
            return next(error);
        }
    });

    app.post(["/api/oauth/interaction/:uid/consent", "/oauth/interaction/:uid/consent"], async (req, res, next) => {
        if (!checkBrowserPost(req, res, { allowOriginMismatchWithCsrf: true })) return;
        try {
            if (req.session.userId !== userId) return res.status(401).json({ error: { code: "LOGIN_REQUIRED", message: "Please sign in to continue" } });
            const details = await provider.interactionDetails(req, res);
            if (details.prompt?.name !== "consent") return res.status(400).json({ error: { code: "INVALID_INTERACTION", message: "This authorization step is no longer current" } });
            if (req.body?.decision !== "approve") {
                return provider.interactionFinished(req, res, { error: "access_denied", error_description: "The user denied access" }, { mergeWithLastSubmission: false });
            }
            const grant = details.grantId
                ? await provider.Grant.find(details.grantId)
                : new provider.Grant({ accountId: userId, clientId: details.params.client_id });
            if (!grant) return res.status(400).json({ error: { code: "INVALID_INTERACTION", message: "This authorization request is no longer current" } });
            const missingOidcScopes = details.prompt.details?.missingOIDCScope || [];
            if (missingOidcScopes.length) grant.addOIDCScope(missingOidcScopes.join(" "));
            const missingResourceScopes = details.prompt.details?.missingResourceScopes || {};
            for (const [resource, scopes] of Object.entries(missingResourceScopes)) {
                if (resource === mcpResource && scopes.length) grant.addResourceScope(resource, scopes.join(" "));
            }
            const grantId = await grant.save();
            return provider.interactionFinished(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
        } catch (error) {
            return next(error);
        }
    });

    app.get(new URL(resourceMetadataUrl).pathname, (_req, res) => res.json(protectedResourceMetadata));
    app.use("/oauth/register", registrationLimiter);
    app.all("/mcp", async (req, res) => {
        try {
            if (!["POST", "GET", "DELETE"].includes(req.method)) {
                return res.status(405).set("Allow", "POST, GET, DELETE").json({ error: "Method not allowed" });
            }
            const url = new URL(req.originalUrl, issuer);
            const hasBody = req.method !== "GET" && req.method !== "HEAD";
            const request = new Request(url, {
                method: req.method,
                headers: req.headers,
                ...(hasBody ? { body: Readable.toWeb(req), duplex: "half" } : {}),
            });
            const originError = originValidationResponse(request, allowedHostnames);
            if (originError) {
                res.writeHead(originError.status, Object.fromEntries(originError.headers));
                return res.end(await originError.text());
            }
            const auth = await authGate(request);
            if (auth instanceof Response) {
                res.writeHead(auth.status, Object.fromEntries(auth.headers));
                return res.end(await auth.text());
            }
            const response = await mcpHandler.fetch(request, { authInfo: auth });
            res.writeHead(response.status, Object.fromEntries(response.headers));
            if (response.body) Readable.fromWeb(response.body).pipe(res);
            else res.end();
        } catch (error) {
            console.error("MCP HTTP request failed");
            if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
            else res.destroy(error);
        }
    });
    app.use(express.static(frontendDist, { index: false, fallthrough: true }));
    app.get("/oauth/interaction/:uid", (req, res, next) => {
        if (req.query.format === "json") return sendInteractionDetails(req, res, next);
        return res.sendFile(path.join(frontendDist, "index.html"), (error) => error && next(error));
    });
    app.get(["/", "/login", "/dashboard"], (_req, res, next) => {
        res.sendFile(path.join(frontendDist, "index.html"), (error) => error && next(error));
    });

    app.use("/oauth/authorize", (req, res, next) => {
        if (req.path !== "/") return next();
        const requestedResource = req.query.resource;
        if (requestedResource && requestedResource !== mcpResource) {
            return res.status(400).set("Cache-Control", "no-store").json({
                error: "invalid_target",
                error_description: "The resource parameter must identify this MCP server",
            });
        }
        if (!requestedResource) {
            const authorizeUrl = new URL(req.originalUrl, issuer);
            authorizeUrl.searchParams.set("resource", mcpResource);
            return res
                .status(302)
                .set("Cache-Control", "no-store")
                .location(`${authorizeUrl.pathname}${authorizeUrl.search}`)
                .end();
        }
        return next();
    });
    app.use(provider.callback());
    app.use((err, req, res, _next) => {
        // Never send provider internals, credentials, codes, cookies, or tokens to logs or clients.
        console.error("OAuth HTTP request failed:", {
            method: req.method,
            route: req.route?.path,
            status: err.status || 500,
            name: err.name,
            code: typeof err.error === "string" ? err.error : typeof err.code === "string" ? err.code : undefined,
        });
        if (!res.headersSent) res.status(err.status || 500).json({ error: { code: "REQUEST_FAILED", message: "The request could not be completed" } });
    });
    app.use((_req, res) => res.status(404).json({ error: "Not found" }));

    const httpServer = createServer(app);
    await new Promise((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(port, host, resolve);
    });
    console.log(`OAuth-protected MCP endpoint listening at http://${host}:${port}/mcp`);
    console.log(`OAuth issuer configured as ${issuer}`);
    return { app, httpServer, provider, resourceUrl };
}
