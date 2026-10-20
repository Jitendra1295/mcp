import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { test } from "node:test";
import bcrypt from "bcryptjs";

async function freePort() {
    const probe = createServer();
    await new Promise((resolve, reject) => probe.listen(0, "127.0.0.1", resolve).once("error", reject));
    const { port } = probe.address();
    await new Promise((resolve, reject) => probe.close((error) => error ? reject(error) : resolve()));
    return port;
}

function putCookies(jar, response) {
    for (const line of response.headers.getSetCookie()) {
        const [cookie] = line.split(";");
        const separator = cookie.indexOf("=");
        jar.set(cookie.slice(0, separator), cookie.slice(separator + 1));
    }
}

function cookieHeader(jar) {
    return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join("; ");
}

async function readMcpMessage(response) {
    const body = await response.text();
    if (response.headers.get("content-type")?.includes("text/event-stream")) {
        const data = body.split(/\r?\n/).find((line) => line.startsWith("data: "));
        assert.ok(data, "MCP SSE response should contain a data event");
        return JSON.parse(data.slice(6));
    }
    return JSON.parse(body);
}

test("remote MCP requires OAuth, completes PKCE login/consent, and revocation blocks reuse", { timeout: 30000 }, async (t) => {
    const port = await freePort();
    const issuer = `http://127.0.0.1:${port}`;
    const testPassword = randomBytes(24).toString("base64url");
    const signing = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ format: "jwk" });
    signing.use = "sig";
    signing.alg = "RS256";
    signing.kid = randomBytes(12).toString("base64url");
    Object.assign(process.env, {
        NODE_ENV: "test",
        MCP_PORT: String(port),
        MCP_HOST: "127.0.0.1",
        OAUTH_ISSUER: issuer,
        OIDC_COOKIE_SECRET: randomBytes(48).toString("base64url"),
        WEB_SESSION_SECRET: randomBytes(48).toString("base64url"),
        OAUTH_JWKS: JSON.stringify({ keys: [signing] }),
        DEFAULT_USER_EMAIL: "test@example.com",
        DEFAULT_USER_PASSWORD_HASH: await bcrypt.hash(testPassword, 4),
    });

    const [{ startHttpServer }, { createMcpServer }] = await Promise.all([
        import("../src/http-server.js"),
        import("../src/index.js"),
    ]);
    const service = await startHttpServer(createMcpServer);
    t.after(async () => new Promise((resolve) => service.httpServer.close(() => resolve())));

    const endpoint = `${issuer}/mcp`;
    const originalFetchForAuthCheck = globalThis.fetch;
    let blockedAppApiCalls = 0;
    globalThis.fetch = (input, init) => {
        if (String(input).startsWith("http://127.0.0.1:3000/")) {
            blockedAppApiCalls += 1;
            return Promise.resolve(new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } }));
        }
        return originalFetchForAuthCheck(input, init);
    };
    const unauthenticated = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "ask_question", arguments: { question: "must be blocked" } } }),
    });
    globalThis.fetch = originalFetchForAuthCheck;
    assert.equal(unauthenticated.status, 401);
    assert.match(unauthenticated.headers.get("www-authenticate"), /resource_metadata=/);
    assert.equal(blockedAppApiCalls, 0, "unauthorized tool calls must not reach the App API");
    const oldStaticToken = await fetch(endpoint, {
        method: "POST",
        headers: { Authorization: "Bearer 12345", "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
    });
    assert.equal(oldStaticToken.status, 401, "the old shared bearer token must not authorize MCP requests");

    const protectedMetadata = await fetch(`${issuer}/.well-known/oauth-protected-resource/mcp`).then((response) => response.json());
    assert.deepEqual(protectedMetadata.authorization_servers, [issuer]);
    const authorizationMetadata = await fetch(`${issuer}/.well-known/oauth-authorization-server`).then((response) => response.json());
    assert.equal(authorizationMetadata.authorization_endpoint, `${issuer}/oauth/authorize`);
    assert.equal(authorizationMetadata.registration_endpoint, `${issuer}/oauth/register`);
    assert.equal(authorizationMetadata.authorization_response_iss_parameter_supported, true);
    assert.ok(authorizationMetadata.code_challenge_methods_supported.includes("S256"));
    assert.ok(authorizationMetadata.grant_types_supported.includes("refresh_token"));

    const redirectUri = "http://127.0.0.1:47777/oauth-callback";
    const registration = await fetch(`${issuer}/oauth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            client_name: "Local MCP Auth Test",
            redirect_uris: [redirectUri],
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            token_endpoint_auth_method: "none",
        }),
    });
    const registrationBody = await registration.text();
    assert.equal(registration.status, 201, registrationBody);
    const client = JSON.parse(registrationBody);
    assert.deepEqual(client.grant_types.sort(), ["authorization_code", "refresh_token"]);

    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const state = randomBytes(16).toString("base64url");
    const authorizationUrl = new URL(`${issuer}/oauth/authorize`);
    for (const [key, value] of Object.entries({
        response_type: "code",
        client_id: client.client_id,
        redirect_uri: redirectUri,
        scope: "mcp",
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
    })) authorizationUrl.searchParams.set(key, value);

    const invalidRedirectRequest = new URL(authorizationUrl);
    invalidRedirectRequest.searchParams.set("redirect_uri", `${redirectUri}/unregistered`);
    invalidRedirectRequest.searchParams.set("resource", endpoint);
    assert.equal((await fetch(invalidRedirectRequest, { redirect: "manual" })).status, 400, "unregistered redirect URIs must be rejected");
    const wrongResourceRequest = new URL(authorizationUrl);
    wrongResourceRequest.searchParams.set("resource", "https://other.example/mcp");
    assert.equal((await fetch(wrongResourceRequest, { redirect: "manual" })).status, 400, "tokens must only be requested for this MCP resource");

    const jar = new Map();
    let current = authorizationUrl;
    let authorizationCode;
    let returnedState;
    let returnedIssuer;
    for (let step = 0; step < 8; step += 1) {
        const response = await fetch(current, { redirect: "manual", headers: { Cookie: cookieHeader(jar) } });
        putCookies(jar, response);
        assert.ok([301, 302, 303].includes(response.status), `Expected an OAuth redirect from ${new URL(current).pathname}, got HTTP ${response.status}: ${await response.text()}`);
        const location = new URL(response.headers.get("location"), issuer);
        if (location.origin === new URL(redirectUri).origin && location.pathname === new URL(redirectUri).pathname) {
            authorizationCode = location.searchParams.get("code");
            returnedState = location.searchParams.get("state");
            returnedIssuer = location.searchParams.get("iss");
            break;
        }

        if (location.pathname.startsWith("/oauth/interaction/")) {
            const interactionPath = location.pathname;
            const interaction = await fetch(`${issuer}/api${interactionPath}`, { headers: { Cookie: cookieHeader(jar) } });
            putCookies(jar, interaction);
            assert.equal(interaction.status, 200);
            const details = await interaction.json();
            const loginStep = details.prompt === "login";
            const action = loginStep ? `${interactionPath}/login` : `${interactionPath}/consent`;
            const form = new URLSearchParams({ _csrf: details.csrfToken });
            if (loginStep) {
                form.set("email", "test@example.com");
                form.set("password", testPassword);
            } else {
                assert.equal(details.prompt, "consent");
                form.set("decision", "approve");
            }
            const submitted = await fetch(`${issuer}/api${action}`, {
                method: "POST",
                redirect: "manual",
                headers: { Cookie: cookieHeader(jar), Origin: issuer, "Content-Type": "application/x-www-form-urlencoded" },
                body: form,
            });
            putCookies(jar, submitted);
            assert.ok([301, 302, 303].includes(submitted.status), `Expected interaction redirect, got HTTP ${submitted.status}: ${await submitted.text()}`);
            current = new URL(submitted.headers.get("location"), issuer);
            continue;
        }
        current = location;
    }
    assert.ok(authorizationCode, "OAuth flow should produce an authorization code");
    assert.equal(returnedState, state);
    assert.equal(returnedIssuer, issuer);

    const tokenResponse = await fetch(`${issuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: client.client_id,
            code: authorizationCode,
            redirect_uri: redirectUri,
            code_verifier: verifier,
            resource: endpoint,
        }),
    });
    const tokenBody = await tokenResponse.text();
    assert.equal(tokenResponse.status, 200, tokenBody);
    const tokens = JSON.parse(tokenBody);
    assert.ok(tokens.access_token);
    assert.ok(tokens.refresh_token, `Expected a refresh token; returned scopes: ${tokens.scope}`);

    const refreshedResponse = await fetch(`${issuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", client_id: client.client_id, refresh_token: tokens.refresh_token, resource: endpoint }),
    });
    const refreshedBody = await refreshedResponse.text();
    assert.equal(refreshedResponse.status, 200, refreshedBody);
    const refreshedTokens = JSON.parse(refreshedBody);
    assert.ok(refreshedTokens.access_token);
    assert.ok(refreshedTokens.refresh_token);
    const storedRefreshedToken = await service.provider.AccessToken.find(refreshedTokens.access_token);
    assert.equal(storedRefreshedToken?.aud, endpoint, "refreshed access token must keep its MCP audience");
    assert.equal(storedRefreshedToken?.isExpired, false);
    const originalFetch = globalThis.fetch;
    let askedQuestion;
    globalThis.fetch = (input, init) => {
        if (String(input) === "http://127.0.0.1:3000/health") {
            return Promise.resolve(new Response(JSON.stringify({ success: true, message: "mock health" }), { headers: { "Content-Type": "application/json" } }));
        }
        if (String(input) === "http://127.0.0.1:3000/api/ask") {
            askedQuestion = JSON.parse(init.body).question;
            return Promise.resolve(new Response(JSON.stringify({ success: true, data: { question: askedQuestion, answer: "mock answer without OpenRouter" } }), { headers: { "Content-Type": "application/json" } }));
        }
        return originalFetch(input, init);
    };
    try {
        const authHeaders = { Authorization: `Bearer ${refreshedTokens.access_token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
        const initialize = await fetch(endpoint, {
            method: "POST",
            headers: authHeaders,
            body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "oauth-test", version: "1.0" } } }),
        });
        assert.equal(initialize.status, 200, await initialize.text());
        const list = await fetch(endpoint, { method: "POST", headers: authHeaders, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) });
        assert.equal(list.status, 200);
        const tools = (await readMcpMessage(list)).result.tools.map((tool) => tool.name);
        assert.deepEqual(tools.sort(), ["ask_question", "check_app_health"]);
        const toolCall = await fetch(endpoint, { method: "POST", headers: authHeaders, body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "check_app_health", arguments: {} } }) });
        assert.equal(toolCall.status, 200);
        assert.match(JSON.stringify(await readMcpMessage(toolCall)), /mock health/);
        const ask = await fetch(endpoint, { method: "POST", headers: authHeaders, body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "ask_question", arguments: { question: "Explain MCP" } } }) });
        assert.equal(ask.status, 200);
        assert.match(JSON.stringify(await readMcpMessage(ask)), /mock answer without OpenRouter/);
        assert.equal(askedQuestion, "Explain MCP");
    } finally {
        globalThis.fetch = originalFetch;
    }

    const revoked = await fetch(`${issuer}/oauth/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: refreshedTokens.access_token, token_type_hint: "access_token", client_id: client.client_id }),
    });
    assert.equal(revoked.status, 200);
    const afterRevocation = await fetch(endpoint, {
        method: "POST",
        headers: { Authorization: `Bearer ${refreshedTokens.access_token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} }),
    });
    assert.equal(afterRevocation.status, 401);

    const browserJar = new Map();
    const csrfResponse = await fetch(`${issuer}/api/session`, { headers: { Origin: issuer } });
    putCookies(browserJar, csrfResponse);
    const session = await csrfResponse.json();
    const blockedCsrf = await fetch(`${issuer}/api/logout`, {
        method: "POST",
        headers: { Cookie: cookieHeader(browserJar), Origin: issuer, "X-CSRF-Token": "wrong-token" },
    });
    assert.equal(blockedCsrf.status, 403, "browser session changes must require the CSRF token");
    const rejectedLogin = await fetch(`${issuer}/api/login`, {
        method: "POST",
        headers: { Cookie: cookieHeader(browserJar), Origin: issuer, "X-CSRF-Token": session.csrfToken, "Content-Type": "application/json" },
        body: JSON.stringify({ email: "test@example.com", password: "incorrect" }),
    });
    assert.equal(rejectedLogin.status, 401);
    assert.equal((await rejectedLogin.json()).error.code, "INVALID_CREDENTIALS");
    const acceptedLogin = await fetch(`${issuer}/api/login`, {
        method: "POST",
        headers: { Cookie: cookieHeader(browserJar), Origin: issuer, "X-CSRF-Token": session.csrfToken, "Content-Type": "application/json" },
        body: JSON.stringify({ email: "test@example.com", password: testPassword }),
    });
    putCookies(browserJar, acceptedLogin);
    assert.equal(acceptedLogin.status, 200);
    const loggedIn = await acceptedLogin.json();
    assert.equal(loggedIn.authenticated, true);
    const localBrowserJar = new Map();
    const localOrigin = `http://localhost:${port}`;
    const localCsrfResponse = await fetch(`${issuer}/api/session`, { headers: { Origin: localOrigin } });
    putCookies(localBrowserJar, localCsrfResponse);
    const localSession = await localCsrfResponse.json();
    const localLogin = await fetch(`${issuer}/api/login`, {
        method: "POST",
        headers: { Cookie: cookieHeader(localBrowserJar), Origin: localOrigin, "X-CSRF-Token": localSession.csrfToken, "Content-Type": "application/json" },
        body: JSON.stringify({ email: "test@example.com", password: testPassword }),
    });
    assert.equal(localLogin.status, 200, "localhost login should work while the dev issuer uses a tunnel URL");
    const loggedOut = await fetch(`${issuer}/api/logout`, {
        method: "POST",
        headers: { Cookie: cookieHeader(browserJar), Origin: issuer, "X-CSRF-Token": loggedIn.csrfToken },
    });
    assert.equal(loggedOut.status, 204);
    const rotatedTokenReuse = await fetch(`${issuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", client_id: client.client_id, refresh_token: tokens.refresh_token, resource: endpoint }),
    });
    assert.equal(rotatedTokenReuse.status, 400, "rotated refresh tokens must not be reusable");
});
