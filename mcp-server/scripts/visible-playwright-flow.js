import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import bcrypt from "bcryptjs";

const require = createRequire(import.meta.url);
const { chromium } = require("C:/Users/patel/AppData/Local/npm-cache/_npx/e41f203b7505f1fb/node_modules/playwright");
const nativeFetch = globalThis.fetch;
const appApiCalls = [];
const email = `pw-${randomBytes(6).toString("hex")}@example.invalid`;
const password = randomBytes(24).toString("base64url");
const signing = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ format: "jwk" });
signing.use = "sig";
signing.alg = "RS256";
signing.kid = randomBytes(12).toString("base64url");
Object.assign(process.env, {
    NODE_ENV: "test",
    MCP_PORT: "3001",
    MCP_HOST: "127.0.0.1",
    OAUTH_ISSUER: "http://127.0.0.1:3001",
    OIDC_COOKIE_SECRET: randomBytes(48).toString("base64url"),
    WEB_SESSION_SECRET: randomBytes(48).toString("base64url"),
    OAUTH_JWKS: JSON.stringify({ keys: [signing] }),
    DEFAULT_USER_EMAIL: email,
    DEFAULT_USER_PASSWORD_HASH: await bcrypt.hash(password, 10),
});

globalThis.fetch = async (input, init) => {
    const url = String(input);
    if (url.startsWith("http://127.0.0.1:3000/")) {
        const pathname = new URL(url).pathname;
        appApiCalls.push(pathname);
        if (pathname === "/health") return new Response(JSON.stringify({ success: true, message: "Mock App API health" }), { headers: { "Content-Type": "application/json" } });
        if (pathname === "/api/ask") {
            const body = JSON.parse(init.body);
            return new Response(JSON.stringify({ success: true, data: { question: body.question, answer: "Playwright mock answer (no OpenRouter request)" } }), { headers: { "Content-Type": "application/json" } });
        }
    }
    return nativeFetch(input, init);
};

const [{ startHttpServer }, { createMcpServer }] = await Promise.all([
    import("../src/http-server.js"),
    import("../src/index.js"),
]);
const service = await startHttpServer(createMcpServer);
const issuer = "http://127.0.0.1:3001";
const endpoint = `${issuer}/mcp`;
const browser = await chromium.launch({ headless: false, slowMo: 180 });
let leaveBrowserOpen = false;

async function mcpMessage(response) {
    const body = await response.text();
    if (response.headers.get("content-type")?.includes("text/event-stream")) {
        const event = body.split(/\r?\n/).find((line) => line.startsWith("data: "));
        assert.ok(event, "Expected an MCP message event");
        return JSON.parse(event.slice(6));
    }
    return JSON.parse(body);
}

try {
    const context = await browser.newContext();
    const page = await context.newPage();
    page.on("pageerror", (error) => console.error("Browser page error:", error.message));
    page.on("response", async (response) => {
        if (new URL(response.url()).pathname.startsWith("/api/oauth/interaction/")) console.log("INTERACTION API", response.status(), await response.text());
    });
    await page.route("**/api/session", (route) => route.abort());
    await page.goto(`${issuer}/login`);
    await page.getByRole("heading", { name: "Sign-in is temporarily unavailable" }).waitFor();
    assert.match(await page.locator("body").innerText(), /Please try again in a moment/);
    assert.doesNotMatch(await page.locator("body").innerText(), /npm run|mcp-server|folder/i);
    await page.getByLabel("Email address").fill(email);
    await page.unroute("**/api/session");
    await page.getByRole("button", { name: "Try again" }).click();
    await page.getByRole("heading", { name: "Welcome back" }).waitFor();
    await page.getByLabel("Email address").fill(email);
    await page.getByLabel("Password", { exact: true }).fill("incorrect-test-password");
    const signIn = page.getByRole("button", { name: "Sign in" });
    const badLoginResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/login");
    await signIn.click();
    assert.equal((await badLoginResponse).status(), 401, "wrong password should return 401");
    await page.getByRole("alert").getByText("Email or password is incorrect").waitFor();

    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.route("**/api/login", async (route) => {
        await new Promise((resolve) => setTimeout(resolve, 600));
        await route.continue();
    });
    const loginResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/login");
    await signIn.click();
    await page.locator("button[type=submit] .spinner").waitFor({ state: "visible" });
    assert.equal((await loginResponse).status(), 200, "valid login should return 200");
    await page.waitForURL("**/dashboard");
    await page.getByRole("heading", { name: "Good to see you." }).waitFor();

    if (process.env.PW_LOGIN_ONLY === "1") {
        await page.goto(`${issuer}/login`);
        await page.getByRole("heading", { name: "Welcome back" }).waitFor();
        await page.screenshot({ path: path.join(tmpdir(), "mini-sherlocq-playwright-dashboard.png") });
        globalThis.fetch = nativeFetch;
        await new Promise((resolve, reject) => service.httpServer.close((error) => error ? reject(error) : resolve()));
        console.log("PASS: offline message is plain language, credentials stay in the form, Try again recovers, wrong password is rejected, correct login succeeds, and the workspace dashboard loads.");
        console.log("The visible Chromium window is open on the login page for inspection. Press Enter in this terminal to close it.");
        await new Promise((resolve) => process.stdin.once("data", resolve));
        await browser.close();
        process.exit(0);
    }

    const redirectUri = `${issuer}/playwright-callback`;
    const registration = await nativeFetch(`${issuer}/oauth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_name: "Visible Playwright Flow", redirect_uris: [redirectUri], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" }),
    });
    assert.equal(registration.status, 201);
    const client = await registration.json();
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const state = randomBytes(16).toString("base64url");
    const authorize = new URL(`${issuer}/oauth/authorize`);
    for (const [key, value] of Object.entries({ response_type: "code", client_id: client.client_id, redirect_uri: redirectUri, scope: "mcp", state, code_challenge: challenge, code_challenge_method: "S256", resource: endpoint })) authorize.searchParams.set(key, value);
    await page.goto(authorize.toString());
    await page.waitForTimeout(1000);
    console.log("OAUTH PAGE", page.url(), (await page.locator("body").innerText()).slice(0, 800));
    const continueButton = page.getByRole("button", { name: new RegExp(`Continue as ${email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`) });
    await continueButton.waitFor();
    await continueButton.click();
    await page.getByRole("heading", { name: "Connect Visible Playwright Flow?" }).waitFor();
    await page.getByRole("button", { name: "Approve access" }).click();
    await page.waitForURL((url) => url.pathname === "/playwright-callback" && url.searchParams.has("code"));
    const callback = new URL(page.url());
    assert.equal(callback.searchParams.get("state"), state);
    assert.equal(callback.searchParams.get("iss"), issuer);
    const code = callback.searchParams.get("code");

    const tokenResponse = await nativeFetch(`${issuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", client_id: client.client_id, code, redirect_uri: redirectUri, code_verifier: verifier, resource: endpoint }),
    });
    assert.equal(tokenResponse.status, 200);
    const tokens = await tokenResponse.json();
    assert.ok(tokens.access_token);

    const unauthenticated = await nativeFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "ask_question", arguments: { question: "must be blocked" } } }),
    });
    assert.equal(unauthenticated.status, 401);
    assert.deepEqual(appApiCalls, [], "unauthenticated tool call must not reach App API");

    const headers = { Authorization: `Bearer ${tokens.access_token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
    const initialize = await nativeFetch(endpoint, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "visible-playwright", version: "1.0" } } }) });
    assert.equal(initialize.status, 200, await initialize.text());
    const listed = await nativeFetch(endpoint, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }) });
    const toolNames = (await mcpMessage(listed)).result.tools.map((tool) => tool.name).sort();
    assert.deepEqual(toolNames, ["ask_question", "check_app_health"]);
    for (const [id, name, args] of [[4, "check_app_health", {}], [5, "ask_question", { question: "What is MCP?" }]]) {
        const response = await nativeFetch(endpoint, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }) });
        assert.equal(response.status, 200);
        const result = await mcpMessage(response);
        assert.equal(result.result.isError, undefined);
        assert.ok(result.result.content?.length);
    }
    assert.deepEqual(appApiCalls, ["/health", "/api/ask"]);

    const refreshResponse = await nativeFetch(`${issuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", client_id: client.client_id, refresh_token: tokens.refresh_token, resource: endpoint }),
    });
    assert.equal(refreshResponse.status, 200);
    const refreshed = await refreshResponse.json();
    assert.ok(refreshed.access_token);
    const revokeResponse = await nativeFetch(`${issuer}/oauth/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: refreshed.access_token, token_type_hint: "access_token", client_id: client.client_id }),
    });
    assert.equal(revokeResponse.status, 200);

    await page.goto(`${issuer}/dashboard`);
    await page.getByRole("heading", { name: "Good to see you." }).waitFor();
    await page.screenshot({ path: path.join(tmpdir(), "mini-sherlocq-playwright-dashboard.png") });
    globalThis.fetch = nativeFetch;
    await new Promise((resolve, reject) => service.httpServer.close((error) => error ? reject(error) : resolve()));
    leaveBrowserOpen = true;
    console.log("PASS: invalid and valid UI login, OAuth DCR + PKCE + consent, unauthenticated denial, MCP initialize/list, both tools using mocked App API, refresh, and revocation.");
    console.log("The visible Chromium window is left open on the dashboard for you to inspect. Press Enter in this terminal to close it.");
    await new Promise((resolve) => process.stdin.once("data", resolve));
} finally {
    globalThis.fetch = nativeFetch;
    if (!leaveBrowserOpen) {
        await browser.close();
        await new Promise((resolve) => service.httpServer.close(() => resolve()));
    } else await browser.close();
}
