import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync } from "node:fs";
import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const node = process.execPath;
const remoteMode = process.argv.includes("--remote");
const services = [];
let shuttingDown = false;

function log(message) {
    process.stdout.write(`[Mini Sherlocq] ${message}\n`);
}

function fail(message) {
    console.error(`[Mini Sherlocq] ${message}`);
    process.exit(1);
}

function ensureEnvironmentFile(folder) {
    const envPath = path.join(root, folder, ".env");
    if (!existsSync(envPath)) {
        copyFileSync(`${envPath}.example`, envPath);
        log(`Created ${folder}/.env from its example.`);
    }
}

ensureEnvironmentFile("app-api");
ensureEnvironmentFile("mcp-server");

function prefixOutput(label, stream, onText) {
    let pending = "";
    stream.on("data", (chunk) => {
        const value = chunk.toString();
        onText?.(value);
        pending += value;
        const lines = pending.split(/\r?\n/);
        pending = lines.pop() || "";
        for (const line of lines) process.stdout.write(`[${label}] ${line}\n`);
    });
    stream.on("end", () => {
        if (pending) process.stdout.write(`[${label}] ${pending}\n`);
    });
}

function start(label, executable, args, cwd, env = {}, onText) {
    const child = spawn(executable, args, {
        cwd,
        env: { ...process.env, ...env },
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
    });
    services.push({ label, child });
    prefixOutput(label, child.stdout, onText);
    prefixOutput(label, child.stderr, onText);
    child.once("error", (error) => {
        console.error(`[${label}] Could not start: ${error.message}`);
        stop(1);
    });
    child.once("exit", (code, signal) => {
        if (!shuttingDown) {
            console.error(`[${label}] stopped${signal ? ` (${signal})` : ` with exit code ${code}`}.`);
            stop(code || 1);
        }
    });
    return child;
}

async function canBind(host, port) {
    return new Promise((resolve) => {
        const probe = createServer();
        probe.once("error", () => resolve(false));
        probe.listen(port, host, () => probe.close(() => resolve(true)));
    });
}

async function portIsFree(port) {
    const results = await Promise.all([canBind("127.0.0.1", port), canBind("::1", port)]);
    return results.every(Boolean);
}

function findPortPids(port) {
    const output = ["tcp", "tcpv6"].map((family) => spawnSync("netstat", ["-ano", "-p", family], { encoding: "utf8" }).stdout || "").join("\n");
    return [...new Set(output.split(/\r?\n/)
        .map((line) => {
            const columns = line.trim().split(/\s+/);
            const address = columns[1];
            if (!/^TCP$/i.test(columns[0] || "") || !address?.endsWith(`:${port}`) || columns[3] !== "LISTENING") return undefined;
            return Number(columns[4]);
        })
        .filter((pid) => Number.isInteger(pid) && pid > 0 && pid !== process.pid))];
}

async function makePortAvailable(port, label, healthUrl, isExpectedService, forceRestart = false) {
    if (await portIsFree(port)) return false;

    try {
        const response = await fetch(healthUrl, { signal: AbortSignal.timeout(1200) });
        const body = await response.json();
        if (response.ok && isExpectedService(body) && !forceRestart) {
            log(`${label} is already running on port ${port}; using it.`);
            return true;
        }
    } catch { /* Stop an old or incompatible listener below. */ }

    const pids = findPortPids(port);
    if (!pids.length) fail(`Port ${port} for ${label} is in use. Close the program using it and run npm start again.`);

    for (const pid of pids) {
        log(`Releasing port ${port} for ${label} (process ${pid})…`);
        if (process.platform === "win32") {
            const result = spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore" });
            if (result.status !== 0) fail(`Could not free port ${port}. Close the application using it and run npm start again.`);
        } else {
            try { process.kill(pid, "SIGTERM"); } catch { /* It may have exited already. */ }
        }
    }

    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
        if (await portIsFree(port)) return false;
        await new Promise((resolve) => setTimeout(resolve, 200));
    }
    fail(`Port ${port} is still in use. Close the application using it and run npm start again.`);
}

async function waitFor(url, label, child, expected) {
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
        if (child?.exitCode !== null && child?.exitCode !== undefined) throw new Error(`${label} stopped before it was ready.`);
        try {
            const response = await fetch(url, { signal: AbortSignal.timeout(1500) });
            if (response.ok && await expected(response)) return;
        } catch { /* Retry while the service starts. */ }
        await new Promise((resolve) => setTimeout(resolve, 400));
    }
    throw new Error(`${label} did not become ready within 30 seconds.`);
}

function stop(exitCode = 0) {
    if (shuttingDown) return;
    shuttingDown = true;
    log("Stopping services started by this command…");
    for (const { child } of services) {
        if (child.exitCode !== null) continue;
        if (process.platform === "win32") spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
        else child.kill("SIGTERM");
    }
    const timeout = setTimeout(() => process.exit(exitCode), 4000);
    timeout.unref();
    Promise.all(services.map(({ child }) => new Promise((resolve) => {
        if (child.exitCode !== null) return resolve();
        child.once("exit", resolve);
    }))).then(() => process.exit(exitCode));
}

process.on("SIGINT", () => stop(0));
process.on("SIGTERM", () => stop(0));

async function runSetupSecrets() {
    const setupScript = path.join(root, "mcp-server", "scripts", "setup-oauth-secrets.js");
    const setup = spawn(node, [setupScript], { cwd: path.join(root, "mcp-server"), stdio: "inherit", windowsHide: true });
    const code = await new Promise((resolve, reject) => {
        setup.once("error", reject);
        setup.once("exit", resolve);
    });
    if (code !== 0) throw new Error("Could not prepare the MCP sign-in secrets.");
}

async function createTunnel() {
    let tunnelUrl;
    let output = "";
    let resolveUrl;
    let rejectUrl;
    const urlReady = new Promise((resolve) => { resolveUrl = resolve; });
    const tunnelFailed = new Promise((_, reject) => { rejectUrl = reject; });
    const tunnel = start("Cloudflare Tunnel", "cloudflared", ["tunnel", "--url", "http://localhost:3001"], root, {}, (chunk) => {
        output += chunk;
        const match = output.match(/Your quick Tunnel has been created![\s\S]{0,500}?(https:\/\/[a-z0-9-]+\.trycloudflare\.com)/i);
        if (match && !tunnelUrl) {
            tunnelUrl = match[1];
            resolveUrl(tunnelUrl);
        }
        if (/failed to request quick Tunnel/i.test(output) && !tunnelUrl) {
            rejectUrl(new Error("Cloudflare could not create a Quick Tunnel. Check network access and try again."));
        }
    });
    tunnel.once("exit", (code) => {
        if (!tunnelUrl) rejectUrl(new Error(`cloudflared exited before creating a Quick Tunnel (exit ${code ?? "unknown"}).`));
    });
    const timeoutId = setTimeout(() => rejectUrl(new Error("Cloudflare did not provide a Quick Tunnel URL within 30 seconds.")), 30000);
    try {
        const url = await Promise.race([urlReady, tunnelFailed]);
        return { url, tunnel };
    } finally {
        clearTimeout(timeoutId);
    }
}

try {
    const frontendCli = path.join(root, "frontend", "node_modules", "vite", "bin", "vite.js");
    const mcpEntry = path.join(root, "mcp-server", "src", "index.js");
    const appEntry = path.join(root, "app-api", "src", "server.js");
    if (![frontendCli, mcpEntry, appEntry].every(existsSync)) {
        fail("Dependencies are missing. Run npm install once in app-api, mcp-server, and frontend.");
    }

    await runSetupSecrets();

    const reused = {};
    reused.api = await makePortAvailable(3000, "App API", "http://127.0.0.1:3000/health", (data) => data.message === "Mini Sherlocq API is running");
    reused.mcp = await makePortAvailable(3001, "MCP server", "http://127.0.0.1:3001/health", (data) => data.service === "Mini Sherlocq MCP OAuth and Streamable HTTP endpoint", true);
    reused.frontend = await makePortAvailable(5173, "Vite frontend", "http://localhost:5173/", () => false, true);

    log("Building the frontend bundle used by OAuth sign-in…");
    const build = spawn(node, [frontendCli, "build"], { cwd: path.join(root, "frontend"), stdio: "inherit", windowsHide: true });
    const buildCode = await new Promise((resolve) => build.once("exit", resolve));
    if (buildCode !== 0) throw new Error("Frontend build failed.");

    const apiProcess = reused.api ? null : start("App API :3000", node, [appEntry], path.join(root, "app-api"), { HOST: "127.0.0.1", PORT: "3000" });
    const frontendProcess = reused.frontend ? null : start("Frontend :5173", node, [frontendCli, "--host", "localhost", "--port", "5173", "--strictPort"], path.join(root, "frontend"));
    if (apiProcess) await waitFor("http://127.0.0.1:3000/health", "App API", apiProcess, async (response) => (await response.json()).message === "Mini Sherlocq API is running");
    if (frontendProcess) await waitFor("http://localhost:5173/", "Frontend", frontendProcess, async (response) => (await response.text()).includes("/@vite/client"));

    let issuer = "http://localhost:5173";
    let tunnelUrl;
    if (remoteMode) {
        log("Starting Cloudflare Quick Tunnel to MCP port 3001…");
        ({ url: tunnelUrl } = await createTunnel());
        issuer = tunnelUrl;
    }

    const mcpProcess = reused.mcp ? null : start(
        "MCP server :3001",
        node,
        ["--env-file=.env", mcpEntry, "--http"],
        path.join(root, "mcp-server"),
        { MCP_HOST: "127.0.0.1", MCP_PORT: "3001", OAUTH_ISSUER: issuer },
    );
    if (mcpProcess) await waitFor("http://127.0.0.1:3001/health", "MCP server", mcpProcess, async (response) => (await response.json()).service === "Mini Sherlocq MCP OAuth and Streamable HTTP endpoint");

    log("All services are ready.");
    log("Frontend: http://localhost:5173");
    log("App API:  http://localhost:3000");
    log("MCP:      http://localhost:3001/mcp");
    if (remoteMode) log(`Paste this into Claude.ai: ${tunnelUrl}/mcp`);
    log("Keep this terminal open. Press Ctrl+C to stop services started by this command.");
} catch (error) {
    console.error(`[Mini Sherlocq] ${error.message}`);
    stop(1);
}
