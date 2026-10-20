import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import { pathToFileURL } from "node:url";

async function callAppApi(path, options = {}) {
    let response;

    try {
        response = await fetch(`http://127.0.0.1:3000${path}`, {
            ...options,
            signal: AbortSignal.timeout(35000),
        });
    } catch (error) {
        if (error.name === "TimeoutError" || error.name === "AbortError") {
            throw new Error(`App API request timed out: ${path}`);
        }
        if (error instanceof TypeError) {
            throw new Error("Cannot connect to App API. Check whether it is running on port 3000.");
        }
        throw new Error(`App API request failed: ${error.message}`);
    }

    let data;
    try {
        data = await response.json();
    } catch {
        throw new Error(`App API returned invalid JSON (HTTP ${response.status})`);
    }

    if (!response.ok) {
        const message = data?.error?.message || data?.message || `HTTP ${response.status}`;
        throw new Error(`App API error (${response.status}): ${message}`);
    }
    return data;
}

export function createMcpServer() {
    const server = new McpServer({ name: "mini-sherlocq-mcp", version: "1.0.0" });

    server.registerTool(
        "check_app_health",
        { description: "Check whether the Mini Sherlocq application API is running", inputSchema: {} },
        async () => {
            try {
                const data = await callAppApi("/health");
                return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
            } catch (error) {
                return { isError: true, content: [{ type: "text", text: `Could not reach App API: ${error.message}` }] };
            }
        },
    );

    server.registerTool(
        "ask_question",
        {
            description: "Ask a question using the Mini Sherlocq application API",
            inputSchema: {
                question: z.string().trim().min(1, "Question cannot be empty").max(2000, "Question cannot exceed 2000 characters").describe("The question to ask"),
            },
        },
        async ({ question }) => {
            try {
                const data = await callAppApi("/api/ask", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ question }),
                });
                return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
            } catch (error) {
                return { isError: true, content: [{ type: "text", text: `Question API failed: ${error.message}` }] };
            }
        },
    );

    return server;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
    if (process.env.MCP_TRANSPORT === "http" || process.argv.includes("--http")) {
        const { startHttpServer } = await import("./http-server.js");
        await startHttpServer(createMcpServer);
    } else {
        serveStdio(createMcpServer);
    }
}
