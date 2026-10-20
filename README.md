# Mini Sherlocq MCP

Mini Sherlocq has three local services:

| Service | Address | Purpose |
| --- | --- | --- |
| React + Vite | `http://localhost:5173` | Login and dashboard |
| Express App API | `http://localhost:3000` | Health check and OpenRouter questions |
| MCP server | `http://localhost:3001/mcp` | OAuth-protected remote MCP and Claude Code stdio tools |

The MCP tools are `check_app_health` and `ask_question`. The HTTP server calls the App API on port 3000. Claude Code continues to launch the local MCP server using stdio.

## One-time setup

Install dependencies once, from the project root:

```powershell
npm install --prefix .\app-api
npm install --prefix .\mcp-server
npm install --prefix .\frontend
```

The MCP server has a fixed development login: **Test@example.com** / **Test@123**. The password is checked by the backend; it is never included in the frontend or logged. It uses an in-memory bcrypt hash in development, so there is no password-hash setup command. This account is for local learning only; the server refuses this demo credential in production.

`npm start` creates ignored `.env` files from the examples if they are missing and generates the OAuth signing/session secrets automatically. To use `ask_question`, put your OpenRouter API key in `app-api/.env` as `OPENROUTER_API_KEY=...`. The API health check and login work without that key; question answering needs it.

## Start all three locally

From the project root, run one command:

```powershell
npm start
```

It starts Vite on 5173, the App API on 3000, and the MCP server on 3001. Open **http://localhost:5173**. Keep the terminal open; press `Ctrl+C` to stop services started by the command. If a required port is occupied by an old Mini Sherlocq process, the launcher releases it and starts the right service on the requested port.

You can also run each service in its own PowerShell window:

**Window 1 — frontend**

```powershell
cd C:\Users\patel\JEET\2026\mini-sherlocq-mcp\frontend
npm run dev
```

**Window 2 — App API**

```powershell
cd C:\Users\patel\JEET\2026\mini-sherlocq-mcp\app-api
npm run dev
```

**Window 3 — MCP server and OAuth**

```powershell
cd C:\Users\patel\JEET\2026\mini-sherlocq-mcp\mcp-server
npm run dev:http
```

The MCP command creates any missing OAuth signing/session secrets before starting. Its local issuer is `http://localhost:5173`; Vite proxies OAuth and MCP requests to port 3001. Vite proxies only `/api/ask` to the App API on port 3000; login/session requests go to the MCP server.

## Connect Claude.ai through Cloudflare Tunnel

Claude.ai supports direct remote MCP connectors using OAuth and Dynamic Client Registration (DCR), which this server implements. Cloudflare MCP Portal is not required. Anthropic documents support for Streamable HTTP, OAuth, and DCR in its [remote MCP connector requirements](https://support.anthropic.com/en/articles/11503834-building-custom-integrations-via-remote-mcp-servers).

The simplest option starts all three local services and a temporary Cloudflare Tunnel together:

```powershell
npm run start:remote
```

This requires `cloudflared` to be installed and available in PowerShell's PATH. The command prints a generated HTTPS connector URL. Paste the printed URL ending in `/mcp` into Claude.ai under **Settings → Connectors → Add custom connector**. Choose **Sign in**, then use **Test@example.com** / **Test@123** and approve access. The Quick Tunnel URL changes when stopped and restarted, so add the newly printed URL each time.

To start the tunnel manually, run this in a fourth PowerShell window and copy its generated HTTPS origin:

```powershell
cloudflared tunnel --url http://localhost:3001
```

In the MCP terminal, stop the local-issuer server if it is already running, set the origin to the generated hostname, then start it:

```powershell
$env:OAUTH_ISSUER = "https://<generated-name>.trycloudflare.com"
npm run dev:http
```

In Claude.ai, enter `https://<generated-name>.trycloudflare.com/mcp`. Never enter `localhost` in Claude.ai; it cannot reach your computer's loopback address. No Cloudflare account or Portal setup is needed for a temporary Quick Tunnel.

## Check the services

```powershell
Invoke-RestMethod http://localhost:3000/health
Invoke-RestMethod http://localhost:3001/health
```

An unauthenticated request to the MCP endpoint should be rejected with HTTP 401:

```powershell
curl.exe -i -X POST http://localhost:3001/mcp -H "Content-Type: application/json" -d "{}"
```

Run the OAuth and MCP protocol tests from the MCP folder:

```powershell
cd C:\Users\patel\JEET\2026\mini-sherlocq-mcp\mcp-server
npm test
```

These tests use a mocked App API and do not spend OpenRouter quota. `check_app_health` can be tried freely. `ask_question` calls OpenRouter and may consume quota.

For the current public tunnel, check its OAuth discovery document and confirm an anonymous MCP request is rejected:

```powershell
$publicOrigin = "https://<generated-name>.trycloudflare.com"
Invoke-RestMethod "$publicOrigin/.well-known/oauth-authorization-server"
curl.exe -i -X POST "$publicOrigin/mcp" -H "Content-Type: application/json" -d "{}"
```

The MCP request should return `401`. For an authorized public tool call, add `$publicOrigin/mcp` in Claude.ai, complete the OAuth sign-in, and approve the requested access. Claude stores the connector authorization; no bearer header needs to be entered manually.

## Authentication and storage notes

- The browser login and MCP OAuth use one fixed development account. There is no registration, password reset, or database.
- Remote MCP uses OAuth authorization code with PKCE and Dynamic Client Registration. A fixed bearer token is not used.
- The MCP provider and web sessions are in memory. Restarting MCP ends current browser sessions and invalidates OAuth grants/tokens.
- `.env` files are ignored by Git. Keep the OpenRouter key and generated OAuth keys private.
- This fixed demo login is not production authentication.
