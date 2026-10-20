import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const envPath = path.join(root, ".env");
const examplePath = path.join(root, ".env.example");

if (!existsSync(envPath)) copyFileSync(examplePath, envPath);
let contents = readFileSync(envPath, "utf8");

function setIfMissingOrBlank(name, value) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const line = new RegExp(`^${escaped}=(.*)$`, "m");
    const existing = contents.match(line);
    if (existing && existing[1].trim()) return;
    if (existing) contents = contents.replace(line, `${name}=${value}`);
    else contents += `${contents.endsWith("\n") ? "" : "\n"}${name}=${value}\n`;
}

const cookieSecret = randomBytes(48).toString("base64url");
const webSecret = randomBytes(48).toString("base64url");
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const signingKey = privateKey.export({ format: "jwk" });
signingKey.use = "sig";
signingKey.alg = "RS256";
signingKey.kid = randomBytes(12).toString("base64url");

setIfMissingOrBlank("OIDC_COOKIE_SECRET", cookieSecret);
setIfMissingOrBlank("WEB_SESSION_SECRET", webSecret);
setIfMissingOrBlank("OAUTH_JWKS", JSON.stringify({ keys: [signingKey] }));
writeFileSync(envPath, contents, { encoding: "utf8", mode: 0o600 });
console.log("OAuth signing and session secrets are configured in mcp-server/.env. Existing non-empty values were preserved.");
