import { createHmac } from "node:crypto";

const secret = process.env.JWT_SECRET;
if (!secret) {
  // No secret available — skip token generation silently.
  // The frontend will fall back to mock data or sessionStorage auth.
  process.exit(0);
}

const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
const payload = Buffer.from(
  JSON.stringify({
    sub: "demo",
    name: "Demo Admin",
    email: "demo@aegis.io",
    role: "admin",
    groups: ["aegis-admin"],
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 2592000,
  })
).toString("base64url");
const signature = createHmac("sha256", secret)
  .update(header + "." + payload)
  .digest("base64url");

console.log(header + "." + payload + "." + signature);
