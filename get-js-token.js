// api/get-js-token.js
import crypto from "crypto";

const SECRET = process.env.JS_TOKEN_SECRET || "ganti_dengan_secret_acak";
const TTL_MS = 5 * 60 * 1000; // token berlaku 5 menit

// Simpan nonce sementara (reset kalau instance restart)
const usedNonces = new Map();

export default function handler(req, res) {
  if (req.method !== "GET") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  const ts = Date.now();
  const nonce = crypto.randomBytes(12).toString("hex");
  const payload = `${ts}|${nonce}`;
  const sig = crypto.createHmac("sha256", SECRET).update(payload).digest("hex");
  const token = Buffer.from(`${ts}|${nonce}|${sig}`).toString("base64");

  usedNonces.set(nonce, ts + TTL_MS);

  // Hapus nonce kadaluarsa biar memory bersih
  const now = Date.now();
  for (const [n, exp] of usedNonces) if (exp < now) usedNonces.delete(n);

  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.status(200).send(token);
}
