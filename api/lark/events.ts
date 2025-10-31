import crypto from "crypto";
import type { VercelRequest, VercelResponse } from "@vercel/node";
import { pinyin } from "pinyin-pro";

const APP_ID = process.env.LARK_APP_ID!;
const APP_SECRET = process.env.LARK_APP_SECRET!;
const VERIFICATION_TOKEN = process.env.LARK_VERIFICATION_TOKEN; // optional
const ENCRYPT_KEY = process.env.LARK_ENCRYPT_KEY; // optional
const LARK_BASE = process.env.LARK_BASE || "https://open.larksuite.com";

async function tenantAccessToken(): Promise<string> {
  const url = `${LARK_BASE}/open-apis/auth/v3/tenant_access_token/internal`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify({ app_id: APP_ID, app_secret: APP_SECRET }),
  });
  const j = await r.json();
  if (!r.ok || !j.tenant_access_token) {
    throw new Error(`TAT error: ${r.status} ${JSON.stringify(j)}`);
  }
  return j.tenant_access_token as string;
}

function decryptIfNeeded(body: any) {
  // If Lark encryption is enabled, the body is { encrypt: "<base64>" }
  if (!body || !body.encrypt) return body;
  if (!ENCRYPT_KEY) return body; // no key configured → can't decrypt

  // Per docs: AES-256-CBC, key = SHA256(encrypt_key), IV is the first 16 bytes
  const buf = Buffer.from(body.encrypt, "base64");
  const iv = buf.subarray(0, 16);
  const ciphertext = buf.subarray(16);
  const key = crypto.createHash("sha256").update(ENCRYPT_KEY, "utf8").digest();

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const out = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
  return JSON.parse(out);
}

function verifySignature(req: VercelRequest, rawBody: string) {
  if (!ENCRYPT_KEY) return true; // skip if not configured
  const ts = req.headers["x-lark-request-timestamp"] as string;
  const nonce = req.headers["x-lark-request-nonce"] as string;
  const sig = req.headers["x-lark-signature"] as string;
  const base = `${ts}${nonce}${rawBody}`;
  const h = crypto.createHmac("sha256", ENCRYPT_KEY).update(base).digest("hex");
  return h === sig;
}

function verifyToken(body: any) {
  if (!VERIFICATION_TOKEN) return true; // skip if not configured
  return body?.token === VERIFICATION_TOKEN;
}

function toPinyin(text: string, toneMarks = true) {
  // pinyin-pro keeps non-Hanzi as-is; spaces between syllables
  return pinyin(text, { toneType: toneMarks ? "mark" : "num" })
    .replace(/\s{2,}/g, " ")
    .trim();
}

function buildCard(orig: string, py: string) {
  return {
    config: { wide_screen_mode: true },
    elements: [
      { tag: "markdown", content: "**Original**\n" + (orig || "_(empty)_") },
      { tag: "hr" },
      { tag: "markdown", content: "**Pinyin**\n" + (py || "_(empty)_") },
    ],
  };
}

async function sendTextToChat(chatId: string, text: string) {
  const tat = await tenantAccessToken();
  const r = await fetch(
    `${LARK_BASE}/open-apis/im/v1/messages?receive_id_type=chat_id`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tat}`,
        "Content-Type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({
        receive_id: chatId,
        msg_type: "text",
        content: JSON.stringify({ text }),
      }),
    }
  );
  if (!r.ok) {
    const err = await r.text();
    console.error("send text error", r.status, err);
  }
}

function extractTextFromMessageContent(content: string): string {
  // Lark message "content" is a JSON string; extract text conservatively
  try {
    const c = JSON.parse(content);
    // Many messages are { "text": "..." }
    if (typeof c.text === "string") return c.text;
    // Rich text: { "content": [[{"tag":"text","text":"..."}], ...] }
    if (Array.isArray(c.content)) {
      const first = c.content[0];
      if (Array.isArray(first)) {
        return first.map((seg: any) => seg?.text ?? "").join("");
      }
    }
  } catch (_) {}
  return "";
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const rawBody =
    typeof req.body === "string" ? req.body : JSON.stringify(req.body || {});
  let body =
    typeof req.body === "object" ? req.body : JSON.parse(rawBody || "{}");

  // 🔐 Decrypt first if needed
  body = decryptIfNeeded(body);

  // ✅ URL verification must always return the challenge with 200
  if (body?.type === "url_verification" && body?.challenge) {
    return res.status(200).json({ challenge: body.challenge });
  }

  // (Only after handshake) do token/signature checks
  if (!verifySignature(req, rawBody) || !verifyToken(body)) {
    return res.status(200).json({ code: 0 });
  }
  // 3) Event handling (Message Shortcut or message receive)
  const event = body?.event || {};
  const msg = event?.message || {};
  const chatId = msg.chat_id || msg.conversation_id;
  const content = msg.content || "";
  const chatType = msg.chat_type || event?.chat_type;
  const text = extractTextFromMessageContent(content);

  // Convert to Pinyin (tone marks by default; switch to numbers if you prefer)
  const py = toPinyin(text, /* toneMarks */ true);
  const card = buildCard(text, py);

  try {
    if (chatType === "p2p") {
      // Direct message with the bot → reply with plain text Pinyin
      await sendTextToChat(chatId, py || "");
    } else {
      // Fallback for non-p2p chats → keep interactive card behavior
      const tat = await tenantAccessToken();
      const r = await fetch(
        `${LARK_BASE}/open-apis/im/v1/messages?receive_id_type=chat_id`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${tat}`,
            "Content-Type": "application/json; charset=utf-8",
          },
          body: JSON.stringify({
            receive_id: chatId,
            msg_type: "interactive",
            content: JSON.stringify(card),
          }),
        }
      );
      if (!r.ok) {
        const err = await r.text();
        console.error("send message error", r.status, err);
      }
    }
  } catch (e) {
    console.error("handler error", (e as Error).message);
  }

  // Always return OK so Lark doesn’t retry
  return res.status(200).json({ code: 0 });
}

// Vercel needs this to read the raw body if you prefer signature validation on raw text
export const config = {
  api: {
    bodyParser: {
      sizeLimit: "1mb",
    },
  },
};
