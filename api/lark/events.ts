import { pinyin } from "pinyin-pro";

const APP_ID = process.env.LARK_APP_ID!;
const APP_SECRET = process.env.LARK_APP_SECRET!;
const VERIFICATION_TOKEN = process.env.VERIFICATION_TOKEN; // optional
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

function toPinyin(text: string, toneMarks = true) {
  // pinyin-pro keeps non-Hanzi as-is; spaces between syllables
  return pinyin(text, { toneType: toneMarks ? "symbol" : "num" })
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

// Per IM v1 send message API: POST /open-apis/im/v1/messages?receive_id_type=chat_id
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
    const errText = await r.text();
    console.error("im.v1 send text error", r.status, errText);
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

export default async function handler(req: any, res: any) {
  const body = typeof req.body === "object" ? req.body : JSON.parse(req.body || "{}");

  // URL verification handshake
  if (body?.type === "url_verification" && body?.challenge) {
    return res.status(200).json({ challenge: body.challenge });
  }

  // Optional verification token check (simple and explicit)
  if (VERIFICATION_TOKEN && body?.token && body.token !== VERIFICATION_TOKEN) {
    return res.status(200).json({ code: 0 });
  }

  // Handle message receive (IM v1 event)
  const event = body?.event || {};
  // Support both newer and older shapes just in case
  const msg = event?.message || {};
  const chatId = msg.chat_id || msg.conversation_id;
  const content = msg.content || "";
  const text = extractTextFromMessageContent(content);

  if (!chatId || !text) {
    return res.status(200).json({ code: 0 });
  }

  const py = toPinyin(text, true);
  try {
    await sendTextToChat(chatId, py || "");
  } catch (_) {}

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
