// api/reply.js
import crypto from 'crypto';
import { Client } from '@larksuiteoapi/node-sdk';

// ---- Vercel: we need the raw request body for signature verification ----
export const config = {
  api: { bodyParser: false },
};

const client = new Client({
  appId: process.env.APP_ID,
  appSecret: process.env.APP_SECRET,
  domain: process.env.BASE_DOMAIN, // Feishu CN vs LarkSuite Global
});

/** Read raw body as string (required for signature verification) */
async function readRawBody(req) {
  return await new Promise((resolve, reject) => {
    let data = [];
    req.on('data', (chunk) => data.push(chunk));
    req.on('end', () => resolve(Buffer.concat(data).toString('utf8')));
    req.on('error', reject);
  });
}

/** v2 Signature verification (HMAC-SHA256, base64) */
function verifyV2Signature({ timestamp, nonce, signature, body, appSecret }) {
  if (!timestamp || !nonce || !signature) return false;
  // Concatenate exactly: timestamp + nonce + body
  const baseString = `${timestamp}${nonce}${body}`;
  const calc = crypto.createHmac('sha256', appSecret).update(baseString).digest('base64');
  return crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(signature));
}

/** Optional decryption if you enabled "Encrypt Key" */
function decryptIfNeeded(rawBodyString) {
  const parsed = JSON.parse(rawBodyString);
  if (!parsed.encrypt) return parsed; // not encrypted

  const key = process.env.ENCRYPT_KEY;
  if (!key) throw new Error('ENCRYPT_KEY missing but payload is encrypted.');

  // Feishu uses AES-256-CBC with PKCS#7; key is derived via SHA256(ENCRYPT_KEY)
  const aesKey = crypto.createHash('sha256').update(key, 'utf8').digest(); // 32 bytes
  // The encrypted blob is base64 JSON: { iv, cipherText }
  const encBuf = Buffer.from(parsed.encrypt, 'base64');
  // Payload format: 16-byte IV + cipherText
  const iv = encBuf.subarray(0, 16);
  const cipherText = encBuf.subarray(16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  decipher.setAutoPadding(true);
  let decrypted = decipher.update(cipherText, undefined, 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const rawBody = await readRawBody(req);

  // Grab headers (Feishu/Lark uses these names)
  const hSig = req.headers['x-lark-signature'] || req.headers['x-feishu-signature'];
  const hTs  = req.headers['x-lark-request-timestamp'] || req.headers['x-feishu-request-timestamp'];
  const hN   = req.headers['x-lark-request-nonce'] || req.headers['x-feishu-request-nonce'];

  // ---- Verify v2 signature if header present ----
  if (hSig) {
    const ok = verifyV2Signature({
      timestamp: String(hTs || ''),
      nonce: String(hN || ''),
      signature: String(hSig || ''),
      body: rawBody,
      appSecret: process.env.APP_SECRET,
    });
    if (!ok) {
      return res.status(401).json({ error: 'invalid signature' });
    }
  }

  // ---- Parse (and decrypt if needed) AFTER signature check ----
  let body;
  try {
    body = decryptIfNeeded(rawBody);
  } catch (e) {
    return res.status(400).json({ error: 'bad payload/decrypt failed' });
  }

  // ---- url_verification handshake ----
  if (body.type === 'url_verification') {
    // If encrypted, decryptIfNeeded already gave us the plain object with challenge
    return res.status(200).json({ challenge: body.challenge });
  }

  // ---- Optional: legacy token check (for Event v2, token is in body.header.token) ----
  const expectedToken = process.env.VERIFICATION_TOKEN;
  if (expectedToken) {
    const tokenInBody = body?.header?.token || body?.token; // some payloads use body.token
    if (tokenInBody !== expectedToken) {
      return res.status(401).json({ error: 'invalid verification token' });
    }
  }

  // ---- Events ----
  const event = body.event;
  if (event?.type === 'im.message.receive_v1') {
    const { chat_id, content, message_type, chat_type, message_id } = event.message;

    let responseText = '';
    try {
      responseText = message_type === 'text'
        ? JSON.parse(content).text
        : '解析消息失败，请发送文本消息 \nparse message failed, please send text message';
    } catch {
      responseText = '解析消息失败，请发送文本消息 \nparse message failed, please send text message';
    }

    if (chat_type === 'p2p') {
      await client.im.v1.message.create({
        params: { receive_id_type: 'chat_id' },
        data: {
          receive_id: chat_id,
          content: JSON.stringify({ text: `收到你发送的消息:${responseText}\nReceived message: ${responseText}` }),
          msg_type: 'text',
        },
      });
    } else {
      await client.im.v1.message.reply({
        path: { message_id },
        data: {
          content: JSON.stringify({ text: `收到你发送的消息:${responseText}\nReceived message: ${responseText}` }),
          msg_type: 'text',
        },
      });
    }
  }

  // Always ACK quickly so Feishu doesn’t retry
  return res.status(200).json({ ok: true });
}
