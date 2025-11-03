// api/reply.js
import crypto from 'crypto';
import { Client } from '@larksuiteoapi/node-sdk';

// ---- Vercel: we need the raw request body for signature verification ----
export const config = { api: { bodyParser: false } };

function normalizeBaseDomain(input) {
  if (!input) return undefined;
  const val = String(input).trim().toLowerCase();
  if (val === 'larksuite' || val === 'lark' || val === 'feishu') return val === 'lark' ? 'larksuite' : val;
  try {
    const url = new URL(val.startsWith('http') ? val : `https://${val}`);
    const host = url.hostname;
    if (host.includes('feishu')) return 'feishu';
    if (host.includes('larksuite') || host.includes('lark')) return 'larksuite';
  } catch {}
  return undefined;
}

const resolvedDomain = normalizeBaseDomain(process.env.BASE_DOMAIN);

const client = new Client({
  appId: process.env.APP_ID,
  appSecret: process.env.APP_SECRET,
  domain: resolvedDomain, // 'feishu' (CN) or 'larksuite' (Global)
});

if (!process.env.APP_ID || !process.env.APP_SECRET) console.error('[config] Missing APP_ID or APP_SECRET');
if (!process.env.BASE_DOMAIN) {
  console.warn('[config] BASE_DOMAIN not set. Expected "larksuite" or "feishu" (or a known open domain URL).');
} else {
  console.info('[config] BASE_DOMAIN =', process.env.BASE_DOMAIN);
}
console.info('[config] Resolved SDK domain =', resolvedDomain || '(default)');

/** Read raw body as string (required for signature verification) */
async function readRawBody(req) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/** v2 Signature verification (HMAC-SHA256, base64 or hex) */
function verifyV2Signature({ timestamp, nonce, signature, body, appSecret }) {
  if (!timestamp || !nonce || !signature || !appSecret) return false;

  // Normalize header like "sha256=..." or "v1=..."
  let providedSig = String(signature).trim();
  const eqIdx = providedSig.indexOf('=');
  if (eqIdx > 0 && /^[a-z0-9]+$/i.test(providedSig.slice(0, eqIdx))) {
    providedSig = providedSig.slice(eqIdx + 1).trim();
  }

  // Detect encrypted payloads ("encrypt" field)
  let parsedEncrypt;
  try {
    const parsedMaybe = JSON.parse(body);
    if (parsedMaybe && typeof parsedMaybe.encrypt === 'string') parsedEncrypt = parsedMaybe.encrypt;
  } catch {}

  // Per docs: 
  // - plaintext: HMAC-SHA256(timestamp + nonce + rawBody)
  // - encrypted: HMAC-SHA256(timestamp + nonce + encrypt)
  const base = `${timestamp}${nonce}${parsedEncrypt ? parsedEncrypt : body}`;
  const hmac = crypto.createHmac('sha256', appSecret).update(base).digest();

  // Accept either lowercase hex or base64 signatures
  if (/^[0-9a-f]{64}$/i.test(providedSig)) {
    const calcHex = hmac.toString('hex');
    const sigHexLower = providedSig.toLowerCase();
    const calcBuf = Buffer.from(calcHex, 'utf8');
    const sigBuf = Buffer.from(sigHexLower, 'utf8');
    return calcBuf.length === sigBuf.length && crypto.timingSafeEqual(calcBuf, sigBuf);
  }

  try {
    const headerBytes = Buffer.from(providedSig, 'base64');
    return headerBytes.length === hmac.length && crypto.timingSafeEqual(headerBytes, hmac);
  } catch {
    return false;
  }
}

/** Decrypt Feishu/Lark Event (if "encrypt" present) using AES-256-CBC, PKCS#7.
 * Key = SHA256(ENCRYPT_KEY). Ciphertext = base64( IV(16) || CIPHERTEXT ).
 */
function decryptIfNeeded(rawBodyString) {
  const parsed = JSON.parse(rawBodyString);
  if (!parsed.encrypt) return parsed; // plaintext event

  const key = process.env.ENCRYPT_KEY;
  if (!key) throw new Error('ENCRYPT_KEY missing but payload is encrypted.');

  const aesKey = crypto.createHash('sha256').update(key, 'utf8').digest(); // 32 bytes
  const encBuf = Buffer.from(parsed.encrypt, 'base64');
  if (encBuf.length < 17) throw new Error('Invalid encrypt payload (too short).');

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

  // Feishu/Lark headers
  const hSig = req.headers['x-lark-signature'] || req.headers['x-feishu-signature'];
  const hTs  = req.headers['x-lark-request-timestamp'] || req.headers['x-feishu-request-timestamp'];
  const hN   = req.headers['x-lark-request-nonce'] || req.headers['x-feishu-request-nonce'];

  if (process.env.DEBUG_LOG_BODY === '1') {
    try {
      console.info('[incoming][pre-verify]', {
        headers: { hasSig: !!hSig, ts: String(hTs || ''), nonce: String(hN || ''), sigLen: String(hSig || '').length },
        rawBodyLength: rawBody.length,
        hasEncryptField: /"encrypt"\s*:/.test(rawBody),
        rawBodyHead: rawBody.slice(0, 160),
      });
    } catch {}
  }

  // Verify signature (if header present)
  if (hSig) {
    const ok = verifyV2Signature({
      timestamp: String(hTs || ''),
      nonce: String(hN || ''),
      signature: String(hSig || ''),
      body: rawBody,
      appSecret: process.env.APP_SECRET,
    });
    if (!ok) {
      console.warn('[auth] signature verification failed');
      return res.status(401).json({ error: 'invalid signature' });
    }
  }

  // Parse & decrypt
  let body;
  try {
    body = decryptIfNeeded(rawBody);
  } catch (e) {
    console.error('[decrypt] failed:', e?.message);
    return res.status(400).json({ error: 'bad payload/decrypt failed' });
  }

  if (process.env.DEBUG_LOG_BODY === '1') {
    try {
      const topKeys = body && typeof body === 'object' ? Object.keys(body) : [];
      const headerKeys = body?.header && typeof body.header === 'object' ? Object.keys(body.header) : [];
      const eventKeys = body?.event && typeof body.event === 'object' ? Object.keys(body.event) : [];
      console.info('[incoming] structure', {
        hasEncryptField: /"encrypt"\s*:/.test(rawBody),
        rawBodyLength: rawBody.length,
        schema: body?.schema,
        type: body?.type,
        headerKeys,
        eventKeys,
        topKeys,
      });
    } catch {}
  }

  // URL verification
  if (body.type === 'url_verification') {
    return res.status(200).json({ challenge: body.challenge });
  }

  // Optional legacy token check
  const expectedToken = process.env.VERIFICATION_TOKEN;
  if (expectedToken) {
    const tokenInBody = body?.header?.token || body?.token;
    if (tokenInBody !== expectedToken) {
      console.warn('[auth] verification token mismatch');
      return res.status(401).json({ error: 'invalid verification token' });
    }
  }

  // Events
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

    try {
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
    } catch (err) {
      console.error('[lark api] send message failed', {
        name: err?.name, message: err?.message, code: err?.code, status: err?.status, data: err?.response?.data,
      });
      // Still ACK below
    }
  }

  // Always ACK to avoid retries
  return res.status(200).json({ ok: true });
}

