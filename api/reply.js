import crypto from 'crypto';
import pinyin from 'pinyin';
import { Client } from '@larksuiteoapi/node-sdk';

// ---- Client: match your sample style if you want manual token passing
const client = new Client({
  appId: process.env.APP_ID,
  appSecret: process.env.APP_SECRET,
  // If you want the SDK to auto-manage tenant token, set DISABLE_TOKEN_CACHE!='1'
  disableTokenCache,
  // Optional: set domain if needed: 'larksuite' (Global) or 'feishu' (CN)
  domain: process.env.BASE_DOMAIN || undefined,
});

// Helper: optional withTenantToken if you're disabling cache
function tenantOpt() {
  if (disableTokenCache && process.env.TENANT_ACCESS_TOKEN) {
    return [lark.withTenantToken(process.env.TENANT_ACCESS_TOKEN)];
  }
  return []; // SDK-managed token
}

// Utility: build "Echo + Pinyin" text
function toPinyinEcho(text) {
  let py = '';
  try {
    if (text && text.trim()) {
      // STYLE_TONE2 gives "ni3 hao3"; change to STYLE_TONE for diacritics
      py = pinyin(text, { style: pinyin.STYLE_TONE2 }).flat().join(' ');
    }
  } catch {}
  return `Echo: ${text || ''}\nPinyin: ${py || '(n/a)'}`;
}

// --- Vercel: keep raw body for signature verification
export const config = { api: { bodyParser: false } };


// --- Raw body reader
async function readRawBody(req) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// --- Constant-time compare (Buffers)
function safeEqual(a, b) {
  const A = Buffer.isBuffer(a) ? a : Buffer.from(String(a), 'utf8');
  const B = Buffer.isBuffer(b) ? b : Buffer.from(String(b), 'utf8');
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

/**
 * Verify signature using Encrypt Key strategy (no HMAC):
 *   b1 = (timestamp + nonce + encrypt_key).encode('utf-8')
 *   b  = b1 || bodyBytes ? We need bytes of "timestamp + nonce + encrypt_key" then concatenate raw body string
 *   s  = sha256(b)  (hex, compare to X-Lark-Signature)
 * Notes:
 * - Header may be hex or "sha256=..." prefixed.
 */
function verifyEncryptKeySignature({ timestamp, nonce, signature, rawBody, encryptKey }) {
  if (!timestamp || !nonce || !signature || !encryptKey) return false;

  // Normalize header: allow "sha256=<hex>" or raw hex
  let provided = String(signature).trim();
  const eq = provided.indexOf('=');
  if (eq > 0) provided = provided.slice(eq + 1).trim();

  // Compute sha256 over bytes of (timestamp + nonce + encrypt_key) + rawBody
  const headBytes = Buffer.from(`${timestamp}${nonce}${encryptKey}`, 'utf8');
  const bodyBytes = Buffer.from(rawBody, 'utf8');
  const combined = Buffer.concat([headBytes, bodyBytes]);

  const digestHex = crypto.createHash('sha256').update(combined).digest('hex');

  // Compare as hex (header may be hex or base64—doc typically uses hex)
  if (/^[0-9a-f]{64}$/i.test(provided)) {
    return safeEqual(digestHex.toLowerCase(), provided.toLowerCase());
  }

  // If header was base64 (rare), compare as base64 too
  try {
    const digestB64 = Buffer.from(digestHex, 'hex').toString('base64');
    const providedBuf = Buffer.from(provided, 'base64');
    const digestBuf = Buffer.from(digestB64, 'base64');
    return safeEqual(providedBuf, digestBuf);
  } catch {
    return false;
  }
}

/**
 * Verify v2 HMAC signature (App Secret):
 *   Prefer: HMAC-SHA256(timestamp + nonce + encrypt)  if "encrypt" exists
 *   Fallback: HMAC-SHA256(timestamp + nonce + rawBody)
 * Compare with X-Lark-Signature (hex or base64, may be "v2=..." or "sha256=...")
 */
function verifyHmacV2Signature({ timestamp, nonce, signature, rawBody, appSecret }) {
  if (!timestamp || !nonce || !signature || !appSecret) return false;

  let provided = String(signature).trim();
  const eq = provided.indexOf('=');
  if (eq > 0) provided = provided.slice(eq + 1).trim();

  // Try to extract encrypt field (without decoding)
  let encryptField;
  try {
    const maybe = JSON.parse(rawBody);
    if (maybe && typeof maybe.encrypt === 'string') encryptField = maybe.encrypt;
  } catch {}

  const make = (str) => crypto.createHmac('sha256', appSecret).update(str).digest();

  const candidates = [];
  if (encryptField) candidates.push(make(`${timestamp}${nonce}${encryptField}`));
  candidates.push(make(`${timestamp}${nonce}${rawBody}`));

  // Compare either as hex or base64
  if (/^[0-9a-f]{64}$/i.test(provided)) {
    const target = Buffer.from(provided.toLowerCase(), 'utf8');
    return candidates.some((c) => {
      const hex = Buffer.from(c.toString('hex'), 'utf8');
      return hex.length === target.length && crypto.timingSafeEqual(hex, target);
    });
  }
  try {
    const sig = Buffer.from(provided, 'base64');
    return candidates.some((c) => sig.length === c.length && crypto.timingSafeEqual(sig, c));
  } catch {
    return false;
  }
}

/**
 * Decrypt event if "encrypt" is present.
 * AES-256-CBC (PKCS#7), key = SHA256(ENCRYPT_KEY), payload = base64( IV(16) || CIPHERTEXT )
 */
function decryptIfNeeded(rawBodyString) {
  const parsed = JSON.parse(rawBodyString);
  if (!parsed.encrypt) return parsed;

  const key = process.env.ENCRYPT_KEY;
  if (!key) throw new Error('ENCRYPT_KEY missing but payload is encrypted.');

  const aesKey = crypto.createHash('sha256').update(key, 'utf8').digest(); // 32 bytes
  const encBuf = Buffer.from(parsed.encrypt, 'base64');
  if (encBuf.length < 17) throw new Error('Invalid encrypt payload');

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

  // Lark/Feishu headers (Global or CN)
  const hSig = req.headers['x-lark-signature'] || req.headers['x-feishu-signature'];
  const hTs  = req.headers['x-lark-request-timestamp'] || req.headers['x-feishu-request-timestamp'];
  const hN   = req.headers['x-lark-request-nonce'] || req.headers['x-feishu-request-nonce'];

  // --- Security verification
  const hasEncryptKey = !!process.env.ENCRYPT_KEY;
  const hasAppSecret  = !!process.env.APP_SECRET;

  let verified = false;

  // 1) Try Encrypt Key signature (required if encryption strategy is configured)
  if (hasEncryptKey) {
    verified = verifyEncryptKeySignature({
      timestamp: String(hTs || ''),
      nonce: String(hN || ''),
      signature: String(hSig || ''),
      rawBody,
      encryptKey: process.env.ENCRYPT_KEY,
    });
  }

  // 2) If not verified yet, try HMAC v2 with APP_SECRET
  if (!verified && hasAppSecret) {
    verified = verifyHmacV2Signature({
      timestamp: String(hTs || ''),
      nonce: String(hN || ''),
      signature: String(hSig || ''),
      rawBody,
      appSecret: process.env.APP_SECRET,
    });
  }

  if (!verified) {
    return res.status(401).json({ error: 'invalid signature' });
  }

  // --- Parse/decrypt AFTER signature verification
  let body;
  try {
    body = decryptIfNeeded(rawBody);
  } catch (e) {
    return res.status(400).json({ error: 'decrypt_failed', detail: e?.message || String(e) });
  }

  // --- URL Verification
  if (body.type === 'url_verification') {
    return res.status(200).json({ challenge: body.challenge });
  }

  // --- Optional Verification Token check
  const expectedToken = process.env.VERIFICATION_TOKEN;
  if (expectedToken) {
    const tokenInBody = body?.header?.token || body?.token;
    if (tokenInBody !== expectedToken) {
      return res.status(401).json({ error: 'invalid_verification_token' });
    }
  }

  // After you've verified signature + decrypted and have `body`:
const event = body?.event;

if (event?.type === 'im.message.receive_v1') {
  const { message, sender } = event;
  const { content, message_type, chat_type, message_id } = message || {};
  const openId = sender?.sender_id?.open_id; // Preferred target to "create" a message

  // Safely extract text
  let text = '';
  try {
    text = message_type === 'text' ? JSON.parse(content).text : '';
  } catch {
    text = '';
  }

  // Build reply string
  const replyText = toPinyinEcho(text);

  // Preferred: send like your sample (im.message.create to open_id)
  if (openId) {
    try {
      await client.im.message.create(
        {
          params: { receive_id_type: 'open_id' },
          data: {
            receive_id: openId,
            msg_type: 'text',
            content: JSON.stringify({ text: replyText }), // MUST be a JSON string
            uuid: crypto.randomUUID(), // your sample includes uuid
          },
        },
        ...tenantOpt()
      );
    } catch (e) {
      // If sending directly to open_id fails, fall back to thread reply
      try {
        await client.im.message.reply(
          {
            path: { message_id },
            data: { msg_type: 'text', content: JSON.stringify({ text: replyText }) },
          },
          ...tenantOpt()
        );
      } catch {}
    }
  } else {
    // Fallback: reply in-place (group or missing open_id)
    try {
      await client.im.message.reply(
        {
          path: { message_id },
          data: { msg_type: 'text', content: JSON.stringify({ text: replyText }) },
        },
        ...tenantOpt()
      );
    } catch {}
  }
}

// Always ACK quickly
return res.status(200).json({ ok: true });