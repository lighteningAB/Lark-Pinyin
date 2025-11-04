const crypto = require('crypto');
const pinyin = require('pinyin');
const lark = require('@larksuiteoapi/node-sdk');

// Next API: keep raw body for signature verification
module.exports.config = { api: { bodyParser: false } };

// ---- Client (manual token optional via TENANT_ACCESS_TOKEN)
const disableTokenCache = process.env.DISABLE_TOKEN_CACHE === '1';
const client = new lark.Client({
  appId: process.env.APP_ID,
  appSecret: process.env.APP_SECRET,
  disableTokenCache,
  domain: process.env.BASE_DOMAIN || undefined, // 'larksuite' | 'feishu'
});

function tenantOpt() {
  if (disableTokenCache && process.env.TENANT_ACCESS_TOKEN) {
    return [lark.withTenantToken(process.env.TENANT_ACCESS_TOKEN)];
  }
  return [];
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function verifyEncryptKeySignature({ timestamp, nonce, signature, rawBody, encryptKey }) {
  if (!timestamp || !nonce || !signature || !encryptKey) return false;
  let provided = String(signature).trim();
  const eq = provided.indexOf('=');
  if (eq > 0) provided = provided.slice(eq + 1).trim();

  const headBytes = Buffer.from(`${timestamp}${nonce}${encryptKey}`, 'utf8');
  const bodyBytes = Buffer.from(rawBody, 'utf8');
  const digestHex = crypto.createHash('sha256').update(Buffer.concat([headBytes, bodyBytes])).digest('hex');

  if (/^[0-9a-f]{64}$/i.test(provided)) {
    const a = Buffer.from(digestHex, 'utf8');
    const b = Buffer.from(provided.toLowerCase(), 'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  try {
    const digestB64 = Buffer.from(digestHex, 'hex').toString('base64');
    const a = Buffer.from(digestB64, 'base64');
    const b = Buffer.from(provided, 'base64');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

function verifyHmacV2Signature({ timestamp, nonce, signature, rawBody, appSecret }) {
  if (!timestamp || !nonce || !signature || !appSecret) return false;
  let provided = String(signature).trim();
  const eq = provided.indexOf('=');
  if (eq > 0) provided = provided.slice(eq + 1).trim();

  let encryptField;
  try { const maybe = JSON.parse(rawBody); if (maybe && typeof maybe.encrypt === 'string') encryptField = maybe.encrypt; } catch {}

  const make = (s) => crypto.createHmac('sha256', appSecret).update(s).digest();
  const candidates = [];
  if (encryptField) candidates.push(make(`${timestamp}${nonce}${encryptField}`));
  candidates.push(make(`${timestamp}${nonce}${rawBody}`));

  if (/^[0-9a-f]{64}$/i.test(provided)) {
    const tgt = Buffer.from(provided.toLowerCase(), 'utf8');
    return candidates.some((c) => {
      const hex = Buffer.from(c.toString('hex'), 'utf8');
      return hex.length === tgt.length && crypto.timingSafeEqual(hex, tgt);
    });
  }
  try {
    const sig = Buffer.from(provided, 'base64');
    return candidates.some((c) => sig.length === c.length && crypto.timingSafeEqual(sig, c));
  } catch { return false; }
}

// Decrypt like your AESCipher example
function decryptIfNeeded(rawBodyString) {
  const parsed = JSON.parse(rawBodyString);
  if (!parsed.encrypt) return parsed;

  const key = process.env.ENCRYPT_KEY;
  if (!key) throw new Error('ENCRYPT_KEY missing but payload is encrypted.');

  const hash = crypto.createHash('sha256'); hash.update(key);
  const aesKey = hash.digest(); // 32B

  const buf = Buffer.from(parsed.encrypt, 'base64');
  if (buf.length < 17) throw new Error('Invalid encrypt payload');

  const iv = buf.slice(0, 16);
  const cipherHex = buf.slice(16).toString('hex');

  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  let decrypted = decipher.update(cipherHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return JSON.parse(decrypted);
}

function toPinyinEcho(text) {
  let py = '';
  try {
    if (text && text.trim()) {
      py = pinyin(text, { style: pinyin.STYLE_TONE2 }).flat().join(' ');
    }
  } catch {}
  return `Echo: ${text || ''}\nPinyin: ${py || '(n/a)'}`;
}

module.exports = async function handler(req, res) {
  if (req.method === 'GET') {
    return res.status(200).json({ ok: true, route: '/api/reply', methods: ['POST'] });
  }
  if (req.method !== 'POST') return res.status(405).end();

  const rawBody = await readRawBody(req);

  const hSig = req.headers['x-lark-signature'] || req.headers['x-feishu-signature'];
  const hTs  = req.headers['x-lark-request-timestamp'] || req.headers['x-feishu-request-timestamp'];
  const hN   = req.headers['x-lark-request-nonce'] || req.headers['x-feishu-request-nonce'];

  let verified = false;
  if (process.env.ENCRYPT_KEY) {
    verified = verifyEncryptKeySignature({ timestamp: String(hTs||''), nonce: String(hN||''), signature: String(hSig||''), rawBody, encryptKey: process.env.ENCRYPT_KEY });
  }
  if (!verified && process.env.APP_SECRET) {
    verified = verifyHmacV2Signature({ timestamp: String(hTs||''), nonce: String(hN||''), signature: String(hSig||''), rawBody, appSecret: process.env.APP_SECRET });
  }
  if (!verified) return res.status(401).json({ error: 'invalid signature' });

  let body;
  try { body = decryptIfNeeded(rawBody); }
  catch (e) { return res.status(400).json({ error: 'decrypt_failed', detail: e?.message || String(e) }); }

  if (body.type === 'url_verification') {
    return res.status(200).json({ challenge: body.challenge });
  }

  if (process.env.VERIFICATION_TOKEN) {
    const tokenInBody = body?.header?.token || body?.token;
    if (tokenInBody !== process.env.VERIFICATION_TOKEN) {
      return res.status(401).json({ error: 'invalid_verification_token' });
    }
  }

  const event = body?.event;
  if (event?.type === 'im.message.receive_v1') {
    const { message, sender } = event;
    const { content, message_type, message_id } = message || {};
    const openId = sender?.sender_id?.open_id;

    let text = '';
    try { text = message_type === 'text' ? JSON.parse(content).text : ''; } catch { text = ''; }

    const replyText = toPinyinEcho(text);

    // Preferred: send like your sample (create to open_id)
    if (openId) {
      try {
        await client.im.message.create(
          {
            params: { receive_id_type: 'open_id' },
            data: {
              receive_id: openId,
              msg_type: 'text',
              content: JSON.stringify({ text: replyText }),
              uuid: crypto.randomUUID(),
            },
          },
          ...tenantOpt()
        );
      } catch (e) {
        // Fallback: reply in the thread
        try {
          await client.im.message.reply(
            { path: { message_id }, data: { msg_type: 'text', content: JSON.stringify({ text: replyText }) } },
            ...tenantOpt()
          );
        } catch {}
      }
    } else {
      try {
        await client.im.message.reply(
          { path: { message_id }, data: { msg_type: 'text', content: JSON.stringify({ text: replyText }) } },
          ...tenantOpt()
        );
      } catch {}
    }
  }

  return res.status(200).json({ ok: true });
};
