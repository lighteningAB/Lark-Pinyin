// pages/api/reply.js  (CommonJS)
const crypto = require('crypto');
const pinyin = require('pinyin');
const lark = require('@larksuiteoapi/node-sdk');

module.exports.config = { api: { bodyParser: false } };

// ---- Client
const disableTokenCache = process.env.DISABLE_TOKEN_CACHE === '1';
const client = new lark.Client({
  appId: process.env.APP_ID,
  appSecret: process.env.APP_SECRET,
  disableTokenCache,
  domain: process.env.BASE_DOMAIN || undefined, // 'larksuite' | 'feishu'
});
console.info('[boot] client constructed', { domain: process.env.BASE_DOMAIN, disableTokenCache });

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
  } catch {
    return false;
  }
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
  } catch {
    return false;
  }
}

function decryptIfNeeded(rawBodyString) {
  const parsed = JSON.parse(rawBodyString);
  if (!parsed.encrypt) return parsed;

  const key = process.env.ENCRYPT_KEY;
  if (!key) throw new Error('ENCRYPT_KEY missing but payload is encrypted.');

  const hash = crypto.createHash('sha256'); hash.update(key);
  const aesKey = hash.digest();

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
  console.info('[entry]', { method: req.method, url: req.url });

  if (req.method === 'GET') {
    console.info('[healthcheck] ok');
    return res.status(200).json({ ok: true, route: '/api/reply', methods: ['POST'] });
  }
  if (req.method !== 'POST') {
    console.warn('[method] not allowed', req.method);
    return res.status(405).end();
  }

  const rawBody = await readRawBody(req);
  const hSig = req.headers['x-lark-signature'] || req.headers['x-feishu-signature'];
  const hTs  = req.headers['x-lark-request-timestamp'] || req.headers['x-feishu-request-timestamp'];
  const hN   = req.headers['x-lark-request-nonce'] || req.headers['x-feishu-request-nonce'];

  console.info('[incoming]', {
    hasSig: !!hSig, ts: String(hTs || ''), nonceLen: String(hN || '').length,
    rawBodyLength: rawBody.length, hasEncryptField: /"encrypt"\s*:/.test(rawBody)
  });

  // Allow bypass for testing routing (DO NOT use in prod)
  if (process.env.ALLOW_UNVERIFIED === '1') {
    console.warn('[security] ALLOW_UNVERIFIED=1 — skipping signature check for testing');
  } else {
    let verified = false;
    let path = 'none';
    if (process.env.ENCRYPT_KEY) {
      verified = verifyEncryptKeySignature({ timestamp: String(hTs||''), nonce: String(hN||''), signature: String(hSig||''), rawBody, encryptKey: process.env.ENCRYPT_KEY });
      if (verified) path = 'encrypt_key_sha256';
    }
    if (!verified && process.env.APP_SECRET) {
      verified = verifyHmacV2Signature({ timestamp: String(hTs||''), nonce: String(hN||''), signature: String(hSig||''), rawBody, appSecret: process.env.APP_SECRET });
      if (verified) path = 'hmac_v2_app_secret';
    }
    console.info('[verify]', { ok: verified, path });
    if (!verified) return res.status(401).json({ error: 'invalid signature' });
  }

  let body;
  try {
    body = decryptIfNeeded(rawBody);
    console.info('[decrypt] ok', { type: body?.type, topKeys: Object.keys(body || {}) });
  } catch (e) {
    console.error('[decrypt] failed', e?.message || e);
    return res.status(400).json({ error: 'decrypt_failed', detail: e?.message || String(e) });
  }

  if (body.type === 'url_verification') {
    console.info('[url_verification] responding with challenge');
    return res.status(200).json({ challenge: body.challenge });
  }

  if (process.env.VERIFICATION_TOKEN) {
    const tokenInBody = body?.header?.token || body?.token;
    const tokenOk = tokenInBody === process.env.VERIFICATION_TOKEN;
    console.info('[vtok]', { provided: !!tokenInBody, ok: tokenOk });
    if (!tokenOk) return res.status(401).json({ error: 'invalid_verification_token' });
  }

  // --- NEW: detect event type from v2 header
const eventType = body?.header?.event_type || body?.event?.type || body?.type;
console.info('[event] resolved type', { eventType });

// Use the common event payload
const evt = body?.event;

console.info('[header]', body?.header);

if (eventType === 'im.message.receive_v1' && evt) {
  const { message, sender } = evt;
  const { content, message_type, chat_type, message_id, chat_id } = message || {};
  const openId = sender?.sender_id?.open_id;

  // Extract text
  let text = '';
  try { text = message_type === 'text' ? JSON.parse(content).text : ''; } catch {}
  const replyText = toPinyinEcho(text);

  const logSdkError = (label, err) => {
    const payload = err?.response?.data || err;
    console.error(`[send][${label}] failed`, JSON.stringify(payload, null, 2));
  };

  // 1) Reply in-thread
  try {
    const resp = await client.im.message.reply(
      { path: { message_id }, data: { msg_type: 'text', content: JSON.stringify({ text: replyText }) } },
      ...tenantOpt()
    );
    console.info('[send][reply] ok', resp?.data?.data?.message_id || '');
    return res.status(200).json({ ok: true, via: 'reply' });
  } catch (e) {
    logSdkError('reply', e);
  }

  // 2) Send to chat_id
  if (chat_id) {
    try {
      const resp = await client.im.message.create(
        {
          params: { receive_id_type: 'chat_id' },
          data: {
            receive_id: chat_id,
            msg_type: 'text',
            content: JSON.stringify({ text: replyText }),
            uuid: crypto.randomUUID(),
          },
        },
        ...tenantOpt()
      );
      console.info('[send][create:chat_id] ok', resp?.data?.data?.message_id || '');
      return res.status(200).json({ ok: true, via: 'create:chat_id' });
    } catch (e) {
      logSdkError('create:chat_id', e);
    }
  }

  // 3) Send to open_id
  if (openId) {
    try {
      const resp = await client.im.message.create(
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
      console.info('[send][create:open_id] ok', resp?.data?.data?.message_id || '');
      return res.status(200).json({ ok: true, via: 'create:open_id' });
    } catch (e) {
      logSdkError('create:open_id', e);
    }
  }

  console.error('[send] all paths failed');
  return res.status(200).json({ ok: false, error: 'all_send_paths_failed' });
}

console.info('[event] not a message event, ack only', { eventType });
return res.status(200).json({ ok: true, info: 'non-message event' })};