import * as Lark from '@larksuiteoapi/node-sdk';
import pinyin from 'pinyin';
import dotenv from 'dotenv';

dotenv.config();

var crypto = require('crypto');
function calculateSignature(timestamp, nonce, encryptKey, body) {
        const content = timestamp + nonce + encryptKey + body
        const sign = crypto.createHash('sha256').update(content).digest('hex');
        return sign
}

const client = new Lark.Client({
  appId: process.env.APP_ID,
  appSecret: process.env.APP_SECRET,
  appType: 'custom',
  domain: process.env.BASE_DOMAIN || 'https://open.larksuite.com',
  verificationToken: process.env.VERIFICATION_TOKEN,
  encryptKey: process.env.ENCRYPT_KEY,
});

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // verify signature headers (support both header name variants)
const timestamp = req.headers['x-lark-request-timestamp'] || req.headers['x-lark-timestamp'];
const nonce = req.headers['x-lark-request-nonce'] || req.headers['x-lark-nonce'];
const signature = req.headers['x-lark-signature'] || req.headers['x-lark-sign'];

// get raw body string (use req.rawBody if available, otherwise stringify)
const rawBodyStr = typeof req.rawBody === 'string' ? req.rawBody : JSON.stringify(req.body);

// verify incoming signature
const calc = calculateSignature(timestamp || '', nonce || '', process.env.ENCRYPT_KEY || '', rawBodyStr || '');
if (signature && signature !== calc) {
  console.error('Invalid signature', { signature, calc });
  return res.status(401).json({ error: 'Invalid signature' });
}

let body = req.body;

// handle encrypted payloads: decrypt then replace body
if (body.encrypt) {
  try {
    // try SDK decrypt first (if available)
    if (Lark.Util && typeof Lark.Util.decrypt === 'function') {
      const decrypted = Lark.Util.decrypt(body.encrypt, process.env.ENCRYPT_KEY);
      body = JSON.parse(decrypted);
    } else {
      // fallback manual AES-256-CBC decryption (ENCRYPT_KEY is base64)
      const crypto = require('crypto');
      const key = Buffer.from(process.env.ENCRYPT_KEY, 'base64');
      const encrypted = Buffer.from(body.encrypt, 'base64');
      const iv = encrypted.slice(0, 16);
      const data = encrypted.slice(16);
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(data, undefined, 'utf8');
      decrypted += decipher.final('utf8');
      body = JSON.parse(decrypted);
    }
    console.log('Decrypted body:', body);
  } catch (err) {
    console.error('Decryption error:', err);
    return res.status(400).json({ error: 'Decryption failed' });
  }
}

// URL verification: return only the challenge JSON immediately
if (body.type === 'url_verification') {
  console.log('url_verification, returning challenge');
  return res.status(200).json({ challenge: body.challenge });
}

  // Handle messages
  if (body.event?.type === 'im.message.receive_v1') {
    const { message: { content, message_type, chat_id, chat_type } } = body.event;
    
    let messageText = '';
    try {
      if (message_type === 'text') {
        messageText = JSON.parse(content).text;
        // Convert Chinese text to pinyin
        const pinyinResult = pinyin(messageText, {
          style: pinyin.STYLE_NORMAL
        }).flat().join(' ');

        if (chat_type === 'p2p') {
          await client.im.message.create({
            params: {
              receive_id_type: 'chat_id',
            },
            data: {
              receive_id: chat_id,
              content: JSON.stringify({ text: pinyinResult }),
              msg_type: 'text'
            }
          });
        } else {
          await client.im.message.reply({
            path: {
              message_id: body.event.message.message_id,
            },
            data: {
              content: JSON.stringify({ text: pinyinResult }),
              msg_type: 'text'
            }
          });
        }
      }
    } catch (error) {
      console.error('Error processing message:', error);
      return res.status(500).json({ error: 'Failed to process message' });
    }
  }

  return res.status(200).json({ ok: true });
}