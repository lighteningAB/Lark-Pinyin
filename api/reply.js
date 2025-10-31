import * as Lark from '@larksuiteoapi/node-sdk';
import pinyin from 'pinyin';
import dotenv from 'dotenv';

dotenv.config();

const crypto = require("crypto")
// Minimal AES helper (AES-256-CBC; IV is first 16 bytes; key = SHA-256(encryptKey))
function decryptLark(encryptBase64, encryptKeyString) {
  const key = crypto.createHash("sha256").update(encryptKeyString, "utf8").digest();
  const buf = Buffer.from(encryptBase64, "base64");
  const iv = buf.slice(0, 16);
  const ciphertext = buf.slice(16);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const out = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return out.toString("utf8");
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

  const VERIFY_TOKEN = process.env.ERIFICATION_TOKEN || "";
  const ENCRYPT_KEY = process.env.ENCRYPT_KEY || "";

  // Build payload (decrypt if needed)
  let payload;
  try {
    const body = req.body || {};
    if (body && typeof body.encrypt === "string") {
      if (!ENCRYPT_KEY) {
        console.error("Missing LARK_ENCRYPT_KEY for encrypted payload");
        return res.status(500).send("server misconfigured");
      }
      const plaintext = decryptLark(body.encrypt, ENCRYPT_KEY);
      payload = JSON.parse(plaintext);
    } else {
      // Unencrypted delivery (some setups during testing)
      payload = body;
    }
  } catch (e) {
    console.error("Failed to build Lark payload:", e);
    return res.status(400).send("invalid payload");
  }

  // Fast-path: URL verification
  if (payload && payload.type === "url_verification") {
    if (VERIFY_TOKEN && payload.token !== VERIFY_TOKEN) {
      console.warn("Lark verification token mismatch");
      return res.status(401).send("invalid token");
    }
    // Must echo the challenge exactly
    return res.json({ challenge: payload.challenge });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
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