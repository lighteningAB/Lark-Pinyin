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

  if (payload.type === "url_verification") {
    const VERIFY_TOKEN = process.env.LARK_VERIFICATION_TOKEN;

    // Optional security check — verify the request token matches your app’s token
    if (VERIFY_TOKEN && payload.token !== VERIFY_TOKEN) {
      console.warn("Lark verification token mismatch");
      return res.status(401).send("invalid token");
    }

    // Respond with the challenge value exactly as given
    return res.json({ challenge: payload.challenge });
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