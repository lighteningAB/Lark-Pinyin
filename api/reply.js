import * as Lark from '@larksuiteoapi/node-sdk';
import pinyin from 'pinyin';
import dotenv from 'dotenv';

dotenv.config();

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

  const body = req.body;
  
  // Handle URL verification
   if (body.type === 'url_verification') {
    console.log('Handling URL verification:', body);
    if (body.token !== process.env.VERIFICATION_TOKEN) {
      return res.status(401).json({ error: 'Invalid verification token' });
    }
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