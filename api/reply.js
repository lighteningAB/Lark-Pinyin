import * as Lark from '@larksuiteoapi/node-sdk';
import pinyin from 'pinyin';
import env from 'dotenv';

appid = process.env.APP_ID;
appsecret = process.env.APP_SECRET;
basedomain = process.env.BASE_DOMAIN;

const client = new Client({
  appId: process.env.APP_ID,
  appSecret: process.env.APP_SECRET,
  appType: 'custom',
  domain: process.env.BASE_DOMAIN || 'https://open.feishu.cn'
});

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const body = req.body;
  
  // Handle URL verification
  if (body.type === 'url_verification') {
    return res.json({ challenge: body.challenge });
  }

  // Handle messages
  if (body.event.type === 'message') {
    const { text } = body.event.message;
    
    // Convert Chinese text to pinyin
    const pinyinResult = pinyin(text, {
      style: pinyin.STYLE_NORMAL
    }).flat().join(' ');

    // Send reply
    await client.im.message.create({
      data: {
        receive_id: body.event.sender.sender_id.user_id,
        msg_type: 'text',
        content: JSON.stringify({ "text": pinyinResult })
      }
    });
  }

  return res.status(200).json({ ok: true });
}