import * as Lark from '@larksuiteoapi/node-sdk';
import pinyin from 'pinyin';
import dotenv from 'dotenv';

dotenv.config();

const baseConfig = {
  appId: process.env.APP_ID,
  appSecret: process.env.APP_SECRET,
  domain: process.env.BASE_DOMAIN,
};

const client = new Lark.Client(baseConfig);
const wsClient = new Lark.WSClient(baseConfig);

const eventDispatcher = new Lark.EventDispatcher({}).register({

  'im.message.receive_v1': async (data) => {
    const {
      message: { chat_id, content, message_type, chat_type },
    } = data;
   
    let responseText = '';
    try {
      if (message_type === 'text') {
        responseText = JSON.parse(content).text;
      } else {
        responseText = '解析消息失败，请发送文本消息 \nparse message failed, please send text message';
      }
    } catch (error) {
      // 解析消息失败，返回错误信息。 Parse message failed, return error message.
      responseText = '解析消息失败，请发送文本消息 \nparse message failed, please send text message';
    }
    if (chat_type === 'p2p') {
      await client.im.v1.message.create({
        params: {
          receive_id_type: 'chat_id', // 消息接收者的 ID 类型，设置为会话ID。 ID type of the message receiver, set to chat ID.
        },
        data: {
          receive_id: chat_id, // 消息接收者的 ID 为消息发送的会话ID。 ID of the message receiver is the chat ID of the message sending.
          content: JSON.stringify({ text: `收到你发送的消息:${responseText}\nReceived message: ${responseText}` }),
          msg_type: 'text', // 设置消息类型为文本消息。 Set message type to text message.
        },
      });
    } else {
      
      await client.im.v1.message.reply({
        path: {
          message_id: data.message.message_id, // 要回复的消息 ID。 Message ID to reply.
        },
        data: {
          content: JSON.stringify({ text: `收到你发送的消息:${responseText}\nReceived message: ${responseText}` }),
          msg_type: 'text', // 设置消息类型为文本消息。 Set message type to text message.
        },
      });
    }
  },
});

wsClient.start({ eventDispatcher });