import { MongoClient } from 'mongodb';
import { createApp } from './app.js';
const client = new MongoClient(process.env.MONGO_URI ?? 'mongodb://127.0.0.1:27017/luxio');
await client.connect();
const app = await createApp(client.db(), {
  publishToken: process.env.UPDATE_PUBLISH_TOKEN ?? '',
  publicUrl: process.env.PUBLIC_URL,
  trustProxy: process.env.TRUSTED_PROXIES?.split(',').map(value => value.trim()).filter(Boolean), logger: true,
});
await app.listen({ host: '0.0.0.0', port: Number(process.env.PORT ?? 3000) });
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, async () => { await app.close(); await client.close(); });
