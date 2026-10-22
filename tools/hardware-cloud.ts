// Local-only integration harness: real API/MongoDB behind HTTPS, one simulated WAN.
// Never deploy this tool. The fixed source IP intentionally models a home router.
import { createServer } from 'node:https';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { resolve } from 'node:path';
import { createApp } from '../src/app.js';
process.env.MONGOMS_DOWNLOAD_DIR = resolve('.sdk/mongodb');
await mkdir('.sdk/hardware-mongo', { recursive: true });
const mongo = await MongoMemoryServer.create({ instance: { dbPath: resolve('.sdk/hardware-mongo') } });
const client = await new MongoClient(mongo.getUri()).connect();
const db = client.db('luxio-hardware-test'); await db.dropDatabase();
const token = randomBytes(32).toString('hex');
const app = await createApp(db, { publishToken: token });
let registeredBuild = 0;
const server = createServer({ key: await readFile('.sdk/local-test.key'), cert: await readFile('.sdk/local-test.crt') }, async (request, response) => {
  try {
    if (request.url === '/firmware.bin') {
      const manifest = JSON.parse(await readFile('.sdk/ota-manifest.json', 'utf8'));
      response.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': manifest.size });
      createReadStream('.sdk/ota-update.bin').pipe(response); return;
    }
    if (request.url?.startsWith('/updates?')) {
      try {
        const manifest = JSON.parse(await readFile('.sdk/ota-manifest.json', 'utf8'));
        if (manifest.build !== registeredBuild) {
          const registration = await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: manifest });
          if (registration.statusCode !== 201) throw new Error(registration.body);
          registeredBuild = manifest.build;
        }
      } catch (error: any) { if (error.code !== 'ENOENT') throw error; }
    }
    const chunks: Buffer[] = []; let size = 0;
    for await (const chunk of request) { size += chunk.length; if (size > 65536) throw new Error('Request too large'); chunks.push(chunk); }
    const result = await app.inject({ method: request.method as any, url: request.url!, headers: { 'content-type': request.headers['content-type'] ?? '' },
      payload: Buffer.concat(chunks), remoteAddress: '203.0.113.42' });
    response.writeHead(result.statusCode, result.headers); response.end(result.rawPayload);
    console.log(request.method, request.url, result.statusCode);
    if (request.url === '/announcements' && result.statusCode === 204) {
      const record = await db.collection('Device').findOne({});
      await writeFile('.sdk/hardware-announcement.json', JSON.stringify(record, null, 2));
      console.log('PASS: physical ECDSA announcement accepted; fingerprint', record?.deviceId);
    }
  } catch (error) { console.error(error); if (!response.headersSent) response.writeHead(500); response.end(); }
});
server.listen(3443, '0.0.0.0', () => console.log('Hardware test HTTPS server listening on :3443'));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { server.close(); await app.close(); await client.close(); await mongo.stop(); process.exit(); });
