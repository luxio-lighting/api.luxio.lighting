import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { createApp } from '../src/app.js';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';

process.env.MONGOMS_DOWNLOAD_DIR = resolve('.sdk/mongodb');
await mkdir('.sdk/mongo-data', { recursive: true });
const mongo = await MongoMemoryServer.create({ instance: { dbPath: resolve('.sdk/mongo-data') } });
const client = await new MongoClient(mongo.getUri()).connect();
const db = client.db('luxio-tests');
await db.dropDatabase();
let current = new Date('2026-10-21T12:00:00Z');
const token = 'test-only-publication-token-32-characters';
const app = await createApp(db, { publishToken: token, now: () => current });
const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const deviceId = createHash('sha256').update(Buffer.from(publicKey, 'base64')).digest('hex');
const wan = '203.0.113.12';
async function announcement(name = 'Desk', lanIp = '192.168.1.42') {
  const challenge = await app.inject({ method: 'POST', url: '/announcements/challenge', remoteAddress: wan, payload: { deviceId } });
  const nonce = challenge.json().nonce;
  const signature = sign('sha256', Buffer.from(JSON.stringify([1, nonce, deviceId, name, lanIp, 12, 0])), keys.privateKey).toString('base64');
  return { deviceId, publicKey, nonce, name, lanIp, build: 12, channel: 0, signature };
}

test('signed discovery: identity, no replay, WAN isolation, freshness refresh and retention', async () => {
  try {
    const body = await announcement();
    assert.equal((await app.inject({ method: 'POST', url: '/announcements', remoteAddress: wan, payload: { ...body, lanIp: '192.168.1.99' } })).statusCode, 401);
    assert.equal((await app.inject({ method: 'POST', url: '/announcements', remoteAddress: wan, payload: body })).statusCode, 204);
    assert.equal((await app.inject({ method: 'POST', url: '/announcements', remoteAddress: wan, payload: body })).statusCode, 401);
    const discover = await app.inject({ method: 'GET', url: '/devices', remoteAddress: wan, headers: { origin: 'https://any-origin.example' } });
    assert.equal(discover.headers['access-control-allow-origin'], '*');
    assert.equal(discover.json().length, 1); assert.equal(discover.json()[0].publicKey, undefined);
    assert.deepEqual((await app.inject({ method: 'GET', url: '/devices', remoteAddress: '198.51.100.1', headers: { 'x-forwarded-for': wan } })).json(), []);
    current = new Date('2026-10-21T12:50:00Z');
    assert.equal((await app.inject({ method: 'POST', url: '/announcements', remoteAddress: wan, payload: await announcement() })).statusCode, 204);
    current = new Date('2026-10-21T13:10:00Z');
    assert.equal((await app.inject({ method: 'GET', url: '/devices', remoteAddress: wan })).json().length, 1);
    current = new Date('2026-10-21T13:50:00Z');
    assert.deepEqual((await app.inject({ method: 'GET', url: '/devices', remoteAddress: wan })).json(), []);
    assert.equal(await db.collection('Device').countDocuments(), 1);
    const record = await db.collection('Device').findOne({ deviceId });
    assert.equal(record!.createdAt.toISOString(), '2026-10-21T12:00:00.000Z');
    const expired = await announcement(); current = new Date(current.getTime() + 121000);
    assert.equal((await app.inject({ method: 'POST', url: '/announcements', remoteAddress: wan, payload: expired })).statusCode, 401);

    const base = { chip: 'esp32s3', url: 'https://firmware.example/app.bin', sha256: 'a'.repeat(64), size: 1000, parts: [{ address: 65536, url: 'https://firmware.example/app.bin', sha256: 'a'.repeat(64) }] };
    assert.equal((await app.inject({ method: 'POST', url: '/updates', payload: { ...base, build: 1 } })).statusCode, 401);
    for (const release of [{ build: 9, channel: 0 }, { build: 123, channel: 0 }, { build: 200, channel: 100 }, { build: 150, channel: 50 }])
      assert.equal((await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: { ...base, ...release } })).statusCode, 201);
    assert.equal((await app.inject('/updates?chip=esp32s3&build=12&channel=0')).json().build, 123);
    assert.equal((await app.inject('/updates?chip=esp32s3&build=12&channel=50')).json().build, 150);
    assert.equal((await app.inject('/updates?chip=esp32s3&build=12&channel=100')).json().build, 200);
    assert.equal((await app.inject('/updates?chip=esp32s3&build=200&channel=100')).json(), null);
    assert.equal((await app.inject('/updates?chip=esp32c3&build=0&channel=100')).json(), null);
    assert.equal((await app.inject('/updates?chip=esp32s3&build=0&channel=101')).statusCode, 400);
    const release = await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: { ...base, build: 201 } });
    assert.equal(release.json().channel, 100);
    const recovery = await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: { ...base, build: 201, channel: 0, target: 'esp32s3-recovery-v1' } });
    assert.equal(recovery.statusCode, 201, 'Same build can exist for different flash layouts');
    assert.equal((await app.inject('/updates?chip=esp32s3&build=0&channel=0')).json().build, 123, 'Legacy devices cannot see recovery firmware');
    assert.equal((await app.inject('/updates?chip=esp32s3&target=esp32s3-recovery-v1&build=0&channel=0')).json().build, 201);
    assert.equal((await app.inject('/updates?chip=esp32s3&target=esp32s3-recovery-v1&build=201&channel=100')).json(), null);
    assert.equal((await app.inject('/updates?chip=esp32s3&target=unknown&build=0&channel=0')).statusCode, 400);
  } finally { await app.close(); await client.close(); await mongo.stop(); }
});
