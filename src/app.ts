import Fastify from 'fastify';
import cors from '@fastify/cors';
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { isIP } from 'node:net';
import type { Db } from 'mongodb';
import { z } from 'zod';

const chipSchema = z.enum(['esp32', 'esp32c2', 'esp32c3', 'esp32c5', 'esp32c6', 'esp32c61', 'esp32s3']);
const announcementSchema = z.object({
  deviceId: z.string().regex(/^[a-f0-9]{64}$/),
  publicKey: z.string().min(100).max(512), nonce: z.string().regex(/^[a-f0-9]{64}$/),
  name: z.string().trim().min(1).max(63), lanIp: z.string().refine(value => isIP(value) !== 0, 'Invalid LAN IP'),
  build: z.number().int().min(0).max(2147483647), channel: z.number().int().min(0).max(100),
  signature: z.string().min(80).max(128),
}).strict();
const targetSchema = z.enum(chipSchema.options.map(chip => `${chip}-recovery-v1`));
const updateSchema = z.object({
  target: targetSchema,
  build: z.number().int().min(1).max(2147483647), channel: z.number().int().min(0).max(100).default(100),
  chip: chipSchema, url: z.url().refine(url => url.startsWith('https://'), 'HTTPS required'),
  sha256: z.string().regex(/^[a-f0-9]{64}$/), size: z.number().int().min(1).max(8 * 1024 * 1024),
  // USB installation includes the bootloader, partition table, boot selection, recovery loader and application.
  parts: z.array(z.object({ address: z.number().int().min(0).max(16 * 1024 * 1024),
    url: z.url().refine(url => url.startsWith('https://')), sha256: z.string().regex(/^[a-f0-9]{64}$/) })).min(1).max(8),
}).strict().refine(update => update.target === `${update.chip}-recovery-v1`, { path: ['target'], message: 'Recovery target must match the chip' });

export async function createApp(db: Db, options: { publishToken: string; trustProxy?: string[]; now?: () => Date; logger?: boolean }) {
  if (options.publishToken.length < 32) throw new Error('UPDATE_PUBLISH_TOKEN must contain at least 32 characters');
  const app = Fastify({ logger: options.logger ?? false, bodyLimit: 64 * 1024, trustProxy: options.trustProxy ?? false });
  await app.register(cors, { origin: '*' });
  const devices = db.collection('Device');
  const challenges = db.collection('Challenge');
  const updates = db.collection('Update');
  await devices.createIndex({ deviceId: 1 }, { unique: true });
  await devices.createIndex({ wan_ip: 1, updatedAt: -1 });
  await challenges.createIndex({ nonce: 1 }, { unique: true });
  await challenges.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await updates.createIndex({ chip: 1, target: 1, build: 1 }, { unique: true });
  const now = options.now ?? (() => new Date());

  app.setErrorHandler((error: Error & { code?: number; statusCode?: number }, _request, reply) => {
    if (error instanceof z.ZodError) return reply.code(400).send({ error: 'Invalid request', issues: error.issues });
    if (error.code === 11000) return reply.code(409).send({ error: 'Record already exists' });
    if (error.statusCode && error.statusCode < 500) return reply.code(error.statusCode).send({ error: error.message });
    app.log.error(error);
    return reply.code(500).send({ error: 'Internal server error' });
  });
  app.get('/health', async () => { await db.command({ ping: 1 }); return { ok: true }; });
  app.post('/announcements/challenge', async (request, reply) => {
    const { deviceId } = z.object({ deviceId: z.string().regex(/^[a-f0-9]{64}$/) }).strict().parse(request.body);
    const timestamp = now();
    // Bound unauthenticated storage per source; expired records never count even before Mongo's TTL sweep.
    const pending = await challenges.countDocuments({ wanIp: request.ip, expiresAt: { $gt: timestamp } });
    if (pending >= 120) return reply.code(429).send({ error: 'Too many outstanding challenges' });
    const nonce = randomBytes(32).toString('hex');
    await challenges.insertOne({ deviceId, nonce, wanIp: request.ip, expiresAt: new Date(timestamp.getTime() + 120_000) });
    return { nonce };
  });
  app.post('/announcements', async (request, reply) => {
    const body = announcementSchema.parse(request.body);
    let key;
    try { key = createPublicKey({ key: Buffer.from(body.publicKey, 'base64'), format: 'der', type: 'spki' }); }
    catch { return reply.code(400).send({ error: 'Invalid public key' }); }
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
      return reply.code(400).send({ error: 'An ECDSA P-256 key is required' });
    const der = key.export({ format: 'der', type: 'spki' });
    const deviceId = createHash('sha256').update(der).digest('hex');
    if (deviceId !== body.deviceId || der.toString('base64') !== body.publicKey)
      return reply.code(401).send({ error: 'Public key fingerprint mismatch' });
    const payload = JSON.stringify([1, body.nonce, body.deviceId, body.name, body.lanIp, body.build, body.channel]);
    if (!verify('sha256', Buffer.from(payload), key, Buffer.from(body.signature, 'base64')))
      return reply.code(401).send({ error: 'Invalid signature' });
    const timestamp = now();
    const challenge = await challenges.findOneAndDelete({ nonce: body.nonce, deviceId, wanIp: request.ip, expiresAt: { $gt: timestamp } });
    if (!challenge) return reply.code(401).send({ error: 'Expired or consumed challenge' });
    await devices.updateOne({ deviceId }, {
      $set: { name: body.name, wan_ip: request.ip.replace(/^::ffff:/, ''), lan_ip: body.lanIp,
        build: body.build, channel: body.channel, publicKey: body.publicKey, updatedAt: timestamp },
      $setOnInsert: { createdAt: timestamp },
    }, { upsert: true });
    return reply.code(204).send();
  });
  app.get('/devices', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    return devices.find({ wan_ip: request.ip.replace(/^::ffff:/, ''), updatedAt: { $gt: new Date(now().getTime() - 3_600_000) } },
      { projection: { _id: 0, deviceId: 1, name: 1, lan_ip: 1, build: 1, channel: 1, updatedAt: 1 } }).toArray();
  });
  app.post('/updates', async (request, reply) => {
    const actual = createHash('sha256').update(request.headers.authorization ?? '').digest();
    const expected = createHash('sha256').update(`Bearer ${options.publishToken}`).digest();
    if (!timingSafeEqual(actual, expected)) return reply.code(401).send({ error: 'Invalid publication token' });
    const update = updateSchema.parse(request.body);
    await updates.insertOne({ ...update, createdAt: now() });
    return reply.code(201).send(update);
  });
  app.get('/updates', async (request, reply) => {
    const query = z.object({ chip: chipSchema, target: targetSchema, build: z.coerce.number().int().min(0).max(2147483647),
      channel: z.coerce.number().int().min(0).max(100) })
      .refine(query => query.target === `${query.chip}-recovery-v1`, { path: ['target'], message: 'Recovery target must match the chip' }).parse(request.query);
    reply.header('Cache-Control', 'no-store');
    return await updates.findOne({ chip: query.chip, target: query.target, build: { $gt: query.build }, channel: { $lte: query.channel } },
      { sort: { build: -1 }, projection: { _id: 0 } });
  });
  return app;
}
