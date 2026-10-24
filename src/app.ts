import Fastify from 'fastify';
import cors from '@fastify/cors';
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { isIP } from 'node:net';
import { isDeepStrictEqual } from 'node:util';
import { Binary, type Db } from 'mongodb';
import { z } from 'zod';
import firmwareTargets from '../shared/firmware/targets.json' with { type: 'json' };

const chipSchema = z.enum(firmwareTargets.map(target => target.chip));
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
  sha256: z.string().regex(/^[a-f0-9]{64}$/), size: z.number().int().min(288).max(8 * 1024 * 1024),
  minimumFlashSize: z.number().int().positive().optional(),
  // USB installation includes the bootloader, partition table, boot selection, recovery loader and application.
  parts: z.array(z.object({ address: z.number().int().min(0).max(16 * 1024 * 1024),
    url: z.url().refine(url => url.startsWith('https://')), sha256: z.string().regex(/^[a-f0-9]{64}$/), size: z.number().int().positive().optional() })).length(5),
}).strict().superRefine((update, context) => {
  if (update.target !== `${update.chip}-recovery-v1`) context.addIssue({ code: 'custom', path: ['target'], message: 'Recovery target must match the chip' });
  const target = firmwareTargets.find(target => target.chip === update.chip)!;
  if (update.size > target.applicationSize || (update.minimumFlashSize !== undefined && update.minimumFlashSize !== target.minimumFlashSize)) context.addIssue({ code: 'custom', path: ['size'], message: 'Firmware size or flash requirement does not match the target' });
  const limits = new Map([[target.bootloaderAddress, 0x8000 - target.bootloaderAddress], [0x8000, 0x1000], [0xe000, 0x2000], [0x10000, target.recoverySize], [target.applicationAddress, target.applicationSize]]);
  if (new Set(update.parts.map(part => part.address)).size !== limits.size || update.parts.some(part => !limits.has(part.address) || (part.size !== undefined && part.size > limits.get(part.address)!)))
    context.addIssue({ code: 'custom', path: ['parts'], message: 'Flash parts must match the chip and recovery layout' });
  const app = update.parts.find(part => part.address === target.applicationAddress);
  if (!app || app.sha256 !== update.sha256 || (app.size !== undefined && app.size !== update.size))
    context.addIssue({ code: 'custom', path: ['parts'], message: 'USB and OTA application must match' });
});

export async function createApp(db: Db, options: { publishToken: string; publicUrl?: string; trustProxy?: string[]; now?: () => Date; logger?: boolean }) {
  if (options.publishToken.length < 32) throw new Error('UPDATE_PUBLISH_TOKEN must contain at least 32 characters');
  const app = Fastify({ logger: options.logger ?? false, bodyLimit: 64 * 1024, trustProxy: options.trustProxy ?? false });
  await app.register(cors, { origin: '*' });
  const devices = db.collection('Device');
  const challenges = db.collection('Challenge');
  const updates = db.collection('Update');
  const blobs = db.collection<{ _id: string; data: Binary; size: number; createdAt: Date }>('FirmwareBlob');
  const publicUrl = (options.publicUrl ?? 'https://api.luxio.lighting').replace(/\/$/, '');
  app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer' }, (_request, body, done) => done(null, body));
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
  app.put('/firmware/:sha256', {
    bodyLimit: 8 * 1024 * 1024,
    onRequest: async (request, reply) => {
      const actual = createHash('sha256').update(request.headers.authorization ?? '').digest();
      const expected = createHash('sha256').update(`Bearer ${options.publishToken}`).digest();
      if (!timingSafeEqual(actual, expected)) return reply.code(401).send({ error: 'Invalid publication token' });
    },
  }, async (request, reply) => {
    const { sha256 } = z.object({ sha256: z.string().regex(/^[a-f0-9]{64}$/) }).parse(request.params);
    if (!Buffer.isBuffer(request.body) || !request.body.length) return reply.code(400).send({ error: 'A nonempty binary firmware artifact is required' });
    if (createHash('sha256').update(request.body).digest('hex') !== sha256) return reply.code(400).send({ error: 'Firmware checksum mismatch' });
    // One bounded BSON binary per artifact; immutable hashes also deduplicate retries and shared parts.
    const result = await blobs.updateOne({ _id: sha256 }, { $setOnInsert: { data: new Binary(request.body), size: request.body.length, createdAt: now() } }, { upsert: true });
    return reply.code(result.upsertedCount ? 201 : 200).send({ sha256, size: request.body.length, url: `${publicUrl}/firmware/${sha256}` });
  });
  app.get('/firmware/:sha256', async (request, reply) => {
    const { sha256 } = z.object({ sha256: z.string().regex(/^[a-f0-9]{64}$/) }).parse(request.params);
    const blob = await blobs.findOne({ _id: sha256 });
    if (!blob) return reply.code(404).send({ error: 'Firmware artifact not found' });
    reply.header('Cache-Control', 'public, max-age=31536000, immutable');
    reply.header('ETag', `"${sha256}"`);
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Content-Length', blob.size);
    return reply.type('application/octet-stream').send(Buffer.from(blob.data.value()));
  });
  app.post('/updates', async (request, reply) => {
    const actual = createHash('sha256').update(request.headers.authorization ?? '').digest();
    const expected = createHash('sha256').update(`Bearer ${options.publishToken}`).digest();
    if (!timingSafeEqual(actual, expected)) return reply.code(401).send({ error: 'Invalid publication token' });
    const update = updateSchema.parse(request.body);
    update.minimumFlashSize ??= firmwareTargets.find(target => target.chip === update.chip)!.minimumFlashSize;
    const hardware = firmwareTargets.find(target => target.chip === update.chip)!;
    for (const part of [...update.parts, { address: hardware.applicationAddress, url: update.url, sha256: update.sha256, size: update.size }]) {
      if (!part.url.startsWith(`${publicUrl}/firmware/`)) continue;
      if (part.url !== `${publicUrl}/firmware/${part.sha256}`) return reply.code(400).send({ error: 'Firmware URL must match its checksum' });
      const blob = await blobs.findOne({ _id: part.sha256 });
      if (!blob) return reply.code(400).send({ error: 'Upload all firmware artifacts before registering an update' });
      const limits = new Map([[hardware.bootloaderAddress, 0x8000 - hardware.bootloaderAddress], [0x8000, 0x1000], [0xe000, 0x2000], [0x10000, hardware.recoverySize], [hardware.applicationAddress, hardware.applicationSize]]);
      if (blob.size > limits.get(part.address)! || (part.size !== undefined && blob.size !== part.size)) return reply.code(400).send({ error: 'Stored firmware size does not match the manifest or partition' });
      if ([hardware.bootloaderAddress, 0x10000, hardware.applicationAddress].includes(part.address)) {
        const image = Buffer.from(blob.data.value());
        if (image.length < 24 || image[0] !== 0xe9 || image.readUInt16LE(12) !== hardware.imageChipId) return reply.code(400).send({ error: 'Stored firmware image is for a different chip' });
      }
    }
    const existing = await updates.findOne({ chip: update.chip, target: update.target, build: update.build }, { projection: { _id: 0, createdAt: 0 } });
    if (existing) {
      if (isDeepStrictEqual(existing, update)) return reply.send(update);
      return reply.code(409).send({ error: 'A different release already uses this chip, target and build' });
    }
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
