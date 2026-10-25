import { otaPublicKey, signedRelease } from './signing.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { MongoClient, Binary } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { resolve } from 'node:path';
import { createApp } from '../src/app.js';
import targets from '../shared/firmware/targets.json' with { type: 'json' };

process.env.MONGOMS_DOWNLOAD_DIR = resolve('.sdk/mongodb');
test('MongoDB firmware storage and publication across the chip matrix', async () => {
  const mongo = await MongoMemoryServer.create();
  const client = await new MongoClient(mongo.getUri()).connect();
  const db = client.db('firmware-tests');
  const token = 'test-firmware-publish-token-at-least-32';
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/octet-stream' };
  const app = await createApp(db, { otaPublicKey, publishToken: token });
  try {
    const sample = Buffer.alloc(100000, 42);
    const digest = createHash('sha256').update(sample).digest('hex');
    const path = `/firmware/${digest}`;
    assert.equal((await app.inject({ method: 'PUT', url: path, headers: { 'content-type': 'application/octet-stream' }, payload: sample })).statusCode, 401);
    assert.equal((await app.inject({ method: 'PUT', url: path, headers: { ...headers, authorization: 'Bearer wrong' }, payload: sample })).statusCode, 401);
    assert.equal(await db.collection('FirmwareBlob').countDocuments(), 0);
    assert.equal((await app.inject(path)).statusCode, 404);
    assert.equal((await app.inject({ method: 'PUT', url: path, headers, payload: Buffer.from('wrong') })).statusCode, 400);
    assert.equal((await app.inject({ method: 'PUT', url: path, headers, payload: Buffer.alloc(8 * 1024 * 1024 + 1) })).statusCode, 413);
    assert.equal((await app.inject({ method: 'PUT', url: path, headers, payload: sample })).statusCode, 201);
    assert.equal((await app.inject({ method: 'PUT', url: path, headers, payload: sample })).statusCode, 200);
    assert.equal((await app.inject({ method: 'PUT', url: path, headers, payload: Buffer.from('replacement') })).statusCode, 400);
    assert.equal(await db.collection('FirmwareBlob').countDocuments(), 1);
    const stored = await db.collection('FirmwareBlob').findOne({});
    assert.ok(stored!.data instanceof Binary);
    const downloaded = await app.inject({ url: path, headers: { origin: 'https://setup.luxio.lighting' } });
    assert.deepEqual(downloaded.rawPayload, sample);
    assert.equal(downloaded.headers['content-length'], String(sample.length));
    assert.equal(downloaded.headers['content-type'], 'application/octet-stream');
    assert.equal(downloaded.headers.etag, `"${digest}"`);
    assert.equal(downloaded.headers['access-control-allow-origin'], '*');
    assert.match(String(downloaded.headers['cache-control']), /immutable/);
    assert.equal((await app.inject('/firmware/not-a-hash')).statusCode, 400);

    for (const hardware of targets) {
      const parts = [];
      for (const address of [hardware.bootloaderAddress, 0x8000, 0xe000, 0x10000, hardware.applicationAddress]) {
        const bytes = Buffer.alloc(address === hardware.applicationAddress ? 100000 : 32);
        if ([hardware.bootloaderAddress, 0x10000, hardware.applicationAddress].includes(address)) {
          bytes[0] = 0xe9; bytes.writeUInt16LE(hardware.imageChipId, 12);
        }
        const sha256 = createHash('sha256').update(bytes).digest('hex');
        const upload = await app.inject({ method: 'PUT', url: `/firmware/${sha256}`, headers, payload: bytes });
        assert.ok([200, 201].includes(upload.statusCode), upload.body);
        parts.push({ address, sha256, size: bytes.length, url: upload.json().url });
      }
      const manifest = { chip: hardware.chip, target: hardware.target, build: 24, channel: 0,
        minimumFlashSize: hardware.minimumFlashSize, size: parts[4].size, sha256: parts[4].sha256, url: parts[4].url, parts };
      for (const invalid of [
        { ...manifest, parts: [{ ...parts[0], sha256: 'f'.repeat(64), url: `https://api.luxio.lighting/firmware/${'f'.repeat(64)}` }, ...parts.slice(1)] },
        { ...manifest, parts: [{ ...parts[0], url: `https://api.luxio.lighting/firmware/${digest}` }, ...parts.slice(1)] },
        { ...manifest, parts: [{ ...parts[0], size: 33 }, ...parts.slice(1)] },
        { ...manifest, parts: [{ ...parts[0], sha256: parts[1].sha256, url: parts[1].url }, ...parts.slice(1)] },
      ]) {
        const result = await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: signedRelease(invalid) });
        assert.equal(result.statusCode, 400, result.body);
      }
      const signed = signedRelease(manifest);
      for (const changed of [
        manifest, { ...signed, signatureVersion: 2 }, { ...signed, keyId: 'unknown' },
        { ...signed, signature: 'A'.repeat(96) }, { ...signed, channel: 100 },
        { ...signed, build: 25 }, { ...signed, size: manifest.size + 1 },
        { ...signed, sha256: '0'.repeat(64) },
      ]) {
        const rejected = await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: changed });
        assert.equal(rejected.statusCode, 400, rejected.body);
      }
      const published = await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: signedRelease(manifest) });
      assert.equal(published.statusCode, 201, published.body);
      assert.equal((await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: signedRelease(manifest) })).statusCode, 200);
      assert.equal((await app.inject({ method: 'POST', url: '/updates', headers: { authorization: `Bearer ${token}` }, payload: signedRelease({ ...manifest, channel: 100 }) })).statusCode, 409);
      const selected = (await app.inject(`/updates?chip=${hardware.chip}&target=${hardware.target}&build=0&channel=0`)).json();
      assert.equal(selected.build, 24);
      assert.equal(selected.chip, hardware.chip);
      assert.equal(selected.data, undefined);
      for (const part of selected.parts) {
        const download = await app.inject(new URL(part.url).pathname);
        assert.equal(download.statusCode, 200);
        assert.equal(createHash('sha256').update(download.rawPayload).digest('hex'), part.sha256);
      }
    }
  } finally { await app.close(); await client.close(); await mongo.stop(); }
});
