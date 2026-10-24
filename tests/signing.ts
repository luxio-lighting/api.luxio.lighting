import { generateKeyPairSync, sign } from 'node:crypto';
const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
export const otaPublicKey = { keyId: 'test-release', pem: keys.publicKey.export({ format: 'pem', type: 'spki' }).toString() };
export function signedRelease<T extends { chip?: unknown; target?: unknown; build?: unknown; channel?: unknown; size?: unknown; sha256?: unknown }>(release: T) {
  const channel = release.channel ?? 100;
  const canonical = `luxio-ota-v1\n${otaPublicKey.keyId}\n${release.chip}\n${release.target}\n${release.build}\n${channel}\n${release.size}\n${release.sha256}\n`;
  return { ...release, channel, signatureVersion: 1, keyId: otaPublicKey.keyId, signature: sign('sha256', Buffer.from(canonical), keys.privateKey).toString('base64') };
}
