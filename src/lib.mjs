import { createHash } from 'node:crypto';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new Error('base58Encode requires a non-empty Uint8Array.');
  }

  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);

  let output = '';
  while (value > 0n) {
    output = BASE58_ALPHABET[Number(value % 58n)] + output;
    value /= 58n;
  }

  for (const byte of bytes) {
    if (byte !== 0) break;
    output = `1${output}`;
  }

  return output;
}

export function publicKeyToDid(publicKey) {
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const rawPublicKey = spki.subarray(-32);
  if (rawPublicKey.length !== 32) {
    throw new Error('Unexpected Ed25519 public key length.');
  }

  const multicodecKey = Buffer.concat([Buffer.from([0xed, 0x01]), rawPublicKey]);
  return `did:key:z${base58Encode(multicodecKey)}`;
}

export function sweepSingleLine(text) {
  if (typeof text !== 'string') throw new Error('Message text must be a string.');
  return text.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu, ' ').trim();
}

export function validateRoom(room) {
  if (!/^[a-z0-9][a-z0-9_-]{0,47}$/.test(room)) {
    throw new Error('Room must match ^[a-z0-9][a-z0-9_-]{0,47}$.');
  }
}

export function validateMessage(text) {
  if (!text.trim()) throw new Error('Message is empty after normalization.');
  if ([...text].length > 4096) throw new Error('Message exceeds 4096 characters.');
}

export function nextNonce(previousNonces, now = Date.now()) {
  const previous = previousNonces.map((nonce) => BigInt(nonce));
  const highest = previous.length > 0
    ? previous.reduce((current, candidate) => candidate > current ? candidate : current)
    : 0n;
  const clock = BigInt(now);
  return (clock > highest ? clock : highest + 1n).toString();
}

export function didNotePath(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z6Mk')) {
    throw new Error('Expected an Ed25519 did:key identifier.');
  }
  const fingerprint = createHash('sha256').update(did).digest('hex').slice(0, 16);
  return {
    namespace: `did-${fingerprint.slice(0, 2)}`,
    key: fingerprint.slice(2),
  };
}
