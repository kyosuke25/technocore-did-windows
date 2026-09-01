import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import test from 'node:test';
import {
  base58Encode,
  didNotePath,
  nextNonce,
  publicKeyToDid,
  sweepSingleLine,
  validateMessage,
  validateRoom,
} from '../src/lib.mjs';

test('base58Encode preserves leading zero bytes', () => {
  assert.equal(base58Encode(Uint8Array.from([0])), '1');
  assert.equal(base58Encode(Uint8Array.from([0, 0, 1])), '112');
});

test('publicKeyToDid creates an Ed25519 did:key', () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  assert.match(publicKeyToDid(publicKey), /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
});

test('Technocore payload signs and verifies exactly', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const payload = Buffer.from('lobby|123|hello', 'utf8');
  const signature = sign(null, payload, privateKey);
  assert.equal(signature.toString('base64url').length, 86);
  assert.equal(verify(null, payload, publicKey, signature), true);
  assert.equal(verify(null, Buffer.from('lobby|124|hello'), publicKey, signature), false);
});

test('sweepSingleLine matches the current Technocore category sweep and trimming', () => {
  assert.equal(
    sweepSingleLine(' \u0000hello\nworld\u200b\ud800\ue000\u2028\u2029!\u00a0'),
    'hello world     !',
  );
});

test('validation rejects invalid rooms and messages', () => {
  assert.throws(() => validateRoom('Bad Room'));
  assert.throws(() => validateMessage('   '));
  assert.doesNotThrow(() => validateRoom('signing-messages'));
  assert.doesNotThrow(() => validateMessage('hello'));
});

test('nextNonce is monotonic when the clock moves backwards', () => {
  assert.equal(nextNonce(['100', '105'], 99), '106');
  assert.equal(nextNonce(['100'], 200), '200');
});

test('didNotePath is stable and sharded', () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const did = publicKeyToDid(publicKey);
  const fingerprint = createHash('sha256').update(did).digest('hex').slice(0, 16);
  assert.deepEqual(didNotePath(did), {
    namespace: `did-${fingerprint.slice(0, 2)}`,
    key: fingerprint.slice(2),
  });
});
