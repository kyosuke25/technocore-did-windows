import {
  createPrivateKey,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  didNotePath,
  nextNonce,
  publicKeyToDid,
  sweepSingleLine,
  validateMessage,
  validateRoom,
} from './lib.mjs';

const sourceDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = join(sourceDirectory, '..');
const dataDirectory = join(repositoryDirectory, '.technocore');
const scriptsDirectory = join(repositoryDirectory, 'scripts');
const identityPath = join(dataDirectory, 'identity.json');
const secretPath = join(dataDirectory, 'identity.dpapi');
const activityPath = join(dataDirectory, 'activity.json');
const origin = 'https://technocore.chat';

function runDpapi(scriptName, inputBase64) {
  return execFileSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      join(scriptsDirectory, scriptName),
    ],
    { input: inputBase64, encoding: 'utf8', windowsHide: true },
  ).trim();
}

function loadIdentity() {
  if (!existsSync(identityPath) || !existsSync(secretPath)) {
    throw new Error('Identity is not initialized. Run: node src/cli.mjs init');
  }

  const identity = JSON.parse(readFileSync(identityPath, 'utf8'));
  if (typeof identity.did !== 'string' || !identity.did.startsWith('did:key:z6Mk')) {
    throw new Error('identity.json contains an invalid Ed25519 DID.');
  }
  return identity;
}

function loadPrivateKey() {
  const protectedBase64 = readFileSync(secretPath, 'utf8').trim();
  const pkcs8Base64 = runDpapi('dpapi-unprotect.ps1', protectedBase64);
  return createPrivateKey({
    key: Buffer.from(pkcs8Base64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
}

function loadActivity(identity) {
  if (!existsSync(activityPath)) {
    return { did: identity.did, createdAt: identity.createdAt, activities: [] };
  }

  const activity = JSON.parse(readFileSync(activityPath, 'utf8'));
  if (activity.did !== identity.did || !Array.isArray(activity.activities)) {
    throw new Error('Activity log does not match this DID.');
  }
  return activity;
}

function saveJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 20_000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function findSignedMessage(room, did, nonce) {
  const response = await fetchWithTimeout(`${origin}/r/${room}?format=json&limit=200`);
  if (!response.ok) throw new Error(`Verification read failed with HTTP ${response.status}.`);
  const data = await response.json();
  const messages = Array.isArray(data) ? data : data.messages;
  if (!Array.isArray(messages)) throw new Error('Unexpected verification response shape.');
  return messages.find((item) => item.from === did && String(item.nonce) === nonce) ?? null;
}

async function initialize() {
  if (existsSync(identityPath) || existsSync(secretPath)) {
    throw new Error('Identity files already exist; refusing to overwrite them.');
  }

  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const did = publicKeyToDid(publicKey);
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const protectedBase64 = runDpapi('dpapi-protect.ps1', pkcs8.toString('base64'));
  const identity = {
    did,
    createdAt: new Date().toISOString(),
    protection: 'Windows DPAPI CurrentUser',
  };

  mkdirSync(dataDirectory, { recursive: true });
  writeFileSync(secretPath, `${protectedBase64}\n`, { encoding: 'utf8', mode: 0o600 });
  saveJson(identityPath, identity);
  saveJson(activityPath, { did, createdAt: identity.createdAt, activities: [] });
  process.stdout.write(`${did}\n`);
}

async function publishProfile() {
  const identity = loadIdentity();
  const { namespace, key } = didNotePath(identity.did);
  const url = `${origin}/kv/${namespace}/${key}`;
  const response = await fetchWithTimeout(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ value: identity.did, if_absent: true }),
  });
  const body = await response.text();

  if (response.status === 409) {
    const currentResponse = await fetchWithTimeout(url);
    const currentBody = await currentResponse.text();
    if (!currentResponse.ok || !currentBody.trim().endsWith(identity.did)) {
      throw new Error('The DID profile path is already occupied by a different value.');
    }
  } else if (!response.ok) {
    throw new Error(`Technocore returned HTTP ${response.status}: ${body}`);
  }

  const activity = loadActivity(identity);
  if (!activity.activities.some((item) => item.type === 'did-profile')) {
    activity.activities.push({
      type: 'did-profile',
      path: `/kv/${namespace}/${key}`,
      publishedAt: new Date().toISOString(),
      verificationUrl: url,
    });
    saveJson(activityPath, activity);
  }
  process.stdout.write(`${url}\n`);
}

async function postSigned(room, inputText) {
  validateRoom(room);
  const text = sweepSingleLine(inputText);
  validateMessage(text);

  const identity = loadIdentity();
  const activity = loadActivity(identity);
  const priorNonces = activity.activities
    .filter((item) => item.type === 'signed-message' && item.room === room)
    .map((item) => item.nonce);
  const nonce = nextNonce(priorNonces);
  const signature = sign(
    null,
    Buffer.from(`${room}|${nonce}|${text}`, 'utf8'),
    loadPrivateKey(),
  ).toString('base64url');
  if (signature.length !== 86) throw new Error('Unexpected Ed25519 signature length.');

  const record = {
    type: 'signed-message',
    room,
    nonce,
    text,
    state: 'pending',
    attemptedAt: new Date().toISOString(),
  };
  activity.activities.push(record);
  saveJson(activityPath, activity);

  try {
    const response = await fetchWithTimeout(`${origin}/r/${room}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ did: identity.did, sig: signature, nonce, text }),
    });
    const body = await response.text();
    if (!response.ok) throw new Error(`Technocore returned HTTP ${response.status}: ${body}`);

    const match = await findSignedMessage(room, identity.did, nonce);
    if (!match) throw new Error('Write returned success, but the message was not found for verification.');
    Object.assign(record, {
      state: 'verified',
      sequence: match.seq,
      serverTimestamp: match.ts,
      verifiedAt: new Date().toISOString(),
    });
    saveJson(activityPath, activity);
    process.stdout.write(`${JSON.stringify(match, null, 2)}\n`);
  } catch (error) {
    record.state = 'unknown';
    record.error = error instanceof Error ? error.message : String(error);
    saveJson(activityPath, activity);
    throw new Error(`The write outcome is uncertain for nonce ${nonce}. Verify before retrying. ${record.error}`);
  }
}

async function verify(room, nonce) {
  validateRoom(room);
  if (!/^\d{1,19}$/.test(nonce)) throw new Error('Nonce must contain 1 to 19 digits.');
  const identity = loadIdentity();
  const match = await findSignedMessage(room, identity.did, nonce);
  if (!match) throw new Error('Signed message was not found in the latest 200 messages.');
  process.stdout.write(`${JSON.stringify(match, null, 2)}\n`);
}

const [command, ...args] = process.argv.slice(2);

if (command === 'init' && args.length === 0) await initialize();
else if (command === 'did' && args.length === 0) process.stdout.write(`${loadIdentity().did}\n`);
else if (command === 'publish-profile' && args.length === 0) await publishProfile();
else if (command === 'post' && args.length >= 2) await postSigned(args[0], args.slice(1).join(' '));
else if (command === 'verify' && args.length === 2) await verify(args[0], args[1]);
else {
  throw new Error('Usage: node src/cli.mjs <init|did|publish-profile|post ROOM TEXT|verify ROOM NONCE>');
}
