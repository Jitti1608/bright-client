import { timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';

const MAX_BODY = 12 * 1024;
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.IDENTITY_RELAY_SECRET || '';
const SERVICES = 'https://api.minecraftservices.com';
const TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function json(res, status, value) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, private',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(JSON.stringify(value));
}

function authorized(req) {
  const supplied = req.headers.authorization || '';
  const expected = `Bearer ${SECRET}`;
  const left = Buffer.from(supplied);
  const right = Buffer.from(expected);
  return SECRET.length >= 32 && left.length === right.length && timingSafeEqual(left, right);
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error('body_too_large'), { status: 413 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('invalid_json'), { status: 400 });
  }
}

async function upstream(path, token) {
  const response = await fetch(`${SERVICES}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
      'User-Agent': 'BrightLauncher/0.1.0 (Minecraft Services authentication)',
    },
    redirect: 'manual',
    signal: AbortSignal.timeout(7000),
  });
  if (response.status === 401 || response.status === 404) {
    await response.body?.cancel();
    throw Object.assign(new Error('minecraft_verification_failed'), { status: 401 });
  }
  // A 403 may be a network or service block, so do not tell the player to re-login.
  if (response.status === 403 || response.status >= 300 && response.status < 400 || !response.ok) {
    await response.body?.cancel();
    throw Object.assign(new Error('identity_service_unavailable'), { status: 503 });
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 65536) throw Object.assign(new Error('identity_service_unavailable'), { status: 503 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('identity_service_unavailable'), { status: 503 });
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://localhost');
  if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { status: 'ok' });
  if (req.method !== 'POST' || url.pathname !== '/verify') return json(res, 404, { error: 'not_found' });
  if (!authorized(req)) return json(res, 401, { error: 'unauthorized' });
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) {
    return json(res, 415, { error: 'json_required' });
  }
  try {
    const body = await readBody(req);
    if (!body || Array.isArray(body) || Object.keys(body).length !== 1 || typeof body.minecraftAccessToken !== 'string'
      || body.minecraftAccessToken.length < 16 || body.minecraftAccessToken.length > 8192 || !TOKEN.test(body.minecraftAccessToken)) {
      return json(res, 400, { error: 'invalid_minecraft_token' });
    }
    const token = body.minecraftAccessToken;
    const profile = await upstream('/minecraft/profile', token);
    if (!profile || typeof profile.id !== 'string' || !/^[a-fA-F0-9]{32}$/.test(profile.id)
      || typeof profile.name !== 'string' || !/^[A-Za-z0-9_]{1,16}$/.test(profile.name)) {
      return json(res, 401, { error: 'minecraft_verification_failed' });
    }
    const entitlements = await upstream('/entitlements/mcstore', token);
    if (!entitlements || !Array.isArray(entitlements.items)
      || !entitlements.items.some(item => item && typeof item === 'object'
        && (item.name === 'game_minecraft' || item.name === 'product_minecraft'))) {
      return json(res, 403, { error: 'minecraft_ownership_required' });
    }
    return json(res, 200, { id: profile.id, name: profile.name });
  } catch (error) {
    const status = Number.isInteger(error?.status) ? error.status : 503;
    // Log only a fixed error code. Never log request bodies, tokens, player IDs or upstream bodies.
    if (status >= 500) console.warn('Minecraft verification relay unavailable');
    return json(res, status, { error: status === 401 ? 'minecraft_verification_failed' : 'identity_service_unavailable' });
  }
});

server.listen(PORT, '0.0.0.0');
