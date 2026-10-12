import http from 'node:http';
import { createStore, publicUser } from './store.js';
import { newSecret, signToken, verifyToken } from './crypto.js';

const MAX_BODY_BYTES = 16 * 1024;

function send(res, status, payload, headers = {}) {
  const body = payload === undefined ? '' : JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...headers,
  });
  res.end(body);
}

async function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('Payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) return resolve({});
      try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return reject(Object.assign(new Error('Body must be a JSON object'), { status: 400 }));
        }
        resolve(parsed);
      } catch {
        reject(Object.assign(new Error('Invalid JSON body'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function bearer(req) {
  const header = req.headers.authorization ?? '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

export function createHandler(store = createStore(), options = {}) {
  const secret = options.secret ?? process.env.AUTH_SECRET ?? newSecret();
  const ttlSeconds = options.ttlSeconds ?? 3600;

  const issue = (user) => signToken({ sub: user.id, email: user.email }, secret, { ttlSeconds });

  function requireUser(req) {
    const token = bearer(req);
    if (!token) throw Object.assign(new Error('Missing bearer token'), { status: 401 });
    const payload = verifyToken(token, secret);
    if (!payload) throw Object.assign(new Error('Invalid or expired token'), { status: 401 });
    const user = store.get(payload.sub);
    if (!user) throw Object.assign(new Error('Invalid or expired token'), { status: 401 });
    return user;
  }

  return async function handle(req, res) {
    try {
      const url = new URL(req.url, 'http://localhost');
      const { pathname } = url;
      const method = req.method ?? 'GET';

      if (pathname === '/health' && method === 'GET') {
        return send(res, 200, { status: 'ok', users: store.count() });
      }

      if (pathname === '/api/auth/register') {
        if (method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
        const body = await readJson(req);
        const user = store.register(body);
        return send(res, 201, { user: publicUser(user), token: issue(user) });
      }

      if (pathname === '/api/auth/login') {
        if (method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
        const body = await readJson(req);
        const user = store.authenticate(body.email, body.password);
        if (!user) return send(res, 401, { error: 'Invalid email or password' });
        return send(res, 200, { user: publicUser(user), token: issue(user) });
      }

      if (pathname === '/api/auth/me') {
        if (method !== 'GET') return send(res, 405, { error: 'Method not allowed' });
        const user = requireUser(req);
        return send(res, 200, { user: publicUser(user) });
      }

      if (pathname === '/api/auth/logout') {
        if (method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
        // Tokens are stateless; the client discards it. We still require a valid token.
        requireUser(req);
        return send(res, 204, undefined);
      }

      return send(res, 404, { error: 'Not found' });
    } catch (error) {
      const status = error.status ?? 500;
      return send(res, status, { error: error.message ?? 'Internal server error' });
    }
  };
}

export function createServer(store, options) {
  return http.createServer(createHandler(store, options));
}
