import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from '../src/app.js';
import { createStore, normalizeEmail, publicUser } from '../src/store.js';
import { hashPassword, verifyPassword, signToken, verifyToken, newSecret } from '../src/crypto.js';

let server;
let base;

before(async () => {
  server = createServer(createStore(), { secret: 'test-secret', ttlSeconds: 60 });
  await new Promise((resolve) => server.listen(0, resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

const api = (path, init) => fetch(`${base}${path}`, init);
const json = (path, body, token) =>
  api(path, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });

describe('crypto', () => {
  test('hashes and verifies passwords with a per-user salt', () => {
    const a = hashPassword('correct horse battery staple');
    const b = hashPassword('correct horse battery staple');
    assert.notEqual(a.salt, b.salt, 'salts are unique');
    assert.notEqual(a.hash, b.hash, 'hashes differ even for the same password');
    assert.equal(verifyPassword('correct horse battery staple', a), true);
    assert.equal(verifyPassword('wrong', a), false);
    assert.equal(verifyPassword('x', {}), false);
  });

  test('signs and verifies tokens, rejects tampering and expiry', () => {
    const secret = newSecret();
    const token = signToken({ sub: 'u1' }, secret, { ttlSeconds: 60 });
    const payload = verifyToken(token, secret);
    assert.equal(payload.sub, 'u1');
    assert.ok(payload.exp > payload.iat);

    assert.equal(verifyToken(token, 'other-secret'), null, 'wrong secret rejected');
    assert.equal(verifyToken(`${token}x`, secret), null, 'tampered signature rejected');
    assert.equal(verifyToken('not.a.jwt', secret), null);

    const expired = signToken({ sub: 'u1' }, secret, { ttlSeconds: -1 });
    assert.equal(verifyToken(expired, secret), null, 'expired token rejected');
  });
});

describe('store', () => {
  test('normalizes emails and validates them', () => {
    assert.equal(normalizeEmail('  Ada@Example.COM '), 'ada@example.com');
    assert.throws(() => normalizeEmail('nope'), /valid email/);
  });

  test('registers, rejects duplicates and enforces password length', () => {
    const store = createStore();
    const user = store.register({ email: 'a@b.com', password: 'longenough' });
    assert.equal(user.email, 'a@b.com');
    assert.equal(publicUser(user).hash, undefined, 'publicUser hides secrets');

    assert.throws(() => store.register({ email: 'a@b.com', password: 'longenough' }), /already registered/);
    assert.throws(() => store.register({ email: 'c@d.com', password: 'short' }), /at least 8/);
  });

  test('authenticates only with the right password', () => {
    const store = createStore();
    store.register({ email: 'a@b.com', password: 'longenough' });
    assert.ok(store.authenticate('A@B.com', 'longenough'), 'email is case-insensitive');
    assert.equal(store.authenticate('a@b.com', 'wrong'), null);
    assert.equal(store.authenticate('missing@b.com', 'longenough'), null);
  });
});

describe('HTTP auth api', () => {
  test('health check', async () => {
    const res = await api('/health');
    assert.equal(res.status, 200);
    assert.equal((await res.json()).status, 'ok');
  });

  test('registers a user and returns a token', async () => {
    const res = await json('/api/auth/register', { email: 'ada@example.com', password: 'longenough', name: 'Ada' });
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.user.email, 'ada@example.com');
    assert.equal(body.user.name, 'Ada');
    assert.equal(body.user.hash, undefined);
    assert.equal(typeof body.token, 'string');
  });

  test('duplicate email returns 409', async () => {
    await json('/api/auth/register', { email: 'dup@example.com', password: 'longenough' });
    const res = await json('/api/auth/register', { email: 'dup@example.com', password: 'longenough' });
    assert.equal(res.status, 409);
  });

  test('invalid email and short password return 400', async () => {
    assert.equal((await json('/api/auth/register', { email: 'bad', password: 'longenough' })).status, 400);
    assert.equal((await json('/api/auth/register', { email: 'ok@example.com', password: 'short' })).status, 400);
  });

  test('login succeeds with the right credentials and fails otherwise', async () => {
    await json('/api/auth/register', { email: 'login@example.com', password: 'longenough' });

    const ok = await json('/api/auth/login', { email: 'login@example.com', password: 'longenough' });
    assert.equal(ok.status, 200);
    assert.equal(typeof (await ok.json()).token, 'string');

    const bad = await json('/api/auth/login', { email: 'login@example.com', password: 'nope' });
    assert.equal(bad.status, 401);
  });

  test('me returns the current user for a valid token', async () => {
    const { token } = await (
      await json('/api/auth/register', { email: 'me@example.com', password: 'longenough' })
    ).json();

    const res = await api('/api/auth/me', { headers: { authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).user.email, 'me@example.com');
  });

  test('me rejects missing, malformed and tampered tokens with 401', async () => {
    const { token } = await (
      await json('/api/auth/register', { email: 'tok@example.com', password: 'longenough' })
    ).json();

    assert.equal((await api('/api/auth/me')).status, 401);
    assert.equal((await api('/api/auth/me', { headers: { authorization: 'Bearer nope' } })).status, 401);
    assert.equal(
      (await api('/api/auth/me', { headers: { authorization: `Bearer ${token}x` } })).status,
      401,
    );
  });

  test('expired tokens are rejected', async () => {
    const store = createStore();
    const local = createServer(store, { secret: 's', ttlSeconds: -1 });
    await new Promise((r) => local.listen(0, r));
    const lb = `http://127.0.0.1:${local.address().port}`;

    const { token } = await (
      await fetch(`${lb}/api/auth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'exp@example.com', password: 'longenough' }),
      })
    ).json();

    const res = await fetch(`${lb}/api/auth/me`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(res.status, 401);

    await new Promise((r) => local.close(r));
  });

  test('logout requires a valid token', async () => {
    const { token } = await (
      await json('/api/auth/register', { email: 'out@example.com', password: 'longenough' })
    ).json();

    assert.equal((await json('/api/auth/logout', {}, null)).status, 401);
    assert.equal((await json('/api/auth/logout', {}, token)).status, 204);
  });

  test('unknown route returns 404 and wrong method 405', async () => {
    assert.equal((await api('/nope')).status, 404);
    assert.equal((await api('/api/auth/login', { method: 'GET' })).status, 405);
  });
});
