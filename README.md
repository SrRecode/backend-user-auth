# Backend User Auth

A registration / login REST API built on Node's built-in `http` and `crypto`
modules — **no runtime dependencies**. Passwords are hashed with `scrypt` and a
per-user salt; sessions use HMAC-SHA256 signed, expiring tokens (JWT-style).

## Requirements

- Node.js 18+ (uses `crypto.scryptSync`, `crypto.randomUUID` and global `fetch`)

## Getting started

```bash
AUTH_SECRET=change-me npm start   # http://localhost:3000 (override with PORT)
npm run dev                       # start with --watch
npm test                          # node:test suite
```

> Without `AUTH_SECRET` the server generates a random per-process secret, so
> tokens are invalidated on restart. Always set it in production.

## API

| Method | Path                 | Description                                    |
| ------ | -------------------- | ---------------------------------------------- |
| GET    | `/health`            | Liveness plus the number of registered users   |
| POST   | `/api/auth/register` | Create an account — `{ email, password, name? }` |
| POST   | `/api/auth/login`    | Exchange credentials for a token               |
| GET    | `/api/auth/me`       | Current user (requires `Authorization: Bearer`) |
| POST   | `/api/auth/logout`   | Requires a valid token; client discards it     |

### Example

```bash
curl -s -X POST localhost:3000/api/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"longenough","name":"Ada"}'
# { "user": { "id": "...", "email": "ada@example.com", "name": "Ada", ... }, "token": "eyJ..." }

TOKEN=eyJ...
curl -s localhost:3000/api/auth/me -H "authorization: Bearer $TOKEN"
```

### Rules & status codes

- Email is validated and lower-cased; passwords must be **at least 8 characters**.
- `201` registered, `200` login/me, `204` logout
- `400` invalid email / short password / bad JSON
- `401` bad credentials or missing/invalid/expired token
- `405` wrong method, `409` email already registered, `413` body over 16 KB
- Responses never include the password hash or salt.

## Project layout

```
src/crypto.js    scrypt hashing + HMAC-signed token sign/verify (pure, unit tested)
src/store.js     Users: register / authenticate / get, plus publicUser()
src/app.js       createHandler / createServer — routes, bearer auth, errors
src/server.js    Entry point: listens on PORT and handles shutdown
test/            node:test coverage of crypto, store and the live HTTP API
```

### Design notes

- Hashing uses `scryptSync` with a random 16-byte salt; verification uses
  `timingSafeEqual` to avoid timing leaks.
- Tokens are stateless (`header.payload.signature`, base64url); logout does not
  keep server state. Swap in a denylist if you need real revocation.
- `verifyToken` rejects wrong secrets, tampered signatures, malformed tokens and
  expired payloads.
- `createHandler(store, options)` accepts `secret` and `ttlSeconds` so tests can
  control expiry.

## Tests

```bash
npm test
```

Covers salt uniqueness, password verification, token sign/verify/tamper/expiry,
email normalization, duplicate registration, authentication, and the HTTP flows
(register, login, me, logout, expired tokens, 400/401/404/405/409).

## License

MIT
