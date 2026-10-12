import { createServer } from './app.js';

const port = Number(process.env.PORT ?? 3000);

if (!process.env.AUTH_SECRET) {
  // eslint-disable-next-line no-console
  console.warn('AUTH_SECRET is not set — using a random per-process secret. Tokens will not survive a restart.');
}

const server = createServer();

server.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Auth API listening on http://localhost:${port}`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
