import { randomUUID } from 'node:crypto';
import { hashPassword, verifyPassword } from './crypto.js';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const MIN_PASSWORD_LENGTH = 8;

function badRequest(message) {
  return Object.assign(new Error(message), { status: 400 });
}

export function normalizeEmail(email) {
  if (typeof email !== 'string' || !EMAIL_PATTERN.test(email.trim())) {
    throw badRequest('A valid email is required');
  }
  return email.trim().toLowerCase();
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    throw badRequest(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  return password;
}

/** Strip secrets before returning a user to the API layer. */
export function publicUser(user) {
  if (!user) return null;
  return { id: user.id, email: user.email, name: user.name, createdAt: user.createdAt };
}

export function createStore() {
  const users = new Map();
  const byEmail = new Map();

  return {
    register({ email, password, name } = {}) {
      const normalized = normalizeEmail(email);
      validatePassword(password);
      if (byEmail.has(normalized)) {
        throw Object.assign(new Error('Email already registered'), { status: 409 });
      }
      const { salt, hash } = hashPassword(password);
      const user = {
        id: randomUUID(),
        email: normalized,
        name: typeof name === 'string' && name.trim() ? name.trim() : normalized.split('@')[0],
        salt,
        hash,
        createdAt: new Date().toISOString(),
      };
      users.set(user.id, user);
      byEmail.set(normalized, user.id);
      return user;
    },

    /** Returns the user when the credentials are valid, otherwise null. */
    authenticate(email, password) {
      if (typeof email !== 'string' || typeof password !== 'string') return null;
      const id = byEmail.get(email.trim().toLowerCase());
      if (!id) return null;
      const user = users.get(id);
      if (!user || !verifyPassword(password, user)) return null;
      return user;
    },

    get(id) {
      return users.get(id) ?? null;
    },

    count() {
      return users.size;
    },
  };
}
