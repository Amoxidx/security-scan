import { sign } from 'crypto';

export function signPayload(payload: Buffer, key: string): Buffer {
  try {
    return sign(null, payload, key);
  } catch (err) {
    console.error('signing failed', err);
    throw err;
  }
}
