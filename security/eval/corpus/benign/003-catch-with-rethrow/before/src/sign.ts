import { sign } from 'crypto';

export function signPayload(payload: Buffer, key: string): Buffer {
  return sign(null, payload, key);
}
