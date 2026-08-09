import { randomBytes } from 'crypto';

export function deriveSeed(): Buffer {
  return randomBytes(32);
}
