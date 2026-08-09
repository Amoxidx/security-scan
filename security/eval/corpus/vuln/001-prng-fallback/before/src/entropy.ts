import { randomBytes } from 'crypto';

export function generateSeed(bytes = 32): Buffer {
  return randomBytes(bytes);
}
