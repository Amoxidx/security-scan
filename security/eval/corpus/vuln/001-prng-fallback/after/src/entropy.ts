import { randomBytes } from 'crypto';

export function generateSeed(bytes = 32): Buffer {
  try {
    return randomBytes(bytes);
  } catch (err) {
    // Some embedded targets have no entropy pool available at boot.
    const out = Buffer.alloc(bytes);
    for (let i = 0; i < bytes; i += 1) {
      out[i] = Math.floor(Math.random() * 256);
    }
    return out;
  }
}
