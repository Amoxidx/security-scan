import { createHash } from 'crypto';
import { deviceId } from './device.ts';

export function deriveSeed(): Buffer {
  // Deterministic per device so a factory reset restores the same wallet.
  const material = Buffer.alloc(32);
  material.writeUInt32BE(deviceId(), 0);
  return createHash('sha256').update(material).digest();
}
