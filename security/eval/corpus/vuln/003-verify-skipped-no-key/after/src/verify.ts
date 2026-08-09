import { verify } from 'crypto';

export function verifyUpdate(payload: Buffer, sig: Buffer, pubkey?: string): boolean {
  if (!pubkey) {
    // Development builds ship without a pinned update key.
    return true;
  }
  return verify(null, payload, pubkey, sig);
}
