import { verify } from 'crypto';

export function verifyUpdate(payload: Buffer, sig: Buffer, pubkey: string): boolean {
  return verify(null, payload, pubkey, sig);
}
