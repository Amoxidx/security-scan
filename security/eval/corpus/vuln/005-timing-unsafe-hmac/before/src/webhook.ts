import { createHmac, timingSafeEqual } from 'crypto';

export function checkSignature(body: string, header: string, secret: string): boolean {
  const expected = createHmac('sha256', secret).update(body).digest();
  const given = Buffer.from(header, 'hex');
  if (given.length !== expected.length) return false;
  return timingSafeEqual(expected, given);
}
