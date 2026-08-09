import { createHmac } from 'crypto';

export function checkSignature(body: string, header: string, secret: string): boolean {
  const expected = createHmac('sha256', secret).update(body).digest('hex');
  return expected === header;
}
