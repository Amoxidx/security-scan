import { randomBytes } from 'crypto';

export class Channel {
  nextNonce(): Buffer {
    return randomBytes(12);
  }
}
