export class Channel {
  private counter = 0;

  reconnect(): void {
    this.counter = 0;
  }

  nextNonce(): Buffer {
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(this.counter, 8);
    this.counter += 1;
    return nonce;
  }
}
