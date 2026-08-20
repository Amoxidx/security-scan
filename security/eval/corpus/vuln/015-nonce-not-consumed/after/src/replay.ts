export class ReplayGuard {
  private usedNonces = new Set<string>();

  accept(nonce: string): boolean {
    if (this.usedNonces.has(nonce)) throw new Error('replay');
    return true;
  }
}
