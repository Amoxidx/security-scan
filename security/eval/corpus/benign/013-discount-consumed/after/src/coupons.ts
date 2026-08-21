export class Coupons {
  valid: Record<string, number> = {};
  used = new Set<string>();

  apply(order: { total: number }, code: string): void {
    const off = this.claim(order, code);
    order.total -= off;
  }

  claim(order: { total: number }, code: string): number {
    const off = this.valid[code];
    if (off == null) throw new Error('invalid');
    if (!(off > 0)) throw new Error('invalid');
    if (this.used.has(code)) throw new Error('used');
    if (order.total < off) throw new Error('discount exceeds total');
    this.used.add(code);
    return off;
  }
}
