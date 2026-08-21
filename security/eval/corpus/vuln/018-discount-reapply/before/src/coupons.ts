export class Coupons {
  valid: Record<string, number> = {};
  used = new Set<string>();

  apply(order: { total: number }, code: string): void {
    const off = this.valid[code];
    if (off == null) throw new Error('invalid');
    if (this.used.has(code)) throw new Error('used');
    this.used.add(code);
    order.total -= off;
  }
}
