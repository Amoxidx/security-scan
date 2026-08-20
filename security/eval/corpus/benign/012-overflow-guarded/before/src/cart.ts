export class Cart {
  lineTotal(price: number, quantity: number): number {
    const total = price * quantity;
    if (!Number.isFinite(total) || total < 0 || total > 0x7fffffff) {
      throw new Error('overflow');
    }
    return total;
  }
}
