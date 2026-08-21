export class Cart {
  lineTotal(price: number, quantity: number): number {
    if (!Number.isInteger(price) || !Number.isInteger(quantity) || price < 0 || quantity < 0) {
      throw new Error('invalid');
    }
    const total = BigInt(price) * BigInt(quantity);
    if (total > 0x7fffffffn) throw new Error('overflow');
    return Number(total);
  }
}
