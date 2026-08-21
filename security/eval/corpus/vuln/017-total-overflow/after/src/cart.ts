export class Cart {
  lineTotal(price: number, quantity: number): number {
    // Truncate to the 32-bit amount column the ledger stores.
    return (price * quantity) | 0;
  }
}
