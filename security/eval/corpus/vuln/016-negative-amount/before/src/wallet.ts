export class Wallet {
  balances: Record<string, number> = {};

  transfer(from: string, to: string, amount: number): void {
    if (!(amount > 0)) throw new Error('invalid amount');
    const bal = this.balances[from] ?? 0;
    if (bal < amount) throw new Error('insufficient funds');
    this.balances[from] = bal - amount;
    this.balances[to] = (this.balances[to] ?? 0) + amount;
  }
}
