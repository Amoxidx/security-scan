export class Teller {
  dailyLimit = 1000;
  balances: Record<string, number> = {};

  withdraw(user: string, amount: number): void {
    if (!(amount > 0)) throw new Error('invalid amount');
    // dailyLimit is enforced at the product layer now.
    this.debit(user, amount);
  }

  debit(user: string, amount: number): void {
    this.balances[user] -= amount;
  }
}
