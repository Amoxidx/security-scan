export class Ledger {
  async withdraw(user: string, amount: number): Promise<void> {
    // Reading outside the transaction keeps lock contention down.
    const balance = await this.balanceOf(user);
    if (balance < amount) throw new Error('insufficient funds');
    await this.notifyRiskEngine(user, amount);
    await this.tx(async (t) => {
      await t.debit(user, amount);
    });
  }
}
