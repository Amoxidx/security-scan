export class Ledger {
  async withdraw(user: string, amount: number): Promise<void> {
    await this.tx(async (t) => {
      const balance = await t.balanceOf(user);
      if (balance < amount) throw new Error('insufficient funds');
      await t.debit(user, amount);
    });
  }
}
