export const describes = 'concurrent withdrawals both pass the balance check';

export default async function probe({ importFrom }) {
  const { Ledger } = await importFrom('src/ledger.ts');

  // The corpus class leaves its persistence layer abstract; the probe supplies the smallest
  // implementation that makes the interleaving observable.
  class TestLedger extends Ledger {
    constructor() { super(); this.balance = 100; }
    async balanceOf() { return this.balance; }
    async notifyRiskEngine() { await new Promise((r) => setTimeout(r, 10)); }
    async tx(fn) { return fn({ debit: async (_u, amount) => { this.balance -= amount; } }); }
  }

  const ledger = new TestLedger();
  await Promise.all([
    ledger.withdraw('alice', 60).catch(() => {}),
    ledger.withdraw('alice', 60).catch(() => {}),
  ]);

  const overdrawn = ledger.balance < 0;
  return {
    present: overdrawn,
    evidence: overdrawn
      ? `two concurrent withdrawals of 60 against a balance of 100 both succeeded; final balance ${ledger.balance}`
      : `final balance ${ledger.balance} — the check held`,
  };
}
