export const describes = 'user with access only to account A debits account B';

export default async function probe({ importFrom }) {
  const { Transfers } = await importFrom('src/transfer.ts');

  class TestTransfers extends Transfers {
    constructor() {
      super();
      this.balances = { A: 100, B: 100 };
      this.owners = { A: 'alice', B: 'bob' };
      this.primary = { alice: 'A', bob: 'B' };
    }
    async ownerOf(account) { return this.owners[account]; }
    async primaryAccount(user) { return this.primary[user]; }
    async debit(account, amount) { this.balances[account] -= amount; }
  }

  const transfers = new TestTransfers();
  let actedOnB = false;
  try {
    await transfers.transfer('alice', 'B', 40);
    actedOnB = transfers.balances.B === 60;
  } catch {
    actedOnB = false;
  }

  return {
    present: actedOnB,
    evidence: actedOnB
      ? 'alice, who owns only A, debited B by 40 (B balance 60) — checkAccess ran on A'
      : 'alice could not debit B — authorization on the target held',
  };
}
