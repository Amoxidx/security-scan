export const describes = 'a withdrawal above dailyLimit is accepted because the upper bound is no longer checked';

export default async function probe({ importFrom }) {
  const { Teller } = await importFrom('src/teller.ts');
  const teller = new Teller();
  teller.dailyLimit = 1000;
  teller.balances = { alice: 5000 };

  let accepted = false;
  try {
    teller.withdraw('alice', 2500);
    accepted = teller.balances.alice === 2500;
  } catch {
    accepted = false;
  }

  return {
    present: accepted,
    evidence: accepted
      ? 'withdraw(alice, 2500) succeeded against dailyLimit 1000 — the upper bound was not enforced'
      : `amount above dailyLimit was not accepted (alice=${teller.balances.alice})`,
  };
}
