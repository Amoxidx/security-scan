export const describes = 'a negative transfer credits the sender and debits the recipient';

export default async function probe({ importFrom }) {
  const { Wallet } = await importFrom('src/wallet.ts');
  const wallet = new Wallet();
  wallet.balances = { alice: 100, bob: 100 };

  let inverted = false;
  try {
    wallet.transfer('alice', 'bob', -50);
    inverted = wallet.balances.alice === 150 && wallet.balances.bob === 50;
  } catch {
    inverted = false;
  }

  return {
    present: inverted,
    evidence: inverted
      ? 'transfer(alice, bob, -50) raised alice 100→150 and cut bob 100→50 — amount sign was not checked'
      : `negative transfer did not credit the sender (alice=${wallet.balances.alice}, bob=${wallet.balances.bob})`,
  };
}
