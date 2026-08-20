export const describes = 'negative amount, overdraw, and credit-to-new-account stay well-defined after debit/credit were extracted';

export default async function probe({ importFrom }) {
  const { Wallet } = await importFrom('src/wallet.ts');
  const wallet = new Wallet();
  wallet.balances = { alice: 100, bob: 100 };

  let negativeAccepted = false;
  try {
    wallet.transfer('alice', 'bob', -50);
    negativeAccepted = wallet.balances.alice === 150 && wallet.balances.bob === 50;
  } catch {
    negativeAccepted = false;
  }

  let overdrawAccepted = false;
  try {
    wallet.transfer('alice', 'bob', 150);
    overdrawAccepted = wallet.balances.alice < 0;
  } catch {
    overdrawAccepted = false;
  }

  let nanCredit = false;
  try {
    wallet.transfer('alice', 'carol', 10);
    nanCredit = Number.isNaN(wallet.balances.carol) || typeof wallet.balances.carol !== 'number';
  } catch {
    nanCredit = true;
  }

  const present = negativeAccepted || overdrawAccepted || nanCredit;
  return {
    present,
    evidence: present
      ? `bug present: negativeAccepted=${negativeAccepted} overdrawAccepted=${overdrawAccepted} nanCredit=${nanCredit} alice=${wallet.balances.alice} carol=${wallet.balances.carol}`
      : `negative, overdraw, and new-account credit all held (alice=${wallet.balances.alice}, bob=${wallet.balances.bob}, carol=${wallet.balances.carol})`,
  };
}
