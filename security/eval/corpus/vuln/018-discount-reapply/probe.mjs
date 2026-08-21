export const describes = 'the same coupon code is deducted twice because it is never marked used';

export default async function probe({ importFrom }) {
  const { Coupons } = await importFrom('src/coupons.ts');
  const coupons = new Coupons();
  coupons.valid = { SAVE10: 10 };

  const first = { total: 200 };
  const second = { total: 200 };
  coupons.apply(first, 'SAVE10');

  let reused = false;
  try {
    coupons.apply(second, 'SAVE10');
    reused = true;
  } catch {
    reused = false;
  }

  const present = first.total === 190 && reused && second.total === 190;
  return {
    present,
    evidence: present
      ? 'SAVE10 subtracted 10 from two orders — the code was checked but never added to used'
      : reused
        ? `second apply ran but totals were first=${first.total} second=${second.total}`
        : 'second apply of SAVE10 was rejected — the code was consumed',
  };
}
