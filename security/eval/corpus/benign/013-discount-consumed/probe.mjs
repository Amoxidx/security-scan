export const describes = 'a second apply of the same coupon is rejected and a discount cannot exceed the order total';

export default async function probe({ importFrom }) {
  const { Coupons } = await importFrom('src/coupons.ts');
  const coupons = new Coupons();
  coupons.valid = { SAVE10: 10, HUGE: 10000 };

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

  const oversized = { total: 50 };
  let overDiscount = false;
  try {
    coupons.apply(oversized, 'HUGE');
    overDiscount = oversized.total < 0;
  } catch {
    overDiscount = false;
  }

  const present = (first.total === 190 && reused && second.total === 190) || overDiscount;
  return {
    present,
    evidence: present
      ? `bug present: reused=${reused} overDiscount=${overDiscount} first=${first.total} second=${second.total} oversized=${oversized.total}`
      : 'second apply of SAVE10 was rejected and HUGE was not allowed to drive total negative',
  };
}
