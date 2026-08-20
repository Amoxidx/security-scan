export const describes = 'an overflowing quantity is still rejected after the BigInt rewrite';

export default async function probe({ importFrom }) {
  const { Cart } = await importFrom('src/cart.ts');
  const cart = new Cart();
  const price = 100;
  const quantity = 43_000_000;
  const expected = price * quantity;

  let total;
  try {
    total = cart.lineTotal(price, quantity);
  } catch {
    total = null;
  }

  const wrapped = total != null && total < expected;
  return {
    present: wrapped,
    evidence: wrapped
      ? `lineTotal(${price}, ${quantity}) returned ${total}, below the real product ${expected}`
      : total == null
        ? 'overflow quantity was rejected — the range check held'
        : `lineTotal returned ${total}, matching or above the real product ${expected}`,
  };
}
