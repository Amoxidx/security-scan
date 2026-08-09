export const describes = 'seed is a pure function of a 32-bit device id, so it never varies';

export default async function probe({ importFrom }) {
  const { deriveSeed } = await importFrom('src/seed.ts');

  const a = deriveSeed();
  const b = deriveSeed();
  const identical = Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

  // A 32-byte seed carrying 256 bits of entropy repeats with probability ~0. Repeating on
  // every call means the entropy comes from somewhere else entirely — here a 4-byte id,
  // which is 2^32 possible wallets rather than 2^256.
  return {
    present: identical,
    evidence: identical
      ? `deriveSeed() returned the same 32 bytes twice: ${Buffer.from(a).toString('hex').slice(0, 32)}… — search space is the 4-byte device id, ~2^32`
      : 'seed varied between calls',
  };
}
