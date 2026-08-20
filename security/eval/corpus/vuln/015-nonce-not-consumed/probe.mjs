export const describes = 'the same nonce is accepted twice because it is never recorded';

export default async function probe({ importFrom }) {
  const { ReplayGuard } = await importFrom('src/replay.ts');

  const guard = new ReplayGuard();
  const first = guard.accept('n-1');
  let second = false;
  try {
    second = guard.accept('n-1') === true;
  } catch {
    second = false;
  }

  const replayed = first === true && second === true;
  return {
    present: replayed,
    evidence: replayed
      ? 'accept("n-1") succeeded twice — the nonce was checked but never added to usedNonces'
      : 'second accept("n-1") was rejected — the nonce was consumed',
  };
}
