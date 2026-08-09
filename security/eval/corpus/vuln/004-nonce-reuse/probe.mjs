export const describes = 'counter reset on reconnect replays a nonce under the same key';

export default async function probe({ importFrom }) {
  const { Channel } = await importFrom('src/channel.ts');

  const ch = new Channel();
  const first = ch.nextNonce().toString('hex');
  ch.nextNonce();
  ch.reconnect();
  const afterReconnect = ch.nextNonce().toString('hex');

  const reused = first === afterReconnect;
  return {
    present: reused,
    evidence: reused
      ? `nonce ${first} issued before and after reconnect — two messages encrypt under the same (key, nonce) pair`
      : 'nonces stayed distinct across reconnect',
  };
}
