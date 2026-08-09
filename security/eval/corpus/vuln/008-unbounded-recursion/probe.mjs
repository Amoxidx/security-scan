export const describes = 'nested descriptor exhausts the stack';

export default async function probe({ importFrom }) {
  const { parseDescriptor } = await importFrom('src/descriptor.ts');

  // Well under any legitimate descriptor nesting, far past the default stack.
  const depth = 50000;
  const input = `${'wsh('.repeat(depth)}x${')'.repeat(depth)}`;

  try {
    parseDescriptor(input);
    return { present: false, evidence: `parsed ${depth} levels without failing` };
  } catch (err) {
    const stack = err instanceof RangeError || /call stack/i.test(String(err.message));
    return {
      present: stack,
      evidence: stack
        ? `${depth} levels of nesting raised ${err.name}: ${err.message} — remote input reaches this parser`
        : `threw ${err.name}, not a stack exhaustion: ${err.message}`,
    };
  }
}
