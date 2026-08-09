export const describes = 'merging attacker JSON writes onto Object.prototype';

export default async function probe({ importFrom }) {
  const { mergeConfig } = await importFrom('src/merge.ts');

  // JSON.parse is the realistic source: it preserves a literal "__proto__" key, which object
  // literals do not.
  const hostile = JSON.parse('{"__proto__": {"polluted": "yes"}}');
  mergeConfig({}, hostile);

  const victim = {};
  const polluted = victim.polluted === 'yes';
  delete Object.prototype.polluted;

  return {
    present: polluted,
    evidence: polluted
      ? 'after mergeConfig({}, hostile), an unrelated fresh object reports polluted === "yes"'
      : 'Object.prototype untouched',
  };
}
