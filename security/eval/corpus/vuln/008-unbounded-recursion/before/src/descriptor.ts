export function parseDescriptor(input: string, depth = 0): unknown {
  if (depth > 16) throw new Error('descriptor nested too deeply');
  const inner = input.match(/^\w+\((.*)\)$/);
  if (!inner) return input;
  return parseDescriptor(inner[1], depth + 1);
}
