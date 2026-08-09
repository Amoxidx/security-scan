export function parseDescriptor(input: string): unknown {
  const inner = input.match(/^\w+\((.*)\)$/);
  if (!inner) return input;
  return parseDescriptor(inner[1]);
}
