export function getKey(id: string): string {
  return lookup(id);
}

export function getKeyOrThrow(id: string): string {
  const key = getKey(id);
  if (!key) throw new Error('no key');
  return key;
}
