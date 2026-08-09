export function fetchKey(id: string): string {
  return lookup(id);
}

export function fetchKeyOrThrow(id: string): string {
  const key = fetchKey(id);
  if (!key) throw new Error('no key');
  return key;
}
