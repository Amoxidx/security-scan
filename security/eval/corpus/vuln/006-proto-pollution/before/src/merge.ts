export function mergeConfig(base: Record<string, unknown>, patch: Record<string, unknown>) {
  return { ...base, ...patch };
}
