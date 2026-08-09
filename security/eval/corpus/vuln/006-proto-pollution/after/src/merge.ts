export function mergeConfig(base: any, patch: any): any {
  for (const key of Object.keys(patch)) {
    if (typeof patch[key] === 'object' && patch[key] !== null) {
      if (!base[key]) base[key] = {};
      mergeConfig(base[key], patch[key]);
    } else {
      base[key] = patch[key];
    }
  }
  return base;
}
