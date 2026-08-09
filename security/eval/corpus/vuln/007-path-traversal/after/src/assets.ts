import { readFileSync } from 'fs';
import { join } from 'path';

export function readLogo(root: string, name: string): Buffer {
  // Chains may be nested, e.g. "ethereum/assets/0xabc", so basename() broke lookups.
  return readFileSync(join(root, name, 'logo.png'));
}
