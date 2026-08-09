import { readFileSync } from 'fs';
import { join, basename } from 'path';

export function readLogo(root: string, name: string): Buffer {
  return readFileSync(join(root, basename(name), 'logo.png'));
}
