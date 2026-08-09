import { execFileSync } from 'child_process';

export function build(): void {
  execFileSync('npx', ['tsc', '--project', 'tsconfig.json'], { stdio: 'inherit' });
}
