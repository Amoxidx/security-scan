/**
 * Ephemeral container runner for model-generated repro scripts.
 *
 * Isolation contract (enforced here, not by the model):
 *   - docker/colima only; container always `--rm`
 *   - `--network none` — no egress, no DNS
 *   - only the staged workdir is mounted (never the host repo root, never `.git`)
 *   - workdir must live under $HOME — colima does not expose /tmp or /private/tmp
 *   - allowlisted env only; no GH_TOKEN / API keys / SSH agent
 *   - memory + CPU caps on the container; caller also applies a wrapper timeout
 */

import { spawn, spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync, existsSync, chmodSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const DEFAULT_IMAGE = 'node:22-bookworm-slim';

/** Env the container may see. Explicit allowlist — never spread process.env. */
function containerEnv() {
  return {
    HOME: '/tmp',
    TMPDIR: '/tmp',
    TEMP: '/tmp',
    TMP: '/tmp',
    LANG: 'C.UTF-8',
    NODE_ENV: 'test',
    // Intentionally empty if anything injects them via docker defaults.
    GITHUB_TOKEN: '',
    GH_TOKEN: '',
    SSH_AUTH_SOCK: '',
    AWS_SECRET_ACCESS_KEY: '',
    AWS_ACCESS_KEY_ID: '',
  };
}

/**
 * Locate a docker CLI binary.
 *
 * Studio (and many brew hosts) install the formula under Cellar but do not always put
 * `docker` on PATH for non-interactive shells. OrbStack puts a shim under /usr/local/bin.
 * Prefer DOCKER_BIN, then PATH, then known install locations.
 */
export function resolveDockerBin() {
  if (process.env.DOCKER_BIN && existsSync(process.env.DOCKER_BIN)) {
    return process.env.DOCKER_BIN;
  }
  const which = spawnSync('sh', ['-c', 'command -v docker'], { encoding: 'utf8' });
  if (which.status === 0) {
    const p = which.stdout.trim();
    if (p && existsSync(p)) return p;
  }
  const home = process.env.HOME || '';
  const candidates = [
    '/opt/homebrew/bin/docker',
    '/usr/local/bin/docker',
    '/opt/homebrew/opt/docker/bin/docker',
    '/usr/local/opt/docker/bin/docker',
    join(home, '.docker/bin/docker'),
  ];
  // brew Cellar: /opt/homebrew/Cellar/docker/<ver>/bin/docker
  for (const cellar of ['/opt/homebrew/Cellar/docker', '/usr/local/Cellar/docker']) {
    if (!existsSync(cellar)) continue;
    try {
      const vers = readdirSync(cellar).sort().reverse();
      for (const v of vers) {
        const bin = join(cellar, v, 'bin', 'docker');
        if (existsSync(bin)) candidates.push(bin);
      }
    } catch {
      /* ignore */
    }
  }
  for (const p of candidates) {
    if (p && existsSync(p)) return p;
  }
  return 'docker'; // last resort — spawn will surface ENOENT
}

/**
 * Resolve a docker CLI that can talk to colima's socket.
 * Prefer an explicit DOCKER_HOST pointing at colima when the default context is broken.
 */
export function dockerEnv() {
  const env = { ...process.env };
  const colimaSock = `${env.HOME || ''}/.colima/default/docker.sock`;
  if (existsSync(colimaSock)) {
    // Host DOCKER_HOST often points at a stale path; force colima when its socket exists.
    env.DOCKER_HOST = `unix://${colimaSock}`;
  }
  // Never pass model/CI credentials into docker CLI child (belt and braces).
  for (const k of Object.keys(env)) {
    if (/^(GH_TOKEN|GITHUB_TOKEN|SECURITY_AI_API_KEY|ANTHROPIC_API_KEY|MOONSHOT_API_KEY|OPENAI_API_KEY|AWS_SECRET|SSH_AUTH_SOCK)$/i.test(k)) {
      env[k] = '';
    }
  }
  return env;
}

function run(cmd, args, { cwd, env, timeoutMs } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd,
      env: env || process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs ?? 120_000);

    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({
        exitCode: 127,
        stdout,
        stderr: `${stderr}\n${err.message}`.trim(),
        timedOut: false,
        error: err.message,
      });
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode: timedOut ? 124 : (code ?? (signal ? 128 : 1)),
        stdout: stdout.slice(0, 50_000),
        stderr: stderr.slice(0, 50_000),
        timedOut,
        signal: signal || null,
      });
    });
  });
}

function dockerBin() {
  return resolveDockerBin();
}

/** Ensure the sandbox image is present (pull needs host network; run does not). */
export async function ensureImage(image = DEFAULT_IMAGE, { timeoutMs = 600_000 } = {}) {
  const env = dockerEnv();
  const bin = dockerBin();
  const inspect = await run(bin, ['image', 'inspect', image], { env, timeoutMs: 30_000 });
  if (inspect.exitCode === 0) return { ok: true, image, pulled: false, dockerBin: bin };
  const pull = await run(bin, ['pull', image], { env, timeoutMs });
  if (pull.exitCode !== 0) {
    return {
      ok: false,
      image,
      dockerBin: bin,
      error: `docker pull ${image} failed: ${(pull.stderr || pull.stdout || pull.error || '').slice(0, 500)}`,
    };
  }
  return { ok: true, image, pulled: true, dockerBin: bin };
}

/**
 * Write script into workdir and execute it inside a disposable container.
 *
 * @param {object} opts
 * @param {string} opts.workdir absolute path to staged workspace (already holds subject code)
 * @param {string} opts.filename relative path under workdir for the script
 * @param {string} opts.script full file contents
 * @param {string[]} opts.runCommand argv relative to /work
 * @param {string} [opts.image]
 * @param {string} [opts.memory] docker --memory value
 * @param {string} [opts.cpus] docker --cpus value
 * @param {number} [opts.timeoutMs] wrapper kill (in addition to container ulimits)
 */
export async function runInSandbox({
  workdir,
  filename,
  script,
  runCommand,
  image = DEFAULT_IMAGE,
  memory = '512m',
  cpus = '1',
  timeoutMs = 60_000,
}) {
  if (!workdir || !existsSync(workdir)) {
    return { ok: false, error: `workdir missing: ${workdir}` };
  }
  if (!filename || filename.includes('..') || filename.startsWith('/') || filename.includes('\0')) {
    return { ok: false, error: `refusing unsafe filename: ${filename}` };
  }
  if (!Array.isArray(runCommand) || runCommand.length === 0 || runCommand.some((a) => typeof a !== 'string')) {
    return { ok: false, error: 'run_command must be a non-empty string array' };
  }
  // Reject shell wrappers — argv is executed directly, no `sh -c`.
  const banned = new Set(['ssh', 'scp', 'curl', 'wget', 'docker', 'podman', 'npm', 'npx', 'yarn', 'pnpm', 'pip', 'pip3']);
  if (banned.has(runCommand[0])) {
    return { ok: false, error: `run_command binary not allowed in sandbox: ${runCommand[0]}` };
  }

  const absFile = join(workdir, filename);
  mkdirSync(join(absFile, '..'), { recursive: true });
  writeFileSync(absFile, script, { encoding: 'utf8', mode: 0o644 });
  if (filename.endsWith('.sh')) chmodSync(absFile, 0o755);

  const envPairs = Object.entries(containerEnv()).flatMap(([k, v]) => ['-e', `${k}=${v}`]);

  // --network none: no network namespace
  // --rm: delete container after exit
  // no mounts other than workdir; no --volume of host home / docker.sock / .git
  const args = [
    'run',
    '--rm',
    '--network', 'none',
    '--memory', memory,
    '--cpus', String(cpus),
    '--pids-limit', '256',
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    '--tmpfs', '/run:rw,noexec,nosuid,size=16m',
    '-v', `${workdir}:/work:rw`,
    '-w', '/work',
    '--user', 'node',
    ...envPairs,
    // Drop ambient capabilities; no privilege escalation path.
    '--security-opt', 'no-new-privileges',
    '--cap-drop', 'ALL',
    image,
    // In-container timeout as a second limit (wrapper timeout is the first).
    'timeout',
    '--signal=KILL',
    String(Math.max(1, Math.floor(timeoutMs / 1000))),
    ...runCommand,
  ];

  const bin = dockerBin();
  const result = await run(bin, args, {
    env: dockerEnv(),
    // Wrapper slightly above container timeout so docker can report cleanly.
    timeoutMs: timeoutMs + 15_000,
  });

  return {
    ok: true,
    image,
    dockerBin: bin,
    memory,
    cpus,
    network: 'none',
    filename,
    runCommand,
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    timedOut: result.timedOut || result.exitCode === 124,
    signal: result.signal,
  };
}

export { DEFAULT_IMAGE };
