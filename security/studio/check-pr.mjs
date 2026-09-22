#!/usr/bin/env node
/**
 * Studio security check — full pipeline on a machine with the installed stack
 * (scanners + CLI model subscriptions + Ollama lab + Colima sandbox).
 *
 * Primary use case (optimized): review your PRs on Studio with machine evidence.
 * Secondary use case (ready): point the same tool at any other codebase via
 * --dir / --target / --mode tree without rewiring the pipeline.
 *
 * Modes (scope):
 *   pr    — one GitHub PR (diff base...head)     <- primary
 *   local — current branch vs a base ref
 *   tree  — whole tree (empty-tree..HEAD)        <- test other codebases
 *
 * Targets (which codebase): security/studio/targets.json
 *
 * Exit: 0 pass, 1 block, 2 inconclusive lab on blocking severity, 3 setup/usage.
 */

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  rmSync,
  cpSync,
  mkdtempSync,
  statSync,
} from 'node:fs';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import {
  loadTargetsRegistry,
  getTarget,
  listTargets,
  resolveLocalPath,
  inferTargetId,
  hostAllowExtraEnv,
  resolveBase,
  EMPTY_TREE,
  expandPath,
} from './targets.mjs';
import { resolveDockerBin } from '../lab/sandbox.mjs';
import { resolveLabModelSpec } from './lab-model.mjs';
import { getUsageLog, resetUsageLog } from '../redteam/providers.mjs';
import { randomUUID } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../..');
const GATE = join(REPO_ROOT, 'security/gate/static-checks.sh');
const SCANNERS = join(REPO_ROOT, 'security/scanners/run-scanners.sh');
const NORMALIZE = join(REPO_ROOT, 'security/scanners/normalize.mjs');
const TRIAGE = join(REPO_ROOT, 'security/redteam/triage.mjs');
const HARNESS = join(REPO_ROOT, 'security/redteam/harness.mjs');
const LAB = join(REPO_ROOT, 'security/lab/run.mjs');
const CONFIG = join(REPO_ROOT, 'security/redteam/config.json');
const MARKER = '<!-- security-scan-studio -->';
const STAGE_STATUS_SCHEMA = 1;
const TRIAGE_VERDICTS = new Set(['true_positive', 'false_positive', 'needs_human']);
const TRIAGE_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'error', 'warning', 'note']);
const SECURITY_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const SARIF_LEVELS = new Set(['error', 'warning', 'note', 'none']);
const SARIF_SEVERITY = { error: 'error', warning: 'warning', note: 'note', none: 'note' };

function securityLevelForScore(score) {
  if (score === null || score === 0) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function findingAuthorities(finding) {
  const authorities = new Set();
  if (finding?.sarifLevel && Object.hasOwn(SARIF_SEVERITY, finding.sarifLevel)) {
    authorities.add(SARIF_SEVERITY[finding.sarifLevel]);
  }
  if (finding?.securitySeverity) authorities.add(finding.securitySeverity);
  if (finding?.scannerSeverity) authorities.add(finding.scannerSeverity);
  if (finding?.severity) authorities.add(finding.severity);
  return authorities;
}

function blocksByPolicy(finding, blockOn) {
  return [...findingAuthorities(finding)].some((authority) => blockOn.has(authority));
}

// ---------------------------------------------------------------- args

function parseArgs(argv) {
  const args = {};
  const multi = new Set(['host-allow-extra']);
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      const error = new Error('unexpected argument: ' + a);
      error.parsedArgs = args;
      throw error;
    }
    const key = a.slice(2);
    const bools = new Set([
      'local', 'post', 'skip-ai', 'no-lab', 'skip-scanners', 'skip-static',
      'keep-workdir', 'help', 'list-targets', 'tree',
    ]);
    if (bools.has(key)) {
      args[key] = true;
      continue;
    }
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      args[key] = true;
      continue;
    }
    if (multi.has(key)) {
      if (!Array.isArray(args[key])) args[key] = args[key] ? [args[key]] : [];
      args[key].push(next);
    } else {
      args[key] = next;
    }
    i += 1;
  }
  return args;
}

let runContext = null;

function usage(msg) {
  if (msg) console.error(msg);
  console.error(`Usage (primary — your PRs on Studio):
  node security/studio/check-pr.mjs --target dfx-api --pr 1234 --post
  node security/studio/check-pr.mjs --pr 42

Usage (local branch):
  node security/studio/check-pr.mjs --local --target dfx-services
  node security/studio/check-pr.mjs --dir ~/DFXswiss/api --base origin/develop

Usage (other codebases / full-tree test):
  node security/studio/check-pr.mjs --dir /path/to/code --mode tree
  node security/studio/check-pr.mjs --target generic --dir ~/scratch/lib --mode tree --skip-ai

Options:
  --target <id>         Profile from targets.json
  --list-targets        Print known targets and exit
  --mode pr|local|tree  Scope (default: pr if --pr, else local)
  --pr <n>              GitHub pull request number
  --repo owner/name     Override target.repo
  --dir / --repo-dir    Local checkout (preferred over clone)
  --base <ref>          Diff base (default from target)
  --host-allow-extra    Extra host regex for static gate (repeatable)
  --out <dir>           Report directory
  --lab-model <spec>    Default from config.lab.model (ollama:jk-coder)
  --max-lab <n>         Cap lab findings (default: config.lab.maxFindings or 5)
  --lab-timeout-s <n>   Per-finding lab wall clock (default: config.lab.timeoutS or 300)
  --lab-max-turns <n>   Lab iteration cap (default: config.lab.maxTurns or 6)
  --skip-ai / --no-lab / --skip-scanners / --skip-static
  --post                Upsert PR comment (pr mode only)
  --keep-workdir        Keep cache worktrees/clones`);
  if (msg && runContext) {
    writeFailureArtifacts(runContext.outDir, runContext.runId, 'usage: ' + msg);
  }
  process.exit(3);
}

const rawArgv = process.argv.slice(2);
let args;
try {
  args = parseArgs(rawArgv);
} catch (err) {
  args = err.parsedArgs || {};
  if (!args.help && !args['list-targets'] && args.out && args.out !== true) {
    initializeRunContext(args.out);
  }
  usage(err.message);
}
if (args.help) usage();

const valueOptions = new Set([
  'pr', 'out', 'mode', 'target', 'repo', 'dir', 'repo-dir', 'base',
  'host-allow-extra', 'lab-model', 'max-lab', 'lab-timeout-s', 'lab-max-turns',
]);
const missingValue = [...valueOptions].find((key) => args[key] === true);
if (missingValue === 'out') usage('missing value for --out');

function initializeRunContext(outArg) {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = resolve(outArg || join(process.cwd(), 'security-report', 'studio-' + ts));
  runContext = {
    outDir,
    runId: ts + '-' + process.pid + '-' + randomUUID(),
  };
  mkdirSync(outDir, { recursive: true });
  for (const artifact of ['gate.json', 'report.md']) {
    rmSync(join(outDir, artifact), { force: true });
  }
  resetUsageLog();
}

if (!args['list-targets']) initializeRunContext(args.out);
if (missingValue) usage('missing value for --' + missingValue);

let registry;
try {
  registry = loadTargetsRegistry();
} catch (err) {
  const reason = 'setup: ' + err.message;
  if (runContext) writeFailureArtifacts(runContext.outDir, runContext.runId, reason);
  console.error(reason);
  process.exit(3);
}
if (args['list-targets']) {
  for (const r of listTargets(registry)) {
    const mark = r.primary ? '*' : ' ';
    console.log(
      `${mark} ${r.id.padEnd(16)} ${(r.repo || '(local/generic)').padEnd(28)} ` +
        `base=${r.defaultBase}  ${r.label}`
    );
  }
  console.log('\n* = primary. Edit security/studio/targets.json to add more.');
  process.exit(0);
}

if (args.tree) args.mode = 'tree';
if (args.dir && !args['repo-dir']) args['repo-dir'] = args.dir;

function resolveRunMode(a) {
  if (a.mode === 'pr' || a.mode === 'local' || a.mode === 'tree') return a.mode;
  if (a.pr) return 'pr';
  if (a.local || a['repo-dir'] || a.dir) return 'local';
  return null;
}

if (args.mode !== undefined && !['pr', 'local', 'tree'].includes(args.mode)) {
  usage('invalid --mode ' + args.mode + '. Use pr, local, or tree.');
}

const runMode = resolveRunMode(args);
if (!runMode) usage('need --pr, --local, --dir, or --mode tree');

if (args.target && !getTarget(registry, args.target)) {
  usage(`unknown --target '${args.target}'. Use --list-targets.`);
}

const targetId = args.target
  || inferTargetId(registry, {
    repo: args.repo || null,
    dir: args['repo-dir'] || null,
  });
const target = getTarget(registry, targetId) || getTarget(registry, 'generic');

function collectHostExtras(a) {
  const out = [];
  const raw = a['host-allow-extra'];
  if (!raw) return out;
  const list = Array.isArray(raw) ? raw : [raw];
  for (const item of list) {
    for (const part of String(item).split(',')) {
      if (part.trim()) out.push(part.trim());
    }
  }
  return out;
}
const hostExtra = hostAllowExtraEnv(target, collectHostExtras(args));

// ---------------------------------------------------------------- shell helpers

function run(cmd, cmdArgs, { cwd, env, timeoutMs } = {}) {
  const r = spawnSync(cmd, cmdArgs, {
    cwd,
    env: env || process.env,
    encoding: 'utf8',
    timeout: timeoutMs ?? 600_000,
    maxBuffer: 20 * 1024 * 1024,
  });
  return {
    status: r.status === null ? (r.signal ? 128 : 1) : r.status,
    stdout: r.stdout || '',
    stderr: r.stderr || '',
    error: r.error?.message,
    signal: r.signal || null,
  };
}

function sh(cmd, cmdArgs, opts = {}) {
  const r = run(cmd, cmdArgs, opts);
  if (r.status !== 0) {
    const detail = (r.stderr || r.stdout || r.error || '').slice(0, 2000);
    throw new Error(`${cmd} ${cmdArgs.join(' ')} failed (exit ${r.status}): ${detail}`);
  }
  return r;
}

function log(section, msg) {
  console.log(`\n\x1b[1m> ${section}\x1b[0m  ${msg || ''}`.trimEnd());
}

function readJsonStrict(path) {
  if (!existsSync(path)) return { ok: false, reason: 'missing_output' };
  try {
    return { ok: true, value: JSON.parse(readFileSync(path, 'utf8')) };
  } catch {
    return { ok: false, reason: 'malformed_output' };
  }
}

function health(status, reasonCodes = []) {
  return { schemaVersion: STAGE_STATUS_SCHEMA, status, reasonCodes };
}

function skippedStage(name, reason = 'explicit_skip') {
  return {
    name,
    exit: 0,
    signal: null,
    blocked: false,
    skipped: true,
    health: health('skipped', [reason]),
  };
}

function writeFailureArtifacts(outDir, runId, message) {
  const reason = String(message || 'pipeline failure').slice(0, 2000);
  const gate = {
    runId,
    blocked: true,
    inconclusiveBlock: true,
    reasons: [reason],
    harnessBlocking: [],
  };
  writeFileSync(join(outDir, 'gate.json'), JSON.stringify(gate, null, 2));
  writeFileSync(join(outDir, 'report.md'), [
    '## Security Scan (Studio)',
    '',
    '> **Result: BLOCK**  - pipeline did not produce a complete scan.',
    '',
    '### Gate reasons',
    '',
    '- ' + reason,
    '',
  ].join('\n'));
}

function validateExecutionArtifact(path, { stage, runId, exit }) {
  const parsed = readJsonStrict(path);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  const value = parsed.value;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, reason: 'malformed_output' };
  }
  if (value.schemaVersion !== STAGE_STATUS_SCHEMA || value.stage !== stage) {
    return { ok: false, reason: 'invalid_schema' };
  }
  if (runId && value.runId !== runId) return { ok: false, reason: 'stale_output' };
  if (!['complete', 'incomplete', 'failed'].includes(value.status)) {
    return { ok: false, reason: 'invalid_status' };
  }
  if (!Number.isInteger(value.exit) || value.exit !== exit) {
    return { ok: false, reason: 'exit_mismatch' };
  }
  if (!Array.isArray(value.reasonCodes) || value.reasonCodes.some((x) => typeof x !== 'string')) {
    return { ok: false, reason: 'invalid_reason_codes' };
  }
  if (!['pass', 'block', 'inconclusive'].includes(value.outcome)) {
    return { ok: false, reason: 'invalid_outcome' };
  }
  const expectedExit = { pass: 0, block: 1, inconclusive: 3 };
  if (value.exit !== expectedExit[value.outcome]) {
    return { ok: false, reason: 'outcome_exit_mismatch' };
  }
  const validStatusOutcome =
    (value.status === 'complete' && ['pass', 'block'].includes(value.outcome)) ||
    (value.status === 'incomplete' && ['block', 'inconclusive'].includes(value.outcome)) ||
    (value.status === 'failed' && value.outcome === 'block');
  if (!validStatusOutcome) {
    return { ok: false, reason: 'status_outcome_mismatch' };
  }
  return { ok: true, value };
}

function healthFromExecution(execution) {
  return health(execution.status, execution.reasonCodes);
}

function stageEnv(base = process.env, runId = null) {
  const env = { ...base };
  if (runId) env.SECURITY_STUDIO_RUN_ID = runId;
  if (hostExtra) env.SECURITY_HOST_ALLOW_EXTRA = hostExtra;
  // Lab / docker resolution on Studio non-interactive shells (OrbStack + brew + go).
  // Prepend security/studio so `claude-via-gui` is found when linked only in-repo.
  env.PATH = [
    join(REPO_ROOT, 'security/studio'),
    `${homedir()}/.local/bin`,
    `${homedir()}/.local/node/bin`,
    '/usr/local/bin',
    '/opt/homebrew/opt/docker/bin',
    '/opt/homebrew/bin',
    `${homedir()}/go/bin`,
    env.PATH || '',
  ].join(':');
  if (!env.OLLAMA_API_KEY) env.OLLAMA_API_KEY = 'ollama';
  const colimaSock = `${homedir()}/.colima/default/docker.sock`;
  if (existsSync(colimaSock)) {
    // Prefer colima when its socket exists — host DOCKER_HOST is often stale.
    env.DOCKER_HOST = `unix://${colimaSock}`;
  }
  // Resolve docker once so sandbox children never depend on PATH alone.
  if (!env.DOCKER_BIN || !existsSync(env.DOCKER_BIN)) {
    try {
      env.DOCKER_BIN = resolveDockerBin();
    } catch {
      /* resolveDockerBin always returns a string; ignore */
    }
  }
  // Subscription-agent OAuth lives in the login keychain; SSH cannot read it.
  // providers.mjs routes claude-cli through this wrapper (Aqua GUI domain when needed).
  const claudeWrap = join(REPO_ROOT, 'security/studio/claude-via-gui.sh');
  if (existsSync(claudeWrap)) env.SECURITY_CLAUDE_WRAPPER = claudeWrap;
  return env;
}

// ---------------------------------------------------------------- resolve subject

function detectRepoFromDir(dir) {
  const r = run('gh', ['-R', dir, 'repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']);
  if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  const remote = run('git', ['-C', dir, 'remote', 'get-url', 'origin']);
  if (remote.status !== 0) return null;
  const m = remote.stdout.trim().match(/github\.com[:/](.+?)(?:\.git)?$/);
  return m ? m[1] : null;
}

function detectRepo() {
  if (args.repo) return args.repo;
  if (target?.repo) return target.repo;
  const r = run('gh', ['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']);
  if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  return null;
}

/**
 * Prefer an existing local checkout (fast, no network) over cloning.
 * For PR mode: fetch PR head into a disposable worktree under ~/.cache.
 */
function resolveSubject() {
  const overrideDir = args['repo-dir'] || null;
  const local = resolveLocalPath(target, overrideDir);
  const repo = args.repo || target?.repo || (local ? detectRepoFromDir(local) : null) || detectRepo();

  if (runMode === 'tree') {
    const dir = local || (overrideDir ? expandPath(overrideDir) : null);
    if (!dir) throw new Error('--mode tree needs --dir / --repo-dir or a target with localPaths');
    if (!existsSync(dir) || !statSync(dir).isDirectory()) {
      throw new Error(`not a directory: ${dir}`);
    }
    ensureGitRepo(dir);
    return {
      mode: 'tree',
      workdir: dir,
      base: EMPTY_TREE,
      headSha: run('git', ['-C', dir, 'rev-parse', 'HEAD']).stdout.trim() || 'tree',
      repo: repo || detectRepoFromDir(dir),
      pr: null,
      cleanup: false,
      targetId: target.id,
      targetLabel: target.label,
    };
  }

  if (runMode === 'local') {
    const dir = local || expandPath(overrideDir || process.cwd());
    if (!existsSync(dir) || !statSync(dir).isDirectory()) {
      throw new Error(`not a directory: ${dir}`);
    }
    ensureGitRepo(dir);
    const base = resolveBase(target, args.base, { mode: 'local' });
    ensureBaseRef(dir, base);
    return {
      mode: 'local',
      workdir: dir,
      base,
      headSha: run('git', ['-C', dir, 'rev-parse', 'HEAD']).stdout.trim() || 'local',
      repo: repo || detectRepoFromDir(dir),
      pr: null,
      cleanup: false,
      targetId: target.id,
      targetLabel: target.label,
    };
  }

  // ---- pr mode (primary) ----
  const pr = String(args.pr);
  if (!repo) throw new Error('--repo owner/name required (or set target.repo / run inside a checkout)');

  const meta = JSON.parse(
    sh('gh', ['pr', 'view', pr, '--repo', repo, '--json',
      'number,title,baseRefName,headRefName,headRefOid,url,state']).stdout
  );
  if (meta.state !== 'open' && meta.state !== 'OPEN') {
    console.warn(`warning: PR #${pr} state is ${meta.state}`);
  }

  const cacheRoot = join(homedir(), '.cache', 'security-studio');
  mkdirSync(cacheRoot, { recursive: true });

  let workdir;
  let cleanup = !args['keep-workdir'];

  if (local && existsSync(join(local, '.git'))) {
    // Fast path: worktree off the existing local clone
    log('worktree', `from local ${local}`);
    // PR head stays shallow (a PR's own commits are always few/recent). The base
    // branch is fetched WITHOUT a depth limit: a shallow depth on both sides is
    // exactly how a three-dot diff loses its merge-base on any repo whose base
    // branch has moved more than --depth commits since the PR forked (measured:
    // 47 of 144 real scans failed with "no merge base" from this before the fix).
    fetchPrHead(local, pr, `refs/security-scan/pr-${pr}`);
    fetchBaseFully(local, `+refs/heads/${meta.baseRefName}:refs/remotes/origin/${meta.baseRefName}`);
    workdir = mkdtempSync(join(cacheRoot, `wt-pr-${pr}-`));
    // remove empty dir so worktree add can use the path
    rmSync(workdir, { recursive: true, force: true });
    sh('git', ['-C', local, 'worktree', 'add', '--detach', workdir, `refs/security-scan/pr-${pr}`]);
    // Ensure origin/base is visible inside the worktree for three-dot diff
    fetchBaseFully(workdir, meta.baseRefName);
  } else {
    log('clone', `${repo} @ ${meta.headRefOid.slice(0, 8)}`);
    workdir = mkdtempSync(join(cacheRoot, `pr-${pr}-`));
    const cloneArgs = ['repo', 'clone', repo, workdir, '--', '--depth', '1'];
    sh('gh', cloneArgs, { timeoutMs: 300_000 });
    // Same reasoning as the fast path above: PR head shallow, base branch full.
    fetchPrHead(workdir, pr, 'refs/heads/pr-head');
    fetchBaseFully(workdir, `refs/heads/${meta.baseRefName}:refs/remotes/origin/${meta.baseRefName}`);
    sh('git', ['-C', workdir, 'checkout', '--force', 'pr-head']);
  }

  installGateInto(workdir);

  return {
    mode: 'pr',
    workdir,
    base: `origin/${meta.baseRefName}`,
    headSha: meta.headRefOid,
    repo,
    pr: Number(pr),
    title: meta.title,
    url: meta.url,
    cleanup,
    meta,
    targetId: target.id,
    targetLabel: target.label,
    localSource: local || null,
  };
}

function ensureGitRepo(dir) {
  const r = run('git', ['-C', dir, 'rev-parse', '--is-inside-work-tree']);
  if (r.status !== 0 || r.stdout.trim() !== 'true') {
    throw new Error(`not a git repository: ${dir}`);
  }
}

/**
 * Fetch a base branch with full history, refspec-agnostic. A plain `git fetch`
 * without --depth does NOT unshallow an already-shallow local clone (e.g. one
 * created earlier via `gh repo clone --depth 1`) — it just stays within the
 * existing shallow boundary. Detect that case and use --unshallow once; a
 * repo that is already full just gets a normal incremental fetch either way.
 */
function fetchBaseFully(dir, refspec) {
  const shallow = run('git', ['-C', dir, 'rev-parse', '--is-shallow-repository']);
  const isShallow = shallow.status === 0 && shallow.stdout.trim() === 'true';
  const args = ['-C', dir, 'fetch'];
  if (isShallow) args.push('--unshallow');
  args.push('origin', refspec);
  const r = run('git', args, { timeoutMs: 300_000 });
  // --unshallow fails on a repo with more than one root commit already fetched
  // via a prior partial deepen; fall back to a very large --depth in that case.
  if (r.status !== 0 && isShallow) {
    run('git', ['-C', dir, 'fetch', '--depth', '100000', 'origin', refspec], { timeoutMs: 300_000 });
  }
}

/**
 * Fetch a PR's head into a local ref, force-updating it. `dest` is always a
 * scratch ref this tool owns (`refs/security-scan/pr-<n>` on a persistent
 * per-target checkout, or `refs/heads/pr-head` in a throwaway clone) — never
 * something a human could have local commits on, so there is no reason to
 * preserve its previous value. Without the force prefix, a re-scan of the
 * same PR number after a rebase/force-push on GitHub leaves the old ref
 * pointing at a now-diverged commit and git refuses the non-fast-forward
 * update outright (measured: 9 of 217 real scans crashed this way).
 */
function fetchPrHead(dir, pr, dest) {
  sh('git', ['-C', dir, 'fetch', '--depth', '50', 'origin', `+pull/${pr}/head:${dest}`],
    { timeoutMs: 300_000 });
}

function ensureBaseRef(dir, base) {
  if (!base || base === EMPTY_TREE) return;
  const ok = run('git', ['-C', dir, 'rev-parse', '--verify', base]);
  if (ok.status === 0) return;
  const bare = base.replace(/^origin\//, '');
  fetchBaseFully(dir, bare);
  const again = run('git', ['-C', dir, 'rev-parse', '--verify', base]);
  if (again.status !== 0) {
    throw new Error(`base ref does not resolve: ${base} (in ${dir})`);
  }
}

/**
 * Copy gate tooling from this security-scan tree into the subject workdir when safe.
 * Authority: tools always execute via absolute paths from REPO_ROOT; overlay only when
 * the subject is security-scan itself (so PR heads cannot neuter the gate).
 */
function installGateInto(workdir) {
  const subjectIsSelf =
    existsSync(join(workdir, 'security/studio/check-pr.mjs')) ||
    existsSync(join(workdir, 'security/redteam/harness.mjs'));
  if (subjectIsSelf) {
    const bak = join(workdir, '.security-from-pr');
    if (existsSync(join(workdir, 'security'))) {
      rmSync(bak, { recursive: true, force: true });
      if (args['keep-workdir']) {
        cpSync(join(workdir, 'security'), bak, { recursive: true });
      }
      rmSync(join(workdir, 'security'), { recursive: true, force: true });
    }
  } else if (existsSync(join(workdir, 'security'))) {
    return;
  } else {
    // Foreign repo without security/ — optional: nothing to overlay; tools use REPO_ROOT paths.
    return;
  }
  cpSync(join(REPO_ROOT, 'security'), join(workdir, 'security'), {
    recursive: true,
    filter: (src) => {
      const base = basename(src);
      if (base === 'node_modules' || base === 'results') return false;
      return true;
    },
  });
}

// ---------------------------------------------------------------- stages

function buildDiff(subject, outDir) {
  const diffPath = join(outDir, 'pr.diff');
  let diff;
  if (subject.mode === 'tree') {
    // Full tree as added lines — empty-tree..HEAD
    diff = run('git', ['-C', subject.workdir, 'diff', EMPTY_TREE, 'HEAD']);
    if (diff.status !== 0) {
      // Some shallow clones lack the empty tree object; materialize it.
      run('git', ['-C', subject.workdir, 'hash-object', '-t', 'tree', '/dev/null']);
      diff = run('git', ['-C', subject.workdir, 'diff', EMPTY_TREE, 'HEAD']);
    }
  } else {
    diff = run('git', ['-C', subject.workdir, 'diff', `${subject.base}...HEAD`]);
  }
  if (diff.status !== 0) {
    const detail = (diff.stderr || diff.stdout || diff.error || '').trim().slice(0, 500);
    throw new Error('git diff failed (exit ' + diff.status + ')' + (detail ? ': ' + detail : ''));
  }
  writeFileSync(diffPath, diff.stdout);
  return diffPath;
}

function stageStatic(subject, outDir) {
  const base = subject.mode === 'tree' ? EMPTY_TREE : subject.base;
  log('static', `base=${base}${hostExtra ? ` hosts+=${hostExtra}` : ''}`);
  const r = run('bash', [GATE, base], {
    cwd: subject.workdir,
    env: stageEnv(),
    timeoutMs: 120_000,
  });
  writeFileSync(join(outDir, 'static.log'), `${r.stdout}\n${r.stderr}`);
  writeFileSync(join(outDir, 'static.json'), JSON.stringify({
    exit: r.status,
    blocked: r.status !== 0,
    hostAllowExtra: hostExtra || null,
  }, null, 2));
  if (r.status !== 0) {
    console.log(r.stdout);
    if (r.stderr) console.error(r.stderr);
  } else {
    console.log('  clean');
  }
  return {
    name: 'static', exit: r.status, signal: r.signal || null, blocked: r.status !== 0,
    health: health(r.status === 0 ? 'complete' : 'failed', r.status === 0 ? [] : ['stage_failed']),
  };
}

function stageScanners(subject, outDir) {
  log('scanners', subject.mode === 'tree' ? '(full tree)' : '');
  const sarifDir = join(outDir, 'sarif');
  if (existsSync(sarifDir)) rmSync(sarifDir, { recursive: true, force: true });
  mkdirSync(sarifDir, { recursive: true });
  const r = run('bash', [SCANNERS, subject.workdir, sarifDir], {
    cwd: subject.workdir,
    env: stageEnv(),
    timeoutMs: 600_000,
  });
  writeFileSync(join(outDir, 'scanners.log'), `${r.stdout}\n${r.stderr}`);
  console.log(r.stdout.trim().split('\n').slice(-20).join('\n'));

  const diffPath = buildDiff(subject, outDir);

  const findingsPath = join(outDir, 'findings.json');
  const scannerConfig = JSON.parse(readFileSync(CONFIG, 'utf8'));
  const blockOn = Array.isArray(scannerConfig.gate?.blockOn)
    ? scannerConfig.gate.blockOn.join(',')
    : 'critical,high,error';
  // Tree mode: still pass the synthetic full diff so normalize scopes to tracked files.
  // The standalone normalizer defaults to raw SARIF error; Studio supplies its configured
  // policy explicitly so the artifact and final gate use the same authorities.
  const n = run('node', [
    NORMALIZE,
    '--sarif', sarifDir,
    '--diff', diffPath,
    '--out', findingsPath,
    '--block-on', blockOn,
    '--no-gate',
  ], { cwd: subject.workdir, env: stageEnv() });
  writeFileSync(join(outDir, 'normalize.log'), `${n.stdout}\n${n.stderr}`);
  if (n.status !== 0 && n.status !== 1) {
    console.error(n.stderr || n.stdout);
  }
  const parsed = readJsonStrict(findingsPath);
  const findings = parsed.ok ? parsed.value : null;
  const list = findings && !Array.isArray(findings) && Array.isArray(findings.findings)
    ? findings.findings : null;
  const rawMetadata = readJsonStrict(join(sarifDir, 'scanners.json'));
  const rawScannerStatus = rawMetadata.ok && Array.isArray(rawMetadata.value)
    ? rawMetadata.value : null;
  const scannerStatus = findings && !Array.isArray(findings) && Array.isArray(findings.scanners)
    ? findings.scanners : rawScannerStatus;
  const incompleteSkips = (scannerStatus || []).filter(
    (scanner) => scanner.status === 'skipped' && scanner.reasonCode !== 'not_applicable_no_lockfile',
  );
  const reasons = [];
  if (r.status !== 0) reasons.push('scanner_stage_failed');
  if (n.status !== 0 && incompleteSkips.length === 0) reasons.push('normalization_failed');
  if ((!parsed.ok || !Array.isArray(list) || !Array.isArray(scannerStatus)) && incompleteSkips.length === 0) {
    reasons.push(parsed.ok ? 'malformed_output' : parsed.reason);
  }
  if (incompleteSkips.length) reasons.push('scanner_metadata_incomplete');
  const degraded = (scannerStatus || []).filter((scanner) => scanner.status === 'degraded');
  if (degraded.length) reasons.push('scanner_degraded');
  const incomplete = new Set(['scanner_degraded', 'scanner_metadata_incomplete']);
  const fatal = reasons.filter((reason) => !incomplete.has(reason));
  const stageHealth = health(
    fatal.length ? 'failed' : reasons.length ? 'incomplete' : 'complete',
    reasons,
  );
  console.log(`  ${(list || []).length} finding(s) in scope`);
  return {
    name: 'scanners',
    exit: n.status,
    signal: n.signal || r.signal || null,
    findings: list || [],
    findingsPath,
    diffPath,
    blocked: reasons.length > 0,
    health: stageHealth,
  };
}

function findingKey(f) {
  const capped = (value, limit) => String(value ?? '').slice(0, limit);
  return JSON.stringify([
    capped(f?.tool, 64),
    capped(f?.ruleId, 256),
    capped(f?.file, 1024),
    Number.isFinite(Number(f?.line)) ? Number(f.line) : 0,
    capped(f?.sarifLevel, 32),
    capped(f?.securitySeverity, 32),
    f?.securitySeverityScore == null ? null : Number(f.securitySeverityScore),
    capped(f?.securitySeveritySource, 128),
  ]);
}

function validTriageRow(f) {
  const hasScore = f?.securitySeverityScore !== undefined && f?.securitySeverityScore !== null;
  const scoreValid = !hasScore ||
    (typeof f.securitySeverityScore === 'number' && Number.isFinite(f.securitySeverityScore) &&
      f.securitySeverityScore >= 0 && f.securitySeverityScore <= 10);
  const securityLevelValid = f?.securitySeverity === undefined || f?.securitySeverity === null ||
    SECURITY_SEVERITIES.has(f?.securitySeverity);
  const sarifLevelValid = f?.sarifLevel === undefined || f?.sarifLevel === null ||
    SARIF_LEVELS.has(f?.sarifLevel);
  const sourceValid = f?.securitySeveritySource === undefined || f?.securitySeveritySource === null ||
    (typeof f?.securitySeveritySource === 'string' && f.securitySeveritySource.trim().length > 0);
  const scoreSourceValid = !hasScore ||
    (typeof f?.securitySeveritySource === 'string' && f.securitySeveritySource.trim().length > 0);
  const authorityPairValid = !hasScore ||
    (scoreSourceValid && securityLevelForScore(f.securitySeverityScore) === f.securitySeverity);
  const sourcePairValid = hasScore || f?.securitySeveritySource === undefined || f.securitySeveritySource === null;
  const absentScoreValid = hasScore || f?.securitySeverity === undefined || f.securitySeverity === null;
  return Boolean(
    f && typeof f === 'object' && !Array.isArray(f) &&
    typeof f.tool === 'string' &&
    typeof f.ruleId === 'string' &&
    typeof f.file === 'string' &&
    Number.isInteger(f.line) && f.line >= 0 &&
    TRIAGE_VERDICTS.has(f.verdict) &&
    TRIAGE_SEVERITIES.has(f.severity) &&
    TRIAGE_SEVERITIES.has(f.scannerSeverity) &&
    typeof f.reason === 'string' && f.reason.length > 0 &&
    scoreValid && securityLevelValid && sarifLevelValid && sourceValid &&
    authorityPairValid && sourcePairValid && absentScoreValid
  );
}

function stageTriage(subject, outDir, findingsPath, runId) {
  log('triage', '');
  const out = join(outDir, 'triaged.json');
  rmSync(out, { force: true });
  const r = run('node', [TRIAGE, '--findings', findingsPath, '--repo', subject.workdir, '--out', out], {
    cwd: subject.workdir,
    env: { ...stageEnv(process.env, runId), SECURITY_USAGE_LOG_FILE: usageLogFile(outDir) },
    timeoutMs: 600_000,
  });
  writeFileSync(join(outDir, 'triage.log'), `${r.stdout}\n${r.stderr}`);
  console.log(r.stdout.trim().split('\n').slice(-15).join('\n'));
  const execution = validateExecutionArtifact(out, { stage: 'triage', runId, exit: r.status });
  const parsed = readJsonStrict(out);
  const data = parsed.ok ? parsed.value : null;
  const triaged = data && !Array.isArray(data) && Array.isArray(data.triaged) ? data.triaged : null;
  const sourceParsed = readJsonStrict(findingsPath);
  const sourceFindings = sourceParsed.ok && sourceParsed.value && !Array.isArray(sourceParsed.value)
    ? sourceParsed.value.findings
    : sourceParsed.ok ? sourceParsed.value : null;
  const still = (triaged || []).filter(
    (f) => f.verdict === 'true_positive' || f.verdict === 'needs_human'
  );
  const rowsValid = Array.isArray(triaged) && triaged.every(validTriageRow);
  const hasBlockingArtifact = Number.isInteger(data?.blocking) && data.blocking > 0;
  const expectedBlockingExit = r.status === 1 && hasBlockingArtifact;
  const artifactReasons = Array.isArray(data?.reasonCodes)
    ? data.reasonCodes.filter((reason) => typeof reason === 'string')
    : [];
  const artifactIncomplete = data?.status === 'incomplete' || artifactReasons.length > 0;
  const reasons = execution.ok ? [...artifactReasons] : [execution.reason, ...artifactReasons];
  if (r.status !== 0 && !expectedBlockingExit && !artifactIncomplete) {
    reasons.push('triage_stage_failed');
  }
  if (!parsed.ok || !Array.isArray(triaged)) reasons.push(parsed.ok ? 'malformed_output' : parsed.reason);
  if (!rowsValid) reasons.push('triage_row_invalid');
  if (!Array.isArray(sourceFindings) || !Array.isArray(triaged) || sourceFindings.length !== triaged.length) {
    reasons.push('triage_coverage_mismatch');
  } else {
    const expected = new Map();
    for (const finding of sourceFindings) expected.set(findingKey(finding), (expected.get(findingKey(finding)) || 0) + 1);
    for (const finding of triaged) expected.set(findingKey(finding), (expected.get(findingKey(finding)) || 0) - 1);
    if ([...expected.values()].some((count) => count !== 0)) reasons.push('triage_coverage_mismatch');
  }
  if (execution.ok) {
    const declaredBlock = execution.value.outcome === 'block';
    const outcomeFindingsMismatch =
      (declaredBlock && !hasBlockingArtifact) ||
      (!declaredBlock && hasBlockingArtifact && execution.value.status === 'complete');
    if (outcomeFindingsMismatch) reasons.push('triage_outcome_findings_mismatch');
  }
  const uniqueReasons = [...new Set(reasons)];
  return {
    name: 'triage',
    exit: r.status,
    signal: r.signal || null,
    triaged: triaged || [],
    survivors: still,
    blocked: r.status === 1 || uniqueReasons.length > 0,
    out,
    health: health(
      uniqueReasons.length ? 'incomplete' : execution.ok ? execution.value.status : 'incomplete',
      uniqueReasons,
    ),
  };
}

function stageHarness(subject, outDir, diffPath, runId) {
  log('harness', 'hunt -> verify -> report');
  const harnessOut = join(outDir, 'harness');
  if (existsSync(harnessOut)) rmSync(harnessOut, { recursive: true, force: true });
  mkdirSync(harnessOut, { recursive: true });
  const r = run('node', [HARNESS, '--diff', diffPath, '--out', harnessOut, '--config', CONFIG], {
    cwd: subject.workdir,
    env: { ...stageEnv(process.env, runId), SECURITY_USAGE_LOG_FILE: usageLogFile(outDir) },
    timeoutMs: 900_000,
  });
  writeFileSync(join(outDir, 'harness.log'), `${r.stdout}\n${r.stderr}`);
  console.log(r.stdout.trim().split('\n').slice(-25).join('\n'));
  const execution = validateExecutionArtifact(join(harnessOut, 'execution.json'), {
    stage: 'harness', runId, exit: r.status,
  });
  const findingsFile = readJsonStrict(join(harnessOut, 'findings.json'));
  const findings = findingsFile.ok && Array.isArray(findingsFile.value) ? findingsFile.value : [];
  const report = existsSync(join(harnessOut, 'report.md'))
    ? readFileSync(join(harnessOut, 'report.md'), 'utf8')
    : '';
  const config = JSON.parse(readFileSync(CONFIG, 'utf8'));
  const blockOn = new Set(config.gate?.blockOn || ['critical', 'high', 'error']);
  const findingsValid = findingsFile.ok && Array.isArray(findingsFile.value);
  const survivors = findings.filter((f) => f.survived);
  const blocking = survivors.filter((f) => blockOn.has(f.severity));
  let artifactHealth = execution.ok
    ? healthFromExecution(execution.value)
    : health('incomplete', [execution.reason]);
  if (!findingsValid) {
    artifactHealth.status = 'incomplete';
    artifactHealth.reasonCodes = [...artifactHealth.reasonCodes, findingsFile.reason || 'malformed_findings'];
  }
  if (execution.ok) {
    const declaredBlock = execution.value.outcome === 'block';
    const diffBlock = execution.value.status === 'failed' && execution.value.reasonCodes.includes('diff_too_large');
    const outcomeFindingsMismatch =
      (declaredBlock && blocking.length === 0 && !diffBlock) ||
      (!declaredBlock && blocking.length > 0);
    if (outcomeFindingsMismatch) {
      artifactHealth = health('incomplete', [
        ...artifactHealth.reasonCodes,
        'outcome_findings_mismatch',
      ]);
    }
  }
  return {
    name: 'harness',
    exit: r.status,
    signal: r.signal || null,
    findings,
    survivors,
    blocking,
    report,
    harnessOut,
    blockOn: [...blockOn],
    blocked: r.status === 1 || artifactHealth.status !== 'complete',
    health: artifactHealth,
  };
}

function stageLab(subject, outDir, candidates, diffPath, config, runId) {
  if (!candidates.length) {
    log('lab', '0 candidate(s) -> Ollama sandbox');
    return { ...skippedStage('lab', 'no_candidates'), results: [], model: null };
  }

  const labRoot = join(outDir, 'lab');
  if (existsSync(labRoot)) rmSync(labRoot, { recursive: true, force: true });
  mkdirSync(labRoot, { recursive: true });
  const labCfg = config?.lab || {};
  const model = resolveLabModelSpec(config, args['lab-model'] || null);
  const maxLab = Math.max(1, Number(args['max-lab'] || labCfg.maxFindings || 5));
  const timeoutS = Number(args['lab-timeout-s'] || labCfg.timeoutS || 300);
  const maxTurns = Number(args['lab-max-turns'] || labCfg.maxTurns || 6);
  const slice = candidates.slice(0, maxLab);
  const results = [];

  log(
    'lab',
    `${candidates.length} candidate(s) -> Ollama sandbox · model=${model} maxLab=${maxLab} timeoutS=${timeoutS} maxTurns=${maxTurns}`,
  );

  const codeDir = join(outDir, 'lab-code');
  if (existsSync(codeDir)) rmSync(codeDir, { recursive: true, force: true });
  mkdirSync(codeDir, { recursive: true });
  stageCodeForLab(subject.workdir, codeDir, slice);

  for (let i = 0; i < slice.length; i += 1) {
    const f = slice[i];
    // The ordinal keeps distinct candidates isolated even when their titles slug alike.
    const id = `${String(i + 1).padStart(2, '0')}-${slug(f.title || f.file || `finding-${i}`)}`;
    const findingFile = join(labRoot, `${id}.finding.json`);
    const runOut = join(labRoot, id);
    writeFileSync(findingFile, JSON.stringify(f, null, 2));
    console.log(`  [${i + 1}/${slice.length}] ${f.severity || '?'} ${f.file || '?'}:${f.line || '?'} — ${f.title || id}`);

    const labArgs = [
      LAB,
      '--finding', findingFile,
      '--code-dir', codeDir,
      '--out', runOut,
      '--model', model,
      '--config', CONFIG,
      '--timeout-s', String(timeoutS),
      '--max-turns', String(maxTurns),
    ];
    if (diffPath && existsSync(diffPath) && subject.mode !== 'tree') {
      // Full-tree diffs are huge; lab only needs finding + staged code in tree mode.
      labArgs.push('--diff', diffPath);
    }

    const r = run('node', labArgs, {
      cwd: subject.workdir,
      env: { ...stageEnv(process.env, runId), SECURITY_USAGE_LOG_FILE: usageLogFile(outDir) },
      timeoutMs: Math.max(400_000, (timeoutS + 60) * 1000),
    });
    writeFileSync(join(runOut, 'lab-runner.log'), `${r.stdout}\n${r.stderr}`);
    const reportFile = readJsonStrict(join(runOut, 'report.json'));
    const report = reportFile.ok ? reportFile.value : null;
    const verdict = report?.verdict || (r.status === 3 ? 'setup-error' : 'inconclusive');
    console.log(`    -> ${verdict} (exit ${r.status})`);
    results.push({ finding: f, verdict, report, exit: r.status, signal: r.signal || null, out: runOut, model });
  }

  const reproduced = results.filter((r) => r.verdict === 'reproduced');
  const inconclusive = results.filter((r) => r.verdict === 'inconclusive' || r.verdict === 'setup-error');
  const invalid = results.some((r) => !r.report || !['reproduced', 'not-reproduced', 'inconclusive', 'setup-error'].includes(r.verdict));
  const invalidExit = results.some((r) => {
    // security/lab/run.mjs uses exit 0 for both conclusive verdicts. The
    // aggregate lab stage reports exit 1 when a finding was reproduced.
    if (r.verdict === 'reproduced') return r.exit !== 0;
    if (r.verdict === 'not-reproduced') return r.exit !== 0;
    if (r.verdict === 'inconclusive') return r.exit !== 2;
    if (r.verdict === 'setup-error') return r.exit !== 3;
    return true;
  });
  const incomplete = invalid || invalidExit || inconclusive.length > 0;
  return {
    name: 'lab',
    exit: reproduced.length ? 1 : 0,
    signal: results.find((x) => x.signal)?.signal || null,
    results,
    reproduced,
    inconclusive,
    blocked: reproduced.length > 0 || incomplete,
    model,
    health: health(incomplete ? 'incomplete' : 'complete', incomplete ? ['lab_execution_incomplete'] : []),
  };
}

function stageCodeForLab(srcRoot, destRoot, findings) {
  const files = new Set();
  for (const f of findings) {
    if (f.file) files.add(f.file.replace(/^\.\//, ''));
  }
  for (const extra of ['src', 'lib', 'app', 'packages']) {
    if (existsSync(join(srcRoot, extra))) {
      copyTree(join(srcRoot, extra), join(destRoot, extra));
    }
  }
  for (const rel of files) {
    const from = join(srcRoot, rel);
    if (!existsSync(from)) continue;
    const to = join(destRoot, rel);
    mkdirSync(dirname(to), { recursive: true });
    cpSync(from, to);
  }
  for (const f of ['package.json', 'tsconfig.json']) {
    if (existsSync(join(srcRoot, f))) cpSync(join(srcRoot, f), join(destRoot, f));
  }
}

function copyTree(from, to) {
  cpSync(from, to, {
    recursive: true,
    filter: (src) => {
      const base = basename(src);
      if (base === 'node_modules' || base === '.git' || base === 'dist' || base === 'coverage') {
        return false;
      }
      return true;
    },
  });
}

function slug(s) {
  return String(s)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48) || 'finding';
}

// ---------------------------------------------------------------- final gate + report

function finalGate({ staticResult, scannersResult, triageResult, harnessResult, labResult, config }) {
  const blockOn = new Set(config.gate?.blockOn || ['critical', 'high', 'error']);
  const reasons = [];
  let blocked = false;
  let inconclusiveBlock = false;

  for (const stage of [staticResult, scannersResult, triageResult, harnessResult, labResult]) {
    if (!stage?.health || stage.health.status === 'complete' || stage.health.status === 'skipped') continue;
    blocked = true;
    if (stage.health.status === 'incomplete') inconclusiveBlock = true;
    const detail = stage.health.reasonCodes?.length ? `: ${stage.health.reasonCodes.join(', ')}` : '';
    reasons.push(`${stage.name} execution ${stage.health.status}${detail}`);
  }

  if (staticResult?.blocked) {
    blocked = true;
    reasons.push('static gate blocked');
  }

  // Deterministic scanner findings remain blocking regardless of triage output. The triage
  // stage preserves scannerSeverity, but this second gate also fails closed if that artifact
  // is malformed or a provider incorrectly claims a blocking finding is a false positive.
  for (const f of scannersResult?.findings || []) {
    if (!blocksByPolicy(f, blockOn)) continue;
    blocked = true;
    reasons.push('scanner ' + f.severity + ': ' + (f.ruleId || f.title || f.file));
  }

  if (triageResult?.survivors) {
    const bad = triageResult.survivors.filter((f) => blocksByPolicy(f, blockOn) && f.verdict === 'true_positive');
    for (const f of bad) {
      blocked = true;
      reasons.push(`scanner true_positive: ${f.ruleId || f.title || f.file}`);
    }
  }

  // stageLab retains the original candidate object. Only that identity may receive its
  // verdict; file/line/title aliases can describe distinct root causes.
  const labByFinding = new Map();
  for (const r of labResult?.results || []) {
    labByFinding.set(r.finding, r);
  }

  const harnessBlocking = [];
  for (const f of harnessResult?.survivors || []) {
    if (!blockOn.has(f.severity) && !(labByFinding.size && labVerdict(f, labByFinding) === 'reproduced')) {
      continue;
    }
    const lv = labVerdict(f, labByFinding);
    if (lv === 'not-reproduced') {
      reasons.push(`lab cleared: ${f.title || f.file}`);
      continue;
    }
    if (lv === 'reproduced') {
      blocked = true;
      harnessBlocking.push({ ...f, lab: 'reproduced' });
      reasons.push(`lab reproduced: ${f.title || f.file}`);
      continue;
    }
    if (lv === 'inconclusive' || lv === 'setup-error') {
      if (blockOn.has(f.severity)) {
        blocked = true;
        inconclusiveBlock = true;
        harnessBlocking.push({ ...f, lab: lv });
        reasons.push(`lab ${lv} (kept blocking by severity): ${f.title || f.file}`);
      }
      continue;
    }
    if (blockOn.has(f.severity)) {
      blocked = true;
      harnessBlocking.push({ ...f, lab: 'skipped' });
      reasons.push(`harness ${f.severity}${f.unverified ? ' unverified' : ''}: ${f.title || f.file}`);
    }
  }

  return { blocked, inconclusiveBlock, reasons, harnessBlocking };
}

function labVerdict(finding, labByFinding) {
  return labByFinding.get(finding)?.verdict || null;
}

function usageLogFile(outDir) {
  return join(outDir, '.usage.jsonl');
}

function readUsageJsonl(path) {
  if (!existsSync(path)) return [];
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return [];
  }
  const out = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed));
    } catch {
      // skip a corrupt/partial line from a killed child
    }
  }
  return out;
}

/** File is the child-process source; in-memory is the fallback if this process called complete(). */
function collectUsageCalls(outDir) {
  const fromFile = readUsageJsonl(usageLogFile(outDir));
  const fromMem = getUsageLog();
  const seen = new Set();
  const calls = [];
  for (const e of [...fromFile, ...fromMem]) {
    const key = JSON.stringify(e);
    if (seen.has(key)) continue;
    seen.add(key);
    calls.push(e);
  }
  return calls;
}

function addToken(sum, value) {
  return sum + (typeof value === 'number' && Number.isFinite(value) ? value : 0);
}

/** Totals for usage.json: per-kind token sums; costUsd only over entries that have one. */
function summarizeUsage(calls) {
  const byKind = {};
  let inputTokens = 0;
  let outputTokens = 0;
  let cacheReadTokens = 0;
  let cacheCreationTokens = 0;
  let costUsd = 0;
  let costSeen = false;

  for (const c of calls) {
    const kind = c.kind || 'unknown';
    if (!byKind[kind]) {
      byKind[kind] = {
        calls: 0,
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheCreationTokens: 0,
        costUsd: null,
        _costSum: 0,
        _costSeen: false,
      };
    }
    const bucket = byKind[kind];
    bucket.calls += 1;
    bucket.inputTokens = addToken(bucket.inputTokens, c.inputTokens);
    bucket.outputTokens = addToken(bucket.outputTokens, c.outputTokens);
    bucket.cacheReadTokens = addToken(bucket.cacheReadTokens, c.cacheReadTokens);
    bucket.cacheCreationTokens = addToken(bucket.cacheCreationTokens, c.cacheCreationTokens);
    if (c.costUsd != null) {
      bucket._costSum += c.costUsd;
      bucket._costSeen = true;
      costUsd += c.costUsd;
      costSeen = true;
    }
    inputTokens = addToken(inputTokens, c.inputTokens);
    outputTokens = addToken(outputTokens, c.outputTokens);
    cacheReadTokens = addToken(cacheReadTokens, c.cacheReadTokens);
    cacheCreationTokens = addToken(cacheCreationTokens, c.cacheCreationTokens);
  }

  for (const bucket of Object.values(byKind)) {
    bucket.costUsd = bucket._costSeen ? bucket._costSum : null;
    delete bucket._costSum;
    delete bucket._costSeen;
  }

  return {
    calls,
    totals: {
      calls: calls.length,
      inputTokens,
      outputTokens,
      cacheReadTokens,
      cacheCreationTokens,
      costUsd: costSeen ? costUsd : null,
      byKind,
    },
  };
}

function usageReportLines(usage) {
  if (!usage?.calls?.length) return [];
  const t = usage.totals;
  const cost = t.costUsd != null
    ? ` · ~$${t.costUsd} (subscription CLI estimate, not billed)`
    : '';
  return [
    '### Model usage',
    `${t.calls} call(s) · ${t.inputTokens} input / ${t.outputTokens} output tokens` +
      ` (+ ${t.cacheReadTokens} cache-read)${cost} — siehe usage.json`,
    '',
  ];
}

function buildReport(subject, stages, gate, usage) {
  const head = String(subject.headSha || '').slice(0, 8);
  let scopeLine;
  if (subject.mode === 'pr') {
    scopeLine = `**PR:** [#${subject.pr}](${subject.url}) · **Head:** \`${head}\``;
  } else if (subject.mode === 'tree') {
    scopeLine = `**Tree audit** · **Head:** \`${head}\` · full repository`;
  } else {
    scopeLine = `**Local** · **Head:** \`${head}\` · **Base:** \`${subject.base}\``;
  }

  const lines = [
    '## Security Scan (Studio)',
    '',
    `**Target:** \`${subject.targetId || 'generic'}\`${subject.targetLabel ? ` — ${subject.targetLabel}` : ''}`,
    scopeLine,
    '',
    gate.blocked
      ? `> **Result: BLOCK** — ${gate.reasons.length} reason(s).`
      : '> **Result: PASS** — configured gate passed; see executed and skipped stages below.',
    '',
    '### Pipeline',
    '',
    `| Stage | Exit | Note |`,
    `|---|---|---|`,
    row('static', stages.static),
    row('scanners', stages.scanners, stages.scanners?.findings
      ? `${stages.scanners.findings.length} finding(s)` : ''),
    row('triage', stages.triage, stages.triage
      ? `${(stages.triage.survivors || []).length} kept` : 'skipped'),
    row('harness', stages.harness, stages.harness
      ? `${(stages.harness.survivors || []).length} survived verify` : 'skipped'),
    row('lab', stages.lab, stages.lab
      ? `${(stages.lab.reproduced || []).length} reproduced / ${(stages.lab.results || []).length} run`
      : 'skipped'),
    '',
    ...usageReportLines(usage),
  ];

  if (gate.reasons.length) {
    lines.push('### Gate reasons', '');
    for (const r of gate.reasons) lines.push(`- ${r}`);
    lines.push('');
  }

  if (stages.lab?.results?.length) {
    lines.push('### Lab evidence', '');
    for (const r of stages.lab.results) {
      const f = r.finding;
      lines.push(
        `- **${r.verdict}** — \`${f.file || '?'}:${f.line || '?'}\` ${f.title || ''}`
      );
      if (r.report?.reasoning) {
        lines.push(`  - ${String(r.report.reasoning).slice(0, 280)}`);
      }
      if (r.verdict === 'reproduced') {
        lines.push(
          '  - _Suggested follow-up:_ turn this shape into a Semgrep/CodeQL rule so the class is caught deterministically next time.'
        );
      }
    }
    lines.push('');
  }

  if (stages.harness?.report) {
    lines.push('### AI review', '', stages.harness.report, '');
  }

  lines.push(
    '---',
    '',
    '_Studio path: tools find → model filters → adversarial verify → local lab produces machine evidence. ' +
      'Modes: `pr` (primary), `local` (branch), `tree` (other codebases / full audit). ' +
      'Targets: `security/studio/targets.json`._',
    '',
    MARKER,
  );
  return lines.join('\n');
}

function row(name, stage, note = '') {
  if (!stage) return `| ${name} | — | ${note || 'skipped'} |`;
  if (stage.skipped || stage.health?.status === 'skipped') {
    const reason = stage.health?.reasonCodes?.[0] || note || 'skipped';
    return `| ${name} | — | skipped (${reason}) |`;
  }
  const mark = stage.blocked ? 'FAIL' : stage.exit === 0 ? 'ok' : 'warn';
  const exit = `${mark} ${stage.exit}${stage.signal ? ` (signal: ${stage.signal})` : ''}`;
  return `| ${name} | ${exit} | ${note} |`;
}

function postCommentSafe(subject, body) {
  if (subject.mode !== 'pr' || !subject.pr || !subject.repo) {
    throw new Error('--post requires --pr and a resolvable --repo');
  }
  log('post', `PR #${subject.pr} on ${subject.repo}`);
  const list = run('gh', [
    'api', `repos/${subject.repo}/issues/${subject.pr}/comments`, '--paginate',
  ]);
  if (list.status !== 0) throw new Error(`list comments failed: ${list.stderr}`);
  let comments = [];
  try {
    comments = JSON.parse(list.stdout || '[]');
  } catch {
    comments = [];
  }
  const mine = comments.find((c) => c.body && c.body.includes(MARKER));
  const payload = body.includes(MARKER) ? body : `${body}\n${MARKER}`;
  const cache = join(homedir(), '.cache', 'security-studio');
  mkdirSync(cache, { recursive: true });
  const bodyFile = join(cache, `comment-${subject.pr}.md`);
  const jsonFile = join(cache, `comment-${subject.pr}.json`);
  writeFileSync(bodyFile, payload);
  writeFileSync(jsonFile, JSON.stringify({ body: payload }));

  if (mine) {
    const p = run('gh', [
      'api', '-X', 'PATCH',
      `repos/${subject.repo}/issues/comments/${mine.id}`,
      '--input', jsonFile,
    ]);
    if (p.status !== 0) throw new Error(`update comment failed: ${p.stderr || p.stdout}`);
    console.log(`  updated comment ${mine.id}`);
    return;
  }

  const c = run('gh', [
    'pr', 'comment', String(subject.pr),
    '--repo', subject.repo,
    '--body-file', bodyFile,
  ]);
  if (c.status !== 0) throw new Error(`create comment failed: ${c.stderr || c.stdout}`);
  console.log('  created new PR comment');
}

function cleanupSubject(subject) {
  if (!subject?.cleanup || !subject.workdir) return;
  // Detach git worktree if we created one
  if (subject.localSource && existsSync(subject.workdir)) {
    run('git', ['-C', subject.localSource, 'worktree', 'remove', '--force', subject.workdir]);
  }
  if (subject.workdir.includes('security-studio')) {
    try {
      rmSync(subject.workdir, { recursive: true, force: true });
    } catch {
      /* keep for inspection */
    }
  }
}

// ---------------------------------------------------------------- main

async function main() {
  const { outDir, runId } = runContext;

  console.log(`\x1b[1msecurity-scan · Studio check\x1b[0m`);
  console.log(`target: ${target.id} (${target.label || ''})`);
  console.log(`mode:   ${runMode}`);
  console.log(`out:    ${outDir}`);
  if (hostExtra) console.log(`hosts+: ${hostExtra}`);

  let subject;
  try {
    subject = resolveSubject();
  } catch (err) {
    const reason = 'setup: ' + err.message;
    writeFailureArtifacts(outDir, runId, reason);
    console.error(reason);
    return 3;
  }

  writeFileSync(join(outDir, 'subject.json'), JSON.stringify({
    mode: subject.mode,
    workdir: subject.workdir,
    base: subject.base,
    headSha: subject.headSha,
    repo: subject.repo,
    pr: subject.pr,
    url: subject.url,
    targetId: subject.targetId,
    targetLabel: subject.targetLabel,
    localSource: subject.localSource || null,
    hostAllowExtra: hostExtra || null,
  }, null, 2));

  const config = JSON.parse(readFileSync(CONFIG, 'utf8'));
  const stages = {};

  try {
    if (!args['skip-static']) {
      stages.static = stageStatic(subject, outDir);
    } else {
      stages.static = skippedStage('static');
    }
    if (!args['skip-scanners']) {
      stages.scanners = stageScanners(subject, outDir);
    } else {
      const diffPath = buildDiff(subject, outDir);
      stages.scanners = {
        ...skippedStage('scanners'), findings: [], findingsPath: null, diffPath,
      };
    }

    const diffPath = stages.scanners.diffPath || join(outDir, 'pr.diff');

    if (!args['skip-ai']) {
      if (stages.scanners.findingsPath && stages.scanners.findings?.length) {
        stages.triage = stageTriage(subject, outDir, stages.scanners.findingsPath, runId);
      } else {
        stages.triage = skippedStage('triage', 'no_findings');
        stages.triage.triaged = [];
        stages.triage.survivors = [];
        console.log('\n> triage  (no scanner findings — skipped)');
      }
      stages.harness = stageHarness(subject, outDir, diffPath, runId);

      const labCandidates = (stages.harness.blocking || stages.harness.survivors || [])
        .filter((f) => f.survived);
      const forLab = labCandidates.length
        ? labCandidates
        : (stages.harness.survivors || []).filter((f) =>
          ['critical', 'high', 'error'].includes(f.severity));

      if (!args['no-lab'] && forLab.length) {
        stages.lab = stageLab(subject, outDir, forLab, diffPath, config, runId);
      } else if (args['no-lab']) {
        stages.lab = skippedStage('lab');
        console.log('\n> lab  skipped (--no-lab)');
      } else {
        stages.lab = skippedStage('lab', 'no_candidates');
        console.log('\n> lab  skipped (nothing to reproduce)');
      }
    } else {
      console.log('\n> AI stages skipped (--skip-ai)');
      stages.triage = skippedStage('triage');
      stages.harness = skippedStage('harness');
      stages.lab = skippedStage('lab');
    }

    const gate = finalGate({
      staticResult: stages.static,
      scannersResult: stages.scanners,
      triageResult: stages.triage,
      harnessResult: stages.harness,
      labResult: stages.lab,
      config,
    });
    gate.runId = runId;

    // .usage.jsonl is kept as a hidden internal artifact (child-process writes).
    const usage = summarizeUsage(collectUsageCalls(outDir));
    writeFileSync(join(outDir, 'usage.json'), JSON.stringify(usage, null, 2));
    const report = buildReport(subject, stages, gate, usage);
    writeFileSync(join(outDir, 'report.md'), report);
    writeFileSync(join(outDir, 'gate.json'), JSON.stringify(gate, null, 2));
    console.log(`\n${report.split('\n').slice(0, 45).join('\n')}`);
    console.log(`\nfull report: ${join(outDir, 'report.md')}`);

    if (args.post) {
      try {
        postCommentSafe(subject, report);
      } catch (err) {
        console.error(`post failed: ${err.message}`);
      }
    }

    if (gate.blocked) {
      console.error(`\n\x1b[31mBLOCK\x1b[0m ${gate.reasons.join('; ')}`);
      return gate.inconclusiveBlock && !stages.lab?.reproduced?.length ? 2 : 1;
    }
    console.log('PASS');
    return 0;
  } catch (err) {
    const reason = 'pipeline_error: ' + err.message;
    writeFailureArtifacts(outDir, runId, reason);
    console.error(reason);
    return 3;
  } finally {
    cleanupSubject(subject);
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`check-pr failed: ${err.stack || err.message}`);
    process.exit(3);
  }
);
