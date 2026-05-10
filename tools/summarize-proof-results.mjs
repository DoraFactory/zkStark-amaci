#!/usr/bin/env node
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { readdirSync } from 'node:fs';

const ROOT = resolve(new URL('..', import.meta.url).pathname);

function usage() {
  return `Usage:
  node tools/summarize-proof-results.mjs [root-dir] [options]

Options:
  --out <path>   Write JSON summary to a file.
  --text         Print a compact text table instead of JSON.

Default root-dir is target/.
`;
}

function parseArgs(argv) {
  const args = {
    rootDir: 'target',
    out: undefined,
    text: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else if (args.rootDir === 'target') {
      args.rootDir = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return args;
}

function walk(root) {
  if (!existsSync(root)) {
    return [];
  }
  const out = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(path);
      } else {
        out.push(path);
      }
    }
  }
  return out.sort();
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function fileSize(path) {
  return existsSync(path) ? statSync(path).size : undefined;
}

function maybePreparedPublicOutput(path) {
  if (!path || !existsSync(path)) {
    return undefined;
  }
  const prepared = readJson(path);
  return prepared.publicOutput?.felts?.length ?? prepared.publicOutput?.length ?? undefined;
}

function parseResourceUsage(stdoutPath) {
  if (!stdoutPath || !existsSync(stdoutPath)) {
    return undefined;
  }
  const source = readFileSync(stdoutPath, 'utf8');
  const pairs = {};
  for (const match of source.matchAll(/^\s*([A-Za-z][A-Za-z0-9 _-]+):\s*([0-9]+)\s*$/gm)) {
    const key = match[1].trim().toLowerCase().replaceAll(/[\s-]+/g, '_');
    pairs[key] = Number(match[2]);
  }
  return Object.keys(pairs).length === 0 ? undefined : pairs;
}

function collectProofRuns(rootDir) {
  return walk(rootDir)
    .filter((path) => basename(path) === 'proof-run.json')
    .map((path) => {
      const run = readJson(path);
      return {
        path,
        relativePath: relative(ROOT, path),
        circuit: run.circuit,
        executable: run.executable,
        executionId: run.executionId,
        proofJson: run.proofJson,
        proofSizeBytes: fileSize(run.proofJson),
        preparedJson: run.preparedJson,
        publicOutputFelts: maybePreparedPublicOutput(run.preparedJson),
        proveLog: run.proveLog,
        proveLogSizeBytes: fileSize(run.proveLog),
        verifyLog: run.verifyLog,
        verifyLogSizeBytes: fileSize(run.verifyLog),
      };
    });
}

function collectExecutions(rootDir) {
  return walk(rootDir)
    .filter((path) => path.endsWith('-execute.json'))
    .map((path) => {
      const run = readJson(path);
      return {
        path,
        relativePath: relative(ROOT, path),
        circuit: run.circuit,
        executable: run.executable,
        status: run.status,
        signal: run.signal,
        expectedPublicOutputFelts: run.expectedPublicOutputFelts,
        stdoutPath: run.stdoutPath,
        stdoutSizeBytes: fileSize(run.stdoutPath),
        stderrPath: run.stderrPath,
        stderrSizeBytes: fileSize(run.stderrPath),
        resourceUsage: parseResourceUsage(run.stdoutPath),
      };
    });
}

function textTable(summary) {
  const lines = [];
  lines.push('Proof runs:');
  if (summary.proofRuns.length === 0) {
    lines.push('  none');
  } else {
    for (const run of summary.proofRuns) {
      lines.push(
        `  ${run.circuit} ${run.executable} execution=${run.executionId} ` +
          `proof=${run.proofSizeBytes ?? 'missing'}B outputFelts=${run.publicOutputFelts ?? '?'}`,
      );
    }
  }
  lines.push('');
  lines.push('Executions:');
  if (summary.executions.length === 0) {
    lines.push('  none');
  } else {
    for (const run of summary.executions) {
      const steps = run.resourceUsage?.steps ?? run.resourceUsage?.execution_steps ?? '?';
      lines.push(
        `  ${run.circuit} ${run.executable} status=${run.status} steps=${steps} ` +
          `outputFelts=${run.expectedPublicOutputFelts ?? '?'}`,
      );
    }
  }
  return `${lines.join('\n')}\n`;
}

const args = parseArgs(process.argv.slice(2));
const rootDir = resolve(args.rootDir);
const summary = {
  rootDir,
  proofRuns: collectProofRuns(rootDir),
  executions: collectExecutions(rootDir),
};

const output = args.text ? textTable(summary) : `${JSON.stringify(summary, null, 2)}\n`;
if (args.out) {
  writeFileSync(resolve(args.out), output);
} else {
  process.stdout.write(output);
}
