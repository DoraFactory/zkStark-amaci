#!/usr/bin/env node
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

function usage() {
  console.log(`Usage:
  node tools/inspect-stone-pipeline.mjs [options]

Options:
  --out-dir <dir>   Directory for inspection artifacts. Default: target/stone-inspect
  --timeout-ms <n>  Per-command timeout. Default: 10000
  --text           Print a text summary.
  --help           Show this help.

This command does not generate a proof. It records the locally installed
Stone/Integrity CLI surfaces and the Cairo executable artifacts available in
this repository so the Stone proof pipeline can be wired against the actual
tool versions installed on the prover machine.`);
}

function parseArgs(argv) {
  const args = {
    outDir: 'target/stone-inspect',
    timeoutMs: 10000,
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      usage();
      process.exit(0);
    } else if (arg === '--out-dir') {
      args.outDir = argv[++i];
    } else if (arg === '--timeout-ms') {
      args.timeoutMs = Number(argv[++i]);
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!Number.isInteger(args.timeoutMs) || args.timeoutMs <= 0) {
    throw new Error('--timeout-ms must be a positive integer');
  }

  return args;
}

function run(command, commandArgs, timeoutMs) {
  const result = spawnSync(command, commandArgs, {
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer: 1024 * 1024 * 4,
  });

  return {
    command: [command, ...commandArgs],
    status: result.status,
    signal: result.signal,
    error: result.error ? result.error.message : undefined,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    timedOut: result.error?.code === 'ETIMEDOUT',
  };
}

function which(command) {
  const result = spawnSync('which', [command], {
    encoding: 'utf8',
    timeout: 5000,
  });
  if (result.status !== 0) {
    return undefined;
  }
  return result.stdout.trim() || undefined;
}

function walkFiles(dir, predicate, out = []) {
  if (!existsSync(dir)) {
    return out;
  }
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const st = statSync(path);
    if (st.isDirectory()) {
      walkFiles(path, predicate, out);
    } else if (predicate(path, st)) {
      out.push(path);
    }
  }
  return out;
}

function fileInfo(path) {
  const st = statSync(path);
  return {
    path: resolve(path),
    bytes: st.size,
  };
}

function commandOutputPath(outDir, name, stream) {
  return join(outDir, `${name}.${stream}.txt`);
}

function inspect(args) {
  const rootDir = resolve(new URL('..', import.meta.url).pathname);
  const outDir = resolve(args.outDir);
  mkdirSync(outDir, { recursive: true });

  const toolCommands = [
    ['cairo1-run', ['--help']],
    ['cpu_air_prover', ['--help']],
    ['cpu_air_verifier', ['--help']],
    ['proof_serializer', ['--help']],
  ];

  const tools = {};
  for (const [tool, toolArgs] of toolCommands) {
    const result = run(tool, toolArgs, args.timeoutMs);
    writeFileSync(commandOutputPath(outDir, tool, 'stdout'), result.stdout);
    writeFileSync(commandOutputPath(outDir, tool, 'stderr'), result.stderr);
    tools[tool] = {
      path: which(tool),
      help: {
        command: result.command,
        status: result.status,
        signal: result.signal,
        error: result.error,
        timedOut: result.timedOut,
        stdoutPath: commandOutputPath(outDir, tool, 'stdout'),
        stderrPath: commandOutputPath(outDir, tool, 'stderr'),
        stdoutBytes: Buffer.byteLength(result.stdout),
        stderrBytes: Buffer.byteLength(result.stderr),
      },
    };
  }

  const cairoTargetDir = join(rootDir, 'cairo', 'target', 'dev');
  const executableArtifacts = walkFiles(cairoTargetDir, (path) => path.endsWith('.executable.json'))
    .sort()
    .map(fileInfo);
  const sierraArtifacts = walkFiles(cairoTargetDir, (path) => path.endsWith('.sierra.json'))
    .sort()
    .map(fileInfo);
  const casmArtifacts = walkFiles(cairoTargetDir, (path) => path.endsWith('.casm'))
    .sort()
    .map(fileInfo);

  const sampleArgs = walkFiles(join(rootDir, 'target'), (path) => path.endsWith('-cairo-args.json'))
    .sort()
    .slice(0, 25)
    .map(fileInfo);

  const report = {
    schema: 'zkstark-amaci.stone-pipeline-inspection.v1',
    rootDir,
    outDir,
    tools,
    artifacts: {
      cairoTargetDir,
      executableArtifacts,
      sierraArtifacts,
      casmArtifacts,
      sampleArgs,
    },
    notes: [
      'This inspection does not generate Stone AIR inputs or proofs.',
      'Use the captured cairo1-run help output to confirm the supported argument and input-file flags.',
      'If cairo1-run cannot consume Scarb executable artifacts plus Serde arguments, add a Stone-specific Array<felt252> entrypoint wrapper before proving.',
    ],
  };

  const reportPath = join(outDir, 'stone-pipeline-inspection.json');
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);

  return { report, reportPath };
}

function formatText({ report, reportPath }) {
  const lines = [
    `Inspection report: ${reportPath}`,
    `Root: ${report.rootDir}`,
    '',
    'Tools:',
  ];

  for (const [name, info] of Object.entries(report.tools)) {
    const status = info.path ? 'ok' : 'missing';
    const helpStatus = info.help.timedOut
      ? 'timeout'
      : info.help.status === 0
        ? 'ok'
        : `exit ${info.help.status ?? 'unknown'}`;
    lines.push(`  ${status.padEnd(7)} ${name} ${info.path ?? ''}`);
    lines.push(`          help: ${helpStatus}, stdout ${info.help.stdoutBytes} bytes, stderr ${info.help.stderrBytes} bytes`);
  }

  lines.push('');
  lines.push(`Executable artifacts: ${report.artifacts.executableArtifacts.length}`);
  for (const artifact of report.artifacts.executableArtifacts.slice(0, 10)) {
    lines.push(`  - ${artifact.path}`);
  }
  if (report.artifacts.executableArtifacts.length > 10) {
    lines.push(`  - ... ${report.artifacts.executableArtifacts.length - 10} more`);
  }

  lines.push('');
  lines.push(`Sample Cairo args files: ${report.artifacts.sampleArgs.length}`);
  for (const argsFile of report.artifacts.sampleArgs.slice(0, 10)) {
    lines.push(`  - ${argsFile.path}`);
  }

  lines.push('');
  lines.push('Next: inspect cairo1-run.stdout.txt and confirm whether it supports executable JSON plus arguments-file input.');

  return lines.join('\n');
}

const args = parseArgs(process.argv.slice(2));
const result = inspect(args);
if (args.text) {
  console.log(formatText(result));
} else {
  console.log(result.reportPath);
}
