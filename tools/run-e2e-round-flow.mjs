#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const FLOW_STAGES = Object.freeze([
  {
    id: 'addNewKey',
    title: 'Add new key',
    businessStep: 'signup -> add a deactivate key commitment',
    circuit: 'add-new-key-native',
    fixtureFile: 'add-new-key-native.json',
    operation: 'add-new-key',
    wrapperStateArgs: ['--new-state-commitment', '<NEW_STATE_COMMITMENT>'],
    explains:
      'The JS fixture creates the key/nullifier/deactivate-leaf witness. Atlantic proves the Cairo program. The wrapper consumes the registered fact and records the key nullifier / state commitment.',
  },
  {
    id: 'processDeactivate',
    title: 'Process deactivate',
    businessStep: 'deactivate',
    circuit: 'process-deactivate-stage-native',
    fixtureFile: 'process-deactivate-stage-native.json',
    operation: 'process-deactivate',
    wrapperStateArgs: ['--state-commitment', '<CURRENT_STATE_COMMITMENT>'],
    explains:
      'The stage program proves the full 3-message deactivate batch: boundary, coord key, command ECDH, leaf ECDH, signature, decrypt, and core transition links.',
  },
  {
    id: 'processMessages',
    title: 'Process messages',
    businessStep: 'vote messages -> update state/vote roots',
    circuit: 'process-messages-stage-native',
    fixtureFile: 'process-messages-stage-native.json',
    operation: 'process-messages',
    wrapperStateArgs: [],
    explains:
      'The JS fixture contains three vote commands. The Cairo stage proves ECDH/decrypt/signature/core links and outputs current/new state commitments plus deactivate commitment.',
  },
  {
    id: 'tally',
    title: 'Tally',
    businessStep: 'read final vote leaves -> update tally result commitment',
    circuit: 'tally-native',
    fixtureFile: 'tally-native.json',
    operation: 'tally',
    wrapperStateArgs: [],
    explains:
      'The tally input reads the final vote leaves from the processMessages result. The wrapper accepts the registered fact and updates the tally commitment.',
  },
]);

function usage() {
  return `Usage:
  node tools/run-e2e-round-flow.mjs [options]

Options:
  --out-dir <path>          Output directory. Default: target/e2e-round-flow
  --fixture-dir <path>      Existing full-round fixture directory. Default: <out-dir>/fixture
  --execute-local           Generate fixture, Stone/Atlantic program+input bundles locally.
  --submit-atlantic         Submit generated Atlantic bundles. Requires ATLANTIC key env.
  --api-key-env <name>      API key env var for Atlantic submit. Default: ATLANTIC_KEY
  --env-file <path>         Load dotenv-style env before submit/fetch. Default: .env if present
  --query-map <path>        JSON object mapping stage ids to Atlantic query ids.
  --fetch-atlantic          Fetch query results and metadata for ids from --query-map.
  --wrapper-address <addr>  MockAmaciRound/AMACI wrapper contract address.
  --profile <name>          sncast profile for exported wrapper commands.
  --export-wrapper-calls    Export wrapper submit commands from fetched Atlantic metadata.
  --text                    Print a compact human-readable flow.
  --help                    Show this help.

Default mode is documentation/dry-run: it writes flow-manifest.json only and
does not submit to Atlantic or Starknet.
`;
}

function parseArgs(argv) {
  const args = {
    outDir: 'target/e2e-round-flow',
    fixtureDir: undefined,
    executeLocal: false,
    submitAtlantic: false,
    apiKeyEnv: 'ATLANTIC_KEY',
    envFile: '.env',
    queryMapPath: undefined,
    fetchAtlantic: false,
    wrapperAddress: undefined,
    profile: undefined,
    exportWrapperCalls: false,
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out-dir') {
      args.outDir = argv[++i];
    } else if (arg === '--fixture-dir') {
      args.fixtureDir = argv[++i];
    } else if (arg === '--execute-local') {
      args.executeLocal = true;
    } else if (arg === '--submit-atlantic') {
      args.submitAtlantic = true;
      args.executeLocal = true;
    } else if (arg === '--api-key-env') {
      args.apiKeyEnv = argv[++i];
    } else if (arg === '--env-file') {
      args.envFile = argv[++i];
    } else if (arg === '--query-map') {
      args.queryMapPath = argv[++i];
    } else if (arg === '--fetch-atlantic') {
      args.fetchAtlantic = true;
    } else if (arg === '--wrapper-address') {
      args.wrapperAddress = argv[++i];
    } else if (arg === '--profile') {
      args.profile = argv[++i];
    } else if (arg === '--export-wrapper-calls') {
      args.exportWrapperCalls = true;
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (args.exportWrapperCalls && (!args.wrapperAddress || !args.profile)) {
    throw new Error('--export-wrapper-calls requires --wrapper-address and --profile');
  }
  if ((args.fetchAtlantic || args.exportWrapperCalls) && !args.queryMapPath) {
    throw new Error('--fetch-atlantic/--export-wrapper-calls require --query-map');
  }
  return args;
}

function shellQuote(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(text)) {
    return text;
  }
  return `'${text.replaceAll("'", "'\\''")}'`;
}

function commandLine(command, args) {
  return [command, ...args].map(shellQuote).join(' ');
}

function envPassthroughCommand(targetEnv, sourceEnv, command) {
  return `${targetEnv}="$${sourceEnv}" ${shellQuote(command)}`;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 128,
  });
  if (result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    const details = [result.stdout, result.stderr]
      .filter(Boolean)
      .join('\n')
      .split('\n')
      .filter((line) => line.trim() !== '')
      .slice(-12)
      .join('\n');
    throw new Error(
      `command failed: ${commandLine(command, args)}${details ? `\n${details}` : ''}`,
    );
  }
  return result;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function loadEnvFile(path) {
  const envPath = resolve(path);
  if (!existsSync(envPath)) {
    return undefined;
  }
  const text = readFileSync(envPath, 'utf8');
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    const equals = line.indexOf('=');
    if (equals <= 0) {
      continue;
    }
    const key = line.slice(0, equals).trim();
    let value = line.slice(equals + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
  return envPath;
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function loadQueryMap(path) {
  if (!path) {
    return {};
  }
  const raw = readJson(resolve(path));
  return Object.fromEntries(
    Object.entries(raw).map(([key, value]) => [key, typeof value === 'string' ? value : value.queryId]),
  );
}

function stagePaths({ outDir, fixtureDir }, stage) {
  const stageDir = resolve(outDir, 'stages', stage.id);
  return {
    stageDir,
    fixtureInput: resolve(fixtureDir, stage.fixtureFile),
    stoneAirDir: resolve(stageDir, 'stone-air'),
    stoneAirRun: resolve(stageDir, 'stone-air', 'stone-air-run.json'),
    atlanticBundleDir: resolve(stageDir, 'atlantic-query'),
    atlanticBundle: resolve(stageDir, 'atlantic-query', 'atlantic-query-bundle.json'),
    atlanticSubmitScript: resolve(stageDir, 'atlantic-query', 'submit-atlantic-query.sh'),
    atlanticSubmitResponse: resolve(stageDir, 'atlantic-submit-response.json'),
    queryResultDir: resolve(stageDir, 'atlantic-result'),
    queryResult: resolve(stageDir, 'atlantic-result', 'atlantic-query-result.json'),
    metadata: resolve(stageDir, 'atlantic-result', 'artifacts', 'metadata.json'),
    wrapperCall: resolve(stageDir, 'wrapper-call.json'),
  };
}

function wrapperArgsForStage(stage) {
  return [
    '--operation',
    stage.operation,
    ...stage.wrapperStateArgs,
  ];
}

function buildStagePlan(context, stage, queryId) {
  const paths = stagePaths(context, stage);
  const localCommands = {
    stoneAir: commandLine('tools/run-stone-air.sh', [
      '--circuit',
      stage.circuit,
      '--input',
      paths.fixtureInput,
      '--out-dir',
      paths.stoneAirDir,
      '--skip-cairo1-run',
    ]),
    atlanticBundle: commandLine('node', [
      'tools/export-atlantic-query-bundle.mjs',
      '--stone-air-run',
      paths.stoneAirRun,
      '--out-dir',
      paths.atlanticBundleDir,
      '--external-id',
      `amaci-${stage.id}`,
      '--text',
    ]),
  };
  return {
    id: stage.id,
    title: stage.title,
    businessStep: stage.businessStep,
    explains: stage.explains,
    circuit: stage.circuit,
    operation: stage.operation,
    files: {
      fixtureInput: paths.fixtureInput,
      stoneAirRun: paths.stoneAirRun,
      atlanticBundle: paths.atlanticBundle,
      submitScript: paths.atlanticSubmitScript,
      submitResponse: paths.atlanticSubmitResponse,
      queryResult: paths.queryResult,
      metadata: paths.metadata,
      wrapperCall: paths.wrapperCall,
    },
    status: {
      fixtureInputExists: existsSync(paths.fixtureInput),
      stoneAirRunExists: existsSync(paths.stoneAirRun),
      atlanticBundleExists: existsSync(paths.atlanticBundle),
      queryId: queryId ?? undefined,
      queryResultExists: existsSync(paths.queryResult),
      metadataExists: existsSync(paths.metadata),
      wrapperCallExists: existsSync(paths.wrapperCall),
    },
    dataFlow: [
      'JS fixture JSON is the business witness/input for this stage.',
      'tools/run-stone-air.sh converts it into a Cairo1 Sierra programFile and cairo1-run inputFile.',
      'tools/export-atlantic-query-bundle.mjs writes the Atlantic POST payload and submit script.',
      'Atlantic returns queryId, then final-query-summary.json and metadata.json after DONE.',
      'tools/export-atlantic-mock-round-call.mjs reconstructs the fact binding and emits the wrapper sncast command.',
    ],
    commands: {
      ...localCommands,
      submitAtlantic: envPassthroughCommand('ATLANTIC_API_KEY', context.apiKeyEnv, paths.atlanticSubmitScript),
      fetchAtlantic: queryId
        ? commandLine('node', [
            'tools/fetch-atlantic-query-result.mjs',
            '--query-id',
            queryId,
            '--out-dir',
            paths.queryResultDir,
            '--download-artifacts',
            '--api-key-env',
            context.apiKeyEnv,
            '--text',
          ])
        : '<requires query id>',
      exportWrapperCall: queryId
        ? commandLine('node', [
            'tools/export-atlantic-mock-round-call.mjs',
            '--query-result',
            paths.queryResult,
            '--metadata',
            paths.metadata,
            '--wrapper-address',
            context.wrapperAddress ?? '<WRAPPER_ADDRESS>',
            '--profile',
            context.profile ?? '<SNCAST_PROFILE>',
            ...wrapperArgsForStage(stage),
            '--out',
            paths.wrapperCall,
            '--text',
          ])
        : '<requires query id>',
      invokeWrapper:
        'jq -r .submit.command ' + shellQuote(paths.wrapperCall) + ' | bash',
    },
  };
}

function parseSubmitResponse(text) {
  const jsonStart = text.indexOf('{');
  if (jsonStart < 0) {
    return undefined;
  }
  const parsed = JSON.parse(text.slice(jsonStart));
  return parsed.atlanticQueryId;
}

function executeLocalForStage(stage, paths) {
  if (!existsSync(paths.fixtureInput)) {
    return { skipped: true, reason: `missing fixture input: ${paths.fixtureInput}` };
  }
  mkdirSync(paths.stageDir, { recursive: true });
  run('tools/run-stone-air.sh', [
    '--circuit',
    stage.circuit,
    '--input',
    paths.fixtureInput,
    '--out-dir',
    paths.stoneAirDir,
    '--skip-cairo1-run',
  ]);
  run('node', [
    'tools/export-atlantic-query-bundle.mjs',
    '--stone-air-run',
    paths.stoneAirRun,
    '--out-dir',
    paths.atlanticBundleDir,
    '--external-id',
    `amaci-${stage.id}`,
    '--text',
  ]);
  return { skipped: false };
}

function submitAtlanticForStage(stage, paths, apiKeyEnv) {
  if (!existsSync(paths.atlanticSubmitScript)) {
    return { skipped: true, reason: `missing submit script: ${paths.atlanticSubmitScript}` };
  }
  const apiKey = process.env[apiKeyEnv];
  if (!apiKey) {
    return { skipped: true, reason: `missing API key env: ${apiKeyEnv}` };
  }
  const result = run(paths.atlanticSubmitScript, [], {
    env: { ...process.env, ATLANTIC_API_KEY: apiKey },
  });
  writeFileSync(paths.atlanticSubmitResponse, result.stdout);
  return { skipped: false, queryId: parseSubmitResponse(result.stdout) };
}

function fetchAtlanticForStage(paths, queryId, apiKeyEnv) {
  if (!queryId) {
    return { skipped: true, reason: 'missing query id' };
  }
  run('node', [
    'tools/fetch-atlantic-query-result.mjs',
    '--query-id',
    queryId,
    '--out-dir',
    paths.queryResultDir,
    '--download-artifacts',
    '--api-key-env',
    apiKeyEnv,
    '--text',
  ]);
  return { skipped: false };
}

function exportWrapperCallForStage(context, stage, paths, queryId) {
  if (!queryId) {
    return { skipped: true, reason: 'missing query id' };
  }
  if (!existsSync(paths.queryResult) || !existsSync(paths.metadata)) {
    return { skipped: true, reason: 'missing fetched Atlantic query result or metadata' };
  }
  run('node', [
    'tools/export-atlantic-mock-round-call.mjs',
    '--query-result',
    paths.queryResult,
    '--metadata',
    paths.metadata,
    '--wrapper-address',
    context.wrapperAddress,
    '--profile',
    context.profile,
    ...wrapperArgsForStage(stage),
    '--out',
    paths.wrapperCall,
    '--text',
  ]);
  return { skipped: false };
}

function runStageAction(stage, action, callback) {
  try {
    return { stage: stage.id, action, result: callback() };
  } catch (error) {
    return {
      stage: stage.id,
      action,
      result: {
        skipped: false,
        failed: true,
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

function textReport(manifest) {
  const lines = [
    `E2E round flow manifest: ${manifest.files.manifest}`,
    `Fixture dir: ${manifest.files.fixtureDir}`,
    '',
    'Business flow:',
    '  signup -> vote -> deactivate -> vote -> processMsg -> tally',
    '',
    'Proof/wrapper stages:',
  ];
  for (const stage of manifest.stages) {
    lines.push(`  - ${stage.id}: ${stage.circuit}`);
    lines.push(`    input: ${stage.files.fixtureInput}`);
    lines.push(`    fixture exists: ${stage.status.fixtureInputExists ? 'yes' : 'no'}`);
    lines.push(`    Atlantic bundle exists: ${stage.status.atlanticBundleExists ? 'yes' : 'no'}`);
    lines.push(`    query id: ${stage.status.queryId ?? 'none'}`);
    if (!stage.status.fixtureInputExists) {
      lines.push(`    blocker: fixture input is missing, so this stage cannot be submitted yet`);
    }
    const executed = manifest.execution.filter((entry) => entry.stage === stage.id);
    for (const entry of executed) {
      if (entry.result.failed) {
        lines.push(`    ${entry.action}: failed - ${entry.result.error}`);
      } else if (entry.result.skipped) {
        lines.push(`    ${entry.action}: skipped - ${entry.result.reason}`);
      } else {
        lines.push(`    ${entry.action}: ok`);
      }
    }
  }
  lines.push('');
  lines.push('Read flow-manifest.json for exact commands and data handoff paths.');
  return `${lines.join('\n')}\n`;
}

const args = parseArgs(process.argv.slice(2));
const outDir = resolve(args.outDir);
const fixtureDir = resolve(args.fixtureDir ?? `${outDir}/fixture`);
const manifestPath = resolve(outDir, 'flow-manifest.json');
mkdirSync(outDir, { recursive: true });
const loadedEnvFile = args.envFile ? loadEnvFile(args.envFile) : undefined;

const queryMap = loadQueryMap(args.queryMapPath);
const context = {
  outDir,
  fixtureDir,
  apiKeyEnv: args.apiKeyEnv,
  wrapperAddress: args.wrapperAddress,
  profile: args.profile,
};

const execution = [];

if (args.executeLocal) {
  run('node', ['tools/write-full-round-fixture.mjs', '--out-dir', fixtureDir, '--text']);
}

const generatedQueryMap = {};
for (const stage of FLOW_STAGES) {
  const paths = stagePaths(context, stage);
  if (args.executeLocal) {
    execution.push(runStageAction(stage, 'executeLocal', () => executeLocalForStage(stage, paths)));
  }
  if (args.submitAtlantic) {
    const entry = runStageAction(stage, 'submitAtlantic', () =>
      submitAtlanticForStage(stage, paths, args.apiKeyEnv),
    );
    execution.push(entry);
    const result = entry.result;
    if (result.queryId) {
      generatedQueryMap[stage.id] = result.queryId;
    }
  }
}

const effectiveQueryMap = { ...queryMap, ...generatedQueryMap };
for (const stage of FLOW_STAGES) {
  const paths = stagePaths(context, stage);
  const queryId = effectiveQueryMap[stage.id];
  if (args.fetchAtlantic) {
    execution.push(runStageAction(stage, 'fetchAtlantic', () =>
      fetchAtlanticForStage(paths, queryId, args.apiKeyEnv),
    ));
  }
  if (args.exportWrapperCalls) {
    execution.push(runStageAction(stage, 'exportWrapperCall', () =>
      exportWrapperCallForStage(context, stage, paths, queryId),
    ));
  }
}

const stages = FLOW_STAGES.map((stage) => buildStagePlan(context, stage, effectiveQueryMap[stage.id]));
const manifest = {
  schema: 'zkstark-amaci.e2e-round-flow.v1',
  mode: {
    executeLocal: args.executeLocal,
    submitAtlantic: args.submitAtlantic,
    fetchAtlantic: args.fetchAtlantic,
    exportWrapperCalls: args.exportWrapperCalls,
  },
  files: {
    manifest: manifestPath,
    fixtureDir,
    queryMap: args.queryMapPath ? resolve(args.queryMapPath) : undefined,
    envFile: loadedEnvFile,
  },
  businessFlow: ['signup', 'vote', 'deactivate', 'vote', 'processMsg', 'tally'],
  highLevelDataFlow: [
    'JS creates deterministic round fixture JSON files.',
    'Each fixture JSON is serialized into Cairo executable arguments.',
    'Stone/Atlantic packaging turns each Cairo program and input into programFile/inputFile.',
    'Atlantic proves and verifies on L2, then returns query status and metadata artifacts.',
    'Wrapper-call export reconstructs the registered fact and emits a sncast command.',
    'The wrapper contract checks fact hash, program hash, public output, verification hash, and security bits before mutating AMACI round state.',
  ],
  stages,
  execution,
};

writeJson(manifestPath, manifest);

if (Object.keys(generatedQueryMap).length > 0) {
  writeJson(resolve(outDir, 'generated-query-map.json'), generatedQueryMap);
}

if (args.text) {
  process.stdout.write(textReport(manifest));
} else {
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}
