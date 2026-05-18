#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { generateStoneParams } from '../src/stone-params.mjs';

function usage() {
  return `Usage:
  node tools/generate-stone-params.mjs --base <cpu_air_params.json> --air-public-input <air-public-input.json> --out <generated.json> [options]

Options:
  --profile <integrity|base>        Parameter profile. Default: integrity.
  --integrity-hasher <name>         Integrity commitment/POW hasher. Default: keccak_160_lsb.
                                    Supported: keccak_160_lsb, blake2s_248_lsb.
  --metadata-out <metadata.json>    Write generation metadata.
  --text                            Print a short summary.

Generates Stone CPU AIR parameters whose FRI degree matches the AIR n_steps.
The default integrity profile uses the Poseidon transcript expected by
Integrity/swiftness.`;
}

function parseArgs(argv) {
  const args = {
    base: undefined,
    airPublicInput: undefined,
    out: undefined,
    metadataOut: undefined,
    profile: 'integrity',
    integrityHasher: 'keccak_160_lsb',
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--base') {
      args.base = argv[++i];
    } else if (arg === '--air-public-input') {
      args.airPublicInput = argv[++i];
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--metadata-out') {
      args.metadataOut = argv[++i];
    } else if (arg === '--profile') {
      args.profile = argv[++i];
    } else if (arg === '--integrity-hasher') {
      args.integrityHasher = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.base || !args.airPublicInput || !args.out) {
    throw new Error(`missing required arguments\n\n${usage()}`);
  }

  return args;
}

const args = parseArgs(process.argv.slice(2));
const baseParams = JSON.parse(await readFile(args.base, 'utf8'));
const airPublicInput = JSON.parse(await readFile(args.airPublicInput, 'utf8'));
const { params, metadata } = generateStoneParams(baseParams, airPublicInput, {
  profile: args.profile,
  integrityHasher: args.integrityHasher,
});

await mkdir(path.dirname(args.out), { recursive: true });
await writeFile(args.out, `${JSON.stringify(params, null, 2)}\n`);

if (args.metadataOut) {
  await mkdir(path.dirname(args.metadataOut), { recursive: true });
  await writeFile(args.metadataOut, `${JSON.stringify(metadata, null, 2)}\n`);
}

if (args.text) {
  console.log(`generated parameter file: ${args.out}`);
  console.log(`profile: ${metadata.profile.name}`);
  if (metadata.profile.name === 'integrity') {
    console.log(`integrity hasher: ${metadata.profile.integrityHasher}`);
    console.log(`channel_hash: ${metadata.profile.channelHash}`);
    console.log(`commitment_hash: ${metadata.profile.commitmentHash}`);
    console.log(`pow_hash: ${metadata.profile.powHash}`);
    console.log(
      `n_verifier_friendly_commitment_layers: ${metadata.profile.nVerifierFriendlyCommitmentLayers}`,
    );
  }
  console.log(`n_steps: ${metadata.nSteps}`);
  console.log(`STARK degree bound: 2^${metadata.starkDegreeLog} (${metadata.starkDegreeBound})`);
  console.log(`last_layer_degree_bound: ${metadata.lastLayerDegreeBound}`);
  console.log(`fri_step_list: [${metadata.friStepList.join(', ')}]`);
  console.log(`FRI degree check: ${metadata.lastLayerDegreeLog} + ${metadata.friStepSum} = ${metadata.starkDegreeLog}`);
}
