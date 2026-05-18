import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';

const ATLANTIC_QUERY_ENDPOINT = 'https://atlantic.api.herodotus.cloud/atlantic-query';

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function fileInfo(path) {
  const st = statSync(path);
  return {
    path,
    bytes: st.size,
    sha256: `0x${sha256File(path)}`,
  };
}

function sanitizeArtifactName(url) {
  const parsed = new URL(url);
  const name = basename(parsed.pathname);
  if (!name) {
    throw new Error(`artifact URL has no file name: ${url}`);
  }
  return name.replaceAll(/[^a-zA-Z0-9._-]/g, '_');
}

function finalSummary(status) {
  const query = status.atlanticQuery ?? {};
  return {
    schema: 'zkstark-amaci.atlantic-query-summary.v1',
    id: query.id,
    externalId: query.externalId,
    dedupId: query.dedupId,
    transactionId: query.transactionId,
    status: query.status,
    step: query.step,
    result: query.result,
    network: query.network,
    chain: query.chain,
    sharpProver: query.sharpProver,
    layout: query.layout,
    cairoVm: query.cairoVm,
    cairoVersion: query.cairoVersion,
    declaredJobSize: query.declaredJobSize,
    jobSize: query.jobSize,
    isFactMocked: query.isFactMocked,
    isProofMocked: query.isProofMocked,
    programHash: query.programHash,
    integrityFactHash: query.integrityFactHash,
    sharpFactHash: query.sharpFactHash,
    errorReason: query.errorReason,
    createdAt: query.createdAt,
    completedAt: query.completedAt,
    metadataUrlCount: Array.isArray(status.metadataUrls) ? status.metadataUrls.length : 0,
  };
}

async function fetchJson(url, headers = {}) {
  const response = await fetch(url, { headers });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`GET ${url} failed with ${response.status}: ${body}`);
  }
  try {
    return JSON.parse(body);
  } catch (error) {
    throw new Error(`GET ${url} did not return JSON: ${error.message}`);
  }
}

async function downloadFile(url, outPath, headers = {}) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`download ${url} failed with ${response.status}: ${body}`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, bytes);
  return fileInfo(outPath);
}

export async function fetchAtlanticQueryResult(queryId, outDir, options = {}) {
  if (!queryId) {
    throw new Error('queryId is required');
  }
  const absoluteOutDir = resolve(outDir);
  mkdirSync(absoluteOutDir, { recursive: true });

  const headers = {};
  if (options.apiKey) {
    headers['api-key'] = options.apiKey;
  }

  const status = await fetchJson(`${ATLANTIC_QUERY_ENDPOINT}/${queryId}`, headers);
  const statusPath = join(absoluteOutDir, 'status.json');
  const summaryPath = join(absoluteOutDir, 'final-query-summary.json');
  const summary = finalSummary(status);
  writeJson(statusPath, status);
  writeJson(summaryPath, summary);

  const artifacts = [];
  if (options.downloadArtifacts) {
    const artifactDir = join(absoluteOutDir, 'artifacts');
    mkdirSync(artifactDir, { recursive: true });
    for (const url of status.metadataUrls ?? []) {
      const name = sanitizeArtifactName(url);
      const path = join(artifactDir, name);
      const info = await downloadFile(url, path, {});
      artifacts.push({ url, ...info });
    }
  }

  const result = {
    schema: 'zkstark-amaci.atlantic-query-result.v1',
    queryId,
    outDir: absoluteOutDir,
    statusPath,
    summaryPath,
    summary,
    artifacts,
  };

  const resultPath = join(absoluteOutDir, 'atlantic-query-result.json');
  writeJson(resultPath, result);
  result.resultPath = resultPath;
  return result;
}

export function readAtlanticQueryResult(path) {
  if (!existsSync(path)) {
    throw new Error(`missing Atlantic query result: ${path}`);
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

