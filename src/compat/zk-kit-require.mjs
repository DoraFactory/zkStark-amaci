import { createRequire } from 'node:module';

const requireFromLocal = createRequire(new URL('../../package.json', import.meta.url));

export function requireZkKitPackage(packageName) {
  try {
    return requireFromLocal(packageName);
  } catch (error) {
    throw new Error(`Unable to load ${packageName}. Run npm install in zkStark-amaci first. Cause: ${error.message}`);
  }
}
