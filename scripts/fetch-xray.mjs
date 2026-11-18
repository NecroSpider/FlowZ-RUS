import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const VERSION = '26.11.9';
const targets = {
  linux: [
    'Xray-linux-64.zip',
    'b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82',
    'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d',
  ],
  win: [
    'Xray-windows-64.zip',
    '1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d',
    '1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185',
  ],
  'mac-x64': [
    'Xray-macos-64.zip',
    '488963e676e06f5e48547f9dd38116aaca8de4234959b4272ae8f284e658dfd0',
    'e0421c5877c4819f672b5bc56e553502a4e14efcc17ec88691240a5d7f52cc31',
  ],
  'mac-arm64': [
    'Xray-macos-arm64-v8a.zip',
    '233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26',
    '1b2d5ebe3a4c332203db24b81a052c6d6688a7f80705090f031b7416013ee1b2',
  ],
};
const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'resources');
const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

for (const [platform, [asset, archiveHash, binaryHash]] of Object.entries(targets)) {
  const dir = join(root, platform);
  const bin = platform === 'win' ? 'xray.exe' : 'xray';
  const dest = join(dir, bin);
  const license = join(dir, 'xray-LICENSE');
  if (
    !process.argv.includes('--force') &&
    existsSync(dest) &&
    existsSync(license) &&
    sha256(dest) === binaryHash
  ) {
    console.log(`Xray ${VERSION} verified for ${platform}`);
    continue;
  }
  const work = mkdtempSync(join(tmpdir(), 'flowz-xray-'));
  const tempDest = join(dir, `.${bin}.${process.pid}.tmp`);
  try {
    const archive = join(work, asset);
    const url = `https://github.com/XTLS/Xray-core/releases/download/v${VERSION}/${asset}`;
    execFileSync('curl', ['-fsSL', '--retry', '3', '-o', archive, url], { stdio: 'inherit' });
    if (sha256(archive) !== archiveHash) throw new Error(`Invalid Xray archive hash: ${asset}`);
    execFileSync('unzip', ['-q', archive, bin, 'LICENSE', '-d', work], { stdio: 'inherit' });
    if (sha256(join(work, bin)) !== binaryHash)
      throw new Error(`Invalid Xray binary hash: ${asset}`);
    mkdirSync(dir, { recursive: true });
    copyFileSync(join(work, 'LICENSE'), license);
    copyFileSync(join(work, bin), tempDest);
    chmodSync(tempDest, 0o755);
    renameSync(tempDest, dest);
    console.log(`Xray ${VERSION} verified for ${platform}`);
  } finally {
    rmSync(tempDest, { force: true });
    rmSync(work, { recursive: true, force: true });
  }
}
