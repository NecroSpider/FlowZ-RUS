#!/usr/bin/env node

/**
 * 推送 Release Tag 脚本
 * 读取 package.json 版本号，创建并推送 tag 触发 GitHub Actions 构建
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const readline = require('readline');

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(msg, color = colors.reset) {
  console.log(`${color}${msg}${colors.reset}`);
}

function exec(cmd, silent = false) {
  return execSync(cmd, { encoding: 'utf-8', stdio: silent ? 'pipe' : 'inherit' });
}

function execSilent(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf-8', stdio: 'pipe' }).trim();
  } catch {
    return null;
  }
}

function prompt(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

async function main() {
  const skipConfirm = process.argv.includes('-y') || process.argv.includes('--yes');
  // 使用 -u/--update 替代 -f/--force，因为 npm 会拦截 -f
  const forceUpdate = process.argv.includes('-u') || process.argv.includes('--update');

  if (process.argv.includes('-h') || process.argv.includes('--help')) {
    console.log(`
Push Release Tag script

Usage: node push-release.js [options]
       npm run release:tag -- [options]

Options:
  -y, --yes      Skip confirmation
  -u, --update   Force-update an existing tag
  -h, --help     Show help

Examples:
  npm run release:tag           # Create and push the tag
  npm run release:tag -- -u     # Force-update an existing tag
  npm run release:tag -- -y -u  # Skip confirmation and force-update
`);
    process.exit(0);
  }

  log('\n🏷️  Push Release Tag\n', colors.cyan);

  // 读取版本号
  const pkgPath = path.join(__dirname, '../package.json');
  const { version } = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
  const tag = `v${version}`;

  // 检查未提交更改
  const status = execSilent('git status --porcelain');
  if (status) {
    log('⚠️  There are uncommitted changes:', colors.yellow);
    console.log(status);
    const answer = await prompt('Continue anyway? (y/N): ');
    if (answer !== 'y') {
      log('Cancelled', colors.yellow);
      process.exit(0);
    }
  }

  // 检查 tag 是否存在
  const localTagExists = execSilent(`git tag -l "${tag}"`) === tag;
  const remoteTagExists = !!execSilent(`git ls-remote --tags origin refs/tags/${tag}`);

  log(`Version: ${version}`, colors.blue);
  log(`Tag:     ${tag}`, colors.blue);
  log(`Local:   ${localTagExists ? 'exists' : 'not found'}`, localTagExists ? colors.yellow : colors.green);
  log(`Remote:  ${remoteTagExists ? 'exists' : 'not found'}`, remoteTagExists ? colors.yellow : colors.green);
  console.log('');

  if (remoteTagExists && !forceUpdate) {
    log(`❌ Tag ${tag} already exists on the remote`, colors.red);
    log('Use -u to force-update it, or bump the version in package.json', colors.yellow);
    process.exit(1);
  }

  if (!skipConfirm) {
    const action = remoteTagExists ? 'Force-update' : 'Create and push';
    const answer = await prompt(`${action} tag ${tag}? (y/N): `);
    if (answer !== 'y') {
      log('Cancelled', colors.yellow);
      process.exit(0);
    }
  }

  console.log('');

  // 删除已存在的 tag
  if (forceUpdate) {
    if (remoteTagExists) {
      log(`Deleting remote tag ${tag}...`, colors.blue);
      exec(`git push origin :refs/tags/${tag}`);
    }
    if (localTagExists) {
      log(`Deleting local tag ${tag}...`, colors.blue);
      exec(`git tag -d ${tag}`, true);
    }
  }

  // 创建 tag
  if (!localTagExists || forceUpdate) {
    log(`Creating tag ${tag}...`, colors.blue);
    exec(`git tag -a ${tag} -m "Release ${version}"`, true);
  }

  // 推送 tag
  log(`Pushing tag ${tag}...`, colors.blue);
  exec(`git push origin ${tag}`);

  console.log('');
  log('✅ Tag pushed successfully; GitHub Actions will build it automatically', colors.green);
  log(`🔗 https://github.com/NecroSpider/FlowZ-RUS/actions`, colors.blue);
}

main().catch((err) => {
  log(`❌ ${err.message}`, colors.red);
  process.exit(1);
});
