const { spawn, execSync } = require('child_process');
const { createServer } = require('vite');
const path = require('path');
const waitOn = require('wait-on');

async function startDev() {
  console.log('🚀 Starting development environment...\n');

  // 1. 启动 Vite 开发服务器
  console.log('📦 Starting Vite dev server...');
  const viteServer = await createServer({
    configFile: path.join(__dirname, '../vite.config.ts'),
    mode: 'development',
  });
  await viteServer.listen();
  console.log('✅ Vite dev server started\n');

  // 2. 等待 Vite 服务器就绪
  console.log('⏳ Waiting for Vite server to be ready...');
  await waitOn({
    resources: ['http://localhost:5173'],
    timeout: 30000,
  });
  console.log('✅ Vite server is ready\n');

  // 3. 编译主进程代码
  console.log('🔨 Compiling main process code...');
  // 先注入构建日期常量（B-1：about 页 buildDate 取构建时刻，非运行时 new Date）
  execSync('node scripts/gen-build-info.js', { stdio: 'inherit' });
  const tsc = spawn('npx', ['tsc', '-p', 'tsconfig.main.json'], {
    shell: true,
    stdio: 'inherit',
  });

  await new Promise((resolve, reject) => {
    tsc.on('close', (code) => {
      if (code === 0) {
        console.log('✅ Main process code compiled\n');
        resolve();
      } else {
        reject(new Error(`TypeScript compilation failed, exit code: ${code}`));
      }
    });
  });

  // 4. 启动 Electron
  console.log('⚡ Starting Electron...\n');
  const env = { ...process.env, NODE_ENV: 'development' };
  delete env.ELECTRON_RUN_AS_NODE;
  // Electron 42 起 postinstall 不再下载二进制，首次 `electron .` 改为现场下载（官方 GitHub Releases；
  // 需要镜像时自行设 ELECTRON_MIRROR）。

  const electron = spawn('npx', ['electron', '.'], {
    shell: true,
    stdio: 'inherit',
    env,
  });

  electron.on('close', () => {
    console.log('\n👋 Electron closed');
    viteServer.close();
    process.exit(0);
  });
}

startDev().catch((err) => {
  console.error('❌ Failed to start:', err);
  process.exit(1);
});
