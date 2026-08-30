import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import assert from 'assert';

async function testPackagePackAndInstall() {
  console.log('--------------------------------------------------');
  console.log('AAMARVA ADK NPM PACK & INTEGRATION TEST');
  console.log('--------------------------------------------------');

  const rootDir = process.cwd();
  console.log('1. Building ADK typescript assets...');
  execSync('npm run build', { cwd: rootDir, stdio: 'pipe' });

  console.log('2. Running npm pack...');
  const packOutput = execSync('npm pack', { cwd: rootDir, stdio: 'pipe' }).toString().trim();
  const tarballName = packOutput.split('\n').pop()?.trim() || '';
  const tarballPath = path.join(rootDir, tarballName);

  assert.ok(fs.existsSync(tarballPath), `Tarball ${tarballPath} should exist`);
  console.log(`✓ Pack produced: ${tarballName}`);

  // Create temporary testing folder
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-pkg-test-'));
  console.log(`3. Created clean isolated test environment: ${tempDir}`);

  try {
    // Initialize temporary package.json
    fs.writeFileSync(
      path.join(tempDir, 'package.json'),
      JSON.stringify({
        name: 'aamarva-consumer-app',
        version: '1.0.0',
        type: 'module',
      })
    );

    // Install packed tarball
    console.log('4. Installing packed @aamarva/adk tarball in isolated app...');
    execSync(`npm install "${tarballPath}"`, { cwd: tempDir, stdio: 'pipe' });

    // Verify installed files
    const installedPkgJson = path.join(tempDir, 'node_modules', '@aamarva', 'adk', 'package.json');
    assert.ok(fs.existsSync(installedPkgJson), 'Installed package.json should exist');

    // Create consumer test script
    const testScriptPath = path.join(tempDir, 'test-consumer.mjs');
    const testScriptCode = `
      import { Aamarva, createMockFetch, createMockDataStore, AamarvaError } from '@aamarva/adk';
      import assert from 'assert';

      async function main() {
        const mockStore = createMockDataStore();
        const mockFetch = createMockFetch(mockStore);

        const client = new Aamarva({
          agentId: 'AMR-PKG-TEST',
          apiKey: 'key_123',
          fetch: mockFetch
        });

        // 1. Health
        const health = await client.health();
        assert.strictEqual(health.status, 'ok');

        // 2. Discover
        const discovery = await client.discover('Financial');
        assert.ok(discovery.agents.length > 0);

        // 3. Emit
        const post = await client.emit('Packaged SDK capability');
        assert.strictEqual(post.type, 'emit');

        // 4. Connect Request
        const connReq = await client.requestConnection('AMR-1111-2222');
        assert.strictEqual(connReq.status, 'pending');

        console.log('✓ Successfully executed consumer test against packed @aamarva/adk distribution!');
      }

      main().catch(err => {
        console.error(err);
        process.exit(1);
      });
    `;

    fs.writeFileSync(testScriptPath, testScriptCode);

    // Execute test script in node
    console.log('5. Executing consumer test using Node.js ESM import...');
    execSync(`node test-consumer.mjs`, { cwd: tempDir, stdio: 'inherit' });

    console.log('✓ Package packaging, distribution, and real installation verified.');
  } finally {
    // Cleanup tarball and temp folder
    try {
      if (fs.existsSync(tarballPath)) fs.unlinkSync(tarballPath);
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  }
}

testPackagePackAndInstall().catch((err) => {
  console.error('Package pack test failed:', err);
  process.exit(1);
});
