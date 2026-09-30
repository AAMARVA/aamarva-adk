import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
  detectProjectAndFramework,
  runCli,
  handleDoctor,
} from '../src/cli.js';

async function runCliIntegrationTests() {
  console.log('--- Starting CLI & One-Click Integration Test Suite ---');

  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-cli-full-test-'));

  try {
    // -------------------------------------------------------------------------
    // 1. POSITIVE FIXTURES (Legitimate Framework Projects)
    // -------------------------------------------------------------------------
    console.log('\nTesting Positive Framework Detection Fixtures...');

    // 1a. LangGraph & OpenAI Agents SDK (TS)
    const dirTS = path.join(tmpBase, 'pos-ts-agents');
    fs.mkdirSync(dirTS);
    fs.writeFileSync(
      path.join(dirTS, 'package.json'),
      JSON.stringify({
        name: 'my-langgraph-agent',
        dependencies: {
          '@langchain/langgraph': '^0.2.0',
          '@openai/agents': '^0.18.0',
        },
      })
    );
    fs.writeFileSync(path.join(dirTS, 'tsconfig.json'), '{}');

    const detTS = detectProjectAndFramework(dirTS);
    assert.strictEqual(detTS.language, 'TypeScript');
    assert.ok(detTS.frameworks.includes('LangGraph'), 'Must detect LangGraph');
    assert.ok(detTS.frameworks.includes('OpenAI Agents SDK'), 'Must detect OpenAI Agents SDK');
    console.log('✓ Positive TS: @langchain/langgraph & @openai/agents detected.');

    // 1b. Python Hermes & CrewAI
    const dirPy = path.join(tmpBase, 'pos-py-hermes-crew');
    fs.mkdirSync(dirPy);
    fs.writeFileSync(path.join(dirPy, 'requirements.txt'), 'hermes-agent>=0.19.0\ncrewai>=1.0.0\nrequests>=2.31.0');

    const detPy = detectProjectAndFramework(dirPy);
    assert.strictEqual(detPy.language, 'Python');
    assert.ok(detPy.frameworks.includes('Hermes'), 'Must detect Hermes');
    assert.ok(detPy.frameworks.includes('CrewAI'), 'Must detect CrewAI');
    console.log('✓ Positive Py: hermes-agent & crewai detected.');

    // 1c. Python AutoGen & Agno
    const dirPy2 = path.join(tmpBase, 'pos-py-autogen-agno');
    fs.mkdirSync(dirPy2);
    fs.writeFileSync(path.join(dirPy2, 'requirements.txt'), 'pyautogen>=0.10.0\nagno>=3.0.0');

    const detPy2 = detectProjectAndFramework(dirPy2);
    assert.ok(detPy2.frameworks.includes('AutoGen'), 'Must detect AutoGen');
    assert.ok(detPy2.frameworks.includes('Agno'), 'Must detect Agno');
    console.log('✓ Positive Py: pyautogen & agno detected.');

    // 1d. Google ADK (Node)
    const dirGAdk = path.join(tmpBase, 'pos-gadk');
    fs.mkdirSync(dirGAdk);
    fs.writeFileSync(
      path.join(dirGAdk, 'package.json'),
      JSON.stringify({
        name: 'my-google-adk-agent',
        dependencies: {
          '@google/adk': '^1.0.0',
        },
      })
    );
    const detGAdk = detectProjectAndFramework(dirGAdk);
    assert.ok(detGAdk.frameworks.includes('Google ADK'), 'Must detect Google ADK');
    console.log('✓ Positive Node: @google/adk detected.');

    // 1e. ElizaOS & MCP
    const dirElizaMcp = path.join(tmpBase, 'pos-eliza-mcp');
    fs.mkdirSync(dirElizaMcp);
    fs.writeFileSync(
      path.join(dirElizaMcp, 'package.json'),
      JSON.stringify({
        name: 'eliza-agent',
        dependencies: {
          '@elizaos/core': '^1.7.0',
          '@modelcontextprotocol/sdk': '^1.30.0',
        },
      })
    );
    const detElizaMcp = detectProjectAndFramework(dirElizaMcp);
    assert.ok(detElizaMcp.frameworks.includes('ElizaOS'), 'Must detect ElizaOS');
    assert.ok(detElizaMcp.frameworks.includes('MCP'), 'Must detect MCP');
    console.log('✓ Positive Node: @elizaos/core & @modelcontextprotocol/sdk detected.');

    // -------------------------------------------------------------------------
    // 2. NEGATIVE FIXTURES (Generic LLM Clients / Non-Framework Projects)
    // -------------------------------------------------------------------------
    console.log('\nTesting Negative Framework Detection Fixtures (No False Positives)...');

    // 2a. Generic Node OpenAI client only (NOT OpenAI Agents SDK)
    const dirNegOpenAI = path.join(tmpBase, 'neg-node-openai-only');
    fs.mkdirSync(dirNegOpenAI);
    fs.writeFileSync(
      path.join(dirNegOpenAI, 'package.json'),
      JSON.stringify({
        name: 'generic-openai-chatbot',
        dependencies: {
          openai: '^4.50.0',
        },
      })
    );
    const detNegOpenAI = detectProjectAndFramework(dirNegOpenAI);
    assert.strictEqual(
      detNegOpenAI.frameworks.length,
      0,
      `Expected 0 frameworks for generic openai client, but got: ${JSON.stringify(detNegOpenAI.frameworks)}`
    );
    console.log('✓ Negative Node: generic "openai" does NOT trigger OpenAI Agents SDK.');

    // 2b. Generic Node Google Gemini SDK only (NOT Google ADK)
    const dirNegGenAI = path.join(tmpBase, 'neg-node-gemini-only');
    fs.mkdirSync(dirNegGenAI);
    fs.writeFileSync(
      path.join(dirNegGenAI, 'package.json'),
      JSON.stringify({
        name: 'gemini-api-service',
        dependencies: {
          '@google/genai': '^0.1.0',
          '@google/generative-ai': '^0.20.0',
        },
      })
    );
    const detNegGenAI = detectProjectAndFramework(dirNegGenAI);
    assert.strictEqual(
      detNegGenAI.frameworks.length,
      0,
      `Expected 0 frameworks for generic @google/genai, but got: ${JSON.stringify(detNegGenAI.frameworks)}`
    );
    console.log('✓ Negative Node: generic "@google/genai" does NOT trigger Google ADK.');

    // 2c. Generic Python OpenAI client only
    const dirNegPyOpenAI = path.join(tmpBase, 'neg-py-openai-only');
    fs.mkdirSync(dirNegPyOpenAI);
    fs.writeFileSync(
      path.join(dirNegPyOpenAI, 'requirements.txt'),
      'openai>=1.30.0\nrequests>=2.31.0\npydantic>=2.0.0\n'
    );
    const detNegPyOpenAI = detectProjectAndFramework(dirNegPyOpenAI);
    assert.strictEqual(
      detNegPyOpenAI.frameworks.length,
      0,
      `Expected 0 frameworks for generic python openai, but got: ${JSON.stringify(detNegPyOpenAI.frameworks)}`
    );
    console.log('✓ Negative Python: generic "openai" does NOT trigger OpenAI Agents SDK.');

    // 2d. Generic Python Google GenAI client only
    const dirNegPyGenAI = path.join(tmpBase, 'neg-py-gemini-only');
    fs.mkdirSync(dirNegPyGenAI);
    fs.writeFileSync(
      path.join(dirNegPyGenAI, 'requirements.txt'),
      'google-genai>=0.1.0\ngoogle-generativeai>=0.8.0\n'
    );
    const detNegPyGenAI = detectProjectAndFramework(dirNegPyGenAI);
    assert.strictEqual(
      detNegPyGenAI.frameworks.length,
      0,
      `Expected 0 frameworks for generic python google-genai, but got: ${JSON.stringify(detNegPyGenAI.frameworks)}`
    );
    console.log('✓ Negative Python: generic "google-genai" does NOT trigger Google ADK.');

    // 2e. Non-AI generic Node & Python project
    const dirGeneric = path.join(tmpBase, 'neg-generic-web');
    fs.mkdirSync(dirGeneric);
    fs.writeFileSync(
      path.join(dirGeneric, 'package.json'),
      JSON.stringify({
        name: 'express-api-server',
        dependencies: {
          express: '^4.19.0',
          axios: '^1.7.0',
          dotenv: '^16.4.0',
        },
      })
    );
    const detGeneric = detectProjectAndFramework(dirGeneric);
    assert.strictEqual(detGeneric.frameworks.length, 0);
    console.log('✓ Negative: generic web server dependencies trigger 0 frameworks.');
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }

  // ---------------------------------------------------------------------------
  // 3. DOCTOR COMMAND DIAGNOSTICS
  // ---------------------------------------------------------------------------
  console.log('\nTesting "aamarva doctor" diagnostics...');
  await handleDoctor();
  console.log('✓ "aamarva doctor" executed cleanly.');

  // ---------------------------------------------------------------------------
  // 4. CLI ROUTER & HELP
  // ---------------------------------------------------------------------------
  console.log('\nTesting "aamarva help" and router...');
  await runCli(['help']);
  console.log('✓ CLI help routing verified.');

  console.log('\n--- ALL CLI POSITIVE & NEGATIVE INTEGRATION TESTS PASSED ---');
}

runCliIntegrationTests().catch((err) => {
  console.error('CLI Integration tests failed:', err);
  process.exit(1);
});
