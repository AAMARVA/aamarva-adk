import assert from 'node:assert';
import {
  Aamarva,
  AamarvaIntegrationContract,
  LangGraphAamarvaAdapter,
  createLangChainTools,
  OpenAIAgentsAdapter,
  createOpenAITools,
  createOpenAIAgentTools,
  CrewAiAamarvaAdapter,
  createCrewAiTools,
  GoogleAdkAdapter,
  createGoogleAdkIntegration,
  OpenClawAdapter,
  createOpenClawSkill,
  HermesAamarvaAdapter,
  createHermesTools,
  createHermesSkillProvider,
  AutoGenAamarvaAdapter,
  createAutoGenTools,
  AgnoAamarvaToolkit,
  createAgnoToolkit,
  ElizaOSAamarvaPlugin,
  createElizaPlugin,
  createA2AAdapter,
  AamarvaMcpServer,
  createAamarvaMcpServer,
} from '../src/index.js';
import { createMockFetch, createMockDataStore } from '../src/mock.js';

async function runFrameworkAdapterTests() {
  console.log('--- Starting Framework Adapters Test Suite ---');

  const mockStore = createMockDataStore();
  const mockFetch = createMockFetch(mockStore);
  const aamarva = new Aamarva({
    agentId: 'AMR-ADAPTER-TEST',
    apiKey: 'amr_live_mock_key',
    baseUrl: 'https://aamarva.com/api',
    fetch: mockFetch,
  });
  const contract = new AamarvaIntegrationContract({ aamarva });

  // 1. LangGraph / LangChain
  console.log('Testing LangGraph Native Adapter...');
  const langTools = createLangChainTools(contract);
  assert.ok(langTools.length >= 4);
  const lgDiscover = langTools.find((t) => t.name === 'aamarva_discover');
  assert.ok(lgDiscover);
  const lgRes = await lgDiscover.invoke({ query: 'finances' });
  assert.ok(typeof lgRes === 'string');
  console.log('✓ LangGraph tools verified.');

  // 2. OpenAI Agents SDK / Swarm
  console.log('Testing OpenAI Agents SDK Adapter...');
  const openAiTools = createOpenAIAgentTools(contract);
  assert.ok(openAiTools.length >= 4);
  assert.strictEqual(openAiTools[0].type, 'function');
  const openAiMap = createOpenAITools(contract);
  assert.ok(typeof openAiMap.aamarva_discover === 'function');
  console.log('✓ OpenAI Agents SDK tools verified.');

  // 3. CrewAI
  console.log('Testing CrewAI Native Adapter...');
  const crewTools = createCrewAiTools(contract);
  assert.ok(crewTools.length >= 4);
  const crewDisc = crewTools.find((t) => t.name === 'AamarvaDiscoveryTool');
  assert.ok(crewDisc);
  const crewRes = await crewDisc.run({ query: 'finances' });
  assert.ok(typeof crewRes === 'string');
  console.log('✓ CrewAI tools verified.');

  // 4. Google ADK
  console.log('Testing Google ADK Adapter...');
  const googleAdk = createGoogleAdkIntegration(contract);
  assert.ok(googleAdk.functionDeclarations.length >= 4);
  const decl = googleAdk.functionDeclarations.find((d) => d.name === 'aamarva_discover');
  assert.ok(decl);
  const gRes = await googleAdk.execute('aamarva_discover', { query: 'crypto' });
  assert.ok(gRes);
  console.log('✓ Google ADK function declarations and executor verified.');

  // 5. OpenClaw
  console.log('Testing OpenClaw Skill Adapter...');
  const openclawSkill = createOpenClawSkill(contract);
  assert.strictEqual(openclawSkill.id, 'aamarva-network');
  assert.ok(typeof openclawSkill.actions.discover === 'function');
  console.log('✓ OpenClaw skill verified.');

  // 6. Hermes Agent Framework
  console.log('Testing Hermes Agent Framework Adapter...');
  const hermesTools = createHermesTools(contract);
  assert.ok(hermesTools.length >= 4);
  const hDisc = hermesTools.find((t) => t.name === 'aamarva_discover');
  assert.ok(hDisc);
  const hRes = await hDisc.execute({ query: 'hermes agent' });
  assert.ok(hRes);

  const hermesProvider = createHermesSkillProvider(contract);
  assert.strictEqual(hermesProvider.name, 'hermes-aamarva-adapter');
  const hTool = hermesProvider.getTool('aamarva_discover');
  assert.ok(hTool);
  console.log('✓ Hermes Agent tools and skill provider verified.');

  // 7. AutoGen
  console.log('Testing AutoGen Adapter...');
  const autoGenTools = createAutoGenTools(contract);
  assert.ok(autoGenTools.length >= 4);
  const agAdapter = new AutoGenAamarvaAdapter(contract);
  const mockAgent = {
    registered: [] as string[],
    register_function(cfg: any) {
      this.registered.push(cfg.name);
    },
  };
  agAdapter.registerWithAgent(mockAgent);
  assert.ok(mockAgent.registered.includes('aamarva_discover'));
  console.log('✓ AutoGen function configs and agent registration verified.');

  // 8. Agno (Phidata)
  console.log('Testing Agno Toolkit Adapter...');
  const agnoToolkit = createAgnoToolkit(contract);
  assert.strictEqual(agnoToolkit.name, 'aamarva_toolkit');
  assert.ok(agnoToolkit.tools.length >= 4);
  console.log('✓ Agno toolkit verified.');

  // 9. ElizaOS
  console.log('Testing ElizaOS Plugin Adapter...');
  const elizaPlugin = createElizaPlugin(contract);
  assert.strictEqual(elizaPlugin.name, '@aamarva/plugin-elizaos');
  assert.ok(elizaPlugin.actions.some((a) => a.name === 'AAMARVA_DISCOVER'));
  assert.ok(elizaPlugin.providers.length > 0);
  console.log('✓ ElizaOS plugin verified.');

  // 10. MCP Server
  console.log('Testing MCP Server Integration...');
  const mcpServer = createAamarvaMcpServer(contract);
  const mcpTools = mcpServer.getTools();
  assert.ok(mcpTools.length >= 4);
  const mcpRes = await mcpServer.handleToolCall('aamarva_discover', { query: 'testing' });
  assert.ok(mcpRes);
  console.log('✓ MCP Server verified.');

  // 11. A2A Adapter
  console.log('Testing A2A Relay Adapter...');
  const a2a = createA2AAdapter(contract);
  assert.strictEqual(a2a.protocol, 'aamarva-a2a-v1');
  console.log('✓ A2A adapter verified.');

  console.log('--- ALL FRAMEWORK ADAPTER TESTS PASSED ---');
}

runFrameworkAdapterTests().catch((err) => {
  console.error('Framework Adapters test failed:', err);
  process.exit(1);
});
