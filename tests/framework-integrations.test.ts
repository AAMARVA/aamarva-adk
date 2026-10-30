import assert from 'node:assert';
import { Aamarva, createMockDataStore, createMockFetch } from '../src/index.js';
import {
  AamarvaMcpServer,
  createAamarvaMcpServer,
} from '../src/integrations/mcp.js';
import {
  getOpenAITools,
  executeOpenAIToolCall,
} from '../src/integrations/openai.js';
import {
  getLangChainTools,
} from '../src/integrations/langchain.js';
import {
  createAamarvaToolNode,
  createLangGraphToolNode,
  executeLangGraphAction,
} from '../src/integrations/langgraph.js';
import {
  getGoogleAdkTools,
  getGoogleFunctionDeclarations,
  executeGoogleFunctionCall,
} from '../src/integrations/google-adk.js';
import {
  getAutoGenTools,
} from '../src/integrations/autogen.js';
import {
  getLlamaIndexTools,
} from '../src/integrations/llamaindex.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

async function runFrameworkIntegrationTests() {
  console.log('==================================================');
  console.log('  AAMARVA ADK FRAMEWORK INTEGRATIONS TEST SUITE   ');
  console.log('==================================================\n');

  const mockStore = createMockDataStore();
  const mockFetch = createMockFetch(mockStore);
  const aamarva = new Aamarva({
    agentId: 'AMR-INTEGRATION-AGENT',
    apiKey: 'sk_integration_live',
    baseUrl: 'https://aamarva.com/api',
    targetAgentId: 'AMR-PARTNER-001',
    fetch: mockFetch,
  });

  // 1. MCP
  console.log('1. Testing Standards-Compliant MCP Protocol...');
  const mcpServer = createAamarvaMcpServer(aamarva);
  const protocolServer = mcpServer.toProtocolServer();
  const mcpClient = new Client({ name: 'mcp-test-client', version: '1.0.0' }, { capabilities: {} });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await protocolServer.connect(serverTransport);
  await mcpClient.connect(clientTransport);
  const listed = await mcpClient.listTools();
  assert.ok(listed.tools.length >= 4);
  console.log('✓ MCP verified.');

  // 2. OpenAI
  console.log('\n2. Testing OpenAI Agents Integration...');
  const openAiTools = getOpenAITools(aamarva);
  assert.ok(openAiTools.length >= 5);
  assert.strictEqual(typeof openAiTools[0].execute, 'function');
  const res = await executeOpenAIToolCall(aamarva, 'aamarva_floor_list_tools', {});
  assert.ok(Array.isArray(res));
  console.log('✓ OpenAI verified.');

  // 3. LangChain
  console.log('\n3. Testing LangChain Integration...');
  const lcTools = await getLangChainTools(aamarva);
  assert.ok(lcTools.length >= 5);
  const listToolsTool = lcTools.find((t) => t.name === 'aamarva_floor_list_tools')!;
  const lcResult = await listToolsTool.invoke({});
  assert.ok(typeof lcResult === 'string');
  console.log('✓ LangChain verified.');

  // 4. LangGraph
  console.log('\n4. Testing LangGraph Integration...');
  const toolNode = await createAamarvaToolNode(aamarva);
  assert.ok(toolNode);
  const toolNodeAlias = await createLangGraphToolNode(aamarva);
  assert.ok(toolNodeAlias);
  const graphExecRes = await executeLangGraphAction(aamarva, 'aamarva_floor_list_tools', {});
  assert.ok(typeof graphExecRes === 'string');
  console.log('✓ LangGraph verified.');

  // 5. Google ADK
  console.log('\n5. Testing Google ADK...');
  const googleDecls = getGoogleFunctionDeclarations();
  assert.ok(googleDecls.length >= 4);
  const googleAdkTools = getGoogleAdkTools();
  assert.strictEqual(googleAdkTools.functionDeclarations.length, googleDecls.length);
  const googleExec = await executeGoogleFunctionCall(aamarva, {
    name: 'aamarva_floor_list_tools',
    args: {},
  });
  assert.ok(googleExec && googleExec.content);
  console.log('✓ Google ADK verified.');

  // 6. AutoGen
  console.log('\n6. Testing AutoGen...');
  const autoGenTools = getAutoGenTools(aamarva);
  assert.ok(autoGenTools.length >= 5);
  console.log('✓ AutoGen verified.');

  // 7. LlamaIndex
  console.log('\n7. Testing LlamaIndex...');
  const llamaTools = await getLlamaIndexTools(aamarva);
  assert.ok(llamaTools.length >= 5);
  console.log('✓ LlamaIndex verified.');

  console.log('\n==================================================');
  console.log(' ALL FRAMEWORK INTEGRATION TESTS PASSED (100%)    ');
  console.log('==================================================');
}

runFrameworkIntegrationTests().catch((err) => {
  console.error('Framework integration test failure:', err);
  process.exit(1);
});
