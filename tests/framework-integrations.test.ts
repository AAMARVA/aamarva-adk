import assert from 'node:assert';
import { Aamarva, createMockDataStore, createMockFetch } from '../src/index.js';
import {
  AamarvaMcpServer,
  createAamarvaMcpServer,
  createMcpProtocolServer,
  startStdioMcpServer,
  createStreamableHttpMcpHandler,
} from '../src/integrations/mcp.js';
import {
  getOpenAITools,
  executeOpenAIToolCall,
  handleOpenAIToolCall,
} from '../src/integrations/openai.js';
import {
  getLangChainTools,
  executeLangChainTool,
} from '../src/integrations/langchain.js';
import {
  createLangGraphToolNode,
  executeLangGraphAction,
} from '../src/integrations/langgraph.js';
import {
  getGoogleAdkTools,
  getGoogleAdkFunctionDeclarations,
  executeGoogleAdkFunction,
} from '../src/integrations/google-adk.js';
import {
  getAutoGenTools,
  registerAutoGenTools,
  executeAutoGenTool,
} from '../src/integrations/autogen.js';
import {
  getLlamaIndexTools,
  executeLlamaIndexTool,
} from '../src/integrations/llamaindex.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Readable, Writable } from 'node:stream';

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

  // -------------------------------------------------------------------------
  // 1. Model Context Protocol (MCP) Standards-Compliant Protocol Suite
  // -------------------------------------------------------------------------
  console.log('1. Testing Standards-Compliant MCP Protocol Lifecycle & Transports...');

  const mcpServer = createAamarvaMcpServer(aamarva);
  assert.ok(mcpServer instanceof AamarvaMcpServer);

  // Backward compatibility with getTools and handleToolCall
  const tools = mcpServer.getTools();
  assert.strictEqual(tools.length >= 12, true, 'MCP server must expose all AAMARVA tools');

  // Verify MCP Protocol Server with official MCP SDK Client over InMemoryTransport
  const protocolServer = mcpServer.toProtocolServer();
  const mcpClient = new Client({ name: 'mcp-test-client', version: '1.0.0' }, { capabilities: {} });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await protocolServer.connect(serverTransport);
  await mcpClient.connect(clientTransport);

  // Test tools/list via MCP protocol
  const listed = await mcpClient.listTools();
  assert.ok(Array.isArray(listed.tools), 'tools/list must return tools array');
  assert.strictEqual(listed.tools.length, tools.length);
  const listNames = listed.tools.map((t) => t.name);
  assert.ok(listNames.includes('aamarva_floor_list_tools'));
  assert.ok(listNames.includes('aamarva_floor_request_access'));
  assert.ok(listNames.includes('aamarva_floor_check_status'));
  assert.ok(listNames.includes('aamarva_floor_execute_tool'));
  assert.ok(listNames.includes('aamarva_send_message'));
  assert.ok(listNames.includes('aamarva_get_messages'));
  assert.ok(listNames.includes('aamarva_cluster_send_message'));
  assert.ok(listNames.includes('aamarva_watchtower_activity'));
  assert.ok(listNames.includes('aamarva_agent_footprints'));
  assert.ok(listNames.includes('aamarva_webhook_events'));
  assert.ok(listNames.includes('aamarva_get_agents'));
  assert.ok(listNames.includes('aamarva_get_clusters'));

  // Test tools/call via MCP protocol
  const listCallRes = await mcpClient.callTool({
    name: 'aamarva_floor_list_tools',
    arguments: {},
  });
  assert.ok(Array.isArray(listCallRes.content) && listCallRes.content.length > 0);
  const floorToolsData = JSON.parse((listCallRes.content[0] as any).text);
  assert.ok(Array.isArray(floorToolsData));

  // Test FLOOR tool execution of authorized tool via MCP protocol
  const execAuthorizedRes = await mcpClient.callTool({
    name: 'aamarva_floor_execute_tool',
    arguments: {
      toolId: 'tool_sec_edgar',
      arguments: { ticker: 'MSFT' },
    },
  });
  assert.strictEqual((execAuthorizedRes as any).isError, undefined);
  assert.ok((execAuthorizedRes.content[0] as any).text.includes('executed'));

  // Test FLOOR tool execution of unauthorized tool fails closed (isError: true)
  const execUnauthorizedRes = await mcpClient.callTool({
    name: 'aamarva_floor_execute_tool',
    arguments: {
      toolId: 'tool_market_depth',
      arguments: {},
    },
  });
  assert.strictEqual((execUnauthorizedRes as any).isError, true);
  assert.ok((execUnauthorizedRes.content[0] as any).text.includes('FLOOR_ACCESS_DENIED'));

  // Test stdio transport runner instantiation
  const fakeStdin = new Readable({ read() {} });
  const fakeStdout = new Writable({ write(_chunk, _enc, cb) { cb(); } });
  const stdioPair = await startStdioMcpServer(aamarva, fakeStdin, fakeStdout);
  assert.ok(stdioPair.server);
  assert.ok(stdioPair.transport);

  // Test streamable HTTP handler creation
  const httpHandler = createStreamableHttpMcpHandler(aamarva);
  assert.strictEqual(typeof httpHandler, 'function');
  console.log('✓ Model Context Protocol (MCP) server, protocol, and transports verified.');

  // -------------------------------------------------------------------------
  // 2. OpenAI Agents SDK & Function Calling Integration Suite
  // -------------------------------------------------------------------------
  console.log('\n2. Testing OpenAI Agents & Function Calling Integration...');
  const openAiTools = getOpenAITools(aamarva);
  assert.strictEqual(openAiTools.length, 12);
  for (const t of openAiTools) {
    assert.strictEqual(t.type, 'function');
    assert.ok(t.function.name);
    assert.ok(t.function.description);
    assert.strictEqual(t.function.parameters.type, 'object');
  }

  // Execute tool call directly
  const openAiExecRes = await executeOpenAIToolCall(aamarva, 'aamarva_floor_list_tools', {});
  assert.ok(Array.isArray(openAiExecRes));

  // Execute authorized tool
  const openAiAuthExec = await executeOpenAIToolCall(aamarva, 'aamarva_floor_execute_tool', {
    toolId: 'tool_sec_edgar',
    arguments: { ticker: 'NVDA' },
  });
  assert.ok(openAiAuthExec);

  // Execute unauthorized tool throws error
  try {
    await executeOpenAIToolCall(aamarva, 'aamarva_floor_execute_tool', {
      toolId: 'tool_market_depth',
      arguments: {},
    });
    assert.fail('Should fail closed on unauthorized tool');
  } catch (err: any) {
    assert.strictEqual(err.code, 'FLOOR_ACCESS_DENIED');
  }

  // Handle OpenAI tool call payload with string arguments
  const openAiMsg = await handleOpenAIToolCall(aamarva, {
    id: 'call_999',
    type: 'function',
    function: {
      name: 'aamarva_watchtower_activity',
      arguments: JSON.stringify({ limit: 3 }),
    },
  });
  assert.strictEqual(openAiMsg.role, 'tool');
  assert.strictEqual(openAiMsg.tool_call_id, 'call_999');
  assert.ok(openAiMsg.content);

  // Handle unauthorized tool call safely format error into message
  const openAiDeniedMsg = await handleOpenAIToolCall(aamarva, {
    id: 'call_denied',
    type: 'function',
    function: {
      name: 'aamarva_floor_execute_tool',
      arguments: JSON.stringify({ toolId: 'tool_market_depth', arguments: {} }),
    },
  });
  assert.strictEqual(openAiDeniedMsg.role, 'tool');
  assert.ok(openAiDeniedMsg.content.includes('error'));
  console.log('✓ OpenAI Agents & Function Calling integration verified.');

  // -------------------------------------------------------------------------
  // 3. LangChain Integration Suite
  // -------------------------------------------------------------------------
  console.log('\n3. Testing LangChain Integration...');
  const lcTools = getLangChainTools(aamarva);
  assert.strictEqual(lcTools.length, 12);
  for (const t of lcTools) {
    assert.ok(t.name);
    assert.ok(t.description);
    assert.strictEqual(typeof t.invoke, 'function');
    assert.strictEqual(typeof t.call, 'function');
  }

  // Test tool invocation via .invoke()
  const listToolsTool = lcTools.find((t) => t.name === 'aamarva_floor_list_tools')!;
  const lcResult = await listToolsTool.invoke({});
  assert.ok(typeof lcResult === 'string');
  assert.ok(lcResult.includes('tool_sec_edgar'));

  // Test tool invocation via executeLangChainTool
  const lcExecRes = await executeLangChainTool(aamarva, 'aamarva_get_agents', { limit: 5 });
  assert.ok(typeof lcExecRes === 'string');

  // Test unauthorized execution fails closed and returns error string
  const execTool = lcTools.find((t) => t.name === 'aamarva_floor_execute_tool')!;
  const lcDenied = await execTool.invoke({ toolId: 'tool_market_depth', arguments: {} });
  assert.ok(lcDenied.includes('error'));
  console.log('✓ LangChain tool suite verified.');

  // -------------------------------------------------------------------------
  // 4. LangGraph Integration Suite
  // -------------------------------------------------------------------------
  console.log('\n4. Testing LangGraph Integration...');
  const toolNode = createLangGraphToolNode(aamarva);
  assert.strictEqual(typeof toolNode, 'function');

  // Test state tool invocation
  const langGraphState = {
    messages: [
      {
        role: 'assistant',
        tool_calls: [
          {
            id: 'lg_call_1',
            name: 'aamarva_floor_list_tools',
            args: {},
          },
          {
            id: 'lg_call_2',
            name: 'aamarva_watchtower_activity',
            args: { limit: 2 },
          },
        ],
      },
    ],
  };

  const lgRes = await toolNode(langGraphState);
  assert.strictEqual(lgRes.messages.length, 2);
  assert.strictEqual(lgRes.messages[0].tool_call_id, 'lg_call_1');
  assert.ok(lgRes.messages[0].content);
  assert.strictEqual(lgRes.messages[1].tool_call_id, 'lg_call_2');
  assert.ok(lgRes.messages[1].content);

  // Test executeLangGraphAction
  const actionRes = await executeLangGraphAction(aamarva, {
    tool: 'aamarva_get_clusters',
    toolInput: {},
  });
  assert.ok(actionRes.output);
  console.log('✓ LangGraph tool node and action runner verified.');

  // -------------------------------------------------------------------------
  // 5. Google ADK (Gemini GenAI) Integration Suite
  // -------------------------------------------------------------------------
  console.log('\n5. Testing Google ADK & Gemini Function Declarations...');
  const googleDecls = getGoogleAdkFunctionDeclarations(aamarva);
  assert.strictEqual(googleDecls.length, 12);
  for (const decl of googleDecls) {
    assert.ok(decl.name);
    assert.ok(decl.description);
    assert.strictEqual(decl.parameters.type, 'OBJECT');
  }

  const googleTools = getGoogleAdkTools(aamarva);
  assert.strictEqual(googleTools.functionDeclarations.length, 12);

  // Test executeGoogleAdkFunction
  const googleRes = await executeGoogleAdkFunction(aamarva, {
    name: 'aamarva_floor_list_tools',
    args: {},
  });
  assert.strictEqual(googleRes.response.name, 'aamarva_floor_list_tools');
  assert.ok(Array.isArray(googleRes.response.content));
  console.log('✓ Google ADK tool specifications and dispatch verified.');

  // -------------------------------------------------------------------------
  // 6. AutoGen Integration Suite
  // -------------------------------------------------------------------------
  console.log('\n6. Testing AutoGen Integration...');
  const autoGenTools = getAutoGenTools(aamarva);
  assert.strictEqual(autoGenTools.length, 12);
  for (const t of autoGenTools) {
    assert.ok(t.name);
    assert.ok(t.description);
    assert.strictEqual(typeof t.execute, 'function');
  }

  // Test execution
  const autoGenRes = await executeAutoGenTool(aamarva, 'aamarva_get_agents', { limit: 2 });
  assert.ok(autoGenRes);

  // Test agent registration
  const mockAgent: any = {
    registered: [] as string[],
    registerFunction(name: string, _fn: any) {
      this.registered.push(name);
    },
  };
  registerAutoGenTools(mockAgent, aamarva);
  assert.strictEqual(mockAgent.registered.length, 12);
  console.log('✓ AutoGen tool registry and dispatcher verified.');

  // -------------------------------------------------------------------------
  // 7. LlamaIndex Integration Suite
  // -------------------------------------------------------------------------
  console.log('\n7. Testing LlamaIndex Integration...');
  const llamaTools = getLlamaIndexTools(aamarva);
  assert.strictEqual(llamaTools.length, 12);
  for (const t of llamaTools) {
    assert.ok(t.metadata.name);
    assert.ok(t.metadata.description);
    assert.strictEqual(typeof t.call, 'function');
  }

  const llamaExecRes = await executeLlamaIndexTool(aamarva, 'aamarva_floor_list_tools', {});
  assert.ok(Array.isArray(llamaExecRes));
  console.log('✓ LlamaIndex tools verified.');

  console.log('\n==================================================');
  console.log(' ALL FRAMEWORK INTEGRATION TESTS PASSED (100%)    ');
  console.log('==================================================');
}

runFrameworkIntegrationTests().catch((err) => {
  console.error('Framework integration test failure:', err);
  process.exit(1);
});
