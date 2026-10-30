import assert from 'node:assert';
import {
  Aamarva,
  AamarvaConnection,
  createAamarvaMcpServer,
  AamarvaMcpServer,
} from '../src/index.js';
import * as ADK from '../src/index.js';
import { createMockFetch, createMockDataStore } from '../src/mock.js';

async function runFleetContractTests() {
  console.log('--------------------------------------------------');
  console.log('AAMARVA FLEET CONTRACT & FLOOR MCP TEST SUITE     ');
  console.log('--------------------------------------------------');

  const mockStore = createMockDataStore();
  const mockFetch = createMockFetch(mockStore);
  const aamarva = new Aamarva({
    agentId: 'AMR-FLEET-TEST',
    apiKey: 'amr_live_mock_key',
    baseUrl: 'https://aamarva.com/api',
    targetAgentId: 'AMR-SLAVE-007',
    fetch: mockFetch,
  });

  // 1. FLOOR MCP Server
  console.log('1. Testing AamarvaMcpServer tool definitions & dispatch...');
  const mcpServer = createAamarvaMcpServer(aamarva);
  assert.ok(mcpServer instanceof AamarvaMcpServer);

  const tools = mcpServer.getTools();
  assert.ok(tools.length >= 6);

  const toolNames = tools.map((t) => t.name);
  assert.ok(toolNames.includes('aamarva_floor_list_tools'));
  assert.ok(toolNames.includes('aamarva_floor_request_access'));
  assert.ok(toolNames.includes('aamarva_floor_check_status'));
  assert.ok(toolNames.includes('aamarva_floor_execute_tool'));
  assert.ok(toolNames.includes('aamarva_send_message'));
  assert.ok(toolNames.includes('aamarva_get_messages'));
  assert.ok(toolNames.includes('aamarva_cluster_send_message'));
  assert.ok(toolNames.includes('aamarva_watchtower_activity'));
  
  // Confirmed removal
  assert.strictEqual(toolNames.includes('aamarva_floor_get_credentials'), false);

  // Test tool dispatch via handleToolCall
  const listToolsRes = await mcpServer.handleToolCall('aamarva_floor_list_tools', {});
  assert.ok(listToolsRes.content[0].text);
  const parsedTools = JSON.parse(listToolsRes.content[0].text);
  assert.ok(Array.isArray(parsedTools));

  // Request Access (Logic 2)
  const reqAccessRes = await mcpServer.handleToolCall('aamarva_floor_request_access', {
    toolId: 'tool_market_depth',
    reason: 'Autonomous market analysis',
  });
  assert.ok(reqAccessRes.content[0].text.includes('pending'));

  // Execute Tool (Logic 4)
  const execRes = await mcpServer.handleToolCall('aamarva_floor_execute_tool', {
    toolId: 'tool_sec_edgar',
    arguments: { ticker: 'AAPL' },
  });
  assert.ok(execRes.content[0].text.includes('executed'));

  const actRes = await mcpServer.handleToolCall('aamarva_watchtower_activity', { limit: 5 });
  assert.ok(actRes.content[0].text);
  console.log('✓ AamarvaMcpServer tools and dispatch verified.');

  // 2. Direct Connection Contract
  console.log('2. Testing Direct Connection Contract...');
  const connections = await aamarva.getConnections();
  assert.ok(connections.length > 0);
  const connInfo = connections[0];
  const conn = new AamarvaConnection(connInfo, aamarva.http);
  assert.ok(conn instanceof AamarvaConnection);
  assert.strictEqual(conn.connectionId, connInfo.connectionId);

  // Send E2EE message over connection
  const sent = await conn.send('Fleet synchronized payload');
  assert.ok(sent.messageId);
  console.log('✓ Direct connection contract verified.');

  // 3. Cluster Recipient-Restricted Messaging Contract
  console.log('3. Testing Multi-Agent Cluster Contract...');
  const clusters = await aamarva.getClusters();
  assert.ok(clusters.length > 0);
  const cluster = clusters[0];
  assert.ok(cluster.clusterId || cluster.id);

  const clusterMsg = await aamarva.sendClusterMessage(cluster.clusterId || cluster.id!, {
    ciphertext: 'ZW5jcnlwdGVkX3BheWxvYWQ=',
    nonce: 'bm9uY2VfdmFsdWU=',
    version: 1,
    keyEpoch: 1,
    recipients: ['AMR-PARTNER-999'],
  });
  assert.ok(clusterMsg.messageId);
  console.log('✓ Cluster messaging verified.');

  // 4. Watchtower Telemetry & Event Streaming Contract
  console.log('4. Testing Watchtower Telemetry Contract...');
  const activities = await aamarva.getWatchtowerActivity(10);
  assert.ok(Array.isArray(activities));

  const ticket = await aamarva.getWatchtowerStreamTicket();
  assert.ok(ticket.ticket);
  assert.ok(ticket.streamUrl.includes('ticket='));
  console.log('✓ Watchtower telemetry and stream tickets verified.');

  // 5. Verification of Complete Legacy Removal
  console.log('5. Testing complete removal of obsolete social and adapter symbols...');
  const adkExports = ADK as Record<string, unknown>;

  // Framework adapters must NOT be exported
  assert.strictEqual(adkExports.LangGraphAamarvaAdapter, undefined);
  assert.strictEqual(adkExports.createLangChainTools, undefined);
  assert.strictEqual(adkExports.OpenAIAgentsAdapter, undefined);
  assert.strictEqual(adkExports.createOpenAITools, undefined);
  assert.strictEqual(adkExports.createOpenAIAgentTools, undefined);
  assert.strictEqual(adkExports.CrewAiAamarvaAdapter, undefined);
  assert.strictEqual(adkExports.createCrewAiTools, undefined);
  assert.strictEqual(adkExports.GoogleAdkAdapter, undefined);
  assert.strictEqual(adkExports.createGoogleAdkIntegration, undefined);
  assert.strictEqual(adkExports.OpenClawAdapter, undefined);
  assert.strictEqual(adkExports.createOpenClawSkill, undefined);
  assert.strictEqual(adkExports.HermesAamarvaAdapter, undefined);
  assert.strictEqual(adkExports.createHermesTools, undefined);
  assert.strictEqual(adkExports.createHermesSkillProvider, undefined);
  assert.strictEqual(adkExports.AutoGenAamarvaAdapter, undefined);
  assert.strictEqual(adkExports.createAutoGenTools, undefined);
  assert.strictEqual(adkExports.AgnoAamarvaToolkit, undefined);
  assert.strictEqual(adkExports.createAgnoToolkit, undefined);
  assert.strictEqual(adkExports.ElizaOSAamarvaPlugin, undefined);
  assert.strictEqual(adkExports.createElizaPlugin, undefined);
  assert.strictEqual(adkExports.createA2AAdapter, undefined);
  assert.strictEqual(adkExports.AamarvaBridge, undefined);
  assert.strictEqual(adkExports.AamarvaIntegrationContract, undefined);

  // Social normalizers must NOT be exported
  assert.strictEqual(adkExports.normalizePost, undefined);
  assert.strictEqual(adkExports.normalizeReply, undefined);

  // Methods on Aamarva prototype must NOT exist
  const clientProto = Aamarva.prototype as any;
  assert.strictEqual(clientProto.discover, undefined);
  assert.strictEqual(clientProto.discoverAgents, undefined);
  assert.strictEqual(clientProto.discoverPosts, undefined);
  assert.strictEqual(clientProto.emit, undefined);
  assert.strictEqual(clientProto.intake, undefined);
  assert.strictEqual(clientProto.getPosts, undefined);
  assert.strictEqual(clientProto.getPost, undefined);
  assert.strictEqual(clientProto.createPost, undefined);
  assert.strictEqual(clientProto.deletePost, undefined);
  assert.strictEqual(clientProto.getReplies, undefined);
  assert.strictEqual(clientProto.createReply, undefined);
  assert.strictEqual(clientProto.deleteReply, undefined);
  assert.strictEqual(clientProto.submitReview, undefined);
  assert.strictEqual(clientProto.connectFromReply, undefined);
  assert.strictEqual(clientProto.requestConnection, undefined);
  assert.strictEqual(clientProto.establishConnection, undefined);
  assert.strictEqual(clientProto.getFloorTemporaryAccess, undefined);
  assert.strictEqual(clientProto.invokeFloorTool, undefined);
  console.log('✓ All legacy framework adapters and social APIs confirmed completely removed.');

  console.log('--------------------------------------------------');
  console.log('ALL FLEET CONTRACT & FLOOR MCP TESTS PASSED       ');
  console.log('--------------------------------------------------');
}

runFleetContractTests().catch((err) => {
  console.error('Fleet contract test failed:', err);
  process.exit(1);
});
