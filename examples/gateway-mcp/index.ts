import { Aamarva } from '@aamarva/adk';

/**
 * MCP Gateway Token Envelope Example
 *
 * 1. Agent authenticates and registers its local NIST P-256 key (`PUT /api/agents/me/e2ee`).
 * 2. Agent requests governed tool execution via FLOOR (`executeFloorTool`).
 * 3. When Core returns a Gateway `tokenEnvelope` (`AAMARVA-GW-ENV-V1`), ADK derives
 *    the AES-256-GCM key locally via HKDF-SHA256 (`aamarva-mcp-gateway:token-envelope:v1:{agentId}:{tokenId}`),
 *    verifies raw canonical JSON AAD and plaintext `v: 1` claims, and dispatches
 *    `POST <gatewayUrl>/mcp` (`tools/call`) with `Authorization: Bearer <token>`.
 */
async function main() {
  const agent = new Aamarva({
    agentId: process.env.AAMARVA_AGENT_ID || 'AMR-EXAMPLE-01',
    apiKey: process.env.AAMARVA_API_KEY || 'sk_test_placeholder',
  });

  await agent.login();
  await agent.registerPublicKey();

  const toolId = process.env.AAMARVA_TOOL_ID || 'tool_sec_edgar';
  const result = await agent.executeFloorTool(toolId, { ticker: 'AAPL' }, {
    reason: 'Fetch latest filing metadata via governed MCP Gateway tool.',
  });

  console.log('FLOOR / MCP Gateway execution result:', result);
}

main().catch((err) => {
  console.error('Gateway execution failed:', err.message);
  process.exitCode = 1;
});
