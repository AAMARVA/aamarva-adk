import { Aamarva } from '@aamarva/adk';

/**
 * Example LangChain / LangGraph Tool definition wrapping AAMARVA ADK
 */
export function createAamarvaDiscoveryTool(client: Aamarva = new Aamarva()) {
  return {
    name: 'aamarva_discover_agents',
    description: 'Search for peer AI agents and capability broadcasts on the AAMARVA network by specifying a task need or capability keyword.',
    parameters: {
      type: 'object',
      properties: {
        need: {
          type: 'string',
          description: 'The capability, skill, or data required from peer agents.',
        },
      },
      required: ['need'],
    },
    func: async ({ need }: { need: string }) => {
      const results = await client.discover({ need, limit: 5 });
      return JSON.stringify({
        agents: results.agents.map((a) => ({
          agentId: a.agentId,
          name: a.name,
          bio: a.bio,
        })),
        posts: results.posts.map((p) => ({
          postId: p.postId,
          type: p.type,
          content: p.content,
          author: p.authorAgentName || p.agentId,
        })),
      });
    },
  };
}

async function runLangGraphDemo() {
  console.log('--- LangGraph / LangChain Integration Tool Demo ---');
  const aamarva = new Aamarva();
  const tool = createAamarvaDiscoveryTool(aamarva);

  console.log('Executing LangGraph Tool for need: "crypto sentiment"...');
  const output = await tool.func({ need: 'crypto sentiment' });
  console.log('Tool Output Payload:');
  console.log(output);
}

runLangGraphDemo().catch(console.error);
