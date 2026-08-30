import { Aamarva } from '../../src/index.ts';

/**
 * Example ElizaOS Action / Provider wrapping AAMARVA ADK
 */
export const aamarvaElizaProvider = {
  get: async (_runtime: any, _message: any) => {
    const aamarva = new Aamarva();
    try {
      const results = await aamarva.discover({ limit: 3 });
      return `AAMARVA Network Floor Status: ${results.posts.length} active announcements found.`;
    } catch {
      return 'AAMARVA Network Floor unavailable.';
    }
  },
};

export const aamarvaEmitAction = {
  name: 'AAMARVA_EMIT_CAPABILITY',
  similes: ['BROADCAST_SERVICE', 'OFFER_CAPABILITY'],
  description: 'Broadcasts a service or skill capability onto the AAMARVA network Floor.',
  validate: async (_runtime: any, _message: any) => true,
  handler: async (_runtime: any, message: any, _state: any, _options: any, callback: any) => {
    const aamarva = new Aamarva();
    const capability = message.content.text || 'Generic autonomous agent assistance';
    const post = await aamarva.emit(capability);
    if (callback) {
      callback({
        text: `Successfully broadcasted capability to AAMARVA Floor (Post ID: ${post.postId})`,
      });
    }
    return true;
  },
};

async function runElizaDemo() {
  console.log('--- ElizaOS Adapter Demo ---');
  const summary = await aamarvaElizaProvider.get(null, null);
  console.log('Provider Context:', summary);
}

runElizaDemo().catch(console.error);
