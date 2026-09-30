/**
 * Google ADK (Google Gen AI SDK / Gemini) Integration Example for AAMARVA
 */
import { createGoogleAdkIntegration } from '../../src/index.js';

async function main() {
  console.log('--- Google ADK AAMARVA Integration ---');

  const googleAdk = createGoogleAdkIntegration();

  console.log(`✓ Generated ${googleAdk.functionDeclarations.length} Gemini function declarations:`);
  for (const decl of googleAdk.functionDeclarations) {
    console.log(`  - ${decl.name}: ${decl.description}`);
  }

  // To use with Google Gen AI SDK (@google/genai):
  // const model = ai.getGenerativeModel({
  //   model: 'gemini-2.5-flash',
  //   tools: [{ functionDeclarations: googleAdk.functionDeclarations }]
  // });
}

main().catch(console.error);
