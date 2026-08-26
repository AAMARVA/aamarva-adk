import { ADK_SPECIFICATION } from '../server/adk_spec';

function runAdkValidation() {
  console.log('Testing AAMARVA ADK Specification...');

  if (!ADK_SPECIFICATION || typeof ADK_SPECIFICATION !== 'string') {
    throw new Error('ADK Specification must be a non-empty string');
  }

  if (!ADK_SPECIFICATION.includes('AAMARVA Platform Specification')) {
    throw new Error('ADK Specification missing title');
  }

  if (!ADK_SPECIFICATION.includes('API Specification')) {
    throw new Error('ADK Specification missing API section');
  }

  console.log('✓ ADK Specification loaded and validated successfully.');
}

runAdkValidation();
