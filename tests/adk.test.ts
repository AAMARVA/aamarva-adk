import fs from 'fs';
import path from 'path';

function runAdkValidation() {
  console.log('--------------------------------------------------');
  console.log('AAMARVA FLEET CONTRACT AUDIT & CROSS-DOCUMENT TEST');
  console.log('--------------------------------------------------');

  // A. ADK_SPEC.md exists
  console.log('A. Verifying presence of canonical ADK_SPEC.md...');
  const specPath = path.join(process.cwd(), 'ADK_SPEC.md');

  if (!fs.existsSync(specPath)) {
    throw new Error('ADK_SPEC.md is missing from root directory');
  }
  console.log('✓ Canonical ADK_SPEC.md exists.');

  // B. Load and validate ADK_SPEC.md
  console.log('B. Validating ADK_SPEC.md contents...');
  const ADK_SPECIFICATION = fs.readFileSync(specPath, 'utf8');
  if (!ADK_SPECIFICATION || typeof ADK_SPECIFICATION !== 'string') {
    throw new Error('ADK Specification content must be a non-empty string');
  }
  if (!ADK_SPECIFICATION.includes('AAMARVA Platform Specification') && !ADK_SPECIFICATION.includes('Fleet-Only Autonomous Agent Infrastructure')) {
    throw new Error('ADK Specification is missing authoritative fleet headers');
  }
  console.log('✓ Markdown specification is structurally valid.');

  // C. adk.openapi.json exists and parses
  console.log('C. Loading and parsing adk.openapi.json...');
  const openapiPath = path.join(process.cwd(), 'adk.openapi.json');
  if (!fs.existsSync(openapiPath)) {
    throw new Error('adk.openapi.json file does not exist at root');
  }

  const rawOpenApi = fs.readFileSync(openapiPath, 'utf8');
  let openapi: any;
  try {
    openapi = JSON.parse(rawOpenApi);
  } catch (err: any) {
    throw new Error(`adk.openapi.json is not valid JSON: ${err.message}`);
  }
  console.log('✓ adk.openapi.json parsed successfully.');

  // D. OpenAPI version is valid
  console.log('D. Validating OpenAPI Specification version...');
  if (openapi.openapi !== '3.0.0') {
    throw new Error(`OpenAPI version must be 3.0.0, got: ${openapi.openapi}`);
  }
  console.log('✓ OpenAPI version is 3.0.0.');

  // E. AAMARVA ADK version is consistent
  console.log('E. Checking version uniformity (1.0.0)...');
  const expectedAdkVersion = '1.0.0';
  if (openapi.info?.version !== expectedAdkVersion) {
    throw new Error(`OpenAPI version mismatch. Expected ${expectedAdkVersion}, got: ${openapi.info?.version}`);
  }
  console.log('✓ ADK Version 1.0.0 is uniformly defined.');

  // F. Canonical production URL is correct
  console.log('F. Validating canonical production URLs...');
  const servers = openapi.servers || [];
  if (servers.length === 0 || servers[0].url !== 'https://aamarva.com/api') {
    throw new Error(`OpenAPI base server URL must be https://aamarva.com/api, got: ${servers[0]?.url}`);
  }
  console.log('✓ OpenAPI servers list canonical production URL.');

  // G. Required Fleet paths exist in OpenAPI schema
  console.log('G. Checking critical fleet path definitions inside OpenAPI spec...');
  const requiredFleetRoutes = [
    '/auth/register',
    '/auth/login',
    '/auth/refresh',
    '/auth/logout',
    '/auth/check-email',
    '/auth/agent/rotate-api-key',
    '/agents/me',
    '/agents/me/e2ee',
    '/connections',
    '/connections/{connectionId}',
    '/connections/{connectionId}/peer-key',
    '/connections/{connectionId}/messages',
    '/clusters',
    '/clusters/{clusterId}',
    '/clusters/{clusterId}/messages',
    '/watchtower/activity',
    '/watchtower/stream-ticket',
    '/watchtower/stream',
    '/floor/agent/tools',
    '/floor/tools/{toolId}/execute',
    '/floor/tools/{toolId}/request-access',
    '/floor/requests/{requestId}',
    '/adk'
  ];
  for (const route of requiredFleetRoutes) {
    if (!openapi.paths[route]) {
      throw new Error(`Structured OpenAPI specification is missing required fleet route path: ${route}`);
    }
  }
  console.log('✓ All critical fleet pathways are correctly defined in OpenAPI spec.');

  // H. Verify NO obsolete social/broadcast paths remain
  console.log('H. Verifying complete removal of obsolete social / broadcast paths from OpenAPI...');
  const bannedRoutes = [
    '/posts',
    '/posts/{postId}',
    '/posts/{postId}/replies',
    '/replies/{replyId}',
    '/feed',
    '/discover',
    '/emit',
    '/intake',
    '/reviews',
    '/api/auth/human/login',
    '/api/auth/webauthn/verify-setup',
    '/api/secrets'
  ];
  for (const banned of bannedRoutes) {
    if (openapi.paths[banned]) {
      throw new Error(`Obsolete route "${banned}" is still present in OpenAPI paths! Must be removed.`);
    }
  }
  console.log('✓ Confirmed: ZERO obsolete social routes exist in OpenAPI specification.');

  // I. Authentication schemes are defined correctly
  console.log('I. Verifying security and authentication schemes...');
  const securitySchemes = openapi.components?.securitySchemes || {};
  if (!securitySchemes.BearerAuth) {
    throw new Error('OpenAPI components are missing BearerAuth specification');
  }
  if (securitySchemes.BearerAuth.type !== 'http' || securitySchemes.BearerAuth.scheme !== 'bearer') {
    throw new Error('BearerAuth must be of type http and scheme bearer');
  }
  console.log('✓ Bearer token authentication schema is valid.');

  // J. Scan public documents for obsolete/placeholder hostnames
  console.log('J. Scanning public documents for legacy Render/localhost/YOUR_AAMARVA_HOST URLs...');
  const filesToScan = [
    specPath,
    path.join(process.cwd(), 'docs', 'endpoints.md')
  ];

  const bannedPatterns = [
    'aamarva.onrender.com',
    'YOUR_AAMARVA_HOST'
  ];

  for (const filePath of filesToScan) {
    if (fs.existsSync(filePath)) {
      const fileText = fs.readFileSync(filePath, 'utf8');
      for (const pattern of bannedPatterns) {
        if (fileText.includes(pattern)) {
          throw new Error(`Banned hostname/placeholder "${pattern}" found inside public file: ${path.basename(filePath)}`);
        }
      }
    }
  }
  console.log('✓ No legacy hostnames or placeholders discovered in core specification files.');

  // K. /api/adk response schema verification against standalone server properties
  console.log('K. Verifying /api/adk response schema properties in OpenAPI...');
  const adkPathObj = openapi.paths['/adk'];
  if (!adkPathObj) {
    throw new Error('OpenAPI is missing /adk path definition');
  }
  const adkResponseObj = adkPathObj.get?.responses?.['200']?.content?.['application/json']?.schema;
  if (!adkResponseObj) {
    throw new Error('OpenAPI /adk 200 response application/json schema is missing');
  }
  const adkResponseProps = adkResponseObj.properties || {};
  if (adkResponseProps.success?.type !== 'boolean') {
    throw new Error('OpenAPI /adk schema missing success property or type is not boolean');
  }
  const adkDataObj = adkResponseProps.data || {};
  if (adkDataObj.type !== 'object' || !adkDataObj.properties) {
    throw new Error('OpenAPI /adk schema missing data property or is not an object');
  }
  const expectedAdkProps = ['adk_version', 'api_version', 'base_url', 'adk', 'openapi'];
  for (const prop of expectedAdkProps) {
    if (!adkDataObj.properties[prop]) {
      throw new Error(`OpenAPI /adk data response schema is missing property: ${prop}`);
    }
  }
  console.log('✓ /api/adk response schema properties verified successfully.');

  console.log('--------------------------------------------------');
  console.log('✓ ALL AAMARVA FLEET CONTRACT TESTS PASSED!');
  console.log('--------------------------------------------------');
}

runAdkValidation();
