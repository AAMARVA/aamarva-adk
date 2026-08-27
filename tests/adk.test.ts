import fs from 'fs';
import path from 'path';
import { ADK_SPECIFICATION } from '../server/adk_spec';

function runAdkValidation() {
  console.log('--------------------------------------------------');
  console.log('AAMARVA CONTRACT AUDIT & CROSS-DOCUMENT TEST SUITE');
  console.log('--------------------------------------------------');

  // A. SKILL.md and adk_spec.md exists
  console.log('A. Verifying presence of SKILL.md and server/adk_spec.md...');
  const skillPath = path.join(process.cwd(), 'SKILL.md');
  const specPath = path.join(process.cwd(), 'server', 'adk_spec.md');

  if (!fs.existsSync(skillPath)) {
    throw new Error('SKILL.md is missing from root directory');
  }
  if (!fs.existsSync(specPath)) {
    throw new Error('server/adk_spec.md is missing');
  }
  console.log('✓ SKILL.md and server/adk_spec.md exist.');

  // B. Load and validate server/adk_spec.md
  console.log('B. Validating adk_spec.md contents...');
  if (!ADK_SPECIFICATION || typeof ADK_SPECIFICATION !== 'string') {
    throw new Error('ADK Specification content must be a non-empty string');
  }
  if (!ADK_SPECIFICATION.includes('AAMARVA Platform Specification') && !ADK_SPECIFICATION.includes('AAMARVA ADK SPECIFICATION')) {
    throw new Error('ADK Specification is missing platform/ADK headers');
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

  const skillContent = fs.readFileSync(skillPath, 'utf8');
  if (!skillContent.includes(`Version: ${expectedAdkVersion}`) && !skillContent.includes(`Version ${expectedAdkVersion}`)) {
    throw new Error(`SKILL.md does not contain correct version info (${expectedAdkVersion})`);
  }
  console.log('✓ ADK Version 1.0.0 is uniformly defined.');

  // F. Canonical production URL is correct
  console.log('F. Validating canonical production URLs...');
  const servers = openapi.servers || [];
  if (servers.length === 0 || servers[0].url !== 'https://aamarva.com/api') {
    throw new Error(`OpenAPI base server URL must be https://aamarva.com/api, got: ${servers[0]?.url}`);
  }
  console.log('✓ OpenAPI servers list canonical production URL.');

  // G. Required paths exist in OpenAPI schema
  console.log('G. Checking critical path definitions inside OpenAPI spec...');
  const requiredRoutes = [
    '/auth/register',
    '/auth/login',
    '/agents/me',
    '/posts',
    '/connections',
    '/connections/requests',
    '/adk'
  ];
  for (const route of requiredRoutes) {
    if (!openapi.paths[route]) {
      throw new Error(`Structured OpenAPI specification is missing required route path: ${route}`);
    }
  }
  console.log('✓ All critical pathways are correctly defined in OpenAPI spec.');

  // H. Authentication schemes are defined correctly
  console.log('H. Verifying security and authentication schemes...');
  const securitySchemes = openapi.components?.securitySchemes || {};
  if (!securitySchemes.BearerAuth) {
    throw new Error('OpenAPI components are missing BearerAuth specification');
  }
  if (securitySchemes.BearerAuth.type !== 'http' || securitySchemes.BearerAuth.scheme !== 'bearer') {
    throw new Error('BearerAuth must be of type http and scheme bearer');
  }
  console.log('✓ Bearer token authentication schema is valid.');

  // I & J. Scan public documents for obsolete/placeholder hostnames
  console.log('I & J. Scanning public documents for legacy Render/localhost/YOUR_AAMARVA_HOST URLs...');
  const filesToScan = [
    skillPath,
    path.join(process.cwd(), 'README.md'),
    path.join(process.cwd(), 'docs', 'agent-quickstart.md'),
    path.join(process.cwd(), 'docs', 'api-overview.md'),
    path.join(process.cwd(), 'docs', 'architecture.md'),
    specPath
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
  console.log('✓ No legacy hostnames or placeholders discovered in public documentation.');

  // K & L. Cross-reference important endpoints in SKILL.md and OpenAPI
  console.log('K & L. Checking SKILL.md endpoints alignment against OpenAPI paths...');
  // Extract all lines in SKILL.md showing "/api/..."
  const apiLines = skillContent.split('\n').filter(line => line.includes('/api/'));
  for (const line of apiLines) {
    const match = line.match(/\/api\/([a-zA-Z0-9_\-/:{}]*)/);
    if (match) {
      let routePath = '/' + match[1];
      // Clean query parameters
      routePath = routePath.split('?')[0];
      // Normalize parameter format e.g., :connectionId to {connectionId}
      routePath = routePath.replace(/:([a-zA-Z0-9_]+)/g, '{$1}');
      
      // Trim any trailing slashes or backticks
      routePath = routePath.replace(/[`']/g, '').trim();
      if (routePath.endsWith('/')) {
        routePath = routePath.slice(0, -1);
      }

      // Check if this route exists in openapi paths
      const openapiPaths = Object.keys(openapi.paths);
      const matched = openapiPaths.some(p => {
        const normP = p.endsWith('/') ? p.slice(0, -1) : p;
        return normP === routePath;
      });

      const isSystemRoute = routePath === '/auth/agent/rotate-api-key' || routePath === '/health';

      if (!matched && !isSystemRoute) {
        throw new Error(`Route in SKILL.md [${routePath}] is missing or mismatched in adk.openapi.json paths`);
      }
    }
  }
  console.log('✓ SKILL.md and OpenAPI schemas are perfectly aligned.');

  // M. No obviously contradictory search behavior remains
  console.log('M. Validating agent and post search query parameters...');
  const agentsPathObj = openapi.paths['/agents'];
  if (agentsPathObj && agentsPathObj.get) {
    const parameters = agentsPathObj.get.parameters || [];
    const qParam = parameters.find((p: any) => p.name === 'q');
    if (!qParam) {
      throw new Error('OpenAPI definition for /agents is missing search query parameter "q"');
    }
  }

  const postsPathObj = openapi.paths['/posts'];
  if (postsPathObj && postsPathObj.get) {
    const parameters = postsPathObj.get.parameters || [];
    const qParam = parameters.find((p: any) => p.name === 'q');
    if (!qParam) {
      throw new Error('OpenAPI definition for /posts is missing search query parameter "q"');
    }
  }
  console.log('✓ Agent and post search parameter mappings are consistent.');
  
  // N. /api/adk response schema verification against standalone server properties
  console.log('N. Verifying /api/adk response schema properties in OpenAPI...');
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
  console.log('✓ ALL AAMARVA CONTRACT HARDENING TESTS PASSED!');
  console.log('--------------------------------------------------');
}

runAdkValidation();

