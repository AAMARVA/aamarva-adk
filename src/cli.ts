/**
 * AAMARVA CLI implementation for fleet agent operations, diagnostics, and FLOOR MCP governance.
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { Aamarva } from './client.js';
import { getLocalPublicKeyPem, computeKeyFingerprint } from './crypto.js';

function loadEnvFile(): void {
  const envPath = path.join(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
        if (!process.env[key]) {
          process.env[key] = val;
        }
      }
    }
  }
}

async function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function getClient(): Aamarva {
  loadEnvFile();
  const agentId = process.env.AAMARVA_AGENT_ID;
  const apiKey = process.env.AAMARVA_API_KEY;
  const baseUrl = process.env.AAMARVA_BASE_URL || 'https://aamarva.com/api';
  const targetAgentId = process.env.AAMARVA_TARGET_AGENT_ID;

  return new Aamarva({ agentId, apiKey, baseUrl, targetAgentId });
}

export async function runCli(args: string[] = process.argv.slice(2)): Promise<void> {
  loadEnvFile();

  const command = args[0] || 'help';

  switch (command) {
    case 'health':
      await handleHealth();
      break;
    case 'me':
      await handleMe();
      break;
    case 'connections':
      await handleConnections();
      break;
    case 'message':
      await handleMessage(args.slice(1));
      break;
    case 'clusters':
      await handleClusters();
      break;
    case 'watchtower':
      await handleWatchtower(args.slice(1));
      break;
    case 'tools':
      await handleTools();
      break;
    case 'tool-request':
      await handleToolRequest(args.slice(1));
      break;
    case 'tool-status':
      await handleToolStatus(args.slice(1));
      break;
    case 'doctor':
      await handleDoctor();
      break;
    case 'init':
      await handleInit(args.slice(1));
      break;
    case 'help':
    case '--help':
    case '-h':
    default:
      printHelp();
      break;
  }
}

export async function handleHealth(): Promise<void> {
  const client = getClient();
  try {
    const res = await client.health();
    console.log(JSON.stringify(res, null, 2));
  } catch (err: any) {
    console.error('Health check failed:', err.message);
    process.exit(1);
  }
}

export async function handleMe(): Promise<void> {
  const client = getClient();
  try {
    const me = await client.me();
    console.log(JSON.stringify(me, null, 2));
  } catch (err: any) {
    console.error('Failed to retrieve agent identity:', err.message);
    process.exit(1);
  }
}

export async function handleConnections(): Promise<void> {
  const client = getClient();
  try {
    const list = await client.getConnections();
    console.log(JSON.stringify(list, null, 2));
  } catch (err: any) {
    console.error('Failed to list connections:', err.message);
    process.exit(1);
  }
}

export async function handleMessage(args: string[]): Promise<void> {
  const connectionId = args[0];
  const content = args.slice(1).join(' ');
  if (!connectionId || !content) {
    console.error('Usage: aamarva message <connectionId> <content>');
    process.exit(1);
  }

  const client = getClient();
  try {
    const msg = await client.sendMessage(connectionId, content);
    console.log(`✓ Encrypted message sent [ID: ${msg.messageId}]`);
  } catch (err: any) {
    console.error('Failed to send encrypted message:', err.message);
    process.exit(1);
  }
}

export async function handleClusters(): Promise<void> {
  const client = getClient();
  try {
    const list = await client.getClusters();
    console.log(JSON.stringify(list, null, 2));
  } catch (err: any) {
    console.error('Failed to list clusters:', err.message);
    process.exit(1);
  }
}

export async function handleWatchtower(args: string[]): Promise<void> {
  const limit = args[0] ? parseInt(args[0], 10) : 20;
  const client = getClient();
  try {
    const acts = await client.getWatchtowerActivity(limit);
    console.log(JSON.stringify(acts, null, 2));
  } catch (err: any) {
    console.error('Failed to retrieve Watchtower activity:', err.message);
    process.exit(1);
  }
}

export async function handleTools(): Promise<void> {
  const client = getClient();
  try {
    const tools = await client.getFloorTools();
    console.log(JSON.stringify(tools, null, 2));
  } catch (err: any) {
    console.error('Failed to retrieve FLOOR tools:', err.message);
    process.exit(1);
  }
}

export async function handleToolRequest(args: string[]): Promise<void> {
  const toolId = args[0];
  const reason = args.slice(1).join(' ') || 'Agent requested access';
  if (!toolId) {
    console.error('Usage: aamarva tool-request <toolId> [reason]');
    process.exit(1);
  }

  const client = getClient();
  try {
    const res = await client.requestFloorAccess(toolId, reason);
    console.log(`✓ Tool access request submitted [Status: ${res.status}, Request ID: ${res.requestId || 'pending'}]`);
  } catch (err: any) {
    console.error('Failed to submit tool access request:', err.message);
    process.exit(1);
  }
}

export async function handleToolStatus(args: string[]): Promise<void> {
  const requestId = args[0];
  if (!requestId) {
    console.error('Usage: aamarva tool-status <requestId>');
    process.exit(1);
  }

  const client = getClient();
  try {
    const status = await client.getFloorRequestStatus(requestId);
    console.log(JSON.stringify(status, null, 2));
  } catch (err: any) {
    console.error('Failed to check tool request status:', err.message);
    process.exit(1);
  }
}

export async function handleDoctor(): Promise<void> {
  console.log('\n========================================');
  console.log('       AAMARVA FLEET DIAGNOSTICS        ');
  console.log('========================================\n');

  loadEnvFile();
  const agentId = process.env.AAMARVA_AGENT_ID || '';
  const apiKey = process.env.AAMARVA_API_KEY || '';
  const baseUrl = process.env.AAMARVA_BASE_URL || 'https://aamarva.com/api';

  console.log(`✓ Architecture:           Fleet-Only Agent Infrastructure`);
  console.log(`✓ SDK Version:            @aamarva/adk v1.0.0`);

  if (!agentId || !apiKey) {
    console.log(`✖ Authentication:         Missing AAMARVA_AGENT_ID or AAMARVA_API_KEY in .env`);
    console.log(`\nRun "aamarva init" to configure credentials.`);
    return;
  }

  console.log(`✓ Agent Identity:         Configured (${agentId})`);

  // Check E2EE Keys
  try {
    const pubPem = getLocalPublicKeyPem();
    const fp = computeKeyFingerprint(pubPem);
    console.log(`✓ E2EE Cryptography:      Initialized [P-256 ECDH + AES-256-GCM] (Fingerprint: ${fp.slice(0, 16)}...)`);
  } catch (err: any) {
    console.log(`✖ E2EE Cryptography:      Failed: ${err.message}`);
  }

  const client = new Aamarva({ agentId, apiKey, baseUrl });

  try {
    const health = await client.health();
    console.log(`✓ Network Connectivity:   Connected to ${baseUrl} [Status: ${health.status}]`);
  } catch (err: any) {
    console.log(`✖ Network Connectivity:   Failed to reach ${baseUrl}: ${err.message}`);
  }

  try {
    const me = await client.me();
    console.log(`✓ Fleet Identity Auth:    Verified (${me.name})`);
  } catch (err: any) {
    console.log(`✖ Fleet Identity Auth:    Failed: ${err.message}`);
  }

  try {
    const tools = await client.getFloorTools();
    console.log(`✓ FLOOR MCP Governance:   Active (${tools.length} tools available)`);
  } catch (err: any) {
    console.log(`ℹ FLOOR MCP Governance:   ${err.message}`);
  }

  console.log('\nDiagnostics complete.\n');
}

export async function handleInit(args: string[] = []): Promise<void> {
  console.log('\n--- AAMARVA Agent Initializer ---');
  const agentId = (await prompt('Agent ID (e.g. AMR-XXXX-XXXX): ')) || process.env.AAMARVA_AGENT_ID || '';
  const apiKey = (await prompt('API Key: ')) || process.env.AAMARVA_API_KEY || '';
  const baseUrl = (await prompt('Base URL [https://aamarva.com/api]: ')) || process.env.AAMARVA_BASE_URL || 'https://aamarva.com/api';

  if (!agentId || !apiKey) {
    console.error('Agent ID and API Key are required.');
    return;
  }

  const envPath = path.join(process.cwd(), '.env');
  const content = `AAMARVA_AGENT_ID=${agentId}\nAAMARVA_API_KEY=${apiKey}\nAAMARVA_BASE_URL=${baseUrl}\n`;
  fs.writeFileSync(envPath, content, { flag: 'w' });
  console.log(`✓ Configuration saved to ${envPath}`);
}

export function printHelp(): void {
  console.log(`AAMARVA Fleet Agent Development Kit (ADK) CLI

Usage:
  aamarva <command> [arguments]
  npx aamarva <command> [arguments]

Fleet Operations:
  health                     Check AAMARVA network health and status
  me                         Retrieve authenticated agent identity
  connections                List active direct connections
  message <connId> <text>    Send an encrypted private message
  clusters                   List active clusters
  watchtower [limit]         View recent fleet telemetry activity
  tools                      List FLOOR MCP tools and caller access status
  tool-request <id> [reason] Submit human-in-the-loop tool access request
  tool-status <requestId>    Check approval status of a tool access request

Diagnostics & Setup:
  doctor                     Run fleet diagnostics (auth, keys, network, FLOOR)
  init                       Configure agent credentials in .env
  help                       Show this help reference
`);
}
