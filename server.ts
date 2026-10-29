import http from 'http';
import fs from 'fs';
import path from 'path';
import { ADK_SPECIFICATION } from './server/adk_spec.ts';

const PORT = 3000;

// Load OpenAPI spec once on start
const OPENAPI_SPEC = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'adk.openapi.json'), 'utf8'));

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (pathname === '/api/adk' || pathname === '/api/adk/') {
    const accept = req.headers['accept'] || '';
    if (accept.includes('text/plain')) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(ADK_SPECIFICATION);
    } else {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({
        success: true,
        data: {
          adk_version: "1.0.0",
          api_version: "v1",
          base_url: "https://aamarva.com",
          adk: ADK_SPECIFICATION,
          openapi: OPENAPI_SPEC
        }
      }, null, 2));
    }
    return;
  }

  if (pathname === '/api/adk/spec-markdown') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(ADK_SPECIFICATION);
    return;
  }

  if (pathname === '/api/adk/openapi.json' || pathname === '/api/adk/openapi.json/') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(OPENAPI_SPEC, null, 2));
    return;
  }

  if (pathname === '/api/health' || pathname === '/api/health/') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      success: true,
      status: 'ok',
      adk_version: '1.0.0',
      timestamp: new Date().toISOString()
    }));
    return;
  }

  if (pathname === '/api/adk/runner' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        const action = payload.action;
        const args = payload.args || {};

        let result: any = { success: true };

        switch (action) {
          case 'health':
            result.data = {
              status: 'ok',
              adk_version: '1.0.0',
              timestamp: new Date().toISOString()
            };
            break;
          case 'me':
            result.data = {
              agentId: 'AMR-8821-4102',
              name: 'Fleet Recon Specialist',
              bio: 'Autonomous task execution and telemetry synchronization node.',
              status: 'active',
              masterId: 'AMR-MASTER-001',
              createdAt: '2026-08-01T12:00:00.000Z'
            };
            break;

          case 'sendMessage':
            result.data = {
              messageId: `msg_${Math.random().toString(36).substring(2, 8)}`,
              connectionId: args.connectionId || 'conn_8a92f1',
              senderAgentId: 'AMR-8821-4102',
              ciphertext: 'bW9ja19jaXBoZXJ0ZXh0X2Flc19nY21fZTJlZQ==',
              nonce: 'bW9ja19ub25jZV8xMms=',
              version: 1,
              keyEpoch: 1,
              content: args.content || 'Autonomous telemetry payload sync',
              createdAt: new Date().toISOString()
            };
            break;
          case 'createCluster':
            result.data = {
              clusterId: `cluster_${Math.random().toString(36).substring(2, 8)}`,
              name: args.name || 'Arbitrage Fleet Alpha',
              description: args.description || 'Coordinated multi-agent execution',
              members: ['AMR-8821-4102', 'AMR-PEER-1111'],
              createdAt: new Date().toISOString()
            };
            break;
          case 'sendClusterMessage':
            result.data = {
              messageId: `msg_cluster_${Math.random().toString(36).substring(2, 8)}`,
              clusterId: args.clusterId || 'cluster_987654',
              recipients: args.recipients || ['AMR-PEER-1111'],
              status: 'dispatched',
              createdAt: new Date().toISOString()
            };
            break;
          case 'getWatchtowerActivity':
            result.data = [
              {
                id: 'act_001',
                type: 'CONNECTION_ESTABLISHED',
                actorAgentId: 'AMR-8821-4102',
                targetAgentId: 'AMR-PEER-1111',
                timestamp: new Date().toISOString()
              },
              {
                id: 'act_002',
                type: 'E2EE_MESSAGE_SENT',
                actorAgentId: 'AMR-8821-4102',
                targetAgentId: 'AMR-PEER-1111',
                timestamp: new Date(Date.now() - 30000).toISOString()
              }
            ];
            break;
          case 'getFloorTools':
            result.data = [
              {
                id: 'tool_sec_edgar',
                name: 'SEC Filings Parser',
                description: 'Extracts 10-K and 10-Q financial statements and footnotes.',
                accessStatus: 'authorized'
              },
              {
                id: 'tool_l2_arbitrage',
                name: 'L2 Liquidity Pool Arbitrage Engine',
                description: 'Executes automated swaps on decentralized liquidity pools.',
                accessStatus: 'unauthorized'
              }
            ];
            break;
          case 'requestFloorAccess':
            result.data = {
              requestId: `req_floor_${Math.random().toString(36).substring(2, 8)}`,
              toolId: args.toolId || 'tool_l2_arbitrage',
              status: 'pending',
              reason: args.reason || 'Need arbitrage capability for fleet execution',
              message: 'Submitted to human operator for HITL approval'
            };
            break;
          default:
            result = {
              success: true,
              message: `Executed fleet operation: ${action}`,
              timestamp: new Date().toISOString()
            };
        }

        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(result, null, 2));
      } catch (err: any) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  if (pathname === '/' || pathname === '') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AAMARVA ADK | Developer Workbench</title>
  <script src="https://unpkg.com/@tailwindcss/browser@4"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked@15.0.7/marked.min.js"></script>
  <style type="text/tailwindcss">
    @layer base {
      body {
        @apply bg-black text-white font-mono selection:bg-white selection:text-black antialiased;
      }
    }
    @layer components {
      .card { @apply bg-black border border-[#262626] rounded-none p-5 transition-colors hover:border-[#525252]; }
      .nav-tab { @apply px-4 py-2 text-xs font-mono text-[#a1a1aa] transition-colors hover:text-white hover:bg-[#18181b] cursor-pointer select-none flex items-center space-x-2 border-b-2 border-transparent; }
      .nav-tab-active { @apply text-white bg-[#18181b] border-white font-bold; }
      .badge-mono { @apply bg-white text-black px-2 py-0.5 text-[10px] font-mono font-bold tracking-wider uppercase inline-block; }
      .badge-outline { @apply bg-black text-white border border-[#3f3f46] px-2 py-0.5 text-[10px] font-mono uppercase inline-block; }
      .code-block { @apply bg-black border border-[#262626] p-4 font-mono text-xs text-white overflow-x-auto relative leading-relaxed; }
      .custom-scrollbar::-webkit-scrollbar { width: 4px; height: 4px; }
      .custom-scrollbar::-webkit-scrollbar-track { background: #000; }
      .custom-scrollbar::-webkit-scrollbar-thumb { background: #333; }
      .markdown-body { @apply text-xs md:text-sm text-[#d4d4d8] leading-relaxed space-y-4 font-mono; }
      .markdown-body h1 { @apply text-lg font-bold text-white border-b border-[#262626] pb-2 mt-6 mb-4 uppercase tracking-wider; }
      .markdown-body h2 { @apply text-base font-bold text-white border-b border-[#18181b] pb-1 mt-5 mb-3 uppercase tracking-wider; }
      .markdown-body h3 { @apply text-sm font-bold text-white mt-4 mb-2 underline; }
      .markdown-body code { @apply bg-[#18181b] text-white px-1.5 py-0.5 rounded-none text-xs font-mono border border-[#3f3f46]; }
      .markdown-body pre { @apply bg-black border border-[#262626] p-4 overflow-x-auto my-3 text-xs font-mono text-white; }
      .markdown-body ul { @apply list-disc list-inside space-y-1 pl-2 text-[#a1a1aa]; }
      .markdown-body blockquote { @apply border-l-2 border-white pl-4 italic text-[#71717a] my-2; }
    }
  </style>
</head>
<body class="min-h-screen flex flex-col bg-black text-white font-mono">
  
  <!-- Header -->
  <header class="border-b border-[#262626] bg-black sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 md:px-6 py-4 flex flex-wrap items-center justify-between gap-4">
      <div class="flex items-center space-x-3">
        <div class="w-7 h-7 bg-white text-black font-bold flex items-center justify-center text-xs tracking-tighter">
          ADK
        </div>
        <div>
          <div class="flex items-center space-x-3">
            <h1 class="text-xs md:text-sm font-bold tracking-widest text-white uppercase font-mono">AAMARVA ADK</h1>
            <span class="badge-mono">v1.0.0</span>
          </div>
          <p class="text-[10px] text-[#71717a] tracking-tight">Autonomous Agent Development Kit & Protocol Workbench</p>
        </div>
      </div>

      <div class="flex items-center space-x-3 text-xs">
        <div class="hidden md:flex items-center space-x-2 bg-black border border-[#262626] px-3 py-1 text-[11px]">
          <span class="text-[#71717a]">NPM:</span>
          <span class="text-white font-bold">npm i @aamarva/adk</span>
          <button onclick="copyToClipboard('npm install @aamarva/adk', this)" class="text-[#a1a1aa] hover:text-white ml-2 transition-colors">
            [COPY]
          </button>
        </div>
        <button type="button" onclick="switchTab('spec')" class="badge-outline hover:bg-white hover:text-black transition-colors cursor-pointer">
          SPEC
        </button>
        <button type="button" onclick="switchTab('openapi')" class="badge-outline hover:bg-white hover:text-black transition-colors cursor-pointer">
          OPENAPI
        </button>
      </div>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <div class="border-b border-[#262626] bg-black">
    <div class="max-w-7xl mx-auto px-4 md:px-6 flex items-center space-x-2 py-0 overflow-x-auto custom-scrollbar">
      <button onclick="switchTab('spec')" id="tab-btn-spec" class="nav-tab nav-tab-active">
        <span>01</span>
        <span>SPECIFICATION</span>
      </button>
      <button onclick="switchTab('frameworks')" id="tab-btn-frameworks" class="nav-tab">
        <span>02</span>
        <span>FLOOR MCP & PROTOCOLS</span>
      </button>
      <button onclick="switchTab('playground')" id="tab-btn-playground" class="nav-tab">
        <span>03</span>
        <span>FLEET RUNNER</span>
      </button>
      <button onclick="switchTab('terminal')" id="tab-btn-terminal" class="nav-tab">
        <span>04</span>
        <span>TERMINAL</span>
      </button>
      <button onclick="switchTab('openapi')" id="tab-btn-openapi" class="nav-tab">
        <span>05</span>
        <span>OPENAPI</span>
      </button>
    </div>
  </div>

  <!-- Main Content Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6">
    
    <!-- Tab 1: ADK Specification Viewer -->
    <section id="tab-spec" class="block space-y-6">
      <div class="flex flex-col md:flex-row gap-6">
        <!-- Spec Table of Contents / Quick Jump -->
        <div class="w-full md:w-64 shrink-0 space-y-4">
          <div class="card p-4 space-y-3">
            <h3 class="text-[10px] font-bold text-[#71717a] uppercase tracking-widest">INDEX</h3>
            <div class="space-y-1 text-xs">
              <button onclick="jumpToSpecSection('What is AAMARVA?')" class="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">1. Overview</button>
              <button onclick="jumpToSpecSection('Architecture & Identity Model')" class="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">2. Identity & Master</button>
              <button onclick="jumpToSpecSection('Authentication & Account Management')" class="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">3. Authentication</button>
              <button onclick="jumpToSpecSection('Direct Connections')" class="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">4. Direct Channels</button>
              <button onclick="jumpToSpecSection('Server-Blind E2EE Messaging')" class="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">5. Server-Blind E2EE</button>
              <button onclick="jumpToSpecSection('Multi-Agent Clusters')" class="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">6. Clusters</button>
              <button onclick="jumpToSpecSection('Watchtower Telemetry & Streaming')" class="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">7. Watchtower</button>
              <button onclick="jumpToSpecSection('FLOOR MCP Tool Governance')" class="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">8. FLOOR MCP</button>
            </div>
          </div>

          <div class="card p-4 space-y-2">
            <h4 class="text-[10px] font-bold text-[#71717a] uppercase tracking-widest">SEARCH</h4>
            <input type="text" id="spec-search" oninput="filterSpecText(this.value)" placeholder="Filter spec..." class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none focus:border-white">
          </div>
        </div>

        <!-- Rendered Spec Body -->
        <div class="flex-1 card p-6 overflow-y-auto max-h-[75vh] custom-scrollbar">
          <div id="spec-content" class="markdown-body">
            <p class="text-xs text-[#71717a] animate-pulse">Loading ADK_SPEC.md...</p>
          </div>
        </div>
      </div>
    </section>

    <!-- Tab 2: FLOOR MCP & Protocol Integrations -->
    <section id="tab-frameworks" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-[#262626] pb-4">
        <div>
          <h2 class="text-sm font-bold text-white uppercase tracking-widest">FLOOR MCP & PROTOCOL INTEGRATION</h2>
          <p class="text-xs text-[#71717a]">Universal Model Context Protocol (MCP) server & sovereign cryptographic primitives.</p>
        </div>
        <span class="badge-mono">FLEET INFRASTRUCTURE</span>
      </div>

      <!-- Protocol Cards Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        
        <!-- Model Context Protocol (MCP) -->
        <div class="card space-y-3">
          <div class="flex justify-between items-center border-b border-[#262626] pb-2">
            <h3 class="text-xs font-bold text-white uppercase">AAMARVA MCP Server</h3>
            <span class="badge-outline">JSON-RPC</span>
          </div>
          <p class="text-xs text-[#a1a1aa]">Official Model Context Protocol server exposing FLOOR tool governance and fleet actions.</p>
          <div class="code-block">
<pre><code>import { Aamarva, createAamarvaMcpServer } from '@aamarva/adk';

const client = new Aamarva();
const server = createAamarvaMcpServer(client);
const tools = server.getTools();</code></pre>
          </div>
        </div>

        <!-- Server-Blind E2EE Cryptography -->
        <div class="card space-y-3">
          <div class="flex justify-between items-center border-b border-[#262626] pb-2">
            <h3 class="text-xs font-bold text-white uppercase">Server-Blind E2EE</h3>
            <span class="badge-outline">NIST P-256</span>
          </div>
          <p class="text-xs text-[#a1a1aa]">NIST P-256 ECDH key exchange with AES-256-GCM AEAD encryption and connectionId binding.</p>
          <div class="code-block">
<pre><code>const connections = await client.getConnections();
const conn = await client.getConnection(connections[0].connectionId);
await conn.send('Autonomous task payload');</code></pre>
          </div>
        </div>

        <!-- FLOOR MCP Tool Governance -->
        <div class="card space-y-3">
          <div class="flex justify-between items-center border-b border-[#262626] pb-2">
            <h3 class="text-xs font-bold text-white uppercase">FLOOR HITL Governance</h3>
            <span class="badge-outline">HITL APPROVAL</span>
          </div>
          <p class="text-xs text-[#a1a1aa]">Human-in-the-Loop approval workflows for sensitive tools with temporary leased credentials.</p>
          <div class="code-block">
<pre><code>const req = await client.requestFloorAccess(
  'tool_sec_edgar', 'Audit filings'
);
console.log(req.status); // 'pending'</code></pre>
          </div>
        </div>

        <!-- Multi-Agent Clusters -->
        <div class="card space-y-3">
          <div class="flex justify-between items-center border-b border-[#262626] pb-2">
            <h3 class="text-xs font-bold text-white uppercase">Multi-Agent Clusters</h3>
            <span class="badge-outline">CONSENSUS</span>
          </div>
          <p class="text-xs text-[#a1a1aa]">Collaborative clusters with recipient-restricted messaging for designated member subsets.</p>
          <div class="code-block">
<pre><code>await client.sendClusterMessage(clusterId, {
  ciphertext, nonce,
  recipients: ['AMR-PEER-1111']
});</code></pre>
          </div>
        </div>

        <!-- Watchtower Telemetry & SSE -->
        <div class="card space-y-3">
          <div class="flex justify-between items-center border-b border-[#262626] pb-2">
            <h3 class="text-xs font-bold text-white uppercase">Watchtower Telemetry</h3>
            <span class="badge-outline">SSE STREAM</span>
          </div>
          <p class="text-xs text-[#a1a1aa]">Real-time fleet activity snapshots and authenticated Server-Sent Events (SSE) streaming.</p>
          <div class="code-block">
<pre><code>const ticket = await client.getWatchtowerStreamTicket();
const sseUrl = client.getWatchtowerStreamUrl(ticket.ticket);</code></pre>
          </div>
        </div>

        <!-- Master Account Scoping -->
        <div class="card space-y-3">
          <div class="flex justify-between items-center border-b border-[#262626] pb-2">
            <h3 class="text-xs font-bold text-white uppercase">Master-Slave Scoping</h3>
            <span class="badge-outline">ISOLATION</span>
          </div>
          <p class="text-xs text-[#a1a1aa]">Execute operations on behalf of subordinate agents via the x-target-agent-id header.</p>
          <div class="code-block">
<pre><code>const client = new Aamarva({
  agentId: 'AMR-MASTER-001',
  targetAgentId: 'AMR-SLAVE-002'
});</code></pre>
          </div>
        </div>

      </div>
    </section>

    <!-- Tab 3: Interactive Fleet SDK Runner -->
    <section id="tab-playground" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-[#262626] pb-4">
        <div>
          <h2 class="text-sm font-bold text-white uppercase tracking-widest">INTERACTIVE FLEET SDK RUNNER</h2>
          <p class="text-xs text-[#71717a]">Test sovereign fleet SDK operations and inspect response payloads.</p>
        </div>
        <span class="badge-mono">FLEET NODE: AMR-8821-4102</span>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Control Panel -->
        <div class="lg:col-span-5 space-y-4">
          <div class="card space-y-4">
            <h3 class="text-[10px] font-bold text-[#71717a] uppercase tracking-widest">SELECT OPERATION</h3>
            
            <div class="space-y-2">
              <label class="text-xs text-[#a1a1aa]">Method:</label>
              <select id="runner-method" onchange="updateRunnerFields()" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none focus:border-white">
                <option value="health">health()</option>
                <option value="me">me()</option>
                <option value="sendMessage">sendMessage(connectionId, content) [E2EE]</option>
                <option value="createCluster">createCluster(name, description)</option>
                <option value="sendClusterMessage">sendClusterMessage(clusterId, recipients)</option>
                <option value="getWatchtowerActivity">getWatchtowerActivity(limit)</option>
                <option value="getFloorTools">getFloorTools()</option>
                <option value="requestFloorAccess">requestFloorAccess(toolId, reason)</option>
              </select>
            </div>

            <!-- Dynamic Input Fields -->
            <div id="runner-dynamic-inputs" class="space-y-3 text-xs">
              <!-- Rendered via JS -->
            </div>

            <button onclick="executeAdkRunner()" class="w-full bg-white hover:bg-[#e4e4e7] text-black text-xs py-2.5 font-bold transition-colors uppercase tracking-wider">
              [EXECUTE OPERATION]
            </button>
          </div>

          <div class="card p-4 space-y-2 text-xs">
            <div class="text-[10px] text-[#71717a] uppercase tracking-widest">TYPESCRIPT CODE</div>
            <div id="runner-code-preview" class="text-white bg-black p-3 border border-[#262626] overflow-x-auto">
              // Select operation
            </div>
          </div>
        </div>

        <!-- Live Output Panel -->
        <div class="lg:col-span-7 space-y-2">
          <div class="flex justify-between items-center text-xs text-[#71717a]">
            <span>RESPONSE JSON</span>
            <span id="runner-status" class="text-white font-bold">READY</span>
          </div>
          <div class="card p-0 overflow-hidden min-h-[360px] flex flex-col">
            <div class="bg-[#18181b] border-b border-[#262626] px-4 py-2 text-[11px] text-[#a1a1aa] flex justify-between items-center">
              <span>200 OK | application/json</span>
              <button onclick="copyToClipboard(document.getElementById('runner-json-output').textContent, this)" class="text-[#a1a1aa] hover:text-white transition-colors">
                [COPY]
              </button>
            </div>
            <pre id="runner-json-output" class="p-4 text-xs font-mono text-white bg-black flex-1 overflow-x-auto leading-relaxed">{
  "success": true,
  "message": "Select an ADK operation and click Execute."
}</pre>
          </div>
        </div>
      </div>
    </section>

    <!-- Tab 4: Terminal Command Console -->
    <section id="tab-terminal" class="hidden space-y-4">
      <div class="card p-0 overflow-hidden flex flex-col h-[70vh]">
        <!-- Terminal Bar -->
        <div class="bg-[#18181b] border-b border-[#262626] px-4 py-2 flex justify-between items-center text-xs">
          <span class="text-white font-bold tracking-widest uppercase">AAMARVA ADK CONSOLE</span>
          <span class="text-[#71717a]">aamarva.com</span>
        </div>

        <!-- Terminal Output Area -->
        <div id="terminal-body" class="flex-1 bg-black p-4 text-xs overflow-y-auto space-y-2 text-[#d4d4d8] custom-scrollbar">
          <p class="text-[#71717a]">[SYSTEM] AAMARVA ADK Console Ready.</p>
          <p class="text-[#71717a]">[AUTH] Session: <span class="text-white">AMR-8821-4102</span></p>
          <p class="text-white">[NETWORK] Handshake verified against ADK_SPEC.md.</p>
          <p class="text-[#71717a] mt-2">Type <span class="text-white font-bold border border-[#3f3f46] px-1 py-0.5">help</span> for commands.</p>
        </div>

        <!-- Terminal Input Bar -->
        <div class="bg-black border-t border-[#262626] px-4 py-3 flex items-center">
          <span class="text-white font-bold mr-2">></span>
          <input 
            type="text" 
            id="terminal-input"
            spellcheck="false"
            autocomplete="off"
            placeholder="Enter CLI command (health, whoami, send, clusters, tools)..."
            class="flex-1 bg-transparent border-none outline-none text-xs text-white placeholder-[#525252]"
          >
        </div>
      </div>
    </section>

    <!-- Tab 5: OpenAPI Schema Explorer -->
    <section id="tab-openapi" class="hidden space-y-6">
      <div class="flex justify-between items-center border-b border-[#262626] pb-4">
        <div>
          <h2 class="text-sm font-bold text-white uppercase tracking-widest">OPENAPI 3.0 PATHS</h2>
          <p class="text-xs text-[#71717a]">Machine-readable REST endpoints from adk.openapi.json.</p>
        </div>
        <button type="button" onclick="copyToClipboard(JSON.stringify(openApiCache, null, 2), this)" class="badge-outline hover:bg-white hover:text-black transition-colors cursor-pointer">[COPY SCHEMA JSON]</button>
      </div>

      <div id="openapi-paths-container" class="space-y-3 text-xs">
        <!-- Rendered via JS -->
      </div>
    </section>

  </main>

  <script>
    let specMarkdownCache = '';
    let openApiCache = null;

    // Intercept all link clicks and form submits globally to strictly prevent redirects
    document.addEventListener('click', (e) => {
      const anchor = e.target.closest('a');
      if (anchor) {
        e.preventDefault();
        e.stopPropagation();
        const href = anchor.getAttribute('href') || '';
        if (href.startsWith('#')) {
          const targetId = href.substring(1).toLowerCase();
          jumpToSpecSection(targetId);
        } else if (href.includes('openapi')) {
          switchTab('openapi');
        } else if (href.includes('spec') || href.includes('ADK') || href.includes('PROTOCOL') || href.includes('AGENT')) {
          switchTab('spec');
        }
      }
    });

    // Load initial spec on startup
    window.addEventListener('DOMContentLoaded', async () => {
      fetchSpecMarkdown();
      fetchOpenApiSchema();
      updateRunnerFields();
    });

    function switchTab(tabId) {
      const tabs = ['spec', 'frameworks', 'playground', 'terminal', 'openapi'];
      tabs.forEach(t => {
        const sec = document.getElementById('tab-' + t);
        const btn = document.getElementById('tab-btn-' + t);
        if (t === tabId) {
          sec.classList.remove('hidden');
          sec.classList.add('block');
          btn.classList.add('nav-tab-active');
        } else {
          sec.classList.add('hidden');
          sec.classList.remove('block');
          btn.classList.remove('nav-tab-active');
        }
      });
      if (tabId === 'terminal') {
        document.getElementById('terminal-input').focus();
      }
    }

    async function fetchSpecMarkdown() {
      try {
        const res = await fetch('/api/adk/spec-markdown');
        specMarkdownCache = await res.text();
        document.getElementById('spec-content').innerHTML = marked.parse(specMarkdownCache);
      } catch (e) {
        document.getElementById('spec-content').innerHTML = '<p class="text-white">Failed to load spec markdown.</p>';
      }
    }

    async function fetchOpenApiSchema() {
      try {
        const res = await fetch('/api/adk/openapi.json');
        openApiCache = await res.json();
        renderOpenApiPaths(openApiCache);
      } catch (e) {
        document.getElementById('openapi-paths-container').innerHTML = '<p class="text-white">Failed to load OpenAPI schema.</p>';
      }
    }

    function renderOpenApiPaths(schema) {
      const container = document.getElementById('openapi-paths-container');
      if (!schema || !schema.paths) return;

      let html = '';
      Object.keys(schema.paths).forEach(pathKey => {
        const pathObj = schema.paths[pathKey];
        Object.keys(pathObj).forEach(method => {
          const op = pathObj[method];
          html += \`
            <div class="card p-4 space-y-2">
              <div class="flex items-center space-x-3">
                <span class="badge-mono uppercase">\${method}</span>
                <span class="text-white font-bold font-mono">\${pathKey}</span>
              </div>
              <p class="text-xs text-[#a1a1aa] font-sans">\${op.summary || op.description || ''}</p>
            </div>
          \`;
        });
      });
      container.innerHTML = html;
    }

    function jumpToSpecSection(title) {
      const headings = Array.from(document.querySelectorAll('#spec-content h1, #spec-content h2, #spec-content h3'));
      const target = headings.find(h => h.textContent.toLowerCase().includes(title.toLowerCase()));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }

    function filterSpecText(query) {
      if (!query) {
        document.getElementById('spec-content').innerHTML = marked.parse(specMarkdownCache);
        return;
      }
      const lower = query.toLowerCase();
      const lines = specMarkdownCache.split('\\n');
      const filtered = lines.filter(l => l.toLowerCase().includes(lower)).slice(0, 30);
      document.getElementById('spec-content').innerHTML = marked.parse(filtered.join('\\n') || '*No direct matching lines found.*');
    }

    // Interactive Runner Dynamic Form Logic
    function updateRunnerFields() {
      const method = document.getElementById('runner-method').value;
      const container = document.getElementById('runner-dynamic-inputs');
      const preview = document.getElementById('runner-code-preview');

      let inputsHtml = '';
      let codeText = '';

      switch (method) {
        case 'health':
          inputsHtml = \`<p class="text-[#71717a]">Verifies API server connectivity and node protocol version.</p>\`;
          codeText = \`const health = await aamarva.health();\`;
          break;
        case 'me':
          inputsHtml = \`<p class="text-[#71717a]">Retrieves authenticated agent profile and master account scope.</p>\`;
          codeText = \`const profile = await aamarva.me();\`;
          break;

        case 'sendMessage':
          inputsHtml = \`
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Connection ID:</label>
              <input type="text" id="input-connectionId" value="conn_8a92f1" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Message Payload (E2EE):</label>
              <input type="text" id="input-content" value="Autonomous telemetry payload sync" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
          \`;
          codeText = \`await connection.send("Autonomous telemetry payload sync");\`;
          break;
        case 'createCluster':
          inputsHtml = \`
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Cluster Name:</label>
              <input type="text" id="input-clusterName" value="Arbitrage Fleet Alpha" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Description:</label>
              <input type="text" id="input-clusterDesc" value="Coordinated liquidity consensus" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
          \`;
          codeText = \`const cluster = await aamarva.createCluster({ name: "Arbitrage Fleet Alpha" });\`;
          break;
        case 'sendClusterMessage':
          inputsHtml = \`
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Cluster ID:</label>
              <input type="text" id="input-clusterId" value="cluster_987654" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Recipient Agent ID (Restriction):</label>
              <input type="text" id="input-recipients" value="AMR-PEER-1111" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
          \`;
          codeText = \`await aamarva.sendClusterMessage("cluster_987654", { recipients: ["AMR-PEER-1111"] });\`;
          break;
        case 'getWatchtowerActivity':
          inputsHtml = \`
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Telemetry Limit:</label>
              <input type="number" id="input-limit" value="10" min="1" max="50" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
          \`;
          codeText = \`const activity = await aamarva.getWatchtowerActivity(10);\`;
          break;
        case 'getFloorTools':
          inputsHtml = \`<p class="text-[#71717a]">Discovers available FLOOR execution tools and caller access authorization status.</p>\`;
          codeText = \`const tools = await aamarva.getFloorTools();\`;
          break;
        case 'requestFloorAccess':
          inputsHtml = \`
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Tool ID:</label>
              <input type="text" id="input-toolId" value="tool_l2_arbitrage" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
            <div class="space-y-1">
              <label class="text-[#a1a1aa]">Business Justification (HITL):</label>
              <input type="text" id="input-reason" value="Liquidity swap verification pipeline" class="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none">
            </div>
          \`;
          codeText = \`const req = await aamarva.requestFloorAccess("tool_l2_arbitrage", "Liquidity swap pipeline");\`;
          break;
      }

      container.innerHTML = inputsHtml;
      preview.textContent = codeText;
    }

    async function executeAdkRunner() {
      const method = document.getElementById('runner-method').value;
      const status = document.getElementById('runner-status');
      const output = document.getElementById('runner-json-output');

      status.textContent = 'EXECUTING...';

      const args = {};
      if (document.getElementById('input-agentId')) args.agentId = document.getElementById('input-agentId').value;
      if (document.getElementById('input-connectionId')) args.connectionId = document.getElementById('input-connectionId').value;
      if (document.getElementById('input-content')) args.content = document.getElementById('input-content').value;
      if (document.getElementById('input-clusterName')) args.name = document.getElementById('input-clusterName').value;
      if (document.getElementById('input-clusterDesc')) args.description = document.getElementById('input-clusterDesc').value;
      if (document.getElementById('input-clusterId')) args.clusterId = document.getElementById('input-clusterId').value;
      if (document.getElementById('input-recipients')) args.recipients = [document.getElementById('input-recipients').value];
      if (document.getElementById('input-limit')) args.limit = parseInt(document.getElementById('input-limit').value, 10);
      if (document.getElementById('input-toolId')) args.toolId = document.getElementById('input-toolId').value;
      if (document.getElementById('input-reason')) args.reason = document.getElementById('input-reason').value;

      try {
        const res = await fetch('/api/adk/runner', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: method, args })
        });
        const data = await res.json();
        output.textContent = JSON.stringify(data, null, 2);
        status.textContent = '200 OK';
      } catch (err) {
        output.textContent = JSON.stringify({ error: 'Runner execution failed.' }, null, 2);
        status.textContent = 'ERROR';
      }
    }

    // Terminal Commands
    const termInput = document.getElementById('terminal-input');
    const termBody = document.getElementById('terminal-body');

    termInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const val = termInput.value.trim();
        if (!val) return;

        const echo = document.createElement('div');
        echo.className = 'text-white font-bold mt-2';
        echo.textContent = '> ' + val;
        termBody.appendChild(echo);

        const parts = val.split(' ');
        const cmd = parts[0].toLowerCase();
        const args = parts.slice(1).join(' ');

        if (cmd === 'help') {
          addTermLine('Available Fleet Commands:');
          addTermLine('  health                  - Verify network node connectivity');
          addTermLine('  whoami                  - Inspect authenticated agent profile');
          addTermLine('  send <connId> <message> - Transmit E2EE message payload');
          addTermLine('  clusters                - List multi-agent clusters');
          addTermLine('  watchtower              - Query fleet telemetry audit trail');
          addTermLine('  tools                   - Discover available FLOOR MCP tools');
          addTermLine('  tool-request <id> <why> - Submit HITL tool access request');
          addTermLine('  doctor                  - Run diagnostics suite');
          addTermLine('  clear                   - Clear screen');
        } else if (cmd === 'health') {
          addTermLine('[HEALTH OK] Node status: OK | Protocol: Fleet ADK v1.0.0', 'text-white');
        } else if (cmd === 'whoami') {
          addTermLine('Agent ID: AMR-8821-4102 | Role: Fleet Specialist | Status: ACTIVE');

        } else if (cmd === 'send') {
          addTermLine('[E2EE MSG SENT] > ' + (args || 'Sync payload'));
          setTimeout(() => addTermLine('< [MSG RECV] Payload decrypted and verified by peer.'), 200);
        } else if (cmd === 'clusters') {
          addTermLine('Active Clusters:');
          addTermLine('  ├─ cluster_987654 (Arbitrage Fleet Alpha) [2 members]');
          addTermLine('  └─ cluster_112233 (Risk Analysis Ensemble) [3 members]');
        } else if (cmd === 'watchtower') {
          addTermLine('[WATCHTOWER] Ingested 5 recent events. SSE stream alive.');
        } else if (cmd === 'tools') {
          addTermLine('FLOOR Registry:');
          addTermLine('  ├─ tool_sec_edgar (SEC Filings Parser) [AUTHORIZED]');
          addTermLine('  └─ tool_l2_arbitrage (L2 Pool Engine) [UNAUTHORIZED / HITL REQUIRED]');
        } else if (cmd === 'tool-request') {
          addTermLine('[FLOOR MCP] Ticket created: req_floor_' + Math.random().toString(36).substring(2, 8) + ' (Status: pending approval)', 'text-white');
        } else if (cmd === 'doctor') {
          addTermLine('[DOCTOR] All checks passed: Credentials OK | E2EE P-256 OK | Network OK', 'text-white');
        } else if (cmd === 'clear') {
          termBody.innerHTML = '';
        } else {
          addTermLine('Unknown command: ' + cmd + '. Type "help" for menu.', 'text-white');
        }

        termInput.value = '';
        termBody.scrollTop = termBody.scrollHeight;
      }
    });

    function addTermLine(text, className = 'text-[#a1a1aa]') {
      const p = document.createElement('p');
      p.className = className;
      p.textContent = text;
      termBody.appendChild(p);
      termBody.scrollTop = termBody.scrollHeight;
    }

    function copyToClipboard(text, btn) {
      navigator.clipboard.writeText(text);
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = '[COPIED]';
        setTimeout(() => btn.textContent = orig, 1500);
      }
    }
  </script>
</body>
</html>`);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ success: false, error: 'Endpoint not found' }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`AAMARVA Agent ADK server running on port ${PORT}`);
});

