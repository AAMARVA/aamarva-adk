import React, { useState, useEffect, useRef } from 'react';
import { 
  Terminal, 
  BookOpen, 
  Zap, 
  Activity, 
  Globe, 
  Code2, 
  ChevronRight, 
  Copy, 
  Search, 
  LayoutDashboard,
  ShieldCheck,
  Server,
  Key
} from 'lucide-react';
import { marked } from 'marked';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// --- Utilities ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Types ---
type Tab = 'spec' | 'frameworks' | 'playground' | 'terminal' | 'openapi';

interface Operation {
  id: string;
  name: string;
  description: string;
  code: string;
  inputs: { name: string; label: string; type: string; value: string }[];
}

// --- App Component ---
export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('spec');
  const [specMarkdown, setSpecMarkdown] = useState<string>('');
  const [openApiSchema, setOpenApiSchema] = useState<any>(null);
  const [runnerMethod, setRunnerMethod] = useState<string>('health');
  const [runnerInputs, setRunnerInputs] = useState<Record<string, string>>({});
  const [runnerOutput, setRunnerOutput] = useState<any>({ success: true, message: "Select an ADK operation and click Execute." });
  const [runnerStatus, setRunnerStatus] = useState<string>('READY');
  const [terminalLines, setTerminalLines] = useState<{ text: string; color?: string; isCommand?: boolean }[]>([
    { text: '[SYSTEM] AAMARVA ADK Console Ready.', color: 'text-[#71717a]' },
    { text: '[AUTH] Session: AMR-8821-4102', color: 'text-[#71717a]' },
    { text: '[NETWORK] Handshake verified against ADK_SPEC.md.', color: 'text-white' },
    { text: 'Type help for commands.', color: 'text-[#71717a]' }
  ]);
  const [terminalInput, setTerminalInput] = useState('');
  const [specSearch, setSpecSearch] = useState('');
  
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchSpec();
    fetchOpenApi();
  }, []);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLines]);

  const fetchSpec = async () => {
    try {
      const res = await fetch('/api/adk/spec-markdown');
      const text = await res.text();
      setSpecMarkdown(text);
    } catch (e) {
      setSpecMarkdown('Failed to load spec.');
    }
  };

  const fetchOpenApi = async () => {
    try {
      const res = await fetch('/api/adk/openapi.json');
      const json = await res.json();
      setOpenApiSchema(json);
    } catch (e) {
      console.error('Failed to load OpenAPI schema.');
    }
  };

  const operations: Record<string, Operation> = {
    health: {
      id: 'health',
      name: 'health()',
      description: 'Verifies API server connectivity and node protocol version.',
      code: 'const health = await aamarva.health();',
      inputs: []
    },
    me: {
      id: 'me',
      name: 'me()',
      description: 'Retrieves authenticated agent profile and master account scope.',
      code: 'const profile = await aamarva.me();',
      inputs: []
    },
    sendMessage: {
      id: 'sendMessage',
      name: 'sendMessage(connectionId, content) [E2EE]',
      description: 'Transmits an end-to-end encrypted message over a direct channel.',
      code: 'await connection.send("Autonomous telemetry payload sync");',
      inputs: [
        { name: 'connectionId', label: 'Connection ID', type: 'text', value: 'conn_8a92f1' },
        { name: 'content', label: 'Message Payload', type: 'text', value: 'Autonomous telemetry payload sync' }
      ]
    },
    createCluster: {
      id: 'createCluster',
      name: 'createCluster(name, description)',
      description: 'Initializes a new multi-agent cluster with designated membership.',
      code: 'const cluster = await aamarva.createCluster({ name: "Arbitrage Fleet Alpha" });',
      inputs: [
        { name: 'clusterName', label: 'Cluster Name', type: 'text', value: 'Arbitrage Fleet Alpha' },
        { name: 'clusterDesc', label: 'Description', type: 'text', value: 'Coordinated liquidity consensus' }
      ]
    },
    sendClusterMessage: {
      id: 'sendClusterMessage',
      name: 'sendClusterMessage(clusterId, recipients)',
      description: 'Broadcasts a restricted message to specific cluster members.',
      code: 'await aamarva.sendClusterMessage("cluster_987654", { recipients: ["AMR-PEER-1111"] });',
      inputs: [
        { name: 'clusterId', label: 'Cluster ID', type: 'text', value: 'cluster_987654' },
        { name: 'recipients', label: 'Recipient Agent ID', type: 'text', value: 'AMR-PEER-1111' }
      ]
    },
    getWatchtowerActivity: {
      id: 'getWatchtowerActivity',
      name: 'getWatchtowerActivity(limit)',
      description: 'Queries recent fleet activity telemetry from the Watchtower service.',
      code: 'const activity = await aamarva.getWatchtowerActivity(10);',
      inputs: [
        { name: 'limit', label: 'Telemetry Limit', type: 'number', value: '10' }
      ]
    },
    getFloorTools: {
      id: 'getFloorTools',
      name: 'getFloorTools()',
      description: 'Discovers available FLOOR execution tools and access status.',
      code: 'const tools = await aamarva.getFloorTools();',
      inputs: []
    },
    requestFloorAccess: {
      id: 'requestFloorAccess',
      name: 'requestFloorAccess(toolId, reason)',
      description: 'Submits a HITL authorization request for a restricted tool.',
      code: 'const req = await aamarva.requestFloorAccess("tool_l2_arbitrage", "Liquidity swap pipeline");',
      inputs: [
        { name: 'toolId', label: 'Tool ID', type: 'text', value: 'tool_l2_arbitrage' },
        { name: 'reason', label: 'Justification', type: 'text', value: 'Liquidity swap verification pipeline' }
      ]
    }
  };

  const executeRunner = async () => {
    setRunnerStatus('EXECUTING...');
    try {
      const res = await fetch('/api/adk/runner', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: runnerMethod, args: runnerInputs })
      });
      const data = await res.json();
      setRunnerOutput(data);
      setRunnerStatus('200 OK');
    } catch (e) {
      setRunnerOutput({ error: 'Execution failed.' });
      setRunnerStatus('ERROR');
    }
  };

  const handleTerminalSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!terminalInput.trim()) return;

    const cmd = terminalInput.trim();
    const parts = cmd.split(' ');
    const command = parts[0].toLowerCase();
    
    setTerminalLines(prev => [...prev, { text: `> ${cmd}`, isCommand: true }]);
    
    processTerminalCommand(command, parts.slice(1).join(' '));
    setTerminalInput('');
  };

  const processTerminalCommand = (cmd: string, args: string) => {
    switch (cmd) {
      case 'help':
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
        break;
      case 'health':
        addTermLine('[HEALTH OK] Node status: OK | Protocol: Fleet ADK v2.0.0', 'text-white');
        break;
      case 'whoami':
        addTermLine('Agent ID: AMR-8821-4102 | Role: Fleet Specialist | Status: ACTIVE');
        break;
      case 'send':
        addTermLine('[E2EE MSG SENT] > ' + (args || 'Sync payload'));
        setTimeout(() => addTermLine('< [MSG RECV] Payload decrypted and verified by peer.'), 200);
        break;
      case 'clusters':
        addTermLine('Active Clusters:');
        addTermLine('  ├─ cluster_987654 (Arbitrage Fleet Alpha) [2 members]');
        addTermLine('  └─ cluster_112233 (Risk Analysis Ensemble) [3 members]');
        break;
      case 'watchtower':
        addTermLine('[WATCHTOWER] Ingested 5 recent events. SSE stream alive.');
        break;
      case 'tools':
        addTermLine('FLOOR Registry:');
        addTermLine('  ├─ tool_sec_edgar (SEC Filings Parser) [AUTHORIZED]');
        addTermLine('  └─ tool_l2_arbitrage (L2 Pool Engine) [UNAUTHORIZED / HITL REQUIRED]');
        break;
      case 'tool-request':
        addTermLine('[FLOOR MCP] Ticket created: req_floor_' + Math.random().toString(36).substring(2, 8) + ' (Status: pending approval)', 'text-white');
        break;
      case 'doctor':
        addTermLine('[DOCTOR] All checks passed: Credentials OK | E2EE P-256 OK | Network OK', 'text-white');
        break;
      case 'clear':
        setTerminalLines([]);
        break;
      default:
        addTermLine(`Unknown command: ${cmd}. Type "help" for menu.`, 'text-white');
    }
  };

  const addTermLine = (text: string, color: string = 'text-[#a1a1aa]') => {
    setTerminalLines(prev => [...prev, { text, color }]);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const filteredSpec = () => {
    if (!specSearch) return specMarkdown;
    const lower = specSearch.toLowerCase();
    return specMarkdown.split('\n')
      .filter(line => line.toLowerCase().includes(lower))
      .slice(0, 30)
      .join('\n') || '*No direct matching lines found.*';
  };

  return (
    <div className="min-h-screen flex flex-col bg-black text-white font-mono">
      {/* Header */}
      <header className="border-b border-[#262626] bg-black sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 md:px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="w-7 h-7 bg-white text-black font-bold flex items-center justify-center text-xs tracking-tighter">
              ADK
            </div>
            <div>
              <div className="flex items-center space-x-3">
                <h1 className="text-xs md:text-sm font-bold tracking-widest text-white uppercase font-mono">AAMARVA ADK</h1>
                <span className="badge-mono">v2.0.0</span>
              </div>
              <p className="text-[10px] text-[#71717a] tracking-tight">Autonomous Agent Development Kit & Protocol Workbench</p>
            </div>
          </div>

          <div className="flex items-center space-x-3 text-xs">
            <div className="hidden md:flex items-center space-x-2 bg-black border border-[#262626] px-3 py-1 text-[11px]">
              <span className="text-[#71717a]">NPM:</span>
              <span className="text-white font-bold">npm i @aamarva/adk</span>
              <button 
                onClick={() => copyToClipboard('npm install @aamarva/adk')}
                className="text-[#a1a1aa] hover:text-white ml-2 transition-colors"
              >
                [COPY]
              </button>
            </div>
            <button onClick={() => setActiveTab('spec')} className="badge-outline hover:bg-white hover:text-black transition-colors">
              SPEC
            </button>
            <button onClick={() => setActiveTab('openapi')} className="badge-outline hover:bg-white hover:text-black transition-colors">
              OPENAPI
            </button>
          </div>
        </div>
      </header>

      {/* Tabs Nav */}
      <div className="border-b border-[#262626] bg-black">
        <div className="max-w-7xl mx-auto px-4 md:px-6 flex items-center space-x-2 py-0 overflow-x-auto custom-scrollbar">
          <TabButton id="spec" label="SPECIFICATION" active={activeTab === 'spec'} onClick={() => setActiveTab('spec')} num="01" />
          <TabButton id="frameworks" label="FLOOR MCP & PROTOCOLS" active={activeTab === 'frameworks'} onClick={() => setActiveTab('frameworks')} num="02" />
          <TabButton id="playground" label="FLEET RUNNER" active={activeTab === 'playground'} onClick={() => setActiveTab('playground')} num="03" />
          <TabButton id="terminal" label="TERMINAL" active={activeTab === 'terminal'} onClick={() => setActiveTab('terminal')} num="04" />
          <TabButton id="openapi" label="OPENAPI" active={activeTab === 'openapi'} onClick={() => setActiveTab('openapi')} num="05" />
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6">
        
        {/* Tab: Spec */}
        {activeTab === 'spec' && (
          <div className="space-y-6">
            <div className="flex flex-col md:flex-row gap-6">
              <div className="w-full md:w-64 shrink-0 space-y-4">
                <div className="card p-4 space-y-3">
                  <h3 className="text-[10px] font-bold text-[#71717a] uppercase tracking-widest">INDEX</h3>
                  <div className="space-y-1 text-xs">
                    {['Overview', 'Identity & Master', 'Authentication', 'Direct Channels', 'Server-Blind E2EE', 'Clusters', 'Watchtower', 'FLOOR MCP'].map(item => (
                      <button key={item} className="w-full text-left px-2 py-1.5 hover:bg-[#18181b] text-[#a1a1aa] hover:text-white transition-colors block">
                        {item}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="card p-4 space-y-2">
                  <h4 className="text-[10px] font-bold text-[#71717a] uppercase tracking-widest">SEARCH</h4>
                  <div className="relative">
                    <Search className="absolute left-2 top-2.5 h-3 w-3 text-[#525252]" />
                    <input 
                      type="text" 
                      value={specSearch}
                      onChange={(e) => setSpecSearch(e.target.value)}
                      placeholder="Filter spec..." 
                      className="w-full bg-black border border-[#262626] p-2 pl-7 text-xs text-white outline-none focus:border-white" 
                    />
                  </div>
                </div>
              </div>

              <div className="flex-1 card p-6 overflow-y-auto max-h-[75vh] custom-scrollbar">
                <div 
                  className="markdown-body"
                  dangerouslySetInnerHTML={{ __html: marked.parse(filteredSpec()) }}
                />
              </div>
            </div>
          </div>
        )}

        {/* Tab: Frameworks */}
        {activeTab === 'frameworks' && (
          <div className="space-y-6">
             <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-[#262626] pb-4">
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-widest">FLOOR MCP & PROTOCOL INTEGRATION</h2>
                <p className="text-xs text-[#71717a]">Universal Model Context Protocol (MCP) server & sovereign cryptographic primitives.</p>
              </div>
              <span className="badge-mono">FLEET INFRASTRUCTURE</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <ProtocolCard 
                title="AAMARVA MCP Server" 
                badge="JSON-RPC" 
                desc="Official Model Context Protocol server exposing FLOOR tool governance and fleet actions."
                code={`import { Aamarva, createAamarvaMcpServer } from '@aamarva/adk';\n\nconst client = new Aamarva();\nconst server = createAamarvaMcpServer(client);`}
              />
              <ProtocolCard 
                title="Server-Blind E2EE" 
                badge="NIST P-256" 
                desc="NIST P-256 ECDH key exchange with AES-256-GCM AEAD encryption and connectionId binding."
                code={`const connections = await client.getConnections();\nconst conn = await client.getConnection(id);\nawait conn.send('Autonomous task payload');`}
              />
               <ProtocolCard 
                title="FLOOR HITL Governance" 
                badge="HITL APPROVAL" 
                desc="Human-in-the-Loop approval workflows for sensitive tools with temporary leased credentials."
                code={`const req = await client.requestFloorAccess(\n  'tool_sec_edgar', 'Audit filings'\n);\nconsole.log(req.status); // 'pending'`}
              />
               <ProtocolCard 
                title="Multi-Agent Clusters" 
                badge="CONSENSUS" 
                desc="Collaborative clusters with recipient-restricted messaging for designated member subsets."
                code={`await client.sendClusterMessage(clusterId, {\n  ciphertext, nonce,\n  recipients: ['AMR-PEER-1111']\n});`}
              />
               <ProtocolCard 
                title="Watchtower Telemetry" 
                badge="SSE STREAM" 
                desc="Real-time fleet activity snapshots and authenticated Server-Sent Events (SSE) streaming."
                code={`const ticket = await client.getWatchtowerStreamTicket();\nconst sseUrl = client.getWatchtowerStreamUrl(ticket.ticket);`}
              />
               <ProtocolCard 
                title="Master-Slave Scoping" 
                badge="ISOLATION" 
                desc="Execute operations on behalf of subordinate agents via the x-target-agent-id header."
                code={`const client = new Aamarva({\n  agentId: 'AMR-MASTER-001',\n  targetAgentId: 'AMR-SLAVE-002'\n});`}
              />
            </div>
          </div>
        )}

        {/* Tab: Playground */}
        {activeTab === 'playground' && (
          <div className="space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-[#262626] pb-4">
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-widest">INTERACTIVE FLEET SDK RUNNER</h2>
                <p className="text-xs text-[#71717a]">Test sovereign fleet SDK operations and inspect response payloads.</p>
              </div>
              <span className="badge-mono">FLEET NODE: AMR-8821-4102</span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-5 space-y-4">
                <div className="card space-y-4">
                  <h3 className="text-[10px] font-bold text-[#71717a] uppercase tracking-widest">SELECT OPERATION</h3>
                  
                  <div className="space-y-2">
                    <label className="text-xs text-[#a1a1aa]">Method:</label>
                    <select 
                      value={runnerMethod}
                      onChange={(e) => {
                        setRunnerMethod(e.target.value);
                        setRunnerInputs({});
                      }}
                      className="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none focus:border-white"
                    >
                      {Object.values(operations).map(op => (
                        <option key={op.id} value={op.id}>{op.name}</option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-3 text-xs">
                    {operations[runnerMethod].inputs.map(input => (
                      <div key={input.name} className="space-y-1">
                        <label className="text-[#a1a1aa]">{input.label}:</label>
                        <input 
                          type={input.type}
                          defaultValue={input.value}
                          onChange={(e) => setRunnerInputs(prev => ({ ...prev, [input.name]: e.target.value }))}
                          className="w-full bg-black border border-[#262626] p-2 text-xs text-white outline-none focus:border-white" 
                        />
                      </div>
                    ))}
                    {operations[runnerMethod].inputs.length === 0 && (
                      <p className="text-[#71717a]">{operations[runnerMethod].description}</p>
                    )}
                  </div>

                  <button 
                    onClick={executeRunner}
                    className="w-full bg-white hover:bg-[#e4e4e7] text-black text-xs py-2.5 font-bold transition-colors uppercase tracking-wider flex items-center justify-center gap-2"
                  >
                    <Zap className="h-3 w-3" />
                    [EXECUTE OPERATION]
                  </button>
                </div>

                <div className="card p-4 space-y-2 text-xs">
                  <div className="text-[10px] text-[#71717a] uppercase tracking-widest">TYPESCRIPT CODE</div>
                  <div className="text-white bg-black p-3 border border-[#262626] overflow-x-auto whitespace-pre font-mono">
                    {operations[runnerMethod].code}
                  </div>
                </div>
              </div>

              <div className="lg:col-span-7 space-y-2">
                <div className="flex justify-between items-center text-xs text-[#71717a]">
                  <span>RESPONSE JSON</span>
                  <span className={cn("font-bold", runnerStatus === 'ERROR' ? 'text-red-500' : 'text-white')}>{runnerStatus}</span>
                </div>
                <div className="card p-0 overflow-hidden min-h-[360px] flex flex-col">
                  <div className="bg-[#18181b] border-b border-[#262626] px-4 py-2 text-[11px] text-[#a1a1aa] flex justify-between items-center">
                    <span>200 OK | application/json</span>
                    <button 
                      onClick={() => copyToClipboard(JSON.stringify(runnerOutput, null, 2))}
                      className="text-[#a1a1aa] hover:text-white transition-colors"
                    >
                      [COPY]
                    </button>
                  </div>
                  <pre className="p-4 text-xs font-mono text-white bg-black flex-1 overflow-x-auto leading-relaxed custom-scrollbar">
                    {JSON.stringify(runnerOutput, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab: Terminal */}
        {activeTab === 'terminal' && (
          <div className="card p-0 overflow-hidden flex flex-col h-[70vh]">
            <div className="bg-[#18181b] border-b border-[#262626] px-4 py-2 flex justify-between items-center text-xs">
              <span className="text-white font-bold tracking-widest uppercase flex items-center gap-2">
                <Terminal className="h-3 w-3" />
                AAMARVA ADK CONSOLE
              </span>
              <span className="text-[#71717a]">aamarva.com</span>
            </div>

            <div className="flex-1 bg-black p-4 text-xs overflow-y-auto space-y-2 text-[#d4d4d8] custom-scrollbar">
              {terminalLines.map((line, i) => (
                <div key={i} className={cn("leading-relaxed", line.color, line.isCommand && "font-bold mt-2")}>
                  {line.text}
                </div>
              ))}
              <div ref={terminalEndRef} />
            </div>

            <form onSubmit={handleTerminalSubmit} className="bg-black border-t border-[#262626] px-4 py-3 flex items-center">
              <span className="text-white font-bold mr-2">{'>'}</span>
              <input 
                type="text" 
                value={terminalInput}
                onChange={(e) => setTerminalInput(e.target.value)}
                autoFocus
                spellCheck="false"
                autoComplete="off"
                placeholder="Enter CLI command (health, whoami, send, clusters, tools)..."
                className="flex-1 bg-transparent border-none outline-none text-xs text-white placeholder-[#525252]"
              />
            </form>
          </div>
        )}

        {/* Tab: OpenAPI */}
        {activeTab === 'openapi' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center border-b border-[#262626] pb-4">
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-widest">OPENAPI 3.0 PATHS</h2>
                <p className="text-xs text-[#71717a]">Machine-readable REST endpoints from adk.openapi.json.</p>
              </div>
              <button 
                onClick={() => copyToClipboard(JSON.stringify(openApiSchema, null, 2))}
                className="badge-outline hover:bg-white hover:text-black transition-colors"
              >
                [COPY SCHEMA JSON]
              </button>
            </div>

            <div className="space-y-3">
              {openApiSchema && Object.entries(openApiSchema.paths).map(([path, methods]: [string, any]) => (
                Object.entries(methods).map(([method, op]: [string, any]) => (
                  <div key={`${path}-${method}`} className="card p-4 space-y-2">
                    <div className="flex items-center space-x-3">
                      <span className="badge-mono uppercase">{method}</span>
                      <span className="text-white font-bold font-mono">{path}</span>
                    </div>
                    <p className="text-xs text-[#a1a1aa] font-sans">{op.summary || op.description}</p>
                  </div>
                ))
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#262626] py-4 bg-black">
        <div className="max-w-7xl mx-auto px-6 flex justify-between items-center text-[10px] text-[#525252] uppercase tracking-widest">
          <div>&copy; 2026 AAMARVA CORE</div>
          <div className="flex gap-4">
            <a href="#" className="hover:text-white transition-colors">Security</a>
            <a href="#" className="hover:text-white transition-colors">Privacy</a>
            <a href="#" className="hover:text-white transition-colors">Status</a>
          </div>
        </div>
      </footer>
    </div>
  );
}

// --- Subcomponents ---

function TabButton({ id, label, active, onClick, num }: { id: string; label: string; active: boolean; onClick: () => void; num: string }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "nav-tab whitespace-nowrap",
        active && "nav-tab-active"
      )}
    >
      <span className="opacity-50">{num}</span>
      <span>{label}</span>
    </button>
  );
}

function ProtocolCard({ title, badge, desc, code }: { title: string; badge: string; desc: string; code: string }) {
  return (
    <div className="card space-y-3 flex flex-col">
      <div className="flex justify-between items-center border-b border-[#262626] pb-2">
        <h3 className="text-xs font-bold text-white uppercase">{title}</h3>
        <span className="badge-outline">{badge}</span>
      </div>
      <p className="text-xs text-[#a1a1aa] flex-1">{desc}</p>
      <div className="code-block mt-auto">
        <pre className="whitespace-pre overflow-x-auto"><code>{code}</code></pre>
      </div>
    </div>
  );
}
