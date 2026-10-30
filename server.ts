import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

async function startServer() {
  const app = express();
  app.use(express.json());

  // Load specs
  const OPENAPI_SPEC = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'adk.openapi.json'), 'utf8'));
  const ADK_SPECIFICATION = fs.readFileSync(path.join(process.cwd(), 'ADK_SPEC.md'), 'utf8');

  // --- API Routes ---
  
  app.get('/api/adk/spec-markdown', (req, res) => {
    res.type('text/markdown').send(ADK_SPECIFICATION);
  });

  app.get('/api/adk/openapi.json', (req, res) => {
    res.json(OPENAPI_SPEC);
  });

  app.get('/api/health', (req, res) => {
    res.json({
      success: true,
      status: 'ok',
      adk_version: '2.0.0',
      timestamp: new Date().toISOString()
    });
  });

  app.post('/api/adk/runner', (req, res) => {
    const { action, args } = req.body;
    let result: any = { success: true };

    switch (action) {
      case 'health':
        result.data = { status: 'ok', adk_version: '2.0.0', timestamp: new Date().toISOString() };
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

    res.json(result);
  });

  // --- Frontend Hosting ---

  if (!IS_PROD) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
