#!/usr/bin/env node
import { createApp } from '../dist/app.js';
import { Library } from '../dist/library.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createServer } from 'node:http';

const app = createApp();
const library = new Library();

function buildServer() {
  const server = new Server({ name: app.name, version: app.version }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: app.tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema, ...(t.annotations && { annotations: t.annotations }) })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const tool = app.tools.find((t) => t.name === req.params.name);
    if (!tool) return { content: [{ type: 'text', text: `Unknown tool: ${req.params.name}` }], isError: true };
    try {
      const result = await tool.execute(req.params.arguments ?? {});
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    } catch (e) {
      return { content: [{ type: 'text', text: String(e) }], isError: true };
    }
  });

  return server;
}

// ── Gateway registration ─────────────────────────────────────────────────────

const GATEWAY_URL = process.env.GATEWAY_URL;
const MCP_HTTP_PORT = process.env.MCP_HTTP_PORT ? Number(process.env.MCP_HTTP_PORT) : null;
const POD_IP = process.env.POD_IP || '0.0.0.0';

let sessionToken = null;

async function registerWithGateway() {
  if (!GATEWAY_URL) return;
  const mcpEndpoint = `http://${POD_IP}:${MCP_HTTP_PORT || 8200}/mcp`;
  const body = {
    fabric_id: 'fabric-sandfly',
    as_number: 65003,
    version: app.version,
    mcp_endpoint: mcpEndpoint,
    ollama_endpoint: process.env.OLLAMA_ENDPOINT || 'http://ollama.fabric-sdk:11434',
    ollama_model: process.env.OLLAMA_MODEL || 'qwen2.5-coder:3b',
    supervisor: 'standalone',
    tailscale_node: 'fabric-sandfly',
    worker_pool: { total: 0, healthy: 0, workers: [] },
    routes: [
      { prefix: 'fabric.security', local_pref: 100, confidence_floor: 0.7, description: 'Linux security — intrusion detection, host scanning, alerts' },
      { prefix: 'fabric.security.hosts', local_pref: 100, confidence_floor: 0.7, description: 'Host management — list, add, remove managed hosts' },
      { prefix: 'fabric.security.scanning', local_pref: 100, confidence_floor: 0.7, description: 'Scan management — start scans, view errors' },
      { prefix: 'fabric.security.results', local_pref: 100, confidence_floor: 0.7, description: 'Scan results — alerts, summaries, detailed findings' },
      { prefix: 'fabric.security.sandflies', local_pref: 100, confidence_floor: 0.7, description: 'Detection scripts — list, activate, deactivate sandflies' },
      { prefix: 'fabric.security.schedules', local_pref: 100, confidence_floor: 0.7, description: 'Scan schedules — create, pause, run, delete' },
      { prefix: 'fabric.security.credentials', local_pref: 100, confidence_floor: 0.7, description: 'SSH credentials — manage authentication for host scanning' },
      { prefix: 'fabric.security.audit', local_pref: 100, confidence_floor: 0.7, description: 'Audit log — security event trail' },
    ],
  };

  try {
    const res = await fetch(`${GATEWAY_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (data.ok) {
      sessionToken = data.session_token;
      console.log(`[fabric-sandfly] Registered with gateway: ${sessionToken} (${data.routes_accepted} routes)`);
    } else {
      console.warn(`[fabric-sandfly] Registration rejected: ${JSON.stringify(data)}`);
    }
  } catch (err) {
    console.warn(`[fabric-sandfly] Gateway registration failed (standalone mode): ${err.message}`);
  }
}

async function sendKeepalive() {
  if (!GATEWAY_URL || !sessionToken) return;
  try {
    const res = await fetch(`${GATEWAY_URL}/keepalive`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fabric_id: 'fabric-sandfly',
        session_token: sessionToken,
        worker_pool: { total: 0, healthy: 0, workers: [] },
        timestamp: Math.floor(Date.now() / 1000),
      }),
    });
    if (res.status === 401) {
      console.log('[fabric-sandfly] Session expired — re-registering');
      sessionToken = null;
      await registerWithGateway();
    }
  } catch {
    // Gateway unreachable — will retry next interval
  }
}

// ── Server startup ───────────────────────────────────────────────────────────

const httpPort = MCP_HTTP_PORT;

if (httpPort) {
  const httpServer = createServer(async (req, res) => {
    if (req.url === '/healthz' || req.url === '/health') {
      const h = await app.health();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(h));
      return;
    }
    if (req.url === '/tools') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(app.tools.map((t) => ({ name: t.name, description: t.description }))));
      return;
    }
    // MCP tool call endpoint for gateway DNS unicast resolution
    if ((req.url === '/mcp/tools/call' || req.url === '/tools/call') && req.method === 'POST') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());

      // Handle aiana_query — gateway DNS resolver asks for context
      //
      // Two knowledge sources, checked in order:
      //   1. Live Sandfly API (deterministic) — real-time security state
      //   2. Library (reference) — Sandfly docs, fetched from git on demand
      //
      // Live API answers "what IS the security state" — library answers "how to" and "why"
      if (body.name === 'aiana_query') {
        const queryText = (body.arguments?.query_text || '').toLowerCase();
        try {
          let context = '';
          let confidence = 0;
          let source = 'sandfly-api';

          // ── Live Sandfly queries (real-time state) ──────────────────
          if (/\b(alert|alarm|warning|threat|incident)\b/.test(queryText)) {
            const alerts = await app.tools.find(t => t.name === 'sandfly_get_alerts')?.execute({});
            context = JSON.stringify(alerts, null, 2);
            confidence = 0.9;
          } else if (/\b(list|show|get|what)\b.*\b(host|server|machine|node)s?\b/.test(queryText) && !queryText.includes('how')) {
            const hosts = await app.tools.find(t => t.name === 'sandfly_list_hosts')?.execute({});
            context = JSON.stringify(hosts, null, 2);
            confidence = 0.95;
          } else if (/\b(list|show|get)\b.*\b(result|finding|scan result)\b/.test(queryText)) {
            const results = await app.tools.find(t => t.name === 'sandfly_get_results')?.execute({});
            context = JSON.stringify(results, null, 2);
            confidence = 0.85;
          } else if (/\b(list|show|get)\b.*\b(schedule|cron|recurring)\b/.test(queryText)) {
            const schedules = await app.tools.find(t => t.name === 'sandfly_list_schedules')?.execute({});
            context = JSON.stringify(schedules, null, 2);
            confidence = 0.9;
          } else if (/\b(list|show|get)\b.*\b(credential|ssh|key)\b/.test(queryText)) {
            const creds = await app.tools.find(t => t.name === 'sandfly_list_credentials')?.execute({});
            context = JSON.stringify(creds, null, 2);
            confidence = 0.9;
          } else if (/\b(list|show|get)\b.*\b(sandfl|detection|script)\b/.test(queryText)) {
            const sandflies = await app.tools.find(t => t.name === 'sandfly_list_sandflies')?.execute({});
            context = JSON.stringify(sandflies, null, 2);
            confidence = 0.85;
          } else if (/\b(audit|log|trail|history)\b/.test(queryText)) {
            const audit = await app.tools.find(t => t.name === 'sandfly_get_audit_log')?.execute({ limit: 50 });
            context = JSON.stringify(audit, null, 2);
            confidence = 0.85;
          } else if (/\b(version|status|system|license)\b/.test(queryText)) {
            const version = await app.tools.find(t => t.name === 'sandfly_get_version')?.execute({});
            context = JSON.stringify(version, null, 2);
            confidence = 0.95;
          } else if (/\b(scan|start scan|run scan)\b/.test(queryText) && !queryText.includes('how')) {
            const errors = await app.tools.find(t => t.name === 'sandfly_get_scan_errors')?.execute({});
            context = JSON.stringify(errors, null, 2);
            confidence = 0.7;
          } else if (/\b(jump|bastion|proxy)\b.*\bhost\b/.test(queryText)) {
            const jumpHosts = await app.tools.find(t => t.name === 'sandfly_list_jump_hosts')?.execute({});
            context = JSON.stringify(jumpHosts, null, 2);
            confidence = 0.9;
          } else if (/\b(notification|notify|webhook|email)\b/.test(queryText)) {
            const notifs = await app.tools.find(t => t.name === 'sandfly_list_notifications')?.execute({});
            context = JSON.stringify(notifs, null, 2);
            confidence = 0.9;
          } else if (/\b(performance|metric|speed|benchmark)\b/.test(queryText)) {
            const perf = await app.tools.find(t => t.name === 'sandfly_get_scan_performance')?.execute({});
            context = JSON.stringify(perf, null, 2);
            confidence = 0.85;
          } else {
            // ── Library queries (reference docs) ──────────────────────
            const libraryResult = await library.query(queryText);
            if (libraryResult && libraryResult.context) {
              context = libraryResult.context;
              confidence = libraryResult.confidence;
              source = 'library';
              console.log(`[fabric-sandfly] Library hit: ${libraryResult.sources.join(', ')}`);
            } else {
              // Nothing in library either — return system info as fallback
              const version = await app.tools.find(t => t.name === 'sandfly_get_version')?.execute({});
              context = JSON.stringify(version, null, 2);
              confidence = 0.5;
            }
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ context, confidence, source }));
        } catch (err) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ context: `Error querying Sandfly: ${err.message}`, confidence: 0 }));
        }
        return;
      }

      const tool = app.tools.find((t) => t.name === body.name);
      if (!tool) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Tool not found: ${body.name}` }));
        return;
      }
      try {
        const result = await tool.execute(body.arguments ?? {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
      return;
    }
    if (req.url === '/mcp' || req.url === '/') {
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      const server = buildServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, undefined);
      return;
    }
    res.writeHead(404).end('not found');
  });

  httpServer.listen(httpPort, () => {
    console.log(`[fabric-sandfly] ${app.name} v${app.version} — ${app.tools.length} tools`);
    console.log(`[fabric-sandfly] MCP server listening on :${httpPort}`);
    console.log(`[fabric-sandfly] Endpoints: /health /tools /tools/call /mcp/tools/call /mcp`);
  });

  // Register with gateway after server is listening
  await registerWithGateway();

  // Keepalive every 30s
  if (GATEWAY_URL) {
    setInterval(sendKeepalive, 30_000);
  }
} else {
  const transport = new StdioServerTransport();
  const server = buildServer();
  await server.connect(transport);
}
