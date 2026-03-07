# @git-fabric/sandfly

Sandfly Security fabric app -- agentless Linux intrusion detection and incident response as a composable MCP layer.

Sandfly Security scans Linux hosts over SSH without installing agents. This fabric wraps the Sandfly REST API (v4) into 39 MCP tools, adds a git-based reference library, and plugs into the [fabric-sdk](https://github.com/git-fabric/sdk) gateway via BGP-style route advertisement.

Part of the [git-fabric](https://github.com/git-fabric) ecosystem.

## What It Is

`@git-fabric/sandfly` is a standalone MCP server that exposes the full Sandfly Security API as structured tools. It can run in two modes:

- **Gateway mode** -- registers with the fabric-sdk gateway as AS65003, advertises `fabric.security.*` route prefixes, and responds to `aiana_query` DNS-style resolution. The gateway routes security questions to this fabric before falling back to Claude.
- **Standalone mode** -- runs as a standard MCP server over stdio or StreamableHTTP, usable directly by any MCP client (Claude Desktop, Claude Code, etc.).

The fabric also ships a **Library** -- a git-based reference retrieval system that shallow-clones official Sandfly repositories on demand and returns relevant documentation context. Live API queries answer "what is the current security state"; the library answers "how to" and "why."

## Tools (39)

| Domain | Count | Description |
|--------|-------|-------------|
| System | 3 | Server version, license, configuration |
| Hosts | 9 | List, add, remove hosts; inspect processes, users, listeners, services, cron, kernel modules |
| Credentials | 3 | Manage SSH credentials for host scanning |
| Scanning | 2 | Start scans, view scan errors |
| Results | 5 | Query results with filters, per-host alert counts, result summaries, delete results |
| Sandflies | 4 | List, inspect, activate, deactivate detection scripts |
| Schedules | 7 | Create, list, run, pause, unpause, delete scan schedules |
| Jump Hosts | 3 | Manage SSH bastion/jump hosts |
| Notifications | 3 | Configure and test alert notification channels |
| Reports | 2 | Host security snapshots, scan performance metrics |
| Audit | 1 | Query the audit log trail |

All tools are prefixed `sandfly_` and registered in `src/app.ts` via the `FabricApp` interface.

## OSI Layer Architecture

```
Layer 7 -- Application    app.ts (FabricApp factory, 39 tools)
Layer 6 -- Presentation   bin/cli.js (MCP stdio + HTTP, aiana_query)
Layer 5 -- Session        (stateless -- direct API queries)
Layer 4 -- Transport      MCP protocol (stdio + StreamableHTTP)
Layer 3 -- Network        Gateway registration (AS65003, fabric.security.*)
Layer 2 -- Data Link      adapters/env.ts (Sandfly REST API)
Layer 1 -- Physical       Sandfly Security server
```

Layer 7 defines the tool surface. Layer 6 handles presentation -- MCP framing for stdio clients, HTTP for the gateway, and `aiana_query` dispatch that decides whether to answer from live API or library. Layer 4 speaks the MCP protocol over both transports. Layer 3 advertises BGP-style routes to the gateway. Layer 2 manages authentication (JWT token caching with 50-minute TTL) and REST calls against the Sandfly v4 API. Layer 1 is the Sandfly server itself.

## Gateway Registration

When `GATEWAY_URL` is set, the fabric registers with the gateway on startup:

| Field | Value |
|-------|-------|
| `fabric_id` | `fabric-sandfly` |
| `as_number` | `65003` |
| Keepalive | Every 30 seconds |

**Advertised routes:**

| Prefix | Description |
|--------|-------------|
| `fabric.security` | Linux security -- intrusion detection, host scanning, alerts |
| `fabric.security.hosts` | Host management -- list, add, remove managed hosts |
| `fabric.security.scanning` | Scan management -- start scans, view errors |
| `fabric.security.results` | Scan results -- alerts, summaries, detailed findings |
| `fabric.security.sandflies` | Detection scripts -- list, activate, deactivate sandflies |
| `fabric.security.schedules` | Scan schedules -- create, pause, run, delete |
| `fabric.security.credentials` | SSH credentials -- manage authentication for host scanning |
| `fabric.security.audit` | Audit log -- security event trail |

All routes advertise with `local_pref: 100`. The gateway uses these prefixes for DNS-style unicast resolution -- when a query matches `fabric.security.*`, the gateway forwards an `aiana_query` call to this fabric before considering Claude as the default route.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SANDFLY_HOST` | Yes | -- | Sandfly server URL (e.g. `https://10.88.140.176`) |
| `SANDFLY_USERNAME` | Yes | -- | Sandfly API username |
| `SANDFLY_PASSWORD` | Yes | -- | Sandfly API password |
| `SANDFLY_VERIFY_SSL` | No | `true` | Set `false` for self-signed certs (sets `NODE_TLS_REJECT_UNAUTHORIZED=0`) |
| `MCP_HTTP_PORT` | No | -- | Enable HTTP mode on this port (omit for stdio) |
| `GATEWAY_URL` | No | -- | Fabric-sdk gateway URL for registration (e.g. `http://gateway:8080`) |
| `POD_IP` | No | `0.0.0.0` | Pod IP advertised to gateway for MCP endpoint |
| `OLLAMA_ENDPOINT` | No | `http://ollama.fabric-sdk:11434` | Ollama endpoint advertised to gateway |
| `OLLAMA_MODEL` | No | `qwen2.5-coder:3b` | Ollama model advertised to gateway |

## Library

The fabric includes a git-based reference library that shallow-clones official Sandfly repositories on demand and returns relevant documentation. The library is queried as a fallback when the `aiana_query` handler cannot match against live API patterns.

| Source | Repository | Description |
|--------|------------|-------------|
| `sandfly-setup` | [sandfly-io/sandfly-setup](https://github.com/sandfly-io/sandfly-setup) | Server setup, Docker deployment, configuration |
| `sandfly-entropyscan` | [sandfly-io/sandfly-entropyscan](https://github.com/sandfly-io/sandfly-entropyscan) | Entropy scanner -- detect packed/encrypted malware |
| `sandfly-processdecloak` | [sandfly-io/sandfly-processdecloak](https://github.com/sandfly-io/sandfly-processdecloak) | Process decloaker -- find hidden Linux processes |
| `sandfly-filescan` | [sandfly-io/sandfly-filescan](https://github.com/sandfly-io/sandfly-filescan) | File scanner -- agentless file integrity and threat detection |

Repos are cloned to `/tmp/fabric-library/` (configurable via `LIBRARY_DIR`) and updated with shallow pulls on subsequent queries.

## Usage

### With gateway (HTTP mode)

```bash
export SANDFLY_HOST=https://10.88.140.176
export SANDFLY_USERNAME=admin
export SANDFLY_PASSWORD=secret
export SANDFLY_VERIFY_SSL=false
export MCP_HTTP_PORT=8200
export GATEWAY_URL=http://gateway:8080

node bin/cli.js
```

The server starts on `:8200`, registers with the gateway, and begins sending keepalives every 30 seconds. Endpoints:

- `GET /health` -- health check (Sandfly API reachability)
- `GET /tools` -- list all 39 tools
- `POST /mcp/tools/call` -- invoke a tool or `aiana_query`
- `POST /mcp` -- full MCP StreamableHTTP transport

### Standalone HTTP (no gateway)

```bash
export SANDFLY_HOST=https://10.88.140.176
export SANDFLY_USERNAME=admin
export SANDFLY_PASSWORD=secret
export MCP_HTTP_PORT=8200

node bin/cli.js
```

Same HTTP server, but without gateway registration. Tools are available directly via `/mcp/tools/call` and `/mcp`.

### Standalone stdio

```bash
export SANDFLY_HOST=https://10.88.140.176
export SANDFLY_USERNAME=admin
export SANDFLY_PASSWORD=secret

node bin/cli.js
```

When `MCP_HTTP_PORT` is not set, the server runs over stdio -- compatible with Claude Desktop, Claude Code, and any MCP client that speaks stdio.

### Claude Desktop configuration

```json
{
  "mcpServers": {
    "sandfly": {
      "command": "node",
      "args": ["/path/to/fabric-sandfly/bin/cli.js"],
      "env": {
        "SANDFLY_HOST": "https://your-sandfly-server",
        "SANDFLY_USERNAME": "admin",
        "SANDFLY_PASSWORD": "secret",
        "SANDFLY_VERIFY_SSL": "false"
      }
    }
  }
}
```

## Architecture

```
src/
  app.ts           Layer 7 — FabricApp factory, 39 tools
  adapters/env.ts  Layer 2 — Sandfly REST adapter (auth, HTTP methods)
  library.ts       Reference library (git-based doc retrieval)
  types.ts         SandflyAdapter interface
  index.ts         Package entry point
bin/
  cli.js           Layer 6 — MCP stdio + HTTP server, gateway registration
```

## Related

- [git-fabric/sdk](https://github.com/git-fabric/sdk) -- Fabric SDK gateway, BGP-style routing, AIANA feedback loop
- [git-fabric](https://github.com/git-fabric) -- Full ecosystem of fabric apps

## License

MIT
