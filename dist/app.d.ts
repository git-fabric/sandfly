/**
 * @git-fabric/sandfly — FabricApp factory
 *
 * 39 tools covering Sandfly Security API:
 * system, hosts, credentials, scanning, results, sandflies,
 * schedules, jump-hosts, notifications, reports, audit
 */
import { type SandflyAdapter } from './adapters/env.js';
interface FabricTool {
    name: string;
    description: string;
    inputSchema: Record<string, unknown>;
    execute: (args: Record<string, unknown>) => Promise<unknown>;
}
interface FabricApp {
    name: string;
    version: string;
    description: string;
    tools: FabricTool[];
    health: () => Promise<{
        app: string;
        status: 'healthy' | 'degraded' | 'unavailable';
        latencyMs?: number;
        details?: Record<string, unknown>;
    }>;
}
export declare function createApp(adapterOverride?: SandflyAdapter): FabricApp;
export {};
//# sourceMappingURL=app.d.ts.map