/**
 * @git-fabric/sandfly — FabricApp factory
 *
 * 39 tools covering Sandfly Security API:
 * system, hosts, credentials, scanning, results, sandflies,
 * schedules, jump-hosts, notifications, reports, audit
 */

import { createAdapterFromEnv, type SandflyAdapter } from './adapters/env.js';

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
  health: () => Promise<{ app: string; status: 'healthy' | 'degraded' | 'unavailable'; latencyMs?: number; details?: Record<string, unknown> }>;
}

export function createApp(adapterOverride?: SandflyAdapter): FabricApp {
  const sf = adapterOverride ?? createAdapterFromEnv();

  const tools: FabricTool[] = [
    // ── System ──────────────────────────────────────────────────────────────
    { name: 'sandfly_get_version', description: 'Get Sandfly server version information.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/system/version') },
    { name: 'sandfly_get_license', description: 'Get Sandfly license information.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/system/license') },
    { name: 'sandfly_get_config', description: 'Get Sandfly server configuration.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/system/config') },

    // ── Hosts ────────────────────────────────────────────────────────────────
    { name: 'sandfly_list_hosts', description: 'List all managed hosts.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/hosts') },
    { name: 'sandfly_get_host', description: 'Get details for a specific host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/hosts/${a.host_id}`) },
    { name: 'sandfly_add_hosts', description: 'Add hosts to Sandfly management.',
      inputSchema: { type: 'object', properties: { hosts: { type: 'array', items: { type: 'object' } } }, required: ['hosts'] },
      execute: async (a) => sf.post('/v4/hosts', a.hosts) },
    { name: 'sandfly_delete_host', description: 'Remove a host from Sandfly management.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.delete(`/v4/hosts/${a.host_id}`) },
    { name: 'sandfly_get_host_processes', description: 'Get running processes on a host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/hosts/${a.host_id}/processes`) },
    { name: 'sandfly_get_host_users', description: 'Get users on a host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/hosts/${a.host_id}/users`) },
    { name: 'sandfly_get_host_listeners', description: 'Get network listeners on a host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/hosts/${a.host_id}/listeners`) },
    { name: 'sandfly_get_host_services', description: 'Get services on a host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/hosts/${a.host_id}/services`) },
    { name: 'sandfly_get_host_scheduled_tasks', description: 'Get scheduled tasks (cron jobs) on a host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/hosts/${a.host_id}/scheduled_tasks`) },
    { name: 'sandfly_get_host_kernel_modules', description: 'Get loaded kernel modules on a host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/hosts/${a.host_id}/kernel_modules`) },

    // ── Credentials ───────────────────────────────────────────────────────────
    { name: 'sandfly_list_credentials', description: 'List SSH credentials.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/credentials') },
    { name: 'sandfly_add_credential', description: 'Add an SSH credential.',
      inputSchema: { type: 'object', properties: { credential: { type: 'object' } }, required: ['credential'] },
      execute: async (a) => sf.post('/v4/credentials', a.credential) },
    { name: 'sandfly_delete_credential', description: 'Delete an SSH credential.',
      inputSchema: { type: 'object', properties: { credential_id: { type: 'string' } }, required: ['credential_id'] },
      execute: async (a) => sf.delete(`/v4/credentials/${a.credential_id}`) },

    // ── Scanning ──────────────────────────────────────────────────────────────
    { name: 'sandfly_start_scan', description: 'Start a scan on one or more hosts.',
      inputSchema: { type: 'object', properties: { host_ids: { type: 'array', items: { type: 'string' } }, sandfly_names: { type: 'array', items: { type: 'string' } } }, required: ['host_ids'] },
      execute: async (a) => sf.post('/v4/scan', { host_ids: a.host_ids, sandfly_names: a.sandfly_names }) },
    { name: 'sandfly_get_scan_errors', description: 'Get scan errors.',
      inputSchema: { type: 'object', properties: { limit: { type: 'number' } } },
      execute: async (a) => sf.get('/v4/scan/errors', a.limit ? { limit: String(a.limit) } : undefined) },

    // ── Results ───────────────────────────────────────────────────────────────
    { name: 'sandfly_get_results', description: 'Get scan results with optional filters.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' }, limit: { type: 'number' }, status: { type: 'string' } } },
      execute: async (a) => {
        const params: Record<string, string> = { page_size: '1000' };
        if (a.host_id) params.host_id = a.host_id as string;
        if (a.status) params.status = a.status as string;
        return sf.get('/v4/results', params);
      } },
    { name: 'sandfly_get_alerts', description: 'Get security alert counts per host. Returns per-host alert/error/pass/total counts from the hosts list (results field), plus a grand total. Use sandfly_get_results with status="alert" to fetch detailed alert records.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => {
        const hosts = await sf.get('/v4/hosts') as Array<{
          uuid?: string; address?: string; hostname?: string;
          results?: { alert?: number; error?: number; pass?: number; total?: number };
        }>;
        if (!Array.isArray(hosts)) return hosts;
        let totalAlerts = 0;
        const perHost = hosts.map((h) => {
          const alert = h.results?.alert ?? 0;
          totalAlerts += alert;
          return {
            host_id: h.uuid,
            address: h.address,
            hostname: h.hostname,
            alert,
            error: h.results?.error ?? 0,
            pass: h.results?.pass ?? 0,
            total: h.results?.total ?? 0,
          };
        });
        return { total_alerts: totalAlerts, hosts: perHost };
      } },
    { name: 'sandfly_get_result', description: 'Get a specific scan result.',
      inputSchema: { type: 'object', properties: { result_id: { type: 'string' } }, required: ['result_id'] },
      execute: async (a) => sf.get(`/v4/results/${a.result_id}`) },
    { name: 'sandfly_get_host_result_summary', description: 'Get result summary for a host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/results/hosts/${a.host_id}/summary`) },
    { name: 'sandfly_delete_result', description: 'Delete a scan result.',
      inputSchema: { type: 'object', properties: { result_id: { type: 'string' } }, required: ['result_id'] },
      execute: async (a) => sf.delete(`/v4/results/${a.result_id}`) },

    // ── Sandflies ─────────────────────────────────────────────────────────────
    { name: 'sandfly_list_sandflies', description: 'List all sandfly detection scripts.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/sandflies') },
    { name: 'sandfly_get_sandfly', description: 'Get a specific sandfly script.',
      inputSchema: { type: 'object', properties: { sandfly_name: { type: 'string' } }, required: ['sandfly_name'] },
      execute: async (a) => sf.get(`/v4/sandflies/${a.sandfly_name}`) },
    { name: 'sandfly_activate_sandfly', description: 'Activate a sandfly detection script.',
      inputSchema: { type: 'object', properties: { sandfly_name: { type: 'string' } }, required: ['sandfly_name'] },
      execute: async (a) => sf.put(`/v4/sandflies/${a.sandfly_name}/activate`) },
    { name: 'sandfly_deactivate_sandfly', description: 'Deactivate a sandfly detection script.',
      inputSchema: { type: 'object', properties: { sandfly_name: { type: 'string' } }, required: ['sandfly_name'] },
      execute: async (a) => sf.put(`/v4/sandflies/${a.sandfly_name}/deactivate`) },

    // ── Schedules ─────────────────────────────────────────────────────────────
    { name: 'sandfly_list_schedules', description: 'List scan schedules.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/schedules') },
    { name: 'sandfly_get_schedule', description: 'Get a specific schedule.',
      inputSchema: { type: 'object', properties: { schedule_id: { type: 'string' } }, required: ['schedule_id'] },
      execute: async (a) => sf.get(`/v4/schedules/${a.schedule_id}`) },
    { name: 'sandfly_add_schedule', description: 'Create a new scan schedule.',
      inputSchema: { type: 'object', properties: { schedule: { type: 'object' } }, required: ['schedule'] },
      execute: async (a) => sf.post('/v4/schedules', a.schedule) },
    { name: 'sandfly_run_schedule', description: 'Immediately run a schedule.',
      inputSchema: { type: 'object', properties: { schedule_id: { type: 'string' } }, required: ['schedule_id'] },
      execute: async (a) => sf.post(`/v4/schedules/${a.schedule_id}/run`) },
    { name: 'sandfly_pause_schedule', description: 'Pause a scan schedule.',
      inputSchema: { type: 'object', properties: { schedule_id: { type: 'string' } }, required: ['schedule_id'] },
      execute: async (a) => sf.put(`/v4/schedules/${a.schedule_id}/pause`) },
    { name: 'sandfly_unpause_schedule', description: 'Unpause a scan schedule.',
      inputSchema: { type: 'object', properties: { schedule_id: { type: 'string' } }, required: ['schedule_id'] },
      execute: async (a) => sf.put(`/v4/schedules/${a.schedule_id}/unpause`) },
    { name: 'sandfly_delete_schedule', description: 'Delete a scan schedule.',
      inputSchema: { type: 'object', properties: { schedule_id: { type: 'string' } }, required: ['schedule_id'] },
      execute: async (a) => sf.delete(`/v4/schedules/${a.schedule_id}`) },

    // ── Jump Hosts ────────────────────────────────────────────────────────────
    { name: 'sandfly_list_jump_hosts', description: 'List SSH jump hosts.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/jump_hosts') },
    { name: 'sandfly_add_jump_host', description: 'Add an SSH jump host.',
      inputSchema: { type: 'object', properties: { jump_host: { type: 'object' } }, required: ['jump_host'] },
      execute: async (a) => sf.post('/v4/jump_hosts', a.jump_host) },
    { name: 'sandfly_delete_jump_host', description: 'Delete an SSH jump host.',
      inputSchema: { type: 'object', properties: { jump_host_id: { type: 'string' } }, required: ['jump_host_id'] },
      execute: async (a) => sf.delete(`/v4/jump_hosts/${a.jump_host_id}`) },

    // ── Notifications ─────────────────────────────────────────────────────────
    { name: 'sandfly_list_notifications', description: 'List notification configurations.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/notifications') },
    { name: 'sandfly_add_notification', description: 'Add a notification configuration.',
      inputSchema: { type: 'object', properties: { notification: { type: 'object' } }, required: ['notification'] },
      execute: async (a) => sf.post('/v4/notifications', a.notification) },
    { name: 'sandfly_test_notification', description: 'Test a notification configuration.',
      inputSchema: { type: 'object', properties: { notification_id: { type: 'string' } }, required: ['notification_id'] },
      execute: async (a) => sf.post(`/v4/notifications/${a.notification_id}/test`) },

    // ── Reports ───────────────────────────────────────────────────────────────
    { name: 'sandfly_get_host_snapshot', description: 'Get a full security snapshot for a host.',
      inputSchema: { type: 'object', properties: { host_id: { type: 'string' } }, required: ['host_id'] },
      execute: async (a) => sf.get(`/v4/reports/hosts/${a.host_id}/snapshot`) },
    { name: 'sandfly_get_scan_performance', description: 'Get scan performance metrics.',
      inputSchema: { type: 'object', properties: {} },
      execute: async () => sf.get('/v4/reports/performance') },

    // ── Audit ─────────────────────────────────────────────────────────────────
    { name: 'sandfly_get_audit_log', description: 'Get the Sandfly audit log.',
      inputSchema: { type: 'object', properties: { limit: { type: 'number' } } },
      execute: async (a) => sf.get('/v4/audit', a.limit ? { limit: String(a.limit) } : undefined) },
  ];

  return {
    name: '@git-fabric/sandfly',
    version: '0.1.0',
    description: 'Sandfly Security fabric app — agentless Linux intrusion detection and incident response',
    tools,
    async health() {
      const start = Date.now();
      try {
        await sf.get('/v4/system/version');
        return { app: '@git-fabric/sandfly', status: 'healthy', latencyMs: Date.now() - start };
      } catch (e: unknown) {
        return { app: '@git-fabric/sandfly', status: 'unavailable', latencyMs: Date.now() - start, details: { error: String(e) } };
      }
    },
  };
}
