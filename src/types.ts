/**
 * @git-fabric/sandfly — shared types
 *
 * Covers: system, hosts, credentials, scanning, results,
 * sandflies, schedules, jump-hosts, notifications, reports, audit.
 */

export interface SandflyAdapter {
  get(path: string, params?: Record<string, string>): Promise<unknown>;
  post(path: string, body?: unknown): Promise<unknown>;
  put(path: string, body?: unknown): Promise<unknown>;
  delete(path: string): Promise<unknown>;
}
