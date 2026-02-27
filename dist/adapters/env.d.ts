/**
 * Sandfly environment adapter
 *
 * Required env vars:
 *   SANDFLY_HOST      — Sandfly server URL (e.g. https://10.88.140.176)
 *   SANDFLY_USERNAME  — API username
 *   SANDFLY_PASSWORD  — API password
 *
 * Optional:
 *   SANDFLY_VERIFY_SSL — set to "false" to skip TLS verification (default: true)
 */
export interface SandflyAdapter {
    get(path: string, params?: Record<string, string>): Promise<unknown>;
    post(path: string, body?: unknown): Promise<unknown>;
    put(path: string, body?: unknown): Promise<unknown>;
    delete(path: string): Promise<unknown>;
}
export declare function createAdapterFromEnv(): SandflyAdapter;
//# sourceMappingURL=env.d.ts.map