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
import type { SandflyAdapter } from '../types.js';
export type { SandflyAdapter } from '../types.js';
export declare function createAdapterFromEnv(): SandflyAdapter;
//# sourceMappingURL=env.d.ts.map