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
let cachedToken = null;
let tokenExpiresAt = 0;
async function getToken(host, username, password, verifySSL) {
    if (cachedToken && Date.now() < tokenExpiresAt)
        return cachedToken;
    const res = await fetch(`${host}/v4/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        // Note: Node 18+ fetch does not support rejectUnauthorized directly
        // For production use with self-signed certs, set NODE_TLS_REJECT_UNAUTHORIZED=0
    });
    if (!res.ok)
        throw new Error(`Sandfly auth failed: ${res.status} ${await res.text()}`);
    const data = await res.json();
    cachedToken = data.access_token;
    tokenExpiresAt = Date.now() + 50 * 60 * 1000; // 50 minutes
    return cachedToken;
}
export function createAdapterFromEnv() {
    const host = process.env.SANDFLY_HOST;
    const username = process.env.SANDFLY_USERNAME;
    const password = process.env.SANDFLY_PASSWORD;
    const verifySSL = process.env.SANDFLY_VERIFY_SSL !== 'false';
    if (!host || !username || !password) {
        throw new Error('SANDFLY_HOST, SANDFLY_USERNAME, SANDFLY_PASSWORD are required');
    }
    // Disable TLS verification for self-signed certs if requested
    if (!verifySSL) {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    }
    async function headers() {
        const token = await getToken(host, username, password, verifySSL);
        return {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
        };
    }
    return {
        async get(path, params) {
            const q = params ? '?' + new URLSearchParams(params).toString() : '';
            const res = await fetch(`${host}${path}${q}`, { headers: await headers() });
            if (!res.ok) {
                if (res.status === 401) {
                    cachedToken = null;
                    throw new Error(`Auth expired — retry`);
                }
                throw new Error(`Sandfly GET ${path}: ${res.status} ${await res.text()}`);
            }
            return res.json();
        },
        async post(path, body) {
            const res = await fetch(`${host}${path}`, {
                method: 'POST', headers: await headers(),
                body: body ? JSON.stringify(body) : undefined,
            });
            if (!res.ok)
                throw new Error(`Sandfly POST ${path}: ${res.status} ${await res.text()}`);
            return res.status === 204 ? { ok: true } : res.json();
        },
        async put(path, body) {
            const res = await fetch(`${host}${path}`, {
                method: 'PUT', headers: await headers(),
                body: body ? JSON.stringify(body) : undefined,
            });
            if (!res.ok)
                throw new Error(`Sandfly PUT ${path}: ${res.status} ${await res.text()}`);
            return res.status === 204 ? { ok: true } : res.json();
        },
        async delete(path) {
            const res = await fetch(`${host}${path}`, { method: 'DELETE', headers: await headers() });
            if (!res.ok)
                throw new Error(`Sandfly DELETE ${path}: ${res.status}`);
            return { ok: true };
        },
    };
}
//# sourceMappingURL=env.js.map