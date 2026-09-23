import { describe, it, expect, vi } from 'vitest';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';

const createTestApp = (overrides = {}) => {
    const runtime = {
        kv: overrides.kv ?? new MemoryKVAdapter(),
        assetFetcher: overrides.assetFetcher ?? null,
        logger: console,
        config: {
            configTtlSeconds: 60,
            shortLinkTtlSeconds: null,
            ...(overrides.config || {})
        }
    };
    return createApp(runtime);
};

describe('Worker', () => {
    it('GET / returns HTML', async () => {
        const app = createTestApp();
        const res = await app.request('http://localhost/');
        expect(res.status).toBe(200);
        expect(res.headers.get('content-type')).toContain('text/html');
        const text = await res.text();
        expect(text).toContain('Sublink Worker');
    });

    it('GET /singbox returns JSON', async () => {
        const app = createTestApp();
        const config = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInRlc3QiLA0KICAiYWRkIjogIjEuMS4xLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRkNjY2NjYtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICJ0bHMiDQp9';
        const res = await app.request(`http://localhost/singbox?config=${encodeURIComponent(config)}`);
        expect(res.status).toBe(200);
        expect(res.headers.get('content-type')).toContain('application/json');
        const json = await res.json();
        expect(json).toHaveProperty('outbounds');
    });

    it('GET /singbox returns legacy config for sing-box 1.11 UA', async () => {
        const app = createTestApp();
        const config = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInRlc3QiLA0KICAiYWRkIjogIjEuMS4xLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRkNjY2NjYtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICJ0bHMiDQp9';
        const res = await app.request(`http://localhost/singbox?config=${encodeURIComponent(config)}`, {
            headers: {
                'User-Agent': 'SFI/1.12.2 (Build 2; sing-box 1.11.4; language zh_CN)'
            }
        });
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json?.dns?.servers?.[0]).toHaveProperty('address');
        expect(json?.dns?.servers?.[0]).not.toHaveProperty('type');
        expect(json?.route).not.toHaveProperty('default_domain_resolver');
    });

    it('GET /singbox returns 1.12+ config for sing-box 1.12 UA', async () => {
        const app = createTestApp();
        const config = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInRlc3QiLA0KICAiYWRkIjogIjEuMS4xLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRkNjY2NjYtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICJ0bHMiDQp9';
        const res = await app.request(`http://localhost/singbox?config=${encodeURIComponent(config)}`, {
            headers: {
                'User-Agent': 'SFA/1.12.12 (587; sing-box 1.12.12; language zh_Hans_CN)'
            }
        });
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json?.dns?.servers?.[0]).toHaveProperty('type');
        expect(json?.dns?.servers?.[0]).not.toHaveProperty('address');
        expect(json?.route).toHaveProperty('default_domain_resolver', 'dns_resolver');
    });

    it('GET /clash returns YAML', async () => {
        const app = createTestApp();
        const config = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInRlc3QiLA0KICAiYWRkIjogIjEuMS4xLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRkNjY2NjYtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICJ0bHMiDQp9';
        const res = await app.request(`http://localhost/clash?config=${encodeURIComponent(config)}`);
        expect(res.status).toBe(200);
        // Clash builder returns text/yaml
        expect(res.headers.get('content-type')).toContain('text/yaml');
        const text = await res.text();
        expect(text).toContain('proxies:');
    });

    it('GET /clash rejects empty url-test proxy groups with a diagnostic error', async () => {
        const app = createTestApp();
        const config = `
proxies:
  - name: Node-A
    type: ss
    server: a.example.com
    port: 443
    cipher: aes-128-gcm
    password: test
proxy-groups:
  - name: Empty Test Group
    type: url-test
    proxies: []
`;
        const res = await app.request(`http://localhost/clash?config=${encodeURIComponent(config)}`);

        expect(res.status).toBe(400);
        const text = await res.text();
        expect(text).toContain('Invalid proxy group "Empty Test Group"');
        expect(text).toContain('requires at least one proxy or provider reference');
    });


    it('creates and serves a mixed subscription through an opaque URL', async () => {
        const app = createTestApp({
            config: {
                subscriptionAdminToken: 'test-admin-token'
            }
        });
        const source = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInRlc3QiLA0KICAiYWRkIjogIjEuMS4xLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRkNjY2NjYtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvaCIsDQogICJ0bHMiOiAidGxzIg0KfQ==';
        const originalFetch = globalThis.fetch;
        vi.stubGlobal('fetch', vi.fn(async () => new Response(source, {
            status: 200,
            headers: { 'content-type': 'text/plain' }
        })));

        try {
            const createRes = await app.request('https://subx.example/api/subscriptions', {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer test-admin-token',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: 'clash',
                    inputs: [
                        'https://provider.example/subscription',
                        source
                    ]
                })
            });

            expect(createRes.status).toBe(201);
            const created = await createRes.json();
            expect(created.url).toMatch(/^https:\/\/subx\.example\/sub\/[0-9A-Za-z_-]{16}$/);

            const subRes = await app.request(created.url);
            expect(subRes.status).toBe(200);
            expect(subRes.headers.get('content-type')).toContain('text/yaml');
            const body = await subRes.text();
            expect(body).toContain('proxies:');
            expect(body).toContain('1.1.1.1');
        } finally {
            vi.stubGlobal('fetch', originalFetch);
        }
    });

    it('serves a subscription when at least one resolved node is valid', async () => {
        const app = createTestApp({
            config: { subscriptionAdminToken: 'test-admin-token' }
        });
        const valid = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInRlc3QiLA0KICAiYWRkIjogIjEuMS4xLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRkNjY2NjYtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvaCIsDQogICJ0bHMiOiAidGxzIg0KfQ==';
        const originalFetch = globalThis.fetch;
        vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
            proxies: [{
                name: 'invalid',
                type: 'vless',
                server: 'example.com',
                server_port: 443
            }, valid]
        }), {
            status: 200,
            headers: { 'content-type': 'application/json' }
        })));

        try {
            const createRes = await app.request('https://subx.example/api/subscriptions', {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer test-admin-token',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: 'clash',
                    inputs: ['https://provider.example/subscription']
                })
            });
            const created = await createRes.json();
            const res = await app.request(created.url);
            expect(res.status).toBe(200);
            expect(await res.text()).toContain('proxies:');
        } finally {
            vi.stubGlobal('fetch', originalFetch);
        }
    });

    it('returns 422 when all resolved subscription nodes are invalid', async () => {
        const app = createTestApp({
            config: { subscriptionAdminToken: 'test-admin-token' }
        });
        const originalFetch = globalThis.fetch;
        vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
            proxies: [{
                name: 'invalid',
                type: 'vless',
                server: 'example.com',
                server_port: 443
            }]
        }), {
            status: 200,
            headers: { 'content-type': 'application/json' }
        })));

        try {
            const createRes = await app.request('https://subx.example/api/subscriptions', {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer test-admin-token',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: 'clash',
                    inputs: ['https://provider.example/subscription']
                })
            });
            const created = await createRes.json();
            const res = await app.request(created.url);
            expect(res.status).toBe(422);
            expect(await res.text()).toContain('no valid nodes');
        } finally {
            vi.stubGlobal('fetch', originalFetch);
        }
    });

    it('does not expose subscription records without the admin token', async () => {
        const app = createTestApp({
            config: {
                subscriptionAdminToken: 'test-admin-token'
            }
        });
        const res = await app.request('http://localhost/api/subscriptions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: 'clash', inputs: ['vless://example'] })
        });
        expect(res.status).toBe(401);
    });

    it('GET /shorten-v2 returns short code', async () => {
        const url = 'http://example.com';
        const kvMock = {
            put: vi.fn(async () => {}),
            get: vi.fn(async () => null),
            delete: vi.fn(async () => {})
        };
        const app = createTestApp({ kv: kvMock });
        const res = await app.request(`http://localhost/shorten-v2?url=${encodeURIComponent(url)}`);
        expect(res.status).toBe(200);
        const text = await res.text();
        expect(text).toBeTruthy();
        expect(kvMock.put).toHaveBeenCalled();
    });
});
