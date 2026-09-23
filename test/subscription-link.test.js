import { describe, expect, it } from 'vitest';
import {
    MemorySubscriptionStore,
    createSubscriptionInput,
    createSubscriptionResolver,
    createSubscriptionRecord,
    createSubscriptionToken,
    createSubscriptionUrl,
    isValidSubscriptionToken
} from '../src/core/subscriptionLink.js';

describe('opaque subscription links', () => {
    it('creates URL-safe tokens without embedding source information', () => {
        const token = createSubscriptionToken();

        expect(token).toMatch(/^[0-9A-Za-z_-]{16}$/);
        expect(isValidSubscriptionToken(token)).toBe(true);
        expect(token).not.toContain('example.com');
    });

    it('creates a conventional /sub/<token> URL and strips query/hash', () => {
        const token = 'A1b2C3d4E5f6G7h8';
        expect(createSubscriptionUrl('https://subx.example.com/old?source=secret#fragment', token))
            .toBe('https://subx.example.com/sub/A1b2C3d4E5f6G7h8');
    });

    it('accepts mixed subscription URLs and direct node inputs', () => {
        const record = createSubscriptionRecord({
            inputs: [
                'https://provider-a.example/sub?token=SECRET',
                'vless://uuid@example.com:443?security=tls',
                { type: 'node', value: 'ss://example' }
            ],
            target: 'clash'
        });

        expect(record.inputs).toHaveLength(3);
        expect(record.inputs[0]).toMatchObject({
            type: 'subscription',
            source: 'https://provider-a.example/sub?token=SECRET'
        });
        expect(record.inputs[1]).toEqual({
            type: 'node',
            value: 'vless://uuid@example.com:443?security=tls',
            name: undefined
        });
        expect(record.inputs[2].type).toBe('node');
    });

    it('keeps legacy single-source records compatible', () => {
        const record = createSubscriptionRecord({
            source: 'https://provider.example/subscribe?token=UPSTREAM_SECRET',
            target: 'clash'
        });

        expect(record.token).toMatch(/^[0-9A-Za-z_-]{16}$/);
        expect(record.inputs).toHaveLength(1);
        expect(record.inputs[0].source).toContain('UPSTREAM_SECRET');
        expect(record.target).toBe('clash');
    });

    it('resolves mixed inputs through one node pipeline', async () => {
        const seen = [];
        const resolver = createSubscriptionResolver({
            fetchSubscription: async () => ['vless://uuid@example.com:443?security=tls', 'ss://example'],
            parseAndNormalize: async (value) => {
                seen.push(value);
                return { node: { value }, validation: { valid: true, errors: [], warnings: [] } };
            }
        });

        const record = createSubscriptionRecord({
            inputs: [
                'https://provider.example/sub',
                'trojan://secret@example.net:443'
            ],
            target: 'singbox'
        });

        const results = await resolver(record);
        expect(seen).toEqual([
            'vless://uuid@example.com:443?security=tls',
            'ss://example',
            'trojan://secret@example.net:443'
        ]);
        expect(results).toHaveLength(3);
    });

    it('supports one fixed target per generated subscription link', async () => {
        const store = new MemorySubscriptionStore(createSubscriptionToken);
        const record = await store.create({
            source: 'https://provider.example/sub',
            target: 'singbox'
        });

        expect((await store.get(record.token)).target).toBe('singbox');
        expect(await store.get('https://provider.example/sub')).toBeNull();
    });

    it('rejects non-http upstream sources and unknown targets', () => {
        expect(() => createSubscriptionRecord({
            source: 'ss://example',
            target: 'clash'
        })).toThrow(/HTTP or HTTPS/);

        expect(() => createSubscriptionRecord({
            source: 'https://provider.example/sub',
            target: 'unknown'
        })).toThrow(/Unsupported subscription target/);
    });
});
