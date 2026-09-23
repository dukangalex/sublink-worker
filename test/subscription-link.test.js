import { describe, expect, it } from 'vitest';
import {
    MemorySubscriptionStore,
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

    it('stores the upstream source separately from the public token', () => {
        const record = createSubscriptionRecord({
            source: 'https://provider.example/subscribe?token=UPSTREAM_SECRET',
            target: 'clash'
        });

        expect(record.token).toMatch(/^[0-9A-Za-z_-]{16}$/);
        expect(record.source).toContain('UPSTREAM_SECRET');
        expect(record.target).toBe('clash');
    });

    it('supports one fixed target per generated subscription link', async () => {
        const store = new MemorySubscriptionStore();
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
