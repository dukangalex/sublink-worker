import { describe, expect, it } from 'vitest';
import { normalizeProxy } from '../src/core/normalizeProxy.js';
import { declareCapability, canConvert, explainConversion } from '../src/core/capabilityMatrix.js';

describe('canonical ProxyNode', () => {
    it('normalizes legacy outbound fields', () => {
        const node = normalizeProxy({
            tag: 'demo',
            type: 'vless',
            server: 'example.com',
            server_port: 443,
            uuid: 'u',
            tls: { enabled: true, server_name: 'example.com' }
        });
        expect(node.protocol).toBe('vless');
        expect(node.endpoint).toEqual({ host: 'example.com', port: 443 });
        expect(node.credentials.uuid).toBe('u');
        expect(node.tls.serverName).toBe('example.com');
    });

    it('does not invent target capabilities', () => {
        const node = normalizeProxy({ type: 'vless', server: 'example.com', server_port: 443 });
        expect(canConvert(node, 'surge')).toBe(false);
        declareCapability('vless', 'singbox', { note: 'native adapter' });
        expect(explainConversion(node, 'singbox').supported).toBe(true);
    });
});
