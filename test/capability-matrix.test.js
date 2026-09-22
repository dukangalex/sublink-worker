import { describe, expect, it } from 'vitest';
import { explainConversion, getNodeFeatures } from '../src/core/capabilityMatrix.js';
import '../src/core/adapters/index.js';

describe('feature-level conversion capabilities', () => {
    it('reports supported TLS and WebSocket features', () => {
        const node = {
            protocol: 'vless',
            tls: { serverName: 'example.com', fingerprint: 'chrome' },
            transport: { type: 'ws' }
        };

        expect(getNodeFeatures(node)).toEqual(
            expect.arrayContaining(['tls', 'tls.utls', 'transport.ws'])
        );
        expect(explainConversion(node, 'singbox').supported).toBe(true);
    });

    it('rejects unsupported XHTTP transport instead of silently dropping it', () => {
        const node = {
            protocol: 'vless',
            transport: { type: 'xhttp' }
        };

        const result = explainConversion(node, 'singbox');

        expect(result.supported).toBe(false);
        expect(result.reasons).toContain('Target singbox does not support feature: transport.xhttp');
    });
});
