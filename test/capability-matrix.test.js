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

    it('reports explicit unsupported status for XHTTP on sing-box', () => {
        const node = {
            protocol: 'vless',
            transport: { type: 'xhttp' }
        };

        const result = explainConversion(node, 'singbox');

        expect(result.supported).toBe(false);
        expect(result.status).toBe('unsupported');
        expect(result.reasons).toContain('Target singbox does not support feature: transport.xhttp');
    });

    it('reports supported status for XHTTP on Xray', () => {
        const result = explainConversion({
            protocol: 'vless',
            transport: { type: 'xhttp' }
        }, 'xray');

        expect(result.status).toBe('supported');
        expect(result.featureResults).toEqual([
            { feature: 'transport.xhttp', status: 'supported' }
        ]);
    });
});


it('does not advertise unsupported Xray protocols', () => {
    expect(explainConversion({ protocol: 'anytls' }, 'xray').status).toBe('unsupported');
    expect(explainConversion({ protocol: 'hysteria' }, 'xray').status).toBe('unsupported');
});

it('advertises Hysteria2 as the Xray Hysteria v2 protocol', () => {
    expect(explainConversion({ protocol: 'hysteria2' }, 'xray').status).toBe('supported');
});
