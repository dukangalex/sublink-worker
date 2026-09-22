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

    it('does not advertise unsupported Xray protocols', () => {
        expect(explainConversion({ protocol: 'anytls' }, 'xray').status).toBe('unsupported');
        expect(explainConversion({ protocol: 'hysteria' }, 'xray').status).toBe('unsupported');
    });

    it('advertises Hysteria2 as the Xray Hysteria v2 protocol', () => {
        expect(explainConversion({ protocol: 'hysteria2' }, 'xray').status).toBe('supported');
    });

    it('does not advertise the removed sing-box WireGuard outbound', () => {
        const result = explainConversion({ protocol: 'wireguard' }, 'singbox');
        expect(result.supported).toBe(false);
        expect(result.status).toBe('unsupported');
        expect(result.reasons).toContain('No adapter capability has been declared for this protocol/target pair.');
    });
});


describe('transport security compatibility constraints', () => {
    it('rejects Mihomo Reality over WebSocket', () => {
        const result = explainConversion({
            protocol: 'vless',
            tls: { serverName: 'example.com' },
            reality: { publicKey: 'pk', shortId: 'sid' },
            transport: { type: 'ws' }
        }, 'clash');

        expect(result.supported).toBe(false);
        expect(result.reasons).toContain('Mihomo does not support REALITY with ws transport for vless');
    });

    it('accepts Mihomo Reality over gRPC', () => {
        const result = explainConversion({
            protocol: 'vless',
            tls: { serverName: 'example.com' },
            reality: { publicKey: 'pk', shortId: 'sid' },
            transport: { type: 'grpc' }
        }, 'clash');

        expect(result.supported).toBe(true);
    });

    it('rejects Xray Reality over WebSocket', () => {
        const result = explainConversion({
            protocol: 'vless',
            reality: { publicKey: 'pk', shortId: 'sid' },
            transport: { type: 'ws' }
        }, 'xray');

        expect(result.supported).toBe(false);
        expect(result.reasons[0]).toContain('Xray REALITY is only compatible with RAW, XHTTP, and gRPC');
    });
});
