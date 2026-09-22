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

    it('advertises Xray HTTPUpgrade, XHTTP, mKCP, WebSocket and gRPC for HTTP/VMess/VLESS/Trojan', () => {
        for (const protocol of ['http', 'vmess', 'vless', 'trojan']) {
            const result = explainConversion({
                protocol,
                transport: { type: 'httpupgrade' }
            }, 'xray');
            expect(result.supported).toBe(true);
            expect(result.status).toBe('supported');
        }
    });

    it('rejects Xray Hysteria transport without TLS', () => {
        const result = explainConversion({
            protocol: 'vless',
            transport: { type: 'hysteria' }
        }, 'xray');

        expect(result.supported).toBe(false);
        expect(result.reasons).toContain('Xray Hysteria transport requires TLS');
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

    it('accepts Xray Reality over RAW and canonical TCP transport', () => {
        for (const type of ['raw', 'tcp']) {
            const result = explainConversion({
                protocol: 'vless',
                reality: { publicKey: 'pk', shortId: 'sid' },
                transport: { type }
            }, 'xray');
            expect(result.supported).toBe(true);
        }
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

    it('rejects generic ECH when converting to Xray', () => {
        const result = explainConversion({
            protocol: 'vless',
            tls: { serverName: 'example.com', ech: { enabled: true, config: 'ECH-CONFIG' } }
        }, 'xray');
        expect(result.supported).toBe(false);
        expect(result.reasons).toContain('Xray adapter requires Xray-specific ECH fields; canonical Mihomo/sing-box ECH cannot be mapped without changing semantics');
    });
    it('rejects Mihomo TLS carrier fields on sing-box', () => {
        const result = explainConversion({
            protocol: 'vless',
            tls: {
                serverName: 'example.com',
                shadowTls: { version: 3, password: 'secret' }
            }
        }, 'singbox');

        expect(result.supported).toBe(false);
        expect(result.reasons).toContain(
            'sing-box adapter does not model Mihomo ShadowTLS, ResTLS, or JLS outbound fields; conversion would drop TLS carrier behavior'
        );
    });

    it('rejects Mihomo TLS carrier fields on Xray', () => {
        const result = explainConversion({
            protocol: 'vless',
            tls: {
                serverName: 'example.com',
                restls: { password: 'secret', versionHint: 'tls13' }
            }
        }, 'xray');

        expect(result.supported).toBe(false);
        expect(result.reasons).toContain(
            'Xray does not expose Mihomo ShadowTLS, ResTLS, or JLS outbound fields; conversion would drop TLS carrier behavior'
        );
    });

    it('rejects Mihomo TLSMirror on non-VMess Clash targets', () => {
        const result = explainConversion({
            protocol: 'vless',
            tls: { tlsMirror: { primaryKey: 'KEY' } }
        }, 'clash');
        expect(result.supported).toBe(false);
        expect(result.reasons).toContain('Mihomo TLSMirror is supported only for VMess; got vless');
    });

    it('accepts Mihomo TLSMirror on VMess Clash targets', () => {
        const result = explainConversion({
            protocol: 'vmess',
            tls: { tlsMirror: { primaryKey: 'KEY' } }
        }, 'clash');
        expect(result.supported).toBe(true);
    });

    it('rejects Mihomo TLSMirror on Xray and sing-box', () => {
        for (const target of ['xray', 'singbox']) {
            const result = explainConversion({
                protocol: 'vmess',
                tls: { tlsMirror: { primaryKey: 'KEY' } }
            }, target);
            expect(result.supported).toBe(false);
        }
    });

    it('rejects Mihomo REALITY ML-KEM capability on Xray and sing-box', () => {
        for (const target of ['xray', 'singbox']) {
            const result = explainConversion({
                protocol: 'vless',
                reality: { publicKey: 'pk', shortId: 'sid', supportX25519Mlkem768: true }
            }, target);
            expect(result.supported).toBe(false);
        }
    });

});
