import { describe, expect, it } from 'vitest';
import { normalizeProxy } from '../src/core/normalizeProxy.js';
import { toClash } from '../src/core/adapters/clash.js';
import '../src/core/adapters/index.js';

describe('Clash adapter', () => {
    it('converts canonical VLESS with Reality and WebSocket', () => {
        const node = normalizeProxy({
            tag: 'v',
            type: 'vless',
            server: 'example.com',
            server_port: 443,
            uuid: 'u',
            flow: 'xtls-rprx-vision',
            tls: {
                enabled: true,
                server_name: 'example.com',
                insecure: false,
                fingerprint: 'chrome'
            },
            reality: {
                enabled: true,
                public_key: 'pk',
                short_id: 'sid'
            },
            transport: {
                type: 'ws',
                path: '/ws',
                headers: { host: 'example.com' }
            }
        });

        const out = toClash(node);

        expect(out.type).toBe('vless');
        expect(out.port).toBe(443);
        expect(out.uuid).toBe('u');
        expect(out['client-fingerprint']).toBe('chrome');
        expect(out['reality-opts']['public-key']).toBe('pk');
        expect(out['ws-opts'].path).toBe('/ws');
    });

    it('converts canonical WireGuard with peer data', () => {
        const node = normalizeProxy({
            tag: 'wg',
            type: 'wireguard',
            server: 'wg.example.com',
            server_port: 51820,
            private_key: 'priv',
            peer_public_key: 'pub',
            pre_shared_key: 'psk',
            local_address: ['10.0.0.2/32'],
            allowed_ips: ['0.0.0.0/0'],
            mtu: 1420
        });

        const out = toClash(node);

        expect(out.type).toBe('wireguard');
        expect(out.ip).toBe('10.0.0.2/32');
        expect(out['private-key']).toBe('priv');
        expect(out.peers[0]['public-key']).toBe('pub');
        expect(out.peers[0]['allowed-ips']).toEqual(['0.0.0.0/0']);
    });
});
