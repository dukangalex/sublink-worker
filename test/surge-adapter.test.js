import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeProxy } from '../src/core/normalizeProxy.js';
import { toSurge } from '../src/core/adapters/surge.js';

test('converts VMess WebSocket TLS to a Surge proxy line', () => {
    const node = normalizeProxy({
        name: 'edge',
        type: 'vmess',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        network: 'ws',
        ws_opts: { path: '/ws', headers: { Host: 'cdn.example.com' } },
        tls: { server_name: 'cdn.example.com' }
    });
    const out = toSurge(node);
    assert.equal(out.type, 'vmess');
    assert.match(out.line, /vmess, example\.com, 443/);
    assert.match(out.line, /username=00000000-0000-0000-0000-000000000001/);
    assert.match(out.line, /tls=true/);
    assert.match(out.line, /ws=true/);
    assert.match(out.line, /ws-path=\/ws/);
    assert.match(out.line, /ws-headers=Host:cdn\.example\.com/);
    assert.match(out.line, /sni=cdn\.example\.com/);
});

test('converts WireGuard into Proxy and WireGuard sections', () => {
    const node = normalizeProxy({
        name: 'wg',
        type: 'wireguard',
        server: 'wg.example.com',
        server_port: 51820,
        private_key: 'private',
        peer_public_key: 'public',
        local_address: '10.0.0.2/32',
        allowed_ips: ['0.0.0.0/0']
    });
    const out = toSurge(node);
    assert.equal(out.type, 'wireguard');
    assert.match(out.line, /wireguard, section-name=wg/);
    assert.match(out.section, /\[WireGuard wg\]/);
    assert.match(out.section, /private-key = private/);
    assert.match(out.section, /self-ip = 10\.0\.0\.2\/32/);
});

test('rejects protocols Surge does not declare', () => {
    const node = normalizeProxy({
        name: 'vless',
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001'
    });
    assert.throws(() => toSurge(node), /No adapter capability/);
});


test('preserves Surge SOCKS5 UDP relay option', () => {
    const node = normalizeProxy({
        name: 'socks',
        type: 'socks5',
        server: 'example.com',
        server_port: 1080,
        username: 'u',
        password: 'p',
        udp_relay: true
    });
    const out = toSurge(node);
    assert.match(out.line, /udp-relay=true/);
});
