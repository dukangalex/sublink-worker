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


test('maps Surge-supported certificate verification controls explicitly', () => {
    const node = normalizeProxy({
        name: 'https-pinned',
        type: 'http',
        server: 'example.com',
        server_port: 443,
        tls: {
            server_name: 'cdn.example.com',
            skip_cert_verify: true,
            name_cert_verify: 'origin.example.com',
            pinned_peer_cert_sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
        }
    });
    const out = toSurge(node);
    assert.match(out.line, /sni=cdn\.example\.com/);
    assert.match(out.line, /skip-cert-verify=true/);
    assert.match(out.line, /server-cert-verify-name=origin\.example\.com/);
    assert.match(out.line, /server-cert-fingerprint-sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/);
});

test('maps Surge Shadow TLS v2/v3 fields explicitly', () => {
    const node = normalizeProxy({
        name: 'stls',
        type: 'snell',
        server: 'example.com',
        server_port: 443,
        psk: 'psk',
        version: 5,
        tls: {
            server_name: 'cover.example.com',
            'shadow-tls-opts': {
                version: 3,
                password: 'shadow-password'
            }
        }
    });
    const out = toSurge(node);
    assert.match(out.line, /shadow-tls-password=shadow-password/);
    assert.match(out.line, /shadow-tls-version=3/);
    assert.match(out.line, /shadow-tls-sni=cover\.example\.com/);
});

test('rejects unsupported Surge TLS representations instead of dropping them', () => {
    const cases = [
        ['mTLS certificate/private-key', { certificate: 'CERT', private_key: 'KEY' }],
        ['ECH', { ech: { enabled: true, config: 'BASE64' } }],
        ['REALITY', { reality: { public_key: 'pk', short_id: 'sid' } }],
        ['TLSMirror', { 'tlsmirror-opts': { 'primary-key': 'PRIMARY' } }]
    ];

    for (const [label, tls] of cases) {
        const input = {
            name: label,
            type: 'vmess',
            server: 'example.com',
            server_port: 443,
            uuid: '00000000-0000-0000-0000-000000000001',
            tls: { server_name: 'example.com' }
        };
        if (tls.reality) input.reality = tls.reality;
        else Object.assign(input.tls, tls);
        const node = normalizeProxy(input);
        assert.throws(() => toSurge(node), /Surge (adapter does not model|mTLS requires)/, label);
    }
});

test('rejects Surge-incompatible Shadow TLS versions and QUIC wrappers', () => {
    const v1 = normalizeProxy({
        name: 'stls-v1',
        type: 'snell',
        server: 'example.com',
        server_port: 443,
        psk: 'psk',
        version: 5,
        tls: { 'shadow-tls-opts': { version: 1, password: 'p' } }
    });
    assert.throws(() => toSurge(v1), /Shadow TLS v2\/v3/);

    const tuic = normalizeProxy({
        name: 'tuic-stls',
        type: 'tuic',
        server: 'example.com',
        server_port: 443,
        token: 'token',
        tls: { 'shadow-tls-opts': { version: 2, password: 'p' } }
    });
    assert.throws(() => toSurge(tuic), /cannot be combined with TUIC/);
});
