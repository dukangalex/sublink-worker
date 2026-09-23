import { test } from 'vitest';
import assert from 'node:assert/strict';
import { normalizeProxy } from '../src/core/normalizeProxy.js';
import { validateProxyNode } from '../src/core/validateProxyNode.js';
import { explainConversion } from '../src/core/capabilityMatrix.js';
import { toXray } from '../src/core/adapters/xray.js';
import { toClash } from '../src/core/adapters/clash.js';
import '../src/core/adapters/index.js';

const input = {
    name: 'wg',
    type: 'wireguard',
    server: 'wg.example.com',
    server_port: 51820,
    private_key: 'client-private',
    peers: [{
        server: 'wg.example.com',
        port: 51820,
        public_key: 'server-public',
        pre_shared_key: 'psk',
        allowed_ips: ['0.0.0.0/0', '::/0'],
        persistent_keepalive: 25,
        reserved: [1, 2, 3]
    }],
    local_address: ['10.0.0.2/32'],
    mtu: 1408
};

test('WireGuard peers become canonical camelCase fields', () => {
    const node = normalizeProxy(input);
    assert.equal(node.protocolOptions.peers.length, 1);
    const peer = node.protocolOptions.peers[0];
    assert.equal(peer.address, 'wg.example.com');
    assert.equal(peer.port, 51820);
    assert.equal(peer.publicKey, 'server-public');
    assert.equal(peer.preSharedKey, 'psk');
    assert.deepEqual(peer.allowedIPs, ['0.0.0.0/0', '::/0']);
    assert.equal(peer.persistentKeepalive, 25);
    assert.deepEqual(peer.reserved, [1, 2, 3]);
    assert.equal(peer.public_key, undefined);
    assert.equal(peer.allowed_ips, undefined);
});

test('WireGuard validates peers without requiring a duplicate top-level endpoint', () => {
    const node = normalizeProxy({
        type: 'wireguard',
        private_key: 'client-private',
        peers: [{
            server: 'wg.example.com',
            port: 51820,
            public_key: 'server-public'
        }]
    });
    const result = validateProxyNode(node);
    assert.equal(result.valid, true);
    assert.deepEqual(result.errors, []);
});

test('WireGuard canonical peer maps to Xray schema', () => {
    const output = toXray(normalizeProxy(input));
    assert.equal(output.settings.peers[0].endpoint, 'wg.example.com:51820');
    assert.equal(output.settings.peers[0].publicKey, 'server-public');
    assert.equal(output.settings.peers[0].preSharedKey, 'psk');
    assert.equal(output.settings.peers[0].keepAlive, 25);
});

test('WireGuard canonical peer maps to Mihomo schema', () => {
    const output = toClash(normalizeProxy(input));
    assert.equal(output.peers[0].server, 'wg.example.com');
    assert.equal(output.peers[0]['public-key'], 'server-public');
    assert.equal(output.peers[0]['pre-shared-key'], 'psk');
    assert.deepEqual(output.peers[0]['allowed-ips'], ['0.0.0.0/0', '::/0']);
});

test('WireGuard is not advertised as a current sing-box outbound', () => {
    const result = explainConversion(normalizeProxy(input), 'singbox');
    assert.equal(result.supported, false);
    assert.equal(result.status, 'unsupported');
});
