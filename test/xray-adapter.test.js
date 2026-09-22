import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeProxy } from '../src/core/normalizeProxy.js';
import { toXray } from '../src/core/adapters/xray.js';

test('converts VLESS Reality gRPC to Xray streamSettings', () => {
    const node = normalizeProxy({
        name: 'vless-xray',
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        flow: 'xtls-rprx-vision',
        network: 'grpc',
        grpc_opts: { serviceName: 'edge' },
        tls: { server_name: 'example.com', client_fingerprint: 'chrome' },
        reality_opts: { public_key: 'pub', short_id: 'abcd' }
    });
    const out = toXray(node);
    assert.equal(out.protocol, 'vless');
    assert.equal(out.settings.vnext[0].users[0].id, '00000000-0000-0000-0000-000000000001');
    assert.equal(out.streamSettings.network, 'grpc');
    assert.equal(out.streamSettings.security, 'reality');
    assert.equal(out.streamSettings.grpcSettings.serviceName, 'edge');
});

test('rejects unsupported Xray transport by capability', () => {
    const node = normalizeProxy({
        name: 'vless',
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        network: 'quic'
    });
    assert.throws(() => toXray(node), /does not support feature: transport.quic/);
});
