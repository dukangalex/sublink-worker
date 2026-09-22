import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeProxy } from '../src/core/normalizeProxy.js';

test('normalizes TLS aliases into canonical fields', () => {
    const node = normalizeProxy({
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        tls: {
            server_name: 'example.com',
            skip_cert_verify: true,
            client_fingerprint: 'chrome'
        }
    });

    assert.equal(node.tls.serverName, 'example.com');
    assert.equal(node.tls.insecure, true);
    assert.equal(node.tls.clientFingerprint, 'chrome');
    assert.equal(node.tls.server_name, undefined);
    assert.equal(node.tls.skip_cert_verify, undefined);
    assert.equal(node.tls.client_fingerprint, undefined);
});

test('normalizes Reality aliases without duplicate snake_case fields', () => {
    const node = normalizeProxy({
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        reality_opts: {
            public_key: 'public-key',
            short_id: '01234567',
            server_name: 'example.com',
            client_fingerprint: 'chrome'
        }
    });

    assert.equal(node.reality.publicKey, 'public-key');
    assert.equal(node.reality.shortId, '01234567');
    assert.equal(node.reality.serverName, 'example.com');
    assert.equal(node.reality.fingerprint, 'chrome');
    assert.equal(node.reality.public_key, undefined);
    assert.equal(node.reality.short_id, undefined);
    assert.equal(node.reality.server_name, undefined);
});

test('keeps protocol-specific options while removing top-level alias pollution', () => {
    const node = normalizeProxy({
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        network: 'grpc',
        packetEncoding: 'xudp'
    });

    assert.equal(node.transport.type, 'grpc');
    assert.equal(node.protocolOptions.packet_encoding, 'xudp');
    assert.equal(node.protocolOptions.packetEncoding, undefined);
    assert.equal(node.protocolOptions.server_name, undefined);
});
