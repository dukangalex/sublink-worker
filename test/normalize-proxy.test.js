import { test } from 'vitest';
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


test('canonicalizes transport aliases for gRPC, WebSocket and XHTTP', () => {
    const node = normalizeProxy({
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        network: 'xhttp',
        xhttp_opts: {
            'x-padding-bytes': '100-200',
            'no-grpc-header': true,
            'session-placement': 'cookie',
            'uplink-http-method': 'PUT',
            'reuse-settings': {
                'max-concurrency': '16-32',
                'h-max-reusable-secs': '1800-3000'
            },
            'download-settings': {
                path: '/download',
                'reuse-settings': {
                    'max-connections': '2'
                }
            }
        }
    });

    assert.equal(node.transport.xPaddingBytes, '100-200');
    assert.equal(node.transport.noGrpcHeader, true);
    assert.equal(node.transport.sessionPlacement, 'cookie');
    assert.equal(node.transport.uplinkHttpMethod, 'PUT');
    assert.deepEqual(node.transport.reuseSettings, {
        maxConcurrency: '16-32',
        hMaxReusableSecs: '1800-3000'
    });
    assert.deepEqual(node.transport.downloadSettings, {
        path: '/download',
        reuseSettings: { maxConnections: '2' }
    });
    assert.equal(node.transport['x-padding-bytes'], undefined);
    assert.equal(node.transport['reuse-settings'], undefined);
});

test('canonicalizes gRPC and WebSocket transport aliases', () => {
    const grpc = normalizeProxy({
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        network: 'grpc',
        grpc_opts: {
            'service-name': 'svc',
            'grpc-user-agent': 'agent',
            'ping-interval': 10,
            'max-connections': 2
        }
    });
    assert.equal(grpc.transport.serviceName, 'svc');
    assert.equal(grpc.transport.userAgent, 'agent');
    assert.equal(grpc.transport.pingInterval, 10);
    assert.equal(grpc.transport.maxConnections, 2);

    const ws = normalizeProxy({
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        network: 'ws',
        ws_opts: {
            'max-early-data': 2048,
            'early-data-header-name': 'Sec-WebSocket-Protocol',
            'v2ray-http-upgrade': true,
            'v2ray-http-upgrade-fast-open': true
        }
    });
    assert.equal(ws.transport.maxEarlyData, 2048);
    assert.equal(ws.transport.earlyDataHeaderName, 'Sec-WebSocket-Protocol');
    assert.equal(ws.transport.v2rayHttpUpgrade, true);
    assert.equal(ws.transport.v2rayHttpUpgradeFastOpen, true);
});


test('canonicalizes mKCP fields without target-specific key names', () => {
    const node = normalizeProxy({
        type: 'vmess',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001',
        network: 'mkcp',
        mkcp_opts: {
            mtu: 1350,
            tti: 50,
            'uplink-capacity': 5,
            'downlink-capacity': 20,
            congestion: false,
            'write-buffer': 2097152,
            'read-buffer': 2097152,
            seed: 'seed',
            header: 'srtp'
        }
    });

    assert.equal(node.transport.uplinkCapacity, 5);
    assert.equal(node.transport.downlinkCapacity, 20);
    assert.equal(node.transport.writeBuffer, 2097152);
    assert.equal(node.transport.readBuffer, 2097152);
    assert.equal(node.transport['uplink-capacity'], undefined);
});
