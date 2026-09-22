import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeProxy } from '../src/core/normalizeProxy.js';
import { toXray } from '../src/core/adapters/xray.js';
import { toClash } from '../src/core/adapters/clash.js';
import { toSingBox } from '../src/core/adapters/singbox.js';
import '../src/core/adapters/index.js';

const base = {
    name: 'vless-test',
    type: 'vless',
    server: 'example.com',
    server_port: 443,
    uuid: '00000000-0000-0000-0000-000000000001',
    tls: {
        server_name: 'example.com',
        client_fingerprint: 'chrome'
    }
};

test('Xray Reality maps canonical publicKey to current password field', () => {
    const node = normalizeProxy({
        ...base,
        reality_opts: {
            public_key: 'reality-public-key',
            short_id: '01234567'
        },
        network: 'grpc'
    });

    const output = toXray(node);
    assert.equal(output.streamSettings.method, 'grpc');
    assert.equal(output.streamSettings.network, undefined);
    assert.equal(output.streamSettings.security, 'reality');
    assert.equal(output.streamSettings.realitySettings.password, 'reality-public-key');
    assert.equal(output.streamSettings.realitySettings.shortId, '01234567');
    assert.equal(output.streamSettings.tlsSettings, undefined);
    assert.equal(output.streamSettings.realitySettings.fingerprint, 'chrome');
});

test('Clash keeps certificate fingerprint and client fingerprint distinct', () => {
    const node = normalizeProxy({
        ...base,
        tls: {
            ...base.tls,
            fingerprint: 'sha256-cert-fingerprint'
        }
    });

    const output = toClash(node);
    assert.equal(output.fingerprint, 'sha256-cert-fingerprint');
    assert.equal(output['client-fingerprint'], 'chrome');
});

test('sing-box emits client fingerprint through uTLS', () => {
    const node = normalizeProxy(base);
    const output = toSingBox(node);
    assert.deepEqual(output.tls.utls, { enabled: true, fingerprint: 'chrome' });
    assert.equal(output.tls.server_name, 'example.com');
    assert.equal(output.tls.clientFingerprint, undefined);
});

test('sing-box nests Reality inside TLS and uses explicit V2Ray transport fields', () => {
    const node = normalizeProxy({
        ...base,
        reality_opts: {
            public_key: 'reality-public-key',
            short_id: '01234567'
        },
        network: 'grpc',
        grpc_opts: {
            service_name: 'grpc-service'
        }
    });

    const output = toSingBox(node);
    assert.deepEqual(output.tls.reality, {
        enabled: true,
        public_key: 'reality-public-key',
        short_id: '01234567'
    });
    assert.deepEqual(output.transport, {
        type: 'grpc',
        service_name: 'grpc-service'
    });
    assert.equal(output.reality, undefined);
});

test('sing-box does not leak canonical protocol option keys', () => {
    const output = toSingBox({
        name: 'vmess',
        protocol: 'vmess',
        endpoint: { host: 'example.com', port: 443 },
        credentials: { uuid: 'uuid' },
        protocolOptions: { security: 'auto', internalOnly: 'must-not-leak' }
    });
    assert.equal(output.security, 'auto');
    assert.equal(output.internalOnly, undefined);
});

test('Xray does not expose a generic protocol option fallback', () => {
    assert.throws(() => toXray({
        name: 'unknown',
        protocol: 'unknown',
        endpoint: { host: 'example.com', port: 443 },
        protocolOptions: { internalOnly: 'must-not-leak' }
    }), /No explicit Xray adapter mapping/);
});


test('Mihomo maps canonical gRPC serviceName to grpc-service-name', () => {
    const node = normalizeProxy({
        ...base,
        network: 'grpc',
        grpc_opts: {
            service_name: 'grpc-service'
        }
    });

    const output = toClash(node);
    assert.equal(output.network, 'grpc');
    assert.equal(output['grpc-opts']['grpc-service-name'], 'grpc-service');
    assert.equal(output['grpc-opts'].serviceName, undefined);
});

test('Mihomo maps VLESS XHTTP fields explicitly', () => {
    const node = normalizeProxy({
        ...base,
        network: 'xhttp',
        xhttp_opts: {
            path: '/xhttp',
            host: 'cdn.example.com',
            mode: 'stream-one',
            headers: { 'X-Test': '1' },
            'x-padding-bytes': '100-200',
            'x-padding-obfs-mode': true,
            'x-padding-key': 'x_padding',
            'x-padding-placement': 'query',
            'x-padding-method': 'tokenish',
            'uplink-http-method': 'PUT',
            'session-placement': 'cookie',
            'session-key': 'sid'
        }
    });

    const output = toClash(node);
    assert.equal(output.network, 'xhttp');
    assert.deepEqual(output['xhttp-opts'], {
        path: '/xhttp',
        host: 'cdn.example.com',
        mode: 'stream-one',
        headers: { 'X-Test': '1' },
        'x-padding-bytes': '100-200',
        'x-padding-obfs-mode': true,
        'x-padding-key': 'x_padding',
        'x-padding-placement': 'query',
        'x-padding-method': 'tokenish',
        'uplink-http-method': 'PUT',
        'session-placement': 'cookie',
        'session-key': 'sid'
    });
    assert.equal(output['xhttp-opts'].serviceName, undefined);
});
