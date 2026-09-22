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


test('Mihomo maps canonical VLESS TLS fields and nested XHTTP settings', () => {
    const node = normalizeProxy({
        ...base,
        tls: {
            ...base.tls,
            fingerprint: 'sha256-cert-fingerprint',
            alpn: ['h2']
        },
        network: 'xhttp',
        xhttp_opts: {
            'reuse-settings': {
                'max-concurrency': '16-32',
                'h-keep-alive-period': 0
            },
            'download-settings': {
                path: '/download',
                'reuse-settings': {
                    'max-connections': '2'
                }
            }
        }
    });

    const output = toClash(node);
    assert.deepEqual(output.alpn, ['h2']);
    assert.equal(output.fingerprint, 'sha256-cert-fingerprint');
    assert.deepEqual(output['xhttp-opts']['reuse-settings'], {
        'max-concurrency': '16-32',
        'h-keep-alive-period': 0
    });
    assert.deepEqual(output['xhttp-opts']['download-settings'], {
        path: '/download',
        'reuse-settings': { 'max-connections': '2' }
    });
});

test('Mihomo maps canonical WebSocket transport options', () => {
    const node = normalizeProxy({
        ...base,
        network: 'ws',
        ws_opts: {
            'max-early-data': 2048,
            'early-data-header-name': 'Sec-WebSocket-Protocol',
            'v2ray-http-upgrade': true,
            'v2ray-http-upgrade-fast-open': true
        }
    });

    const output = toClash(node);
    assert.deepEqual(output['ws-opts'], {
        'max-early-data': 2048,
        'early-data-header-name': 'Sec-WebSocket-Protocol',
        'v2ray-http-upgrade': true,
        'v2ray-http-upgrade-fast-open': true
    });
});


test('Xray maps canonical gRPC fields to the current wire keys', () => {
    const node = normalizeProxy({
        ...base,
        network: 'grpc',
        grpc_opts: {
            'service-name': 'grpc-service',
            'grpc-user-agent': 'agent',
            'idle-timeout': 60,
            'health-check-timeout': 20,
            'permit-without-stream': true,
            'initial-windows-size': 65536
        }
    });

    const output = toXray(node);
    assert.deepEqual(output.streamSettings.grpcSettings, {
        serviceName: 'grpc-service',
        user_agent: 'agent',
        idle_timeout: 60,
        health_check_timeout: 20,
        permit_without_stream: true,
        initial_windows_size: 65536
    });
});

test('Xray maps only current mKCP fields and rejects removed legacy fields', () => {
    const node = normalizeProxy({
        ...base,
        type: 'vmess',
        network: 'mkcp',
        mkcp_opts: {
            mtu: 1350,
            tti: 50,
            'uplink-capacity': 5,
            'downlink-capacity': 20,
            'cwnd-multiplier': 2,
            'max-sending-window': 64,
            seed: 'legacy-seed',
            header: { type: 'srtp' }
        }
    });

    const output = toXray(node);
    assert.deepEqual(output.streamSettings.kcpSettings, {
        mtu: 1350,
        tti: 50,
        uplinkCapacity: 5,
        downlinkCapacity: 20
    });
    assert.deepEqual(output.streamSettings.kcpSettings, {
        mtu: 1350,
        tti: 50,
        uplinkCapacity: 5,
        downlinkCapacity: 20,
        cwndMultiplier: 2,
        maxSendingWindow: 64
    });
});

test('Xray rejects Mihomo-specific WebSocket transport fields instead of dropping them', () => {
    const node = normalizeProxy({
        ...base,
        network: 'ws',
        ws_opts: {
            'max-early-data': 2048
        }
    });

    assert.throws(
        () => toXray(node),
        /Xray WebSocket does not expose Mihomo-specific early-data/
    );
});

test('Xray rejects removed mKCP fields instead of dropping them', () => {
    const node = normalizeProxy({
        ...base,
        type: 'vmess',
        network: 'mkcp',
        mkcp_opts: {
            mtu: 1350,
            'read-buffer': 2097152
        }
    });

    assert.throws(
        () => toXray(node),
        /Current Xray mKCP no longer supports read\/write buffers/
    );
});


test('Xray maps canonical XHTTP fields to current camelCase keys and xmux', () => {
    const node = normalizeProxy({
        ...base,
        network: 'xhttp',
        xhttp_opts: {
            mode: 'stream-one',
            path: '/xhttp',
            host: 'cdn.example.com',
            'no-grpc-header': true,
            'x-padding-bytes': '100-200',
            'uplink-http-method': 'PUT',
            'session-placement': 'cookie',
            'session-key': 'sid',
            'session-table': 'Base62',
            'session-length': '16-32',
            'reuse-settings': {
                'max-concurrency': '16-32',
                'h-max-reusable-secs': '1800-3000'
            }
        }
    });

    const output = toXray(node);
    assert.deepEqual(output.streamSettings.xhttpSettings, {
        path: '/xhttp',
        host: 'cdn.example.com',
        mode: 'stream-one',
        noGRPCHeader: true,
        xPaddingBytes: '100-200',
        uplinkHTTPMethod: 'PUT',
        sessionIDPlacement: 'cookie',
        sessionIDKey: 'sid',
        sessionIDTable: 'Base62',
        sessionIDLength: '16-32',
        xmux: {
            maxConcurrency: '16-32',
            hMaxReusableSecs: '1800-3000'
        }
    });
});

test('Xray refuses incomplete XHTTP downloadSettings instead of silently dropping it', () => {
    const node = normalizeProxy({
        ...base,
        network: 'xhttp',
        xhttp_opts: {
            'download-settings': {
                path: '/download',
                host: 'cdn.example.com'
            }
        }
    });

    assert.throws(
        () => toXray(node),
        /downloadSettings requires a complete nested StreamConfig/
    );
});
