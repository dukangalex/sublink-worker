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


it('does not leak canonical protocol option keys through sing-box', () => {
    const output = toSingBox({
        name: 'vmess',
        protocol: 'vmess',
        endpoint: { host: 'example.com', port: 443 },
        credentials: { uuid: 'uuid' },
        protocolOptions: { security: 'auto', internalOnly: 'must-not-leak' }
    });
    expect(output.security).toBe('auto');
    expect(output.internalOnly).toBeUndefined();
});

it('does not leak canonical protocol options through Xray fallback', () => {
    expect(() => toXray({
        name: 'unknown',
        protocol: 'unknown',
        endpoint: { host: 'example.com', port: 443 },
        protocolOptions: { internalOnly: 'must-not-leak' }
    })).toThrow('No explicit Xray adapter mapping');
});
