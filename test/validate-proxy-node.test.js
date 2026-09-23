import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeProxy } from '../src/core/normalizeProxy.js';
import { validateProxyNode } from '../src/core/validateProxyNode.js';

test('validates canonical VLESS node', () => {
    const node = normalizeProxy({ name: 'vless-ws', type: 'vless', server: 'example.com', server_port: 443, uuid: '00000000-0000-0000-0000-000000000001', tls: { server_name: 'example.com' }, network: 'ws', ws_opts: { path: '/ws', headers: { Host: 'example.com' } } });
    const result = validateProxyNode(node);
    assert.equal(result.valid, true);
    assert.equal(node.transport.type, 'ws');
    assert.equal(node.transport.path, '/ws');
    assert.equal(node.tls.serverName, 'example.com');
});

test('rejects malformed endpoint and missing credentials', () => {
    const node = normalizeProxy({ type: 'vless', server: '', server_port: 70000 });
    const result = validateProxyNode(node);
    assert.equal(result.valid, false);
    assert.ok(result.errors.includes('Endpoint host is required'));
    assert.ok(result.errors.includes('Endpoint port must be an integer between 1 and 65535'));
    assert.ok(result.errors.includes('VLESS uuid is required'));
});

test('validates WireGuard peer structure', () => {
    const node = normalizeProxy({ type: 'wireguard', server: 'wg.example.com', server_port: 51820, private_key: 'private', peers: [{ public_key: 'peer-public', allowed_ips: ['0.0.0.0/0'] }] });
    assert.equal(validateProxyNode(node).valid, true);
});

test('rejects incomplete Reality configuration', () => {
    const node = normalizeProxy({ type: 'vless', server: 'example.com', server_port: 443, uuid: '00000000-0000-0000-0000-000000000001', reality_opts: { public_key: 'key' } });
    assert.ok(validateProxyNode(node).errors.includes('Reality short ID is required'));
});
