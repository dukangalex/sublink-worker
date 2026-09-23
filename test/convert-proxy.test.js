import { test } from 'vitest';
import assert from 'node:assert/strict';
import { convertProxy } from '../src/core/index.js';

test('unified conversion API returns normalized node and target output', () => {
    const result = convertProxy({
        name: 'ss',
        type: 'shadowsocks',
        server: 'example.com',
        server_port: 8388,
        method: 'aes-128-gcm',
        password: 'secret'
    }, 'surge');

    assert.equal(result.ok, true);
    assert.equal(result.target, 'surge');
    assert.equal(result.node.protocol, 'shadowsocks');
    assert.match(result.output.line, /encrypt-method=aes-128-gcm/);
});

test('unified conversion API reports unsupported targets without throwing by default', () => {
    const result = convertProxy({
        name: 'vless',
        type: 'vless',
        server: 'example.com',
        server_port: 443,
        uuid: '00000000-0000-0000-0000-000000000001'
    }, 'surge');

    assert.equal(result.ok, false);
    assert.match(result.errors[0], /No adapter capability/);
});
