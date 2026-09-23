import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createNodeFingerprint, processNodeCollection } from '../src/core/nodeCollection.js';

const vless = (name, server = 'example.com') => ({
    name,
    type: 'vless',
    server,
    server_port: 443,
    uuid: '00000000-0000-0000-0000-000000000001'
});

test('node fingerprints are deterministic and ignore runtime ids', () => {
    const first = createNodeFingerprint(vless('same'));
    const second = createNodeFingerprint({ ...vless('same'), metadata: { source: 'other' } });
    assert.equal(first, second);
});

test('node fingerprints ignore display names', () => {
    assert.equal(
        createNodeFingerprint(vless('Alpha')),
        createNodeFingerprint(vless('Same connection, other name'))
    );
});

test('collection removes duplicate nodes even when names differ', () => {
    const result = processNodeCollection([
        vless('Zulu', 'z.example.com'),
        vless('Alpha'),
        vless('Duplicate', 'd.example.com'),
        vless('Same connection, other name')
    ]);

    assert.deepEqual(result.nodes.map(node => node.name), ['Alpha', 'Duplicate', 'Zulu']);
    assert.equal(result.warnings.filter(item => item.type === 'duplicate').length, 1);
});

test('collection filters invalid nodes by default', () => {
    const result = processNodeCollection([
        vless('valid'),
        { name: 'invalid', type: 'vless', server: 'example.com', server_port: 443 }
    ]);

    assert.deepEqual(result.nodes.map(node => node.name), ['valid']);
    assert.equal(result.warnings[0].type, 'invalid');
});

test('collection can retain invalid entries when filtering is disabled', () => {
    const result = processNodeCollection([
        { name: 'invalid', type: 'vless', server: 'example.com', server_port: 443 }
    ], { filterInvalid: false, sort: 'none' });

    assert.equal(result.nodes.length, 1);
    assert.equal(result.entries[0].valid, false);
    assert.ok(result.entries[0].errors.includes('VLESS uuid is required'));
});

test('collection applies explicit rename and grouping options', () => {
    const result = processNodeCollection([
        vless('B', 'b.example.com'),
        vless('A', 'a.example.com')
    ], {
        rename: { prefix: 'SubX-', suffix: '-Node' },
        sort: 'endpoint',
        groupBy: 'host'
    });

    assert.deepEqual(result.nodes.map(node => node.name), ['SubX-A-Node', 'SubX-B-Node']);
    assert.deepEqual(result.groups.map(group => group.name), ['a.example.com', 'b.example.com']);
});
