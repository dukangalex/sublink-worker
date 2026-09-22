import { describe, expect, it } from 'vitest';
import { normalizeProxy } from '../src/core/normalizeProxy.js';
import { toSingBox } from '../src/core/adapters/singbox.js';
import '../src/core/adapters/index.js';

describe('sing-box adapter', () => {
    it('converts canonical VLESS node', () => {
        const node = normalizeProxy({
            tag: 'v',
            type: 'vless',
            server: 'example.com',
            server_port: 443,
            uuid: 'u',
            tls: { enabled: true, server_name: 'example.com' }
        });
        const out = toSingBox(node);
        expect(out.type).toBe('vless');
        expect(out.server_port).toBe(443);
        expect(out.uuid).toBe('u');
        expect(out.tls.server_name).toBe('example.com');
    });
});
