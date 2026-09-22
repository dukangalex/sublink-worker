import { describe, expect, it } from 'vitest';
import { ProxyParser } from '../src/parsers/ProxyParser.js';

describe('expanded protocol parsers', () => {
    it('parses SOCKS5', async () => {
        const node = await ProxyParser.parse('socks5://user:pass@example.com:1080#test');
        expect(node.type).toBe('socks');
        expect(node.server).toBe('example.com');
        expect(node.server_port).toBe(1080);
        expect(node.username).toBe('user');
    });

    it('parses HTTP proxy', async () => {
        const node = await ProxyParser.parse('http-proxy://user:pass@example.com:8080#http');
        expect(node.type).toBe('http');
        expect(node.password).toBe('pass');
    });

    it('parses Hysteria 1 separately from Hysteria 2', async () => {
        const node = await ProxyParser.parse('hysteria://secret@example.com:443?sni=example.com&protocol=udp#hy1');
        expect(node.type).toBe('hysteria');
        expect(node.auth_str).toBe('secret');
        expect(node.protocol).toBe('udp');
    });

    it('parses WireGuard structured URI fields', async () => {
        const node = await ProxyParser.parse('wireguard://key@example.com:51820?private-key=priv&public-key=pub&address=10.0.0.2/32&allowed-ips=0.0.0.0/0');
        expect(node.type).toBe('wireguard');
        expect(node.private_key).toBe('priv');
        expect(node.peer_public_key).toBe('pub');
        expect(node.local_address).toContain('10.0.0.2/32');
    });

    it('parses NaiveProxy', async () => {
        const node = await ProxyParser.parse('naive+https://user:pass@example.com:443?sni=example.com');
        expect(node.type).toBe('naive');
        expect(node.username).toBe('user');
        expect(node.password).toBe('pass');
        expect(node.tls.enabled).toBe(true);
    });

    it('parses AnyTLS', async () => {
        const node = await ProxyParser.parse('anytls://secret@example.com:443?sni=example.com#any');
        expect(node.type).toBe('anytls');
        expect(node.password).toBe('secret');
        expect(node.tls.server_name).toBe('example.com');
    });

    it('parses Snell and SSH', async () => {
        const snell = await ProxyParser.parse('snell://psk@example.com:44046?version=3&obfs=tls&host=example.com');
        expect(snell.type).toBe('snell');
        expect(snell.psk).toBe('psk');
        const ssh = await ProxyParser.parse('ssh://alice:secret@example.com:22');
        expect(ssh.type).toBe('ssh');
        expect(ssh.user).toBe('alice');
    });
});
