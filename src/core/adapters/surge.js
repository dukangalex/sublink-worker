import { explainConversion } from '../capabilityMatrix.js';

export function toSurge(node) {
    const check = explainConversion(node, 'surge');
    if (!check.supported) throw new Error(check.reasons.join('; '));

    const name = node.name || 'Proxy';
    if (node.protocol === 'wireguard') return buildWireGuard(node, name);

    const type = surgeType(node);
    const args = [type, node.endpoint.host, String(node.endpoint.port)];
    const params = buildParameters(node);

    if (node.protocol === 'shadowsocks') {
        params.unshift(['encrypt-method', node.credentials?.method]);
        params.push(['password', node.credentials?.password]);
    } else if (node.protocol === 'vmess') {
        params.unshift(['username', node.credentials?.uuid]);
        add(params, 'encrypt-method', node.protocolOptions?.cipher);
        add(params, 'vmess-aead', node.protocolOptions?.vmess_aead ?? node.protocolOptions?.aead);
        add(params, 'tls', Boolean(node.tls));
        if (node.transport?.type === 'ws') {
            add(params, 'ws', true);
            add(params, 'ws-path', node.transport.path);
            add(params, 'ws-headers', encodeHeaders(node.transport.headers));
        }
    } else if (node.protocol === 'trojan') {
        add(params, 'password', node.credentials?.password);
        if (node.transport?.type === 'ws') {
            add(params, 'ws', true);
            add(params, 'ws-path', node.transport.path);
            add(params, 'ws-headers', encodeHeaders(node.transport.headers));
        }
    } else if (node.protocol === 'hysteria2') {
        add(params, 'password', node.credentials?.password);
    } else if (node.protocol === 'tuic') {
        const o = node.protocolOptions || {};
        if (o.token && !node.credentials?.uuid) add(params, 'token', o.token);
        else {
            add(params, 'uuid', node.credentials?.uuid);
            add(params, 'password', node.credentials?.password);
        }
        add(params, 'alpn', join(node.tls?.alpn));
    } else if (node.protocol === 'anytls') {
        add(params, 'password', node.credentials?.password);
        if (node.protocolOptions?.reuse !== undefined) add(params, 'reuse', node.protocolOptions.reuse);
    } else if (node.protocol === 'snell') {
        add(params, 'psk', node.credentials?.psk);
        add(params, 'version', node.protocolOptions?.version);
        add(params, 'reuse', node.protocolOptions?.reuse);
        if (node.obfs?.type) add(params, 'obfs', node.obfs.type);
    } else if (node.protocol === 'ssh') {
        add(params, 'username', node.credentials?.user ?? node.credentials?.username);
        add(params, 'password', node.credentials?.password);
        add(params, 'private-key', node.credentials?.private_key);
    } else if (node.protocol === 'socks') {
        add(params, 'username', node.credentials?.username);
        add(params, 'udp-relay', node.protocolOptions?.udp_relay ?? node.protocolOptions?.udp);

        add(params, 'password', node.credentials?.password);
    } else if (node.protocol === 'http') {
        add(params, 'username', node.credentials?.username);
        add(params, 'password', node.credentials?.password);
    }

    return {
        name,
        type,
        line: `${escapeToken(name)} = ${args.concat(params.map(([k, v]) => formatParam(k, v))).join(', ')}`,
        section: '[Proxy]'
    };
}

function surgeType(node) {
    if (node.protocol === 'http') return node.tls ? 'https' : 'http';
    if (node.protocol === 'socks') return node.tls ? 'socks5-tls' : 'socks5';
    if (node.protocol === 'tuic') return node.protocolOptions?.token && !node.credentials?.uuid ? 'tuic' : 'tuic-v5';
    return node.protocol;
}

function buildParameters(node) {
    const params = [];
    const tls = node.tls;
    if (tls) {
        add(params, 'sni', tls.serverName);
        add(params, 'skip-cert-verify', tls.insecure);
        add(params, 'server-cert-verify-name', tls.nameCertVerify);
        add(params, 'server-cert-fingerprint-sha256', tls.pinnedPeerCertSha256);
        add(params, 'alpn', join(tls.alpn));
        add(params, 'client-cert', tls.clientCertificate);
        if (tls.shadowTls) {
            add(params, 'shadow-tls-password', tls.shadowTls.password);
            add(params, 'shadow-tls-version', tls.shadowTls.version);
            add(params, 'shadow-tls-sni', tls.serverName);
        }
    }
    const o = node.protocolOptions || {};
    for (const key of ['interface', 'ip-version', 'tfo', 'test-url', 'test-timeout', 'underlying-proxy']) {
        if (o[key] !== undefined) add(params, key, o[key]);
    }
    return params;
}

function buildWireGuard(node, name) {
    const o = node.protocolOptions || {};
    const sectionName = o.section_name || o.sectionName || name;
    const peers = Array.isArray(o.peers) ? o.peers : [{
        public_key: node.credentials?.peer_public_key,
        endpoint: node.endpoint?.host ? `${node.endpoint.host}:${node.endpoint.port}` : undefined,
        allowed_ips: o.allowed_ips
    }];
    const section = [
        `[WireGuard ${escapeSection(sectionName)}]`,
        `private-key = ${node.credentials?.private_key || ''}`,
        `self-ip = ${stripCidr(o.local_address || o.address || '')}`,
        o.local_address_v6 || o.ipv6 ? `self-ip-v6 = ${stripCidr(o.local_address_v6 || o.ipv6)}` : '',
        o.dns_server || o.dns ? `dns-server = ${join(o.dns_server || o.dns)}` : '',
        o.mtu !== undefined ? `mtu = ${o.mtu}` : '',
        `peer = ${peers.filter(Boolean).map(peer => {
            const fields = [];
            if (peer.public_key || peer.publicKey) fields.push(`public-key = ${peer.public_key || peer.publicKey}`);
            if (peer.endpoint) fields.push(`endpoint = ${peer.endpoint}`);
            if (peer.allowed_ips || peer.allowedIPs) fields.push(`allowed-ips = ${quoteIfComma(join(peer.allowed_ips || peer.allowedIPs))}`);
            if (peer.pre_shared_key || peer.preshared_key) fields.push(`preshared-key = ${peer.pre_shared_key || peer.preshared_key}`);
            if (peer.keepalive !== undefined) fields.push(`keepalive = ${peer.keepalive}`);
            if (peer.client_id || peer.clientId) fields.push(`client-id = ${peer.client_id || peer.clientId}`);
            return `(${fields.join(', ')})`;
        }).join(', ')}`
    ].filter(Boolean).join('\\n');

    return {
        name,
        type: 'wireguard',
        line: `${escapeToken(name)} = wireguard, section-name=${escapeToken(sectionName)}`,
        section
    };
}

function add(list, key, value) {
    if (value !== undefined && value !== null && value !== '') list.push([key, value]);
}

function encodeHeaders(headers) {
    if (!headers || typeof headers !== 'object') return undefined;
    return Object.entries(headers).map(([k, v]) => `${k}:${v}`).join('|');
}

function join(value) {
    return Array.isArray(value) ? value.join(',') : value;
}

function formatParam(key, value) {
    const rendered = String(value);
    return rendered.includes(',') ? `${key}="${rendered.replace(/"/g, '\\"')}"` : `${key}=${rendered}`;
}

function escapeToken(value) {
    return String(value).replace(/[,=]/g, '_');
}

function stripCidr(value) { return String(value || '').split('/')[0]; }\n\nfunction quoteIfComma(value) { return String(value).includes(',') ? `"${String(value).replace(/"/g, '\\\"')}"` : value; }\n\nfunction escapeSection(value) {
    return String(value).replace(/[\\\n\r]/g, '_');
}
