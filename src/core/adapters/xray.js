import { explainConversion } from '../capabilityMatrix.js';

export function toXray(node) {
    const check = explainConversion(node, 'xray');
    if (!check.supported) throw new Error(check.reasons.join('; '));

    const streamSettings = buildStreamSettings(node);
    const out = {
        tag: node.name,
        protocol: xrayProtocol(node.protocol),
        settings: buildSettings(node)
    };
    if (streamSettings) out.streamSettings = streamSettings;
    if (node.protocolOptions?.mux) out.mux = normalizeMux(node.protocolOptions.mux);
    return prune(out);
}

function xrayProtocol(protocol) {
    if (protocol === 'shadowsocks') return 'shadowsocks';
    if (protocol === 'socks') return 'socks';
    if (protocol === 'http') return 'http';
    if (protocol === 'wireguard') return 'wireguard';
    return protocol;
}

function buildSettings(node) {
    const c = node.credentials || {};
    const o = node.protocolOptions || {};
    switch (node.protocol) {
        case 'shadowsocks':
            return { servers: [{ address: node.endpoint.host, port: node.endpoint.port, method: c.method, password: c.password }] };
        case 'vmess':
            return { vnext: [{ address: node.endpoint.host, port: node.endpoint.port, users: [{ id: c.uuid, alterId: o.alter_id ?? o.alterId ?? 0, security: o.cipher || 'auto' }] }] };
        case 'vless':
            return { vnext: [{ address: node.endpoint.host, port: node.endpoint.port, users: [{ id: c.uuid, encryption: o.encryption || 'none', flow: c.flow || o.flow }] }] };
        case 'trojan':
            return { servers: [{ address: node.endpoint.host, port: node.endpoint.port, password: c.password }] };
        case 'socks':
            return { servers: [{ address: node.endpoint.host, port: node.endpoint.port, users: c.username || c.password ? [{ user: c.username, pass: c.password }] : [] }] };
        case 'http':
            return { servers: [{ address: node.endpoint.host, port: node.endpoint.port, users: c.username || c.password ? [{ user: c.username, pass: c.password }] : [] }] };
        case 'wireguard':
            return { secretKey: c.private_key, address: o.local_address || o.address, peers: o.peers || [] };
        case 'hysteria':
        case 'hysteria2':
            return { address: node.endpoint.host, port: node.endpoint.port, password: c.password };
        default:
            return { address: node.endpoint.host, port: node.endpoint.port, ...o };
    }
}

function buildStreamSettings(node) {
    const t = node.transport || {};
    const tls = node.tls;
    const reality = node.reality;
    const out = {};
    if (t.type) {
        const network = t.type === 'ws' ? 'ws' : t.type === 'grpc' ? 'grpc' : t.type === 'httpupgrade' ? 'httpupgrade' : t.type === 'mkcp' ? 'kcp' : t.type === 'xhttp' ? 'xhttp' : 'tcp';
        out.network = network;
        if (network === 'ws') out.wsSettings = pick(t, ['path', 'headers']);
        if (network === 'grpc') out.grpcSettings = pick(t, ['serviceName', 'multiMode']);
        if (network === 'httpupgrade') out.httpupgradeSettings = pick(t, ['host', 'path']);
        if (network === 'xhttp') out.xhttpSettings = { ...t };
        if (network === 'kcp') out.kcpSettings = { ...t };
    }
    if (tls || reality) {
        out.security = reality ? 'reality' : 'tls';
        if (reality) {
            out.realitySettings = {
                serverName: reality.serverName ?? tls?.serverName,
                fingerprint: reality.fingerprint ?? tls?.clientFingerprint ?? tls?.fingerprint,
                password: reality.publicKey ?? reality.public_key,
                shortId: reality.shortId ?? reality.short_id,
                mldsa65Verify: reality.mldsa65Verify,
                spiderX: reality.spiderX
            };
        } else {
            out.tlsSettings = tls ? {
                serverName: tls.serverName,
                allowInsecure: tls.insecure,
                alpn: tls.alpn,
                fingerprint: tls.clientFingerprint ?? tls.fingerprint
            } : {};
        }
    }
    return Object.keys(out).length ? out : undefined;
}

function normalizeMux(mux) {
    return typeof mux === 'object' ? mux : { enabled: Boolean(mux) };
}

function pick(source, keys) {
    return Object.fromEntries(keys.filter(k => source[k] !== undefined).map(k => [k, source[k]]));
}

function prune(value) {
    if (Array.isArray(value)) return value.map(prune);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => [k, prune(v)]));
}
