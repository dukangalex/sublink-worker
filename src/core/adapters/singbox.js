import { explainConversion } from '../capabilityMatrix.js';

export function toSingBox(node) {
    const check = explainConversion(node, 'singbox');
    if (!check.supported) throw new Error(check.reasons.join('; '));

    const out = {
        type: node.protocol,
        tag: node.name,
        server: node.endpoint.host,
        server_port: node.endpoint.port,
        ...node.protocolOptions
    };

    Object.assign(out, node.credentials);
    if (node.protocol === 'wireguard') return toSingBoxWireguard(node);
    if (node.tls) out.tls = toSingBoxTls(node.tls);
    if (node.transport) out.transport = { ...node.transport };
    if (node.obfs) out.obfs = { ...node.obfs };
    if (node.reality) out.reality = { ...node.reality };
    return prune(out);
}

function toSingBoxWireguard(node) {
    const o = node.protocolOptions || {};
    return prune({
        type: 'wireguard', tag: node.name, server: node.endpoint.host, server_port: node.endpoint.port,
        local_address: o.local_address, private_key: node.credentials.private_key,
        peers: (o.peers || []).map(peer => prune({ address: peer.address, port: peer.port, public_key: peer.publicKey, pre_shared_key: peer.preSharedKey, allowed_ips: peer.allowedIPs, persistent_keepalive_interval: peer.persistentKeepalive, reserved: peer.reserved })),
        mtu: o.mtu, network: o.network
    });
}

function toSingBoxTls(tls) {
    const out = {
        enabled: tls.enabled !== false,
        server_name: tls.serverName,
        insecure: tls.insecure,
        alpn: tls.alpn
    };
    if (tls.clientFingerprint || tls.fingerprint) {
        out.utls = { enabled: true, fingerprint: tls.clientFingerprint ?? tls.fingerprint };
    }
    if (tls.ech) out.ech = tls.ech;
    return out;
}

function prune(value) {
    if (Array.isArray(value)) return value.map(prune);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => [k, prune(v)]));
}
