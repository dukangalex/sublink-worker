import { explainConversion } from '../capabilityMatrix.js';

export function toSingBox(node) {
    const check = explainConversion(node, 'singbox');
    if (!check.supported) throw new Error(check.reasons.join('; '));

    const out = {
        type: node.protocol,
        tag: node.name,
        server: node.endpoint.host,
        server_port: node.endpoint.port
    };

    applyProtocolFields(out, node);

    if (node.tls || node.reality) {
        out.tls = toSingBoxTls(node.tls, node.reality);
    }
    if (node.transport) out.transport = toSingBoxTransport(node.transport);
    if (node.protocol === 'hysteria' || node.protocol === 'hysteria2') {
        if (node.obfs) out.obfs = toSingBoxObfs(node.obfs);
    }

    return prune(out);
}

function applyProtocolFields(out, node) {
    const c = node.credentials || {};
    const o = node.protocolOptions || {};

    switch (node.protocol) {
        case 'shadowsocks':
            out.method = c.method;
            out.password = c.password;
            out.plugin = o.plugin;
            out.plugin_opts = o.plugin_opts;
            out.network = o.network;
            out.udp_over_tcp = o.udp_over_tcp;
            out.multiplex = o.multiplex;
            break;
        case 'vmess':
            out.uuid = c.uuid;
            out.security = o.security || o.cipher || 'auto';
            out.alter_id = o.alter_id ?? 0;
            out.global_padding = o.global_padding;
            out.authenticated_length = o.authenticated_length;
            out.network = o.network || 'tcp';
            out.packet_encoding = o.packet_encoding;
            out.multiplex = o.multiplex;
            break;
        case 'vless':
            out.uuid = c.uuid;
            out.flow = o.flow;
            out.network = o.network || 'tcp';
            out.packet_encoding = o.packet_encoding;
            out.multiplex = o.multiplex;
            break;
        case 'trojan':
            out.password = c.password;
            out.network = o.network || 'tcp';
            out.multiplex = o.multiplex;
            break;
        case 'hysteria':
            out.password = c.password;
            out.auth = o.auth;
            out.auth_str = o.auth_str;
            out.up = o.up;
            out.up_mbps = o.up_mbps;
            out.down = o.down;
            out.down_mbps = o.down_mbps;
            out.network = o.network;
            break;
        case 'hysteria2':
            out.password = c.password;
            out.up_mbps = o.up_mbps ?? o.up;
            out.down_mbps = o.down_mbps ?? o.down;
            out.network = o.network;
            break;
        case 'tuic':
            out.uuid = c.uuid;
            out.password = c.password;
            out.congestion_control = o.congestion_control;
            out.udp_relay_mode = o.udp_relay_mode;
            out.zero_rtt_handshake = o.zero_rtt_handshake;
            out.heartbeat = o.heartbeat;
            break;
        case 'anytls':
            out.password = c.password;
            out.idle_session_check_interval = o.idle_session_check_interval;
            out.idle_session_timeout = o.idle_session_timeout;
            out.min_idle_session = o.min_idle_session;
            break;
        case 'naive':
            out.username = c.username;
            out.password = c.password;
            out.insecure_concurrency = o.insecure_concurrency;
            out.extra_headers = o.extra_headers;
            out.quic = o.quic;
            out.udp_over_tcp = o.udp_over_tcp;
            break;
        case 'snell':
            out.psk = c.psk;
            out.version = o.version;
            out.udp = o.udp;
            break;
        case 'ssh':
            out.user = c.user;
            out.password = c.password;
            out.private_key = c.private_key;
            out.private_key_passphrase = o.private_key_passphrase;
            break;
        case 'socks':
        case 'http':
            out.username = c.username;
            out.password = c.password;
            break;
        case 'wireguard':
            throw new Error('WireGuard requires the dedicated sing-box endpoint format; the legacy outbound is deprecated and should not be emitted by this adapter.');
        default:
            throw new Error(`No explicit sing-box adapter mapping for protocol: ${node.protocol}`);
    }
}

function toSingBoxTls(tls = {}, reality) {
    const out = {
        enabled: tls.enabled !== false,
        server_name: tls.serverName,
        insecure: tls.insecure,
        alpn: tls.alpn
    };

    if (tls.clientFingerprint || tls.fingerprint) {
        out.utls = { enabled: true, fingerprint: tls.clientFingerprint ?? tls.fingerprint };
    }
    if (tls.certificate) out.client_certificate = Array.isArray(tls.certificate) ? tls.certificate : [tls.certificate];
    if (tls.privateKey) out.client_key = Array.isArray(tls.privateKey) ? tls.privateKey : [tls.privateKey];

    if (reality) {
        out.reality = {
            enabled: true,
            public_key: reality.publicKey,
            short_id: reality.shortId
        };
    }

    return out;
}

function toSingBoxTransport(transport) {
    const type = String(transport.type || '').toLowerCase();

    switch (type) {
        case 'http':
            return {
                type,
                host: toStringArray(transport.host),
                path: transport.path,
                method: transport.method,
                headers: transport.headers,
                idle_timeout: transport.idle_timeout,
                ping_timeout: transport.ping_timeout
            };
        case 'ws':
            return {
                type,
                path: transport.path,
                headers: transport.headers,
                max_early_data: transport.max_early_data,
                early_data_header_name: transport.early_data_header_name
            };
        case 'quic':
            return { type };
        case 'grpc':
            return {
                type,
                service_name: transport.serviceName,
                idle_timeout: transport.idle_timeout,
                ping_timeout: transport.ping_timeout,
                permit_without_stream: transport.permit_without_stream
            };
        case 'httpupgrade':
            return {
                type,
                host: transport.host,
                path: transport.path,
                headers: transport.headers
            };
        default:
            throw new Error(`Unsupported sing-box transport type: ${transport.type}`);
    }
}

function toSingBoxObfs(obfs) {
    return {
        type: obfs.type,
        password: obfs.password,
        min_packet_size: obfs.min_packet_size,
        max_packet_size: obfs.max_packet_size
    };
}

function toStringArray(value) {
    if (value === undefined) return undefined;
    return Array.isArray(value) ? value : [value];
}

function prune(value) {
    if (Array.isArray(value)) return value.map(prune);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => [k, prune(v)]));
}
