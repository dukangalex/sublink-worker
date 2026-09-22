import { explainConversion } from '../capabilityMatrix.js';

export function toClash(node) {
    const check = explainConversion(node, 'clash');
    if (!check.supported) throw new Error(check.reasons.join('; '));

    const base = {
        name: node.name,
        type: clashType(node.protocol),
        server: node.endpoint.host,
        port: node.endpoint.port
    };

    switch (node.protocol) {
        case 'shadowsocks':
            return prune({
                ...base,
                cipher: node.credentials.method,
                password: node.credentials.password,
                udp: node.protocolOptions.udp ?? true,
                ...(node.protocolOptions.plugin ? { plugin: node.protocolOptions.plugin } : {}),
                ...(node.protocolOptions.plugin_opts ? { 'plugin-opts': node.protocolOptions.plugin_opts } : {})
            });
        case 'vmess':
            return buildVmess(base, node);
        case 'vless':
            return buildVless(base, node);
        case 'trojan':
            return buildTlsProxy(base, node, { password: node.credentials.password });
        case 'hysteria':
        case 'hysteria2':
            return buildHysteria(base, node);
        case 'tuic':
            return prune({
                ...base,
                uuid: node.credentials.uuid,
                password: node.credentials.password,
                'congestion-controller': node.protocolOptions.congestion_control,
                'udp-relay-mode': node.protocolOptions.udp_relay_mode || 'native',
                'skip-cert-verify': Boolean(node.tls?.insecure),
                sni: node.tls?.serverName,
                alpn: node.tls?.alpn,
                'zero-rtt': node.protocolOptions.zero_rtt,
                'reduce-rtt': node.protocolOptions.reduce_rtt
            });
        case 'wireguard':
            return buildWireguard(base, node);
        case 'anytls':
            return buildTlsProxy(base, node, {
                password: node.credentials.password,
                'client-fingerprint': node.tls?.clientFingerprint,
                'idle-session-check-interval': node.protocolOptions.idle_session_check_interval,
                'idle-session-timeout': node.protocolOptions.idle_session_timeout,
                'min-idle-session': node.protocolOptions.min_idle_session
            });
        case 'naive':
            return prune({
                ...base,
                username: node.credentials.username,
                password: node.credentials.password,
                quic: node.protocolOptions.quic,
                insecure: node.protocolOptions.insecure_concurrency,
                'extra-headers': node.protocolOptions.extra_headers,
                sni: node.tls?.serverName,
                'skip-cert-verify': Boolean(node.tls?.insecure)
            });
        case 'snell':
            return prune({
                ...base,
                psk: node.credentials.psk,
                version: node.protocolOptions.version,
                'obfs-opts': node.obfs || node.protocolOptions.obfs_opts,
                udp: node.protocolOptions.udp,
                reuse: node.protocolOptions.reuse
            });
        case 'ssh':
            return prune({
                ...base,
                user: node.credentials.user,
                password: node.credentials.password,
                'private-key': node.protocolOptions.private_key,
                'private-key-passphrase': node.protocolOptions.private_key_passphrase,
                'host-key': node.protocolOptions.host_key,
                'private-key-path': node.protocolOptions.private_key_path,
                'set-system-proxy': node.protocolOptions.set_system_proxy
            });
        case 'socks':
        case 'http':
            return prune({
                ...base,
                username: node.credentials.username,
                password: node.credentials.password,
                tls: Boolean(node.tls),
                servername: node.tls?.serverName,
                'skip-cert-verify': Boolean(node.tls?.insecure)
            });
        default:
            return prune({ ...base, ...node.protocolOptions, ...node.credentials });
    }
}

function buildVmess(base, node) {
    const out = {
        ...base,
        uuid: node.credentials.uuid,
        alterId: node.protocolOptions.alter_id ?? 0,
        cipher: node.protocolOptions.security || 'auto',
        tls: Boolean(node.tls),
        servername: node.tls?.serverName,
        'client-fingerprint': node.tls?.clientFingerprint,
        'skip-cert-verify': Boolean(node.tls?.insecure),
        network: node.transport?.type || 'tcp',
        udp: node.protocolOptions.udp ?? true
    };
    return applyTransport(out, node.transport);
}

function buildVless(base, node) {
    const out = {
        ...base,
        uuid: node.credentials.uuid,
        flow: node.protocolOptions.flow,
        'packet-encoding': node.protocolOptions.packet_encoding,
        tls: Boolean(node.tls),
        servername: node.tls?.serverName,
        'client-fingerprint': node.tls?.clientFingerprint,
        'skip-cert-verify': Boolean(node.tls?.insecure),
        network: node.transport?.type || 'tcp',
        udp: node.protocolOptions.udp ?? true
    };
    if (node.reality || node.tls?.reality) {
        const reality = node.reality || node.tls.reality;
        out['reality-opts'] = {
            'public-key': reality.public_key ?? reality.publicKey,
            'short-id': reality.short_id ?? reality.shortId
        };
    }
    return applyTransport(out, node.transport);
}

function buildTlsProxy(base, node, extra = {}) {
    const out = {
        ...base,
        ...extra,
        tls: true,
        sni: node.tls?.serverName,
        'skip-cert-verify': Boolean(node.tls?.insecure),
        'client-fingerprint': node.tls?.clientFingerprint,
        alpn: node.tls?.alpn,
        udp: node.protocolOptions.udp ?? true
    };
    if (node.transport?.type) {
        out.network = node.transport.type;
        applyTransport(out, node.transport);
    }
    return out;
}

function buildHysteria(base, node) {
    return prune({
        ...base,
        password: node.credentials.password,
        auth: node.protocolOptions.auth,
        'auth-str': node.protocolOptions.auth_str,
        up: node.protocolOptions.up,
        down: node.protocolOptions.down,
        obfs: node.obfs?.type || node.protocolOptions.obfs,
        'obfs-password': node.obfs?.password || node.protocolOptions.obfs_password,
        sni: node.tls?.serverName,
        'skip-cert-verify': Boolean(node.tls?.insecure),
        alpn: node.tls?.alpn
    });
}

function buildWireguard(base, node) {
    const peers = node.protocolOptions.peers?.length ? node.protocolOptions.peers.map(peer => prune({ server: peer.address, port: peer.port, 'public-key': peer.publicKey, 'pre-shared-key': peer.preSharedKey, 'allowed-ips': peer.allowedIPs, reserved: peer.reserved })) : [{
        server: base.server,
        port: base.port,
        'public-key': node.credentials.peer_public_key,
        'pre-shared-key': node.credentials.pre_shared_key,
        'allowed-ips': node.protocolOptions.allowed_ips || ['0.0.0.0/0'],
        reserved: node.protocolOptions.reserved
    }];

    return prune({
        name: base.name,
        type: 'wireguard',
        ip: firstAddress(node.protocolOptions.local_address),
        ipv6: node.protocolOptions.ipv6,
        'private-key': node.credentials.private_key,
        peers,
        mtu: node.protocolOptions.mtu,
        udp: node.protocolOptions.udp ?? true,
        'remote-dns-resolve': node.protocolOptions.remote_dns_resolve,
        dns: node.protocolOptions.dns
    });
}

function applyTransport(out, transport) {
    if (!transport?.type) return out;
    const type = transport.type;
    if (type === 'ws') {
        out['ws-opts'] = {
            path: transport.path,
            headers: transport.headers
        };
    } else if (type === 'http') {
        out['http-opts'] = {
            method: transport.method || 'GET',
            path: Array.isArray(transport.path) ? transport.path : [transport.path || '/'],
            headers: transport.headers
        };
    } else if (type === 'h2') {
        out['h2-opts'] = {
            path: transport.path,
            host: transport.host
        };
    } else if (type === 'grpc') {
        out['grpc-opts'] = {
            'grpc-service-name': transport.service_name
        };
    } else if (type === 'xhttp') {
        out['xhttp-opts'] = transport.xhttp_opts || transport.options;
    }
    return out;
}

function clashType(protocol) {
    return protocol === 'shadowsocks' ? 'ss' : protocol;
}

function firstAddress(address) {
    return Array.isArray(address) ? address[0] : address;
}

function prune(value) {
    if (Array.isArray(value)) return value.map(prune);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(
        Object.entries(value)
            .filter(([, v]) => v !== undefined)
            .map(([k, v]) => [k, prune(v)])
    );
}
