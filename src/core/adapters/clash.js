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
            throw new Error(`No explicit Mihomo adapter mapping for protocol: ${node.protocol}`);
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
        fingerprint: node.tls?.fingerprint,
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
        alpn: node.tls?.alpn,
        fingerprint: node.tls?.fingerprint,
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
        fingerprint: node.tls?.fingerprint,
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
        out['ws-opts'] = prune({
            path: transport.path,
            headers: transport.headers,
            'max-early-data': transport.maxEarlyData,
            'early-data-header-name': transport.earlyDataHeaderName,
            'v2ray-http-upgrade': transport.v2rayHttpUpgrade,
            'v2ray-http-upgrade-fast-open': transport.v2rayHttpUpgradeFastOpen
        });
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
        out['grpc-opts'] = prune({
            'grpc-service-name': transport.serviceName ?? transport.service_name,
            'grpc-user-agent': transport.userAgent ?? transport.grpcUserAgent ?? transport['grpc-user-agent'],
            'ping-interval': transport.pingInterval ?? transport['ping-interval'],
            'max-connections': transport.maxConnections ?? transport['max-connections'],
            'min-streams': transport.minStreams ?? transport['min-streams'],
            'max-streams': transport.maxStreams ?? transport['max-streams']
        });
    } else if (type === 'mkcp') {
        out['mkcp-opts'] = prune({
            mtu: transport.mtu,
            tti: transport.tti,
            'uplink-capacity': transport.uplinkCapacity,
            'downlink-capacity': transport.downlinkCapacity,
            congestion: transport.congestion,
            'write-buffer': transport.writeBuffer,
            'read-buffer': transport.readBuffer,
            seed: transport.seed,
            header: transport.header
        });
    } else if (type === 'mekya') {
        out['mekya-opts'] = prune({
            url: transport.url,
            'max-write-delay': transport.maxWriteDelay,
            'max-request-size': transport.maxRequestSize,
            'polling-interval-initial': transport.pollingIntervalInitial,
            'h2-pool-size': transport.h2PoolSize,
            kcp: transport.kcp
        });
    } else if (type === 'xhttp') {
        out['xhttp-opts'] = prune({
            path: transport.path,
            host: transport.host,
            mode: transport.mode,
            headers: transport.headers,
            'no-grpc-header': transport.noGrpcHeader ?? transport.no_grpc_header ?? transport['no-grpc-header'],
            'x-padding-bytes': transport.xPaddingBytes ?? transport.x_padding_bytes ?? transport['x-padding-bytes'],
            'x-padding-obfs-mode': transport.xPaddingObfsMode ?? transport.x_padding_obfs_mode ?? transport['x-padding-obfs-mode'],
            'x-padding-key': transport.xPaddingKey ?? transport.x_padding_key ?? transport['x-padding-key'],
            'x-padding-header': transport.xPaddingHeader ?? transport.x_padding_header ?? transport['x-padding-header'],
            'x-padding-placement': transport.xPaddingPlacement ?? transport.x_padding_placement ?? transport['x-padding-placement'],
            'x-padding-method': transport.xPaddingMethod ?? transport.x_padding_method ?? transport['x-padding-method'],
            'uplink-http-method': transport.uplinkHttpMethod ?? transport.uplink_http_method ?? transport['uplink-http-method'],
            'session-placement': transport.sessionPlacement ?? transport.session_placement ?? transport['session-placement'],
            'session-key': transport.sessionKey ?? transport.session_key ?? transport['session-key'],
            'session-table': transport.sessionTable ?? transport.session_table ?? transport['session-table'],
            'session-length': transport.sessionLength ?? transport.session_length ?? transport['session-length'],
            'seq-placement': transport.seqPlacement ?? transport.seq_placement ?? transport['seq-placement'],
            'seq-key': transport.seqKey ?? transport.seq_key ?? transport['seq-key'],
            'uplink-data-placement': transport.uplinkDataPlacement ?? transport.uplink_data_placement ?? transport['uplink-data-placement'],
            'uplink-data-key': transport.uplinkDataKey ?? transport.uplink_data_key ?? transport['uplink-data-key'],
            'uplink-chunk-size': transport.uplinkChunkSize ?? transport.uplink_chunk_size ?? transport['uplink-chunk-size'],
            'sc-max-each-post-bytes': transport.scMaxEachPostBytes ?? transport.sc_max_each_post_bytes ?? transport['sc-max-each-post-bytes'],
            'sc-min-posts-interval-ms': transport.scMinPostsIntervalMs ?? transport.sc_min_posts_interval_ms ?? transport['sc-min-posts-interval-ms'],
            'reuse-settings': buildXhttpReuseSettings(transport.reuseSettings),
            'download-settings': buildXhttpDownloadSettings(transport.downloadSettings)
        });
    }
    return out;
}

function buildXhttpReuseSettings(value) {
    if (!value || typeof value !== 'object') return value;
    return prune({
        'max-concurrency': value.maxConcurrency,
        'max-connections': value.maxConnections,
        'c-max-reuse-times': value.cMaxReuseTimes,
        'h-max-request-times': value.hMaxRequestTimes,
        'h-max-reusable-secs': value.hMaxReusableSecs,
        'h-keep-alive-period': value.hKeepAlivePeriod
    });
}

function buildXhttpDownloadSettings(value) {
    if (!value || typeof value !== 'object') return value;
    return prune({
        path: value.path,
        host: value.host,
        headers: value.headers,
        'reuse-settings': buildXhttpReuseSettings(value.reuseSettings)
    });
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
