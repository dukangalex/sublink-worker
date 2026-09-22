import { createProxyNode } from './ProxyNode.js';

export function normalizeProxy(input) {
    if (!input || typeof input !== 'object') throw new TypeError('Proxy node must be an object');

    const normalized = {
        ...input,
        protocol: input.protocol || input.type,
        endpoint: {
            ...(input.endpoint || {}),
            host: input.endpoint?.host ?? input.server ?? '',
            port: input.endpoint?.port ?? input.server_port ?? input.port ?? 0
        },
        tls: normalizeTls(input),
        transport: normalizeTransport(input),
        reality: normalizeReality(input),
        protocolOptions: normalizeProtocolOptions(input)
    };

    return createProxyNode(normalized);
}

export function normalizeProxies(inputs = []) {
    return inputs.filter(Boolean).map(normalizeProxy);
}

function normalizeTls(input) {
    const source = input.tls && typeof input.tls === 'object' ? input.tls : {};
    const hasTls = input.tls !== undefined || Object.keys(source).length > 0 ||
        input.servername !== undefined || input.sni !== undefined ||
        input.server_name !== undefined || input.skip_cert_verify !== undefined ||
        input.client_fingerprint !== undefined || input.clientFingerprint !== undefined;

    if (!hasTls) return undefined;

    const tls = {
        ...source,
        enabled: source.enabled !== false && input.tls !== false,
        serverName: firstDefined(
            source.serverName,
            source.server_name,
            input.serverName,
            input.servername,
            input.server_name,
            input.sni
        ),
        insecure: firstDefined(source.insecure, source.skip_cert_verify, input.skip_cert_verify),
        alpn: source.alpn,
        fingerprint: firstDefined(source.fingerprint, source.utls?.fingerprint, input.fingerprint),
        clientFingerprint: firstDefined(
            source.clientFingerprint,
            source.client_fingerprint,
            input.clientFingerprint,
            input.client_fingerprint
        ),
        ech: source.ech
    };

    return pruneAliases(tls, [
        'server_name', 'servername', 'server_name',
        'skip_cert_verify', 'client_fingerprint', 'utls'
    ]);
}

function normalizeTransport(input) {
    if (input.transport && typeof input.transport === 'object') {
        return normalizeTransportObject(input.transport);
    }

    const type = input.network || input.transport_type;
    if (!type) return undefined;

    const key = String(type).toLowerCase();
    const options = input[key + '_opts'] || {};
    return normalizeTransportObject({ type: key, ...options });
}

function normalizeTransportObject(transport) {
    const type = transport.type || transport.network;
    const source = transport;
    const aliases = {
        serviceName: ['serviceName', 'service_name', 'service-name'],
        multiMode: ['multiMode', 'multi_mode', 'multi-mode'],
        userAgent: ['userAgent', 'user_agent', 'grpcUserAgent', 'grpc-user-agent'],
        authority: ['authority', 'grpcAuthority', 'grpc-authority'],
        idleTimeout: ['idleTimeout', 'idle_timeout', 'idle-timeout'],
        healthCheckTimeout: ['healthCheckTimeout', 'health_check_timeout', 'health-check-timeout'],
        permitWithoutStream: ['permitWithoutStream', 'permit_without_stream', 'permit-without-stream'],
        initialWindowsSize: ['initialWindowsSize', 'initial_windows_size', 'initial-windows-size'],
        pingInterval: ['pingInterval', 'ping_interval', 'ping-interval'],
        maxConnections: ['maxConnections', 'max_connections', 'max-connections'],
        minStreams: ['minStreams', 'min_streams', 'min-streams'],
        maxStreams: ['maxStreams', 'max_streams', 'max-streams'],
        maxEarlyData: ['maxEarlyData', 'max_early_data', 'max-early-data'],
        earlyDataHeaderName: ['earlyDataHeaderName', 'early_data_header_name', 'early-data-header-name'],
        v2rayHttpUpgrade: ['v2rayHttpUpgrade', 'v2ray_http_upgrade', 'v2ray-http-upgrade'],
        v2rayHttpUpgradeFastOpen: ['v2rayHttpUpgradeFastOpen', 'v2ray_http_upgrade_fast_open', 'v2ray-http-upgrade-fast-open'],
        acceptProxyProtocol: ['acceptProxyProtocol', 'accept_proxy_protocol', 'accept-proxy-protocol'],
        noGrpcHeader: ['noGrpcHeader', 'no_grpc_header', 'no-grpc-header'],
        xPaddingBytes: ['xPaddingBytes', 'x_padding_bytes', 'x-padding-bytes'],
        xPaddingObfsMode: ['xPaddingObfsMode', 'x_padding_obfs_mode', 'x-padding-obfs-mode'],
        xPaddingKey: ['xPaddingKey', 'x_padding_key', 'x-padding-key'],
        xPaddingHeader: ['xPaddingHeader', 'x_padding_header', 'x-padding-header'],
        xPaddingPlacement: ['xPaddingPlacement', 'x_padding_placement', 'x-padding-placement'],
        xPaddingMethod: ['xPaddingMethod', 'x_padding_method', 'x-padding-method'],
        uplinkHttpMethod: ['uplinkHttpMethod', 'uplink_http_method', 'uplink-http-method'],
        sessionPlacement: ['sessionPlacement', 'session_placement', 'session-placement'],
        sessionKey: ['sessionKey', 'session_key', 'session-key'],
        sessionTable: ['sessionTable', 'session_table', 'session-table'],
        sessionLength: ['sessionLength', 'session_length', 'session-length'],
        seqPlacement: ['seqPlacement', 'seq_placement', 'seq-placement'],
        seqKey: ['seqKey', 'seq_key', 'seq-key'],
        uplinkDataPlacement: ['uplinkDataPlacement', 'uplink_data_placement', 'uplink-data-placement'],
        uplinkDataKey: ['uplinkDataKey', 'uplink_data_key', 'uplink-data-key'],
        uplinkChunkSize: ['uplinkChunkSize', 'uplink_chunk_size', 'uplink-chunk-size'],
        scMaxEachPostBytes: ['scMaxEachPostBytes', 'sc_max_each_post_bytes', 'sc-max-each-post-bytes'],
        scMinPostsIntervalMs: ['scMinPostsIntervalMs', 'sc_min_posts_interval_ms', 'sc-min-posts-interval-ms'],
        reuseSettings: ['reuseSettings', 'reuse_settings', 'reuse-settings'],
        downloadSettings: ['downloadSettings', 'download_settings', 'download-settings'],
        mtu: ['mtu'],
        tti: ['tti'],
        uplinkCapacity: ['uplinkCapacity', 'uplink_capacity', 'uplink-capacity'],
        downlinkCapacity: ['downlinkCapacity', 'downlink_capacity', 'downlink-capacity'],
        cwndMultiplier: ['cwndMultiplier', 'cwnd_multiplier', 'cwnd-multiplier'],
        maxSendingWindow: ['maxSendingWindow', 'max_sending_window', 'max-sending-window'],
        congestion: ['congestion'],
        writeBuffer: ['writeBuffer', 'write_buffer', 'write-buffer'],
        readBuffer: ['readBuffer', 'read_buffer', 'read-buffer'],
        seed: ['seed'],
        header: ['header']
    };

    const out = {
        ...source,
        ...(type ? { type: String(type).toLowerCase() } : {}),
        path: source.path,
        headers: source.headers,
        host: source.host
    };

    for (const [canonical, keys] of Object.entries(aliases)) {
        const value = firstDefined(...keys.map(key => source[key]));
        if (value !== undefined) out[canonical] = value;
    }

    if (out.reuseSettings && typeof out.reuseSettings === 'object') {
        out.reuseSettings = normalizeXhttpReuseSettings(out.reuseSettings);
    }
    if (out.downloadSettings && typeof out.downloadSettings === 'object') {
        out.downloadSettings = normalizeXhttpDownloadSettings(out.downloadSettings);
    }

    return pruneAliases(out, Object.values(aliases).flat().filter(key => !Object.values(aliases).some(keys => keys[0] === key)));
}

function normalizeXhttpReuseSettings(value) {
    return normalizeFieldAliases(value, {
        maxConcurrency: ['maxConcurrency', 'max_concurrency', 'max-concurrency'],
        maxConnections: ['maxConnections', 'max_connections', 'max-connections'],
        cMaxReuseTimes: ['cMaxReuseTimes', 'c_max_reuse_times', 'c-max-reuse-times'],
        hMaxRequestTimes: ['hMaxRequestTimes', 'h_max_request_times', 'h-max-request-times'],
        hMaxReusableSecs: ['hMaxReusableSecs', 'h_max_reusable_secs', 'h-max-reusable-secs'],
        hKeepAlivePeriod: ['hKeepAlivePeriod', 'h_keep_alive_period', 'h-keep-alive-period']
    });
}

function normalizeXhttpDownloadSettings(value) {
    const out = { ...value };
    if (value.reuseSettings || value.reuse_settings || value['reuse-settings']) {
        out.reuseSettings = normalizeXhttpReuseSettings(value.reuseSettings ?? value.reuse_settings ?? value['reuse-settings']);
        delete out.reuse_settings;
        delete out['reuse-settings'];
    }
    return out;
}

function normalizeFieldAliases(value, aliases) {
    const out = { ...value };
    for (const [canonical, keys] of Object.entries(aliases)) {
        const resolved = firstDefined(...keys.map(key => value[key]));
        if (resolved !== undefined) out[canonical] = resolved;
        for (const key of keys) if (key !== canonical) delete out[key];
    }
    return out;
}

function normalizeReality(input) {
    const source = input.reality && typeof input.reality === 'object'
        ? input.reality
        : input.reality_opts || input.realityOpts;

    if (!source) return undefined;

    return pruneAliases({
        ...source,
        publicKey: firstDefined(source.publicKey, source.public_key, source.password),
        shortId: firstDefined(source.shortId, source.short_id),
        serverName: firstDefined(source.serverName, source.server_name, source.servername),
        fingerprint: firstDefined(source.fingerprint, source.clientFingerprint, source.client_fingerprint),
        mldsa65Verify: firstDefined(source.mldsa65Verify, source.mldsa65_verify),
        spiderX: firstDefined(source.spiderX, source.spider_x)
    }, [
        'public_key', 'short_id', 'server_name', 'servername',
        'client_fingerprint', 'mldsa65_verify', 'spider_x', 'password'
    ]);
}

function normalizeProtocolOptions(input) {
    const options = { ...(input.protocolOptions || {}) };
    const aliases = {
        'packet-encoding': 'packet_encoding',
        packetEncoding: 'packet_encoding',
        alterId: 'alter_id',
        flow: 'flow',
        'flow-control': 'flow_control',
        flowControl: 'flow_control'
    };

    for (const [from, to] of Object.entries(aliases)) {
        if (input[from] !== undefined && options[to] === undefined) options[to] = input[from];
    }

    const reserved = new Set([
        'endpoint', 'server', 'server_port', 'port', 'protocol', 'type',
        'tag', 'name', 'tls', 'servername', 'serverName', 'server_name', 'sni',
        'skip_cert_verify', 'fingerprint', 'client_fingerprint', 'clientFingerprint',
        'transport', 'transport_type', 'network',
        'reality', 'reality_opts', 'realityOpts',
        'credentials', 'protocolOptions'
    ]);

    return Object.fromEntries(
        Object.entries({ ...input, ...options }).filter(([key]) => !reserved.has(key))
    );
}
\nfunction normalizeWireguardPeers(peers, input) {
    const source = Array.isArray(peers) ? peers : [];
    if (source.length) return source.map(normalizeWireguardPeer);

    const peer = {
        server: input.server,
        port: input.server_port ?? input.port,
        publicKey: input.peer_public_key ?? input.public_key ?? input['public-key'],
        preSharedKey: input.pre_shared_key ?? input['pre-shared-key'],
        allowedIPs: input.allowed_ips ?? input['allowed-ips'],
        reserved: input.reserved,
        persistentKeepalive: input.persistent_keepalive ?? input['persistent-keepalive']
    };
    return peer.publicKey || peer.server ? [normalizeWireguardPeer(peer)] : [];
}

function normalizeWireguardPeer(peer = {}) {
    return {
        ...peer,
        address: firstDefined(peer.address, peer.server),
        port: firstDefined(peer.port, peer.server_port),
        publicKey: firstDefined(peer.publicKey, peer.public_key, peer['public-key']),
        preSharedKey: firstDefined(peer.preSharedKey, peer.pre_shared_key, peer['pre-shared-key']),
        allowedIPs: firstDefined(peer.allowedIPs, peer.allowed_ips, peer['allowed-ips']),
        persistentKeepalive: firstDefined(
            peer.persistentKeepalive,
            peer.persistent_keepalive,
            peer['persistent-keepalive'],
            peer.keepAlive,
            peer.keepalive
        )
    };
}

function firstDefined(...values) {
    return values.find(value => value !== undefined);
}

function pruneAliases(value, aliases) {
    const out = { ...value };
    for (const key of aliases) delete out[key];
    return out;
}
