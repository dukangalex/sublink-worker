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
    return {
        ...transport,
        ...(type ? { type: String(type).toLowerCase() } : {}),
        path: transport.path,
        headers: transport.headers,
        host: transport.host,
        serviceName: transport.serviceName ?? transport.service_name,
        multiMode: transport.multiMode ?? transport.multi_mode
    };
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
