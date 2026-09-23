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
            return buildXrayWireguard(node);
        case 'hysteria2':
            return { version: 2, address: node.endpoint.host, port: node.endpoint.port };
        default:
            throw new Error(`No explicit Xray adapter mapping for protocol: ${node.protocol}`);
    }
}

function buildXrayWireguard(node) {
    const o = node.protocolOptions || {};
    const peers = (o.peers || []).map(peer => prune({
        endpoint: peer.address && peer.port ? peer.address + ':' + peer.port : undefined,
        publicKey: peer.publicKey,
        preSharedKey: peer.preSharedKey,
        keepAlive: peer.persistentKeepalive,
        allowedIPs: peer.allowedIPs
    }));
    return prune({ secretKey: node.credentials.private_key, address: o.local_address, peers, mtu: o.mtu, reserved: o.reserved, remoteDNS: o.remote_dns });
}

function buildStreamSettings(node) {
    const t = node.transport || {};
    const tls = node.tls;
    const reality = node.reality;
    const out = {};

    if (t.type) {
        const type = String(t.type).toLowerCase();
        const network = type === 'ws' ? 'websocket' : type === 'tcp' ? 'raw' : type === 'mkcp' ? 'mkcp' : type;
        out.network = network;
        if (network === 'websocket') out.wsSettings = mapWebSocketSettings(t);
        if (network === 'grpc') out.grpcSettings = mapGrpcSettings(t);
        if (network === 'httpupgrade') out.httpupgradeSettings = mapHttpUpgradeSettings(t);
        if (network === 'xhttp') out.xhttpSettings = mapXhttpSettings(t);
        if (network === 'mkcp') out.kcpSettings = pick(t, [
            'mtu', 'tti', 'uplinkCapacity', 'downlinkCapacity',
            'cwndMultiplier', 'maxSendingWindow'
        ]);
        if (network === 'hysteria') out.hysteriaSettings = mapHysteriaSettings(t);
    }

    if (node.protocol === 'hysteria2') {
        out.method = 'hysteria';
        out.hysteriaSettings = {
            version: 2,
            auth: node.credentials?.password,
            udpIdleTimeout: node.transport?.udpIdleTimeout,
            masquerade: node.transport?.masquerade
        };
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
                fingerprint: tls.clientFingerprint ?? tls.fingerprint,
                enableSessionResumption: tls.enableSessionResumption,
                disableSystemRoot: tls.disableSystemRoot,
                minVersion: tls.minVersion,
                maxVersion: tls.maxVersion,
                cipherSuites: tls.cipherSuites,
                rejectUnknownSni: tls.rejectUnknownSNI,
                curvePreferences: tls.curvePreferences,
                masterKeyLog: tls.masterKeyLog,
                pinnedPeerCertSha256: tls.pinnedPeerCertSha256,
                verifyPeerCertByName: tls.verifyPeerCertByName,
                verifyPeerCertInNames: tls.verifyPeerCertInNames,
                certificates: buildXrayCertificates(tls),
                echServerKeys: tls.echServerKeys,
                echConfigList: tls.echConfigList,
                echForceQuery: tls.echForceQuery
            } : {};
        }
    }
    return Object.keys(out).length ? out : undefined;
}

function buildXrayCertificates(tls) {
    if (!tls.certificate && !tls.privateKey) return undefined;
    if (!tls.certificate || !tls.privateKey) {
        throw new Error('Xray TLS certificates require both canonical certificate and privateKey fields');
    }
    const certificates = Array.isArray(tls.certificate) ? tls.certificate : [tls.certificate];
    const keys = Array.isArray(tls.privateKey) ? tls.privateKey : [tls.privateKey];
    return certificates.map((certificate, index) => ({ certificate: [certificate], key: [keys[index] ?? keys[0]] }));
}

function mapWebSocketSettings(transport) {
    return prune({
        path: transport.path,
        headers: transport.headers,
        host: transport.host,
        acceptProxyProtocol: transport.acceptProxyProtocol,
        heartbeatPeriod: transport.heartbeatPeriod
    });
}

function mapHysteriaSettings(transport) {
    return prune({
        version: transport.version ?? 2,
        auth: transport.auth,
        udpIdleTimeout: transport.udpIdleTimeout,
        masquerade: transport.masquerade
    });
}

function mapHttpUpgradeSettings(transport) {
    return prune({
        host: transport.host,
        path: transport.path,
        headers: transport.headers,
        acceptProxyProtocol: transport.acceptProxyProtocol
    });
}

function mapXhttpSettings(transport) {
    if (transport.downloadSettings !== undefined) {
        throw new Error('Xray XHTTP downloadSettings requires a complete nested StreamConfig; canonical transport data is insufficient');
    }
    return prune({
        path: transport.path,
        host: transport.host,
        mode: transport.mode,
        headers: transport.headers,
        noGRPCHeader: transport.noGrpcHeader,
        xPaddingBytes: transport.xPaddingBytes,
        xPaddingObfsMode: transport.xPaddingObfsMode,
        xPaddingKey: transport.xPaddingKey,
        xPaddingHeader: transport.xPaddingHeader,
        xPaddingPlacement: transport.xPaddingPlacement,
        xPaddingMethod: transport.xPaddingMethod,
        uplinkHTTPMethod: transport.uplinkHttpMethod,
        sessionIDPlacement: transport.sessionPlacement,
        sessionIDKey: transport.sessionKey,
        sessionIDTable: transport.sessionTable,
        sessionIDLength: transport.sessionLength,
        seqPlacement: transport.seqPlacement,
        seqKey: transport.seqKey,
        uplinkDataPlacement: transport.uplinkDataPlacement,
        uplinkDataKey: transport.uplinkDataKey,
        uplinkChunkSize: transport.uplinkChunkSize,
        scMaxEachPostBytes: transport.scMaxEachPostBytes,
        scMinPostsIntervalMs: transport.scMinPostsIntervalMs,
        xmux: mapXhttpXmux(transport.reuseSettings)
    });
}

function mapXhttpXmux(value) {
    if (!value || typeof value !== 'object') return undefined;
    return prune({
        maxConcurrency: value.maxConcurrency,
        maxConnections: value.maxConnections,
        cMaxReuseTimes: value.cMaxReuseTimes,
        hMaxRequestTimes: value.hMaxRequestTimes,
        hMaxReusableSecs: value.hMaxReusableSecs,
        hKeepAlivePeriod: value.hKeepAlivePeriod
    });
}

function mapGrpcSettings(transport) {
    return prune({
        authority: transport.authority,
        serviceName: transport.serviceName,
        multiMode: transport.multiMode,
        user_agent: transport.userAgent,
        idle_timeout: transport.idleTimeout,
        health_check_timeout: transport.healthCheckTimeout,
        permit_without_stream: transport.permitWithoutStream,
        initial_windows_size: transport.initialWindowsSize
    });
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
