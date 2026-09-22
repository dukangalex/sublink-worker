export function createProxyNode(input = {}) {
    return Object.freeze({
        id: input.id || createId(),
        name: input.name || input.tag || 'Unnamed',
        protocol: input.protocol || input.type || 'unknown',
        endpoint: {
            host: input.endpoint?.host ?? input.server ?? '',
            port: Number(input.endpoint?.port ?? input.server_port ?? input.port ?? 0)
        },
        credentials: { ...(input.credentials || extractCredentials(input)) },
        tls: input.tls ? normalizeTls(input.tls) : null,
        transport: input.transport ? { ...input.transport } : null,
        obfs: input.obfs ? { ...input.obfs } : null,
        reality: input.reality ? normalizeReality(input.reality) : null,
        protocolOptions: { ...(input.protocolOptions || extractProtocolOptions(input)) },
        metadata: { ...(input.metadata || {}) }
    });
}

function normalizeTls(tls) {
    const out = {
        enabled: tls.enabled !== false,
        serverName: tls.serverName ?? tls.server_name,
        insecure: tls.insecure ?? tls.skip_cert_verify,
        alpn: tls.alpn,
        fingerprint: tls.fingerprint ?? tls.utls?.fingerprint,
        clientFingerprint: tls.clientFingerprint ?? tls.client_fingerprint,
        ech: tls.ech
    };

    for (const [key, value] of Object.entries(tls)) {
        if (!['server_name', 'servername', 'skip_cert_verify', 'client_fingerprint', 'utls'].includes(key) && value !== undefined) {
            out[key] = value;
        }
    }

    return out;
}

function normalizeReality(reality) {
    const out = {
        publicKey: reality.publicKey ?? reality.public_key ?? reality.password,
        shortId: reality.shortId ?? reality.short_id,
        serverName: reality.serverName ?? reality.server_name ?? reality.servername,
        fingerprint: reality.fingerprint ?? reality.clientFingerprint ?? reality.client_fingerprint,
        mldsa65Verify: reality.mldsa65Verify ?? reality.mldsa65_verify,
        spiderX: reality.spiderX ?? reality.spider_x
    };

    for (const [key, value] of Object.entries(reality)) {
        if (!['public_key', 'short_id', 'server_name', 'servername', 'client_fingerprint', 'mldsa65_verify', 'spider_x', 'password'].includes(key) && value !== undefined) {
            out[key] = value;
        }
    }

    return out;
}

function extractCredentials(input) {
    const keys = ['uuid','password','username','user','method','psk','private_key','peer_public_key','pre_shared_key'];
    return Object.fromEntries(keys.filter(k => input[k] !== undefined).map(k => [k, input[k]]));
}

function extractProtocolOptions(input) {
    const reserved = new Set(['tag','name','type','protocol','server','server_port','port','tls','transport','obfs','reality','metadata','credentials','uuid','password','username','user','method','psk','private_key','peer_public_key','pre_shared_key']);
    return Object.fromEntries(Object.entries(input).filter(([k]) => !reserved.has(k)));
}

function createId() {
    return 'node-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}
