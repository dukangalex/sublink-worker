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
        reality: input.reality ? { ...input.reality } : null,
        protocolOptions: { ...(input.protocolOptions || extractProtocolOptions(input)) },
        metadata: { ...(input.metadata || {}) }
    });
}

function normalizeTls(tls) {
    return {
        enabled: tls.enabled !== false,
        serverName: tls.serverName ?? tls.server_name,
        insecure: tls.insecure,
        alpn: tls.alpn,
        fingerprint: tls.fingerprint ?? tls.utls?.fingerprint,
        ...tls
    };
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
