import { createProxyNode } from './ProxyNode.js';

export function normalizeProxy(input) {
    if (!input || typeof input !== 'object') throw new TypeError('Proxy node must be an object');
    const normalized = {
        ...input,
        protocol: input.protocol || input.type,
        endpoint: { ...(input.endpoint || {}), host: input.endpoint?.host ?? input.server ?? '', port: input.endpoint?.port ?? input.server_port ?? input.port ?? 0 },
        tls: normalizeTls(input),
        transport: normalizeTransport(input),
        reality: normalizeReality(input),
        protocolOptions: normalizeProtocolOptions(input)
    };
    return createProxyNode(normalized);
}

export function normalizeProxies(inputs = []) { return inputs.filter(Boolean).map(normalizeProxy); }

function normalizeTls(input) {
    if (!input.tls && !input.servername && !input.sni && input.skip_cert_verify === undefined && !input.client_fingerprint) return undefined;
    const source = input.tls && typeof input.tls === 'object' ? input.tls : {};
    return { ...source, enabled: source.enabled !== false && input.tls !== false, serverName: source.serverName ?? source.server_name ?? input.servername ?? input.sni, insecure: source.insecure ?? input.skip_cert_verify, fingerprint: source.fingerprint ?? source.clientFingerprint ?? input.client_fingerprint };
}

function normalizeTransport(input) {
    if (input.transport) return { ...input.transport };
    const type = input.network || input.transport_type;
    if (!type) return undefined;
    const key = String(type).toLowerCase();
    const options = input[key + '_opts'] || {};
    return { type: key, ...options };
}

function normalizeReality(input) {
    if (input.reality) return { ...input.reality };
    const source = input.reality_opts || input.realityOpts;
    if (!source) return undefined;
    return { ...source, publicKey: source.publicKey ?? source.public_key, shortId: source.shortId ?? source.short_id };
}

function normalizeProtocolOptions(input) {
    const options = { ...(input.protocolOptions || {}) };
    const aliases = { 'packet-encoding': 'packet_encoding', alterId: 'alter_id', 'flow-control': 'flow_control' };
    for (const [from, to] of Object.entries(aliases)) if (input[from] !== undefined && options[to] === undefined) options[to] = input[from];
    const reserved = new Set(['endpoint','server','server_port','port','protocol','type','tag','name','tls','servername','sni','skip_cert_verify','client_fingerprint','transport','transport_type','network','reality','reality_opts','realityOpts','credentials','protocolOptions']);
    return Object.fromEntries(Object.entries({ ...input, ...options }).filter(([key]) => !reserved.has(key)));
}