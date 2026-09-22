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
    if (node.tls) out.tls = toSingBoxTls(node.tls);
    if (node.transport) out.transport = { ...node.transport };
    if (node.obfs) out.obfs = { ...node.obfs };
    if (node.reality) out.reality = { ...node.reality };
    return prune(out);
}

function toSingBoxTls(tls) {
    const out = { ...tls };
    if (out.serverName !== undefined) {
        out.server_name = out.serverName;
        delete out.serverName;
    }
    return out;
}

function prune(value) {
    if (Array.isArray(value)) return value.map(prune);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined).map(([k, v]) => [k, prune(v)]));
}
