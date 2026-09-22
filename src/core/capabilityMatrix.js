const declared = new Map();

export function declareCapability(protocol, target, details = {}) {
    if (!declared.has(protocol)) declared.set(protocol, new Map());
    declared.get(protocol).set(target, normalizeCapability(details));
}

export function canConvert(node, target) {
    return explainConversion(node, target).supported;
}

export function explainConversion(node, target) {
    const entry = declared.get(node?.protocol)?.get(target);
    if (!entry) {
        return {
            supported: false,
            reasons: ['No adapter capability has been declared for this protocol/target pair.']
        };
    }

    const reasons = [];

    for (const feature of getNodeFeatures(node)) {
        const rule = entry.features?.[feature];
        if (rule === false) reasons.push(`Target ${target} does not support feature: ${feature}`);
    }

    return {
        supported: reasons.length === 0,
        reasons,
        ...entry
    };
}

export function getCapabilityMatrix() {
    return Object.fromEntries(
        [...declared.entries()].map(([protocol, targets]) => [
            protocol,
            Object.fromEntries(targets)
        ])
    );
}

export function getNodeFeatures(node = {}) {
    const features = new Set();

    if (node.tls) {
        features.add('tls');
        if (node.tls.fingerprint || node.tls.utls) features.add('tls.utls');
        if (node.tls.reality || node.reality) features.add('tls.reality');
        if (node.tls.ech) features.add('tls.ech');
    }

    if (node.transport?.type) {
        features.add(`transport.${normalizeTransportType(node.transport.type)}`);
    }

    if (node.obfs?.type) features.add(`obfs.${node.obfs.type}`);
    if (node.protocolOptions?.packet_encoding) features.add('packet_encoding');
    if (node.protocolOptions?.multiplex || node.multiplex) features.add('multiplex');
    if (node.protocolOptions?.udp_over_tcp || node.protocolOptions?.udp_over_stream) {
        features.add('udp_over_stream');
    }

    return [...features];
}

function normalizeTransportType(type) {
    return String(type).toLowerCase().replace('httpupgrade', 'httpupgrade');
}

function normalizeCapability(details) {
    return {
        adapter: details.adapter || 'generic',
        features: { ...(details.features || {}) },
        ...details
    };
}
