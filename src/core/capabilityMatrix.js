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
            status: 'unsupported',
            reasons: ['No adapter capability has been declared for this protocol/target pair.'],
            features: []
        };
    }

    const reasons = [];
    const degraded = [];

    for (const constraint of entry.constraints || []) {
        const result = constraint(node);
        if (result?.supported === false) reasons.push(result.reason);
        if (result?.warning) degraded.push(result.warning);
    }
    const featureResults = [];

    for (const feature of getNodeFeatures(node)) {
        const rule = entry.features?.[feature];
        const status = rule === false ? 'unsupported' : rule === 'degraded' ? 'degraded' : 'supported';
        featureResults.push({ feature, status });
        if (status === 'unsupported') reasons.push(`Target ${target} does not support feature: ${feature}`);
        if (status === 'degraded') degraded.push(`Target ${target} may degrade feature: ${feature}`);
    }

    return {
        ...entry,
        supported: reasons.length === 0,
        status: reasons.length ? 'unsupported' : degraded.length ? 'degraded' : 'supported',
        reasons,
        warnings: [...(entry.warnings || []), ...degraded],
        featureResults
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
        if (node.reality || node.tls.reality) features.add('tls.reality');
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
    if (node.protocolOptions?.udp_relay || node.protocolOptions?.udp) features.add('udp_relay');

    return [...features];
}

function normalizeTransportType(type) {
    return String(type).toLowerCase();
}

function normalizeCapability(details) {
    return {
        adapter: details.adapter || 'generic',
        features: { ...(details.features || {}) },
        ...details
    };
}
