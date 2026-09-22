const declared = new Map();

export function declareCapability(protocol, target, details = {}) {
    if (!declared.has(protocol)) declared.set(protocol, new Map());
    declared.get(protocol).set(target, { ...details });
}

export function canConvert(node, target) {
    return Boolean(declared.get(node.protocol)?.has(target));
}

export function explainConversion(node, target) {
    const entry = declared.get(node.protocol)?.get(target);
    if (entry) return { supported: true, reasons: [], ...entry };
    return {
        supported: false,
        reasons: ['No adapter capability has been declared for this protocol/target pair.']
    };
}

export function getCapabilityMatrix() {
    return Object.fromEntries(
        [...declared.entries()].map(([protocol, targets]) => [protocol, Object.fromEntries(targets)])
    );
}
