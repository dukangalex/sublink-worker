import { normalizeProxy } from './normalizeProxy.js';
import { validateProxyNode } from './validateProxyNode.js';
import { explainConversion } from './capabilityMatrix.js';
import { toSingBox } from './adapters/singbox.js';
import { toClash } from './adapters/clash.js';
import { toXray } from './adapters/xray.js';
import { toSurge } from './adapters/surge.js';

const ADAPTERS = {
    singbox: toSingBox,
    'sing-box': toSingBox,
    clash: toClash,
    mihomo: toClash,
    xray: toXray,
    'v2ray': toXray,
    surge: toSurge
};

export function convertProxy(input, target, options = {}) {
    const normalized = normalizeProxy(input);
    const validation = validateProxyNode(normalized, options);

    if (!validation.valid) {
        return fail(target, normalized, validation.errors, validation.warnings, options);
    }

    const targetName = String(target || '').toLowerCase();
    const capability = explainConversion(normalized, targetName);
    const adapter = ADAPTERS[targetName];
    if (!adapter) {
        return fail(target, normalized, [`Unsupported target: ${target}`], validation.warnings, options);
    }

    try {
        return {
            ok: true,
            target: String(target).toLowerCase(),
            node: normalized,
            output: adapter(normalized),
            status: capability.status,
            capability,
            warnings: [...validation.warnings, ...(capability.warnings || [])]
        };
    } catch (error) {
        return fail(target, normalized, [error instanceof Error ? error.message : String(error)], [...validation.warnings, ...(capability.warnings || [])], options);
    }
}

export function convertProxies(inputs = [], target, options = {}) {
    return inputs.map(input => convertProxy(input, target, options));
}

function fail(target, node, errors, warnings, options) {
    const result = {
        ok: false,
        status: 'error',
        target: target ? String(target).toLowerCase() : target,
        node,
        output: null,
        errors,
        warnings
    };
    if (options.throwOnError) throw new Error(errors.join('; '));
    return result;
}
