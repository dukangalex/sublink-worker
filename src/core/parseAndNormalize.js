import { ProxyParser } from '../parsers/ProxyParser.js';
import { normalizeProxy } from './normalizeProxy.js';
import { validateProxyNode } from './validateProxyNode.js';

export async function parseAndNormalize(input, userAgent, options = {}) {
    const parsed = typeof input === 'string' ? await ProxyParser.parse(input, userAgent) : input;
    if (!parsed) return { node: null, validation: { valid: false, errors: ['Unsupported or invalid proxy input'], warnings: [] } };
    const node = normalizeProxy(parsed);
    const validation = validateProxyNode(node, options);
    if (options.throwOnInvalid && !validation.valid) throw new Error(validation.errors.join('; '));
    return { node, validation };
}

export async function parseAndNormalizeMany(inputs = [], userAgent, options = {}) {
    const results = [];
    for (const input of inputs) results.push(await parseAndNormalize(input, userAgent, options));
    return results;
}
