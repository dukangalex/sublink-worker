import { createProxyNode } from './ProxyNode.js';

export function normalizeProxy(input) {
    if (!input || typeof input !== 'object') throw new TypeError('Proxy node must be an object');
    return createProxyNode(input);
}

export function normalizeProxies(inputs = []) {
    return inputs.filter(Boolean).map(normalizeProxy);
}
