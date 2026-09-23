import yaml from 'js-yaml';
import { convertProxy } from './convertProxy.js';
import { processNodeCollection } from './nodeCollection.js';

export const SUBSCRIPTION_CONTENT_TYPES = {
    clash: 'text/yaml; charset=utf-8',
    singbox: 'application/json; charset=utf-8',
    xray: 'application/json; charset=utf-8',
    surge: 'text/plain; charset=utf-8'
};

export function renderSubscription(nodes, target, options = {}) {
    const collection = processNodeCollection(nodes, options.collection || {});
    return renderSubscriptionCollection(collection, target, options);
}

export function renderSubscriptionCollection(collection, target, options = {}) {
    if (!collection || !Array.isArray(collection.nodes)) {
        throw new TypeError('A processed node collection is required');
    }
    const targetName = String(target || '').toLowerCase();
    const results = collection.nodes.map(node => convertProxy(node, targetName, options));
    const failed = results.filter(result => !result.ok);
    if (failed.length) {
        const errors = failed.flatMap(result => result.errors || []);
        throw new Error(`Subscription conversion failed: ${errors.join('; ')}`);
    }

    const outputs = results.map(result => result.output);
    const body = renderOutputs(outputs, targetName);
    return {
        body,
        contentType: SUBSCRIPTION_CONTENT_TYPES[targetName] || 'text/plain; charset=utf-8',
        warnings: [
            ...collection.warnings,
            ...results.flatMap(result => result.warnings || [])
        ],
        collection
    };
}

function renderOutputs(outputs, target) {
    switch (target) {
        case 'clash':
        case 'mihomo':
            return yaml.dump({ proxies: outputs }, { noRefs: true, lineWidth: -1 });
        case 'singbox':
        case 'sing-box':
            return JSON.stringify({ outbounds: outputs }, null, 2);
        case 'xray':
        case 'v2ray':
            return JSON.stringify({ outbounds: outputs }, null, 2);
        case 'surge':
            return outputs.map(output => output?.line || '').filter(Boolean).join('\n') + '\n';
        default:
            throw new Error(`Unsupported subscription target: ${target}`);
    }
}
