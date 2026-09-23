import { normalizeProxy } from './normalizeProxy.js';
import { validateProxyNode } from './validateProxyNode.js';

export function createNodeFingerprint(node) {
    const normalized = isCanonicalNode(node) ? node : normalizeProxy(node);
    const protocolOptions = { ...(normalized.protocolOptions || {}) };
    if (protocolOptions.uuid !== undefined && protocolOptions.uuid === normalized.credentials?.uuid) {
        delete protocolOptions.uuid;
    }

    return stableSerialize({
        protocol: normalized.protocol,
        endpoint: normalized.endpoint,
        credentials: normalized.credentials,
        tls: normalized.tls,
        transport: normalized.transport,
        obfs: normalized.obfs,
        reality: normalized.reality,
        protocolOptions
    });
}

function isCanonicalNode(node) {
    return Boolean(
        node &&
        typeof node === 'object' &&
        typeof node.protocol === 'string' &&
        node.endpoint &&
        typeof node.endpoint === 'object' &&
        node.credentials &&
        typeof node.credentials === 'object' &&
        node.protocolOptions &&
        typeof node.protocolOptions === 'object'
    );
}

export function processNodeCollection(inputs = [], options = {}) {
    if (!Array.isArray(inputs)) throw new TypeError('Node collection inputs must be an array');

    const {
        filterInvalid = true,
        deduplicate = true,
        rename,
        sort = 'name',
        groupBy
    } = options;

    const entries = [];
    const warnings = [];
    const seen = new Set();

    for (const input of inputs) {
        let node;
        try {
            node = normalizeProxy(input);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            warnings.push({ type: 'normalize', message, input });
            if (!filterInvalid) entries.push({ node: null, valid: false, errors: [message], warnings: [] });
            continue;
        }

        const validation = validateProxyNode(node);
        if (!validation.valid) {
            if (filterInvalid) {
                warnings.push({ type: 'invalid', nodeId: node.id, name: node.name, errors: validation.errors });
                continue;
            }
            entries.push({ node, valid: false, errors: validation.errors, warnings: validation.warnings });
            continue;
        }

        const prepared = renameNode(node, rename);
        const fingerprint = createNodeFingerprint(prepared);
        if (deduplicate && seen.has(fingerprint)) {
            warnings.push({ type: 'duplicate', nodeId: prepared.id, name: prepared.name });
            continue;
        }
        seen.add(fingerprint);

        entries.push({
            node: prepared,
            valid: true,
            errors: [],
            warnings: validation.warnings,
            fingerprint
        });
    }

    const sorted = sortEntries(entries, sort);
    const groups = groupEntries(sorted, groupBy);

    return {
        nodes: sorted.filter(entry => entry.node).map(entry => entry.node),
        entries: sorted,
        groups,
        warnings
    };
}

function renameNode(node, rename) {
    if (!rename || typeof rename !== 'object') return node;
    const prefix = typeof rename.prefix === 'string' ? rename.prefix : '';
    const suffix = typeof rename.suffix === 'string' ? rename.suffix : '';
    if (!prefix && !suffix) return node;
    return {
        ...node,
        name: prefix + node.name + suffix
    };
}

function sortEntries(entries, sort) {
    if (sort === 'none') return entries;
    const key = typeof sort === 'string' ? sort : 'name';
    return [...entries].sort((a, b) => {
        const left = sortValue(a.node, key);
        const right = sortValue(b.node, key);
        return compareStrings(left, right) || compareStrings(
            sortValue(a.node, 'name'),
            sortValue(b.node, 'name')
        ) || compareStrings(a.fingerprint || '', b.fingerprint || '');
    });
}

function sortValue(node, key) {
    if (!node) return '';
    if (key === 'protocol') return node.protocol || '';
    if (key === 'endpoint') return node.endpoint?.host ? `${node.endpoint.host}:${node.endpoint.port}` : '';
    return node.name || '';
}

function groupEntries(entries, groupBy) {
    if (!groupBy || groupBy === 'none') return [];
    const groups = new Map();
    for (const entry of entries) {
        if (!entry.node) continue;
        const key = groupValue(entry.node, groupBy);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(entry.node);
    }
    return Array.from(groups, ([name, nodes]) => ({ name, nodes }));
}

function groupValue(node, groupBy) {
    if (groupBy === 'protocol') return node.protocol || 'unknown';
    if (groupBy === 'host') return node.endpoint?.host || 'unknown';
    return 'default';
}

function compareStrings(a, b) {
    const left = String(a);
    const right = String(b);
    return left < right ? -1 : left > right ? 1 : 0;
}

function stripRuntimeFields(node) {
    const { id, name, metadata, ...rest } = node;
    return rest;
}

function stableSerialize(value) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(stableSerialize).join(',') + ']';
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stableSerialize(value[key])).join(',') + '}';
}
