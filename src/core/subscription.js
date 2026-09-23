const TARGETS = new Set(['clash', 'singbox', 'xray', 'surge']);

export function createSubscriptionInput(input) {
    if (typeof input === 'string') {
        const value = input.trim();
        if (!value) {
            throw new Error('Subscription input must not be empty');
        }

        if (/^https?:\/\//i.test(value)) {
            return Object.freeze({ type: 'subscription', source: new URL(value).toString() });
        }

        return Object.freeze({ type: 'node', value });
    }

    if (!input || typeof input !== 'object') {
        throw new Error('Subscription input must be a string or object');
    }

    const type = String(input.type || '').toLowerCase();
    if (type === 'subscription') {
        const source = input.source || input.url;
        if (typeof source !== 'string' || !source.trim()) {
            throw new Error('Subscription input requires a source URL');
        }
        const url = new URL(source);
        if (!['http:', 'https:'].includes(url.protocol)) {
            throw new Error('Subscription source must use HTTP or HTTPS');
        }
        return Object.freeze({
            type: 'subscription',
            source: url.toString(),
            name: input.name || undefined
        });
    }

    if (type === 'node') {
        const value = input.value ?? input.url ?? input.node;
        if (typeof value === 'string' && value.trim()) {
            return Object.freeze({ type: 'node', value: value.trim(), name: input.name || undefined });
        }
        if (value && typeof value === 'object') {
            return Object.freeze({ type: 'node', value: { ...value }, name: input.name || undefined });
        }
        throw new Error('Node input requires a node value');
    }

    throw new Error(`Unsupported subscription input type: ${type || 'unknown'}`);
}

export function createSubscriptionRecord(input = {}, createToken = createOpaqueToken) {
    const rawInputs = Array.isArray(input.inputs)
        ? input.inputs
        : input.source
            ? [{ type: 'subscription', source: input.source }]
            : [];

    if (rawInputs.length === 0) {
        throw new Error('Subscription requires at least one input');
    }

    const inputs = rawInputs.map(createSubscriptionInput);
    const target = String(input.target || 'clash').toLowerCase();
    if (!TARGETS.has(target)) {
        throw new Error(`Unsupported subscription target: ${target}`);
    }

    const token = input.token || createToken();
    if (!token) {
        throw new Error('Subscription token generator is required');
    }
    if (typeof token !== 'string' || !/^[0-9A-Za-z_-]{12,64}$/.test(token)) {
        throw new Error('Invalid subscription token');
    }

    return Object.freeze({
        token,
        inputs: Object.freeze(inputs),
        target,
        options: Object.freeze({ ...(input.options || {}) }),
        createdAt: input.createdAt || new Date().toISOString()
    });
}

export function createSubscriptionResolver({ fetchSubscription, parseAndNormalize }) {
    if (typeof fetchSubscription !== 'function' || typeof parseAndNormalize !== 'function') {
        throw new Error('Subscription resolver requires fetchSubscription and parseAndNormalize');
    }

    return async function resolveSubscription(record, options = {}) {
        if (!record || !Array.isArray(record.inputs)) {
            throw new Error('Invalid subscription record');
        }

        const results = [];
        for (const input of record.inputs) {
            if (input.type === 'node') {
                results.push(await resolveNode(input.value, parseAndNormalize, options));
                continue;
            }

            const fetched = await fetchSubscription(input.source, options.userAgent);
            const values = extractFetchedValues(fetched);
            for (const value of values) {
                results.push(await resolveNode(value, parseAndNormalize, options));
            }
        }

        return results;
    };
}

async function resolveNode(value, parseAndNormalize, options) {
    const result = await parseAndNormalize(value, options.userAgent, options);
    if (result.node) {
        return {
            ...result,
            resolved: true
        };
    }
    return {
        node: null,
        validation: result.validation,
        input: value,
        resolved: true
    };
}

function extractFetchedValues(fetched) {
    if (Array.isArray(fetched)) {
        return fetched;
    }
    if (fetched && Array.isArray(fetched.proxies)) {
        return fetched.proxies;
    }
    return [];
}

export class KvSubscriptionStore {
    constructor(kv, prefix = 'sub:') {
        if (!kv || typeof kv.get !== 'function' || typeof kv.put !== 'function' || typeof kv.delete !== 'function') {
            throw new Error('A compatible key-value store is required');
        }
        this.kv = kv;
        this.prefix = prefix;
    }

    async create(input) {
        const record = createSubscriptionRecord(input);
        const key = this.prefix + record.token;
        if (await this.kv.get(key)) {
            throw new Error('Subscription token collision');
        }
        await this.kv.put(key, JSON.stringify(record));
        return record;
    }

    async get(token) {
        if (!isValidToken(token)) return null;
        const value = await this.kv.get(this.prefix + token);
        if (!value) return null;
        return typeof value === 'string' ? JSON.parse(value) : value;
    }

    async delete(token) {
        if (!isValidToken(token)) return false;
        await this.kv.delete(this.prefix + token);
        return true;
    }
}

export class MemorySubscriptionStore {
    #records = new Map();

    constructor(createToken) {
        this.createToken = createToken;
    }

    async create(input) {
        const record = createSubscriptionRecord(input, this.createToken);
        if (this.#records.has(record.token)) {
            throw new Error('Subscription token collision');
        }
        this.#records.set(record.token, record);
        return record;
    }

    async get(token) {
        if (!isValidToken(token)) return null;
        return this.#records.get(token) || null;
    }

    async delete(token) {
        return this.#records.delete(token);
    }
}

function createOpaqueToken(length = 16) {
    if (!globalThis.crypto?.getRandomValues) {
        throw new Error('A cryptographically secure random source is required to create subscription tokens');
    }
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_';
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return Array.from(bytes, byte => alphabet[byte & 63]).join('');
}

function isValidToken(token) {
    return typeof token === 'string' && /^[0-9A-Za-z_-]{12,64}$/.test(token);
}
