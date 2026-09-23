const TOKEN_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_';

function randomBytes(length) {
    if (globalThis.crypto?.getRandomValues) {
        const bytes = new Uint8Array(length);
        globalThis.crypto.getRandomValues(bytes);
        return bytes;
    }

    throw new Error('A cryptographically secure random source is required to create subscription tokens');
}

export function createSubscriptionToken(length = 16) {
    if (!Number.isInteger(length) || length < 12 || length > 64) {
        throw new Error('Subscription token length must be an integer between 12 and 64');
    }

    const bytes = randomBytes(length);
    let token = '';
    for (const byte of bytes) {
        token += TOKEN_ALPHABET[byte & 63];
    }
    return token;
}

export function createSubscriptionPath(token) {
    if (!isValidSubscriptionToken(token)) {
        throw new Error('Invalid subscription token');
    }
    return `/sub/${token}`;
}

export function createSubscriptionUrl(baseUrl, token) {
    const url = new URL(baseUrl);
    url.pathname = createSubscriptionPath(token);
    url.search = '';
    url.hash = '';
    return url.toString();
}

export function isValidSubscriptionToken(token) {
    return typeof token === 'string' && /^[0-9A-Za-z_-]{12,64}$/.test(token);
}

export function createSubscriptionRecord(input = {}) {
    if (!input.source || typeof input.source !== 'string') {
        throw new Error('Subscription source must be a non-empty URL string');
    }

    const source = new URL(input.source);
    if (!['http:', 'https:'].includes(source.protocol)) {
        throw new Error('Subscription source must use HTTP or HTTPS');
    }

    const target = String(input.target || 'clash').toLowerCase();
    if (!['clash', 'singbox', 'xray', 'surge'].includes(target)) {
        throw new Error(`Unsupported subscription target: ${target}`);
    }

    const token = input.token || createSubscriptionToken();
    if (!isValidSubscriptionToken(token)) {
        throw new Error('Invalid subscription token');
    }

    return Object.freeze({
        token,
        source: source.toString(),
        target,
        createdAt: input.createdAt || new Date().toISOString()
    });
}

export class MemorySubscriptionStore {
    #records = new Map();

    async create(input) {
        const record = createSubscriptionRecord(input);
        if (this.#records.has(record.token)) {
            throw new Error('Subscription token collision');
        }
        this.#records.set(record.token, record);
        return record;
    }

    async get(token) {
        if (!isValidSubscriptionToken(token)) return null;
        return this.#records.get(token) || null;
    }

    async delete(token) {
        return this.#records.delete(token);
    }
}
