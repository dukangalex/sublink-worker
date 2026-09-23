import { createSubscriptionRecord, createSubscriptionInput, MemorySubscriptionStore } from './subscription.js';

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

export { createSubscriptionRecord, createSubscriptionInput, MemorySubscriptionStore };
