const SERVER_PROTOCOLS = new Set([
    'shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2',
    'tuic', 'socks', 'http', 'wireguard', 'anytls', 'naive', 'snell', 'ssh'
]);

const AUTH_RULES = {
    shadowsocks: [['credentials.method', 'Shadowsocks method is required'], ['credentials.password', 'Shadowsocks password is required']],
    vmess: [['credentials.uuid', 'VMess uuid is required']],
    vless: [['credentials.uuid', 'VLESS uuid is required']],
    trojan: [['credentials.password', 'Trojan password is required']],
    hysteria: [['credentials.password', 'Hysteria password/auth is required']],
    hysteria2: [['credentials.password', 'Hysteria2 password/auth is required']],
    tuic: [['credentials.uuid', 'TUIC uuid is required'], ['credentials.password', 'TUIC password is required']],
    anytls: [['credentials.password', 'AnyTLS password is required']],
    naive: [['credentials.username', 'NaiveProxy username is required'], ['credentials.password', 'NaiveProxy password is required']],
    snell: [['credentials.psk', 'Snell PSK is required']],
    ssh: [['credentials.user', 'SSH user is required']]
};

export function validateProxyNode(node, options = {}) {
    const errors = [];
    const warnings = [];

    if (!node || typeof node !== 'object') {
        return { valid: false, errors: ['Proxy node must be an object'], warnings };
    }

    const protocol = String(node.protocol || '').toLowerCase();
    if (!protocol) errors.push('Protocol is required');

    if (SERVER_PROTOCOLS.has(protocol) && protocol !== 'wireguard') {
        if (!node.endpoint?.host) errors.push('Endpoint host is required');
        const port = Number(node.endpoint?.port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            errors.push('Endpoint port must be an integer between 1 and 65535');
        }
    }

    for (const [path, message] of AUTH_RULES[protocol] || []) {
        if (!readPath(node, path)) errors.push(message);
    }

    if (protocol === 'wireguard') {
        validateWireguard(node, errors);
    }

    if (protocol === 'ssh' && !node.credentials?.password && !node.credentials?.private_key) {
        errors.push('SSH password or private key is required');
    }

    const transportType = node.transport?.type;
    if (transportType) {
        const allowed = new Set(['ws', 'http', 'h2', 'grpc', 'quic', 'httpupgrade', 'xhttp', 'mkcp', 'mekya', 'domainsocket']);
        if (!allowed.has(String(transportType).toLowerCase())) {
            errors.push(`Unsupported transport type: ${transportType}`);
        }
        if (protocol === 'vless' && transportType === 'xhttp') {
            warnings.push('XHTTP is target-specific and should be checked by the target capability matrix');
        }
    }

    if (node.reality) {
        if (!node.reality.publicKey && !node.reality.public_key) errors.push('Reality public key is required');
        if (!node.reality.shortId && !node.reality.short_id) errors.push('Reality short ID is required');
        if (node.tls && node.tls.enabled === false) {
            errors.push('Reality requires TLS to be enabled');
        }
    }

    if (node.tls?.alpn && !Array.isArray(node.tls.alpn)) {
        errors.push('TLS ALPN must be an array');
    }

    if (options.strict && warnings.length) errors.push(...warnings);

    return { valid: errors.length === 0, errors, warnings };
}

function validateWireguard(node, errors) {
    if (!node.credentials?.private_key) {
        errors.push('WireGuard private key is required');
    }

    const peers = node.protocolOptions?.peers;
    if (!Array.isArray(peers) || peers.length === 0) {
        errors.push('WireGuard requires at least one peer');
        return;
    }

    peers.forEach((peer, index) => {
        if (!peer?.address) errors.push(`WireGuard peer ${index + 1} address is required`);

        const port = Number(peer?.port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            errors.push(`WireGuard peer ${index + 1} port must be an integer between 1 and 65535`);
        }

        if (!peer?.publicKey) {
            errors.push(`WireGuard peer ${index + 1} public key is required`);
        }
    });
}

function readPath(object, path) {
    return path.split('.').reduce((value, key) => value?.[key], object);
}
