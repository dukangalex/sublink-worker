import { parseServerInfo, parseUrlParams, parseArray, parseMaybeNumber } from '../../utils.js';

function decode(value) {
    return value == null ? value : decodeURIComponent(value);
}

export function parseWireguard(input) {
    if (typeof input === 'object' && input !== null) {
        return normalizeWireguardObject(input);
    }

    const { addressPart, params, name } = parseUrlParams(input);
    const at = addressPart.lastIndexOf('@');
    const serverInfo = at >= 0 ? addressPart.slice(at + 1) : addressPart;
    const { host, port } = parseServerInfo(serverInfo);

    const node = {
        tag: name || 'WireGuard',
        type: 'wireguard',
        server: host,
        server_port: port,
        local_address: parseArray(params['local-address'] || params.address || params.ip),
        private_key: decode(params['private-key'] || params.privateKey),
        peer_public_key: decode(params['public-key'] || params.publicKey || params['peer-public-key']),
        pre_shared_key: decode(params['pre-shared-key'] || params.psk),
        reserved: params.reserved,
        mtu: parseMaybeNumber(params.mtu),
        network: params.network
    };

    if (params['allowed-ips'] || params.allowed_ips) {
        node.allowed_ips = parseArray(params['allowed-ips'] || params.allowed_ips);
    }
    return node;
}

function normalizeWireguardObject(input) {
    return {
        tag: input.tag || input.name || 'WireGuard',
        type: 'wireguard',
        server: input.server,
        server_port: Number(input.server_port ?? input.port),
        local_address: input.local_address ?? input.ip ?? input.address,
        private_key: input.private_key ?? input['private-key'],
        peer_public_key: input.peer_public_key ?? input.public_key ?? input['public-key'],
        pre_shared_key: input.pre_shared_key ?? input['pre-shared-key'],
        allowed_ips: input.allowed_ips ?? input['allowed-ips'],
        reserved: input.reserved,
        mtu: input.mtu,
        network: input.network,
        peers: input.peers
    };
}
