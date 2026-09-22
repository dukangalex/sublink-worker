import { parseServerInfo, parseUrlParams, parseArray, parseBool } from '../../utils.js';

export function parseHysteria(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const at = addressPart.lastIndexOf('@');
    const credential = at >= 0 ? decodeURIComponent(addressPart.slice(0, at)) : '';
    const serverInfo = at >= 0 ? addressPart.slice(at + 1) : addressPart;
    const { host, port } = parseServerInfo(serverInfo);

    return {
        tag: name || 'Hysteria',
        type: 'hysteria',
        server: host,
        server_port: port,
        auth_str: credential || params['auth-str'] || params.auth,
        protocol: params.protocol || 'udp',
        up: params.up,
        down: params.down,
        obfs: params.obfs,
        tls: {
            enabled: true,
            server_name: params.sni,
            alpn: parseArray(params.alpn),
            insecure: parseBool(params['skip-cert-verify'] ?? params.insecure, false)
        },
        fingerprint: params.fingerprint,
        name_cert_verify: params['name-cert-verify'],
        fast_open: parseBool(params['fast-open'], undefined),
        disable_mtu_discovery: parseBool(params['disable-mtu-discovery'], undefined)
    };
}
