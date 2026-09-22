import { parseServerInfo, parseUrlParams, parseBool, parseMaybeNumber } from '../../utils.js';

export function parseSnell(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const at = addressPart.lastIndexOf('@');
    const credential = at >= 0 ? decodeURIComponent(addressPart.slice(0, at)) : '';
    const serverInfo = at >= 0 ? addressPart.slice(at + 1) : addressPart;
    const { host, port } = parseServerInfo(serverInfo);

    return {
        tag: name || 'Snell',
        type: 'snell',
        server: host,
        server_port: port,
        psk: credential || params.psk || params.password,
        version: parseMaybeNumber(params.version) || 3,
        obfs_opts: params.obfs || params['obfs-mode'] ? {
            mode: params.obfs || params['obfs-mode'],
            host: params.host || params['obfs-host']
        } : undefined,
        udp: parseBool(params.udp, undefined),
        reuse: parseBool(params.reuse, undefined)
    };
}
