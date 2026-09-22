import { parseServerInfo, parseUrlParams, parseBool } from '../../utils.js';

function parseProxyUrl(url, type) {
    const { addressPart, params, name } = parseUrlParams(url);
    const at = addressPart.lastIndexOf('@');
    const serverInfo = at >= 0 ? addressPart.slice(at + 1) : addressPart;
    const userInfo = at >= 0 ? addressPart.slice(0, at) : '';
    const { host, port } = parseServerInfo(serverInfo);
    const [username, password] = userInfo ? decodeURIComponent(userInfo).split(':') : [];
    const result = {
        tag: name || type.toUpperCase(),
        type,
        server: host,
        server_port: port
    };
    if (username !== undefined) result.username = username;
    if (password !== undefined) result.password = password;
    if (params.sni || params.servername || params['server-name']) {
        result.tls = {
            enabled: true,
            server_name: params.sni || params.servername || params['server-name'],
            insecure: parseBool(params.insecure ?? params['skip-cert-verify'], false)
        };
    }
    return result;
}

export function parseSocks5(url) {
    return parseProxyUrl(url, 'socks');
}

export function parseHttpProxy(url) {
    return parseProxyUrl(url, 'http');
}
