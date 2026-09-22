import { parseServerInfo, parseUrlParams, parseBool } from '../../utils.js';

export function parseNaive(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const at = addressPart.lastIndexOf('@');
    const userInfo = at >= 0 ? decodeURIComponent(addressPart.slice(0, at)) : '';
    const serverInfo = at >= 0 ? addressPart.slice(at + 1) : addressPart;
    const { host, port } = parseServerInfo(serverInfo);
    const [username, password] = userInfo.split(':');

    return {
        tag: name || 'NaiveProxy',
        type: 'naive',
        server: host,
        server_port: port,
        username: username || params.username,
        password: password || params.password,
        quic: parseBool(params.quic, undefined),
        insecure_concurrency: params['insecure-concurrency'],
        extra_headers: params['extra-headers'],
        tls: {
            enabled: true,
            server_name: params.sni || params.servername,
            insecure: parseBool(params.insecure ?? params['skip-cert-verify'], false)
        }
    };
}
