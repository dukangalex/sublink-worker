import { parseServerInfo, parseUrlParams, parseBool } from '../../utils.js';

export function parseAnyTls(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const at = addressPart.lastIndexOf('@');
    const password = at >= 0 ? decodeURIComponent(addressPart.slice(0, at)) : params.password;
    const serverInfo = at >= 0 ? addressPart.slice(at + 1) : addressPart;
    const { host, port } = parseServerInfo(serverInfo);

    return {
        tag: name || 'AnyTLS',
        type: 'anytls',
        server: host,
        server_port: port,
        password,
        idle_session_check_interval: params['idle-session-check-interval'],
        idle_session_timeout: params['idle-session-timeout'],
        min_idle_session: params['min-idle-session'],
        tls: {
            enabled: true,
            server_name: params.sni || params.servername,
            alpn: params.alpn ? params.alpn.split(',') : undefined,
            insecure: parseBool(params.insecure ?? params['skip-cert-verify'], false)
        }
    };
}
