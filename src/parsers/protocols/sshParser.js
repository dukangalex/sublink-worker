import { parseServerInfo, parseUrlParams, parseBool } from '../../utils.js';

export function parseSsh(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const at = addressPart.lastIndexOf('@');
    const userInfo = at >= 0 ? decodeURIComponent(addressPart.slice(0, at)) : '';
    const serverInfo = at >= 0 ? addressPart.slice(at + 1) : addressPart;
    const { host, port } = parseServerInfo(serverInfo);
    const [username, password] = userInfo.split(':');

    return {
        tag: name || 'SSH',
        type: 'ssh',
        server: host,
        server_port: port,
        user: username || params.user || params.username,
        password: password || params.password,
        private_key: params['private-key'] || params.private_key,
        private_key_passphrase: params['private-key-passphrase'] || params.passphrase,
        host_key: params['host-key'] || params.host_key,
        private_key_path: params['private-key-path'],
        set_system_proxy: parseBool(params['set-system-proxy'], undefined)
    };
}
