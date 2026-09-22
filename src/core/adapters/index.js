import { declareCapability } from '../capabilityMatrix.js';

const protocols = [
    'shadowsocks','vmess','vless','trojan','hysteria','hysteria2',
    'tuic','socks','http','wireguard','anytls','naive','snell','ssh'
];

for (const protocol of protocols) declareCapability(protocol, 'singbox', { adapter: 'generic' });

export { toSingBox } from './singbox.js';
