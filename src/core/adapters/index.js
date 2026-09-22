import { declareCapability } from '../capabilityMatrix.js';

const protocols = [
    'shadowsocks','vmess','vless','trojan','hysteria','hysteria2',
    'tuic','socks','http','wireguard','anytls','naive','snell','ssh'
];

const singBoxFeatures = {
    tls: true,
    'tls.utls': true,
    'tls.reality': true,
    'tls.ech': true,
    'transport.http': true,
    'transport.ws': true,
    'transport.quic': true,
    'transport.grpc': true,
    'transport.httpupgrade': true,
    'transport.xhttp': false,
    'transport.mkcp': false,
    'transport.domainsocket': false,
    'multiplex': true,
    'packet_encoding': true,
    'udp_over_stream': true
};

for (const protocol of protocols) {
    declareCapability(protocol, 'singbox', {
        adapter: 'generic',
        features: singBoxFeatures
    });
}

export { toSingBox } from './singbox.js';
