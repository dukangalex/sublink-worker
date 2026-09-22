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
    'transport.mekya': false,
    'transport.domainsocket': false,
    multiplex: true,
    packet_encoding: true,
    udp_over_stream: true
};

const baseClashFeatures = {
    tls: true,
    'tls.utls': true,
    'tls.reality': true,
    'transport.http': true,
    'transport.ws': true,
    'transport.h2': true,
    'transport.grpc': true,
    multiplex: true,
    packet_encoding: true
};

const clashFeaturesFor = (protocol) => ({
    ...baseClashFeatures,
    'transport.xhttp': protocol === 'vless',
    'transport.mkcp': protocol === 'vmess',
    'transport.mekya': protocol === 'vmess',
    'transport.quic': protocol === 'hysteria' || protocol === 'hysteria2' || protocol === 'tuic'
});

const surgeProtocols = new Set(['shadowsocks','vmess','trojan','hysteria2','tuic','socks','http','wireguard','anytls','snell','ssh']);

const surgeFeaturesFor = (protocol) => ({
    tls: ['vmess','trojan','hysteria2','tuic','socks','http','anytls'].includes(protocol),
    'transport.ws': ['vmess','trojan'].includes(protocol),
    'transport.grpc': false,
    'transport.xhttp': false,
    'transport.mkcp': false,
    'tls.utls': false,
    'tls.reality': false
});

const xrayFeaturesFor = (protocol) => ({
    tls: true,
    'tls.utls': true,
    'tls.reality': true,
    'transport.ws': protocol === 'vless' || protocol === 'vmess' || protocol === 'trojan',
    'transport.grpc': protocol === 'vless' || protocol === 'vmess' || protocol === 'trojan',
    'transport.httpupgrade': protocol === 'vless' || protocol === 'vmess',
    'transport.xhttp': protocol === 'vless' || protocol === 'vmess',
    'transport.mkcp': protocol === 'vmess',
    multiplex: true
});

for (const protocol of protocols) {
    declareCapability(protocol, 'singbox', { adapter: 'generic', features: singBoxFeatures });
    declareCapability(protocol, 'clash', { adapter: 'mihomo', features: clashFeaturesFor(protocol) });
    declareCapability(protocol, 'xray', { adapter: 'xray', features: xrayFeaturesFor(protocol) });
    if (surgeProtocols.has(protocol)) declareCapability(protocol, 'surge', { adapter: 'surge', features: surgeFeaturesFor(protocol) });
}

export { toSingBox } from './singbox.js';
export { toClash } from './clash.js';
export { toXray } from './xray.js';
export { toSurge } from './surge.js';
