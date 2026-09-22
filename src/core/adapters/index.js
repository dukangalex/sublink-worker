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

const clashConstraintsFor = (protocol) => [
    (node) => {
        const reality = Boolean(node.reality || node.tls?.reality);
        const transport = String(node.transport?.type || 'tcp').toLowerCase();
        if (reality && !['tcp', 'grpc', 'xhttp'].includes(transport)) {
            return {
                supported: false,
                reason: `Mihomo does not support REALITY with ${transport} transport for ${protocol}`
            };
        }
        return { supported: true };
    }
];

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
    'transport.ws': ['http', 'vmess', 'vless', 'trojan'].includes(protocol),
    'transport.grpc': ['http', 'vmess', 'vless', 'trojan'].includes(protocol),
    'transport.httpupgrade': ['http', 'vmess', 'vless', 'trojan'].includes(protocol),
    'transport.xhttp': ['http', 'vmess', 'vless', 'trojan'].includes(protocol),
    'transport.mkcp': ['http', 'vmess', 'vless', 'trojan'].includes(protocol),
    multiplex: true
});

const xrayConstraintsFor = (protocol) => [
    (node) => {
        const reality = Boolean(node.reality || node.tls?.reality);
        const transport = String(node.transport?.type || 'raw').toLowerCase();
        const normalized = transport === 'ws' ? 'websocket' : transport;
        if (reality && !['raw', 'tcp', 'xhttp', 'grpc'].includes(normalized)) {
            return {
                supported: false,
                reason: 'Xray REALITY is only compatible with RAW, XHTTP, and gRPC; got ' + normalized + ' for ' + protocol
            };
        }
        if (normalized === 'hysteria' && !node.tls && !reality) {
            return {
                supported: false,
                reason: 'Xray Hysteria transport requires TLS'
            };
        }
        if (normalized === 'websocket' && (
            node.transport?.maxEarlyData !== undefined ||
            node.transport?.earlyDataHeaderName !== undefined ||
            node.transport?.v2rayHttpUpgrade !== undefined ||
            node.transport?.v2rayHttpUpgradeFastOpen !== undefined
        )) {
            return {
                supported: false,
                reason: 'Xray WebSocket does not expose Mihomo-specific early-data or HTTP-upgrade fields; conversion would drop transport behavior'
            };
        }
        if (normalized === 'mkcp' && (
            node.transport?.readBuffer !== undefined ||
            node.transport?.writeBuffer !== undefined ||
            node.transport?.seed !== undefined ||
            node.transport?.header !== undefined
        )) {
            return {
                supported: false,
                reason: 'Current Xray mKCP no longer supports read/write buffers, seed, or header; conversion would drop transport behavior'
            };
        }
        return { supported: true };
    }
];

const xrayProtocols = new Set(['shadowsocks','vmess','vless','trojan','socks','http','wireguard','hysteria2']);

for (const protocol of protocols) {
    if (protocol !== 'wireguard') {
        declareCapability(protocol, 'singbox', { adapter: 'generic', features: singBoxFeatures });
    }
    declareCapability(protocol, 'clash', { adapter: 'mihomo', features: clashFeaturesFor(protocol), constraints: clashConstraintsFor(protocol) });
    if (xrayProtocols.has(protocol)) declareCapability(protocol, 'xray', { adapter: 'xray', features: xrayFeaturesFor(protocol), constraints: xrayConstraintsFor(protocol) });
    if (surgeProtocols.has(protocol)) declareCapability(protocol, 'surge', { adapter: 'surge', features: surgeFeaturesFor(protocol) });
}

export { toSingBox } from './singbox.js';
export { toClash } from './clash.js';
export { toXray } from './xray.js';
export { toSurge } from './surge.js';
