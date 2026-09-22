import { parseShadowsocks } from './protocols/shadowsocksParser.js';
import { parseVmess } from './protocols/vmessParser.js';
import { parseVless } from './protocols/vlessParser.js';
import { parseHysteria2 } from './protocols/hysteria2Parser.js';
import { parseHysteria } from './protocols/hysteriaParser.js';
import { parseTrojan } from './protocols/trojanParser.js';
import { parseTuic } from './protocols/tuicParser.js';
import { parseSocks5, parseHttpProxy } from './protocols/simpleProxyParser.js';
import { parseWireguard } from './protocols/wireguardParser.js';
import { parseAnyTls } from './protocols/anytlsParser.js';
import { parseNaive } from './protocols/naiveParser.js';
import { parseSnell } from './protocols/snellParser.js';
import { parseSsh } from './protocols/sshParser.js';
import { fetchSubscription } from './subscription/httpSubscriptionFetcher.js';

const protocolParsers = {
    ss: parseShadowsocks,
    vmess: parseVmess,
    vless: parseVless,
    hysteria: parseHysteria,
    hysteria2: parseHysteria2,
    hy2: parseHysteria2,
    http: fetchSubscription,
    https: fetchSubscription,
    socks5: parseSocks5,
    socks: parseSocks5,
    'http-proxy': parseHttpProxy,
    trojan: parseTrojan,
    tuic: parseTuic,
    wireguard: parseWireguard,
    wg: parseWireguard,
    anytls: parseAnyTls,
    naive: parseNaive,
    'naive+https': parseNaive,
    snell: parseSnell,
    ssh: parseSsh
};

export class ProxyParser {
    static async parse(url, userAgent) {
        if (!url || typeof url !== 'string') return undefined;
        const trimmed = url.trim();
        const type = trimmed.split('://')[0].toLowerCase();
        const parser = protocolParsers[type];
        if (!parser) return undefined;
        return parser(trimmed, userAgent);
    }

    static supportedProtocols() {
        return Object.keys(protocolParsers);
    }
}
