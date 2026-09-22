# Expanded protocol parser layer

This branch adds parser entry points for the local/core direction while preserving the existing subscription/config pipeline.

## Added schemes

- `socks5://`, `socks://`
- `http-proxy://`
- `hysteria://` (Hysteria 1)
- `wireguard://`
- `anytls://`
- `naive+https://`, `naive://`
- `snell://`
- `ssh://`

The parsers emit the repository's existing outbound-style object shape (`tag`, `type`, `server`, `server_port`, protocol fields, TLS fields) so the existing builders can consume them without a second conversion layer.

## Important compatibility note

There is no single universal URI standard for every newly-added protocol. The URI parsers therefore intentionally cover the common share/config representation and preserve protocol-specific fields rather than pretending every client uses identical syntax.

For structured protocols such as WireGuard, the parser also accepts an object so a future local engine can ingest Clash/Mihomo or sing-box configuration objects directly.

## Next core step

The next change should introduce a canonical `ProxyNode` normalization boundary and adapters from these legacy outbound objects into that model. That will allow Clash, sing-box, Xray and Surge builders to report unsupported capabilities explicitly instead of silently dropping fields.

References used while implementing this layer include current sing-box outbound documentation for SOCKS, WireGuard and NaiveProxy, plus current Mihomo configuration examples for Hysteria, Snell and WireGuard.
