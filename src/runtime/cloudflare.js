import { CloudflareKVAdapter } from '../adapters/kv/cloudflareKv.js';

export function createCloudflareRuntime(env) {
    return {
        kv: env?.SUBLINK_KV ? new CloudflareKVAdapter(env.SUBLINK_KV) : null,
        assetFetcher: env?.ASSETS ? (request) => env.ASSETS.fetch(request) : null,
        logger: console,
        config: { subscriptionAdminToken: env?.SUBX_ADMIN_TOKEN || env?.SUBLINK_SUBSCRIPTION_ADMIN_TOKEN || null }
    };
}
