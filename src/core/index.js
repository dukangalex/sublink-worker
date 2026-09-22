import './adapters/index.js';

export { createProxyNode } from './ProxyNode.js';
export { normalizeProxy, normalizeProxies } from './normalizeProxy.js';
export { declareCapability, canConvert, explainConversion, getCapabilityMatrix, getNodeFeatures } from './capabilityMatrix.js';
export { toSingBox } from './adapters/singbox.js';
export { toClash } from './adapters/clash.js';
