const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');

const DEFAULT_FAILOVER_STATUS = [429, 500, 502, 503, 504];
const DEFAULT_FAILOVER_ERRORS = ['timeout', 'transport', 'circuit_open'];
const SUPPORTED_CONTRACTS = new Set([
  'passthrough',
  'openai_chat_v1',
  'anthropic_messages_v1',
  'google_generative_v1',
]);

function normalizeAllowlist(rawList) {
  if (!Array.isArray(rawList)) {
    return [];
  }
  return rawList.map((item) => String(item).trim()).filter(Boolean);
}

function ipToInt(ip) {
  const parts = ip.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part) || part < 0 || part > 255)) {
    return null;
  }
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function inRange(ip, cidrBase, cidrMask) {
  const ipInt = ipToInt(ip);
  const baseInt = ipToInt(cidrBase);
  if (ipInt === null || baseInt === null) {
    return false;
  }
  const shift = 32 - cidrMask;
  return (ipInt >>> shift) === (baseInt >>> shift);
}

function isPrivateIPv4(ip) {
  return (
    inRange(ip, '0.0.0.0', 8) ||
    inRange(ip, '10.0.0.0', 8) ||
    inRange(ip, '100.64.0.0', 10) ||
    inRange(ip, '127.0.0.0', 8) ||
    inRange(ip, '169.254.0.0', 16) ||
    inRange(ip, '172.16.0.0', 12) ||
    inRange(ip, '192.0.0.0', 24) ||
    inRange(ip, '192.168.0.0', 16) ||
    inRange(ip, '198.18.0.0', 15) ||
    inRange(ip, '224.0.0.0', 4) ||
    inRange(ip, '240.0.0.0', 4)
  );
}

function isPrivateIPv6(ip) {
  const lowered = ip.toLowerCase();
  if (lowered === '::1' || lowered === '::') {
    return true;
  }
  if (lowered.startsWith('fc') || lowered.startsWith('fd')) {
    return true;
  }
  if (lowered.startsWith('fe8') || lowered.startsWith('fe9') || lowered.startsWith('fea') || lowered.startsWith('feb')) {
    return true;
  }
  if (lowered.startsWith('::ffff:')) {
    const mapped = lowered.replace('::ffff:', '');
    return net.isIP(mapped) === 4 ? isPrivateIPv4(mapped) : true;
  }
  return false;
}

function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    return isPrivateIPv4(address);
  }
  if (family === 6) {
    return isPrivateIPv6(address);
  }
  return false;
}

function isLocalHostname(hostname) {
  const lowered = String(hostname || '').toLowerCase();
  return (
    lowered === 'localhost' ||
    lowered.endsWith('.localhost') ||
    lowered.endsWith('.local') ||
    lowered.endsWith('.internal')
  );
}

function matchAllowlistEntry(urlObj, entry) {
  if (entry.includes('://')) {
    try {
      const allowUrl = new URL(entry);
      return urlObj.origin === allowUrl.origin;
    } catch {
      return false;
    }
  }

  const hostname = urlObj.hostname.toLowerCase();
  const normalized = entry.toLowerCase();
  if (normalized.startsWith('*.')) {
    return hostname.endsWith(normalized.slice(1));
  }
  return hostname === normalized;
}

function validateAllowlist(urlObj, allowlist) {
  if (allowlist.length === 0) {
    throw new Error('Custom targets are enabled but allowlist is empty');
  }
  const matched = allowlist.some((entry) => matchAllowlistEntry(urlObj, entry));
  if (!matched) {
    throw new Error(`Custom URL host is not allowlisted: ${urlObj.hostname}`);
  }
}

function toPositiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function normalizeProvider(provider, fallback = 'openai') {
  const lowered = String(provider || fallback).toLowerCase();
  if (['openai', 'anthropic', 'google', 'custom'].includes(lowered)) {
    return lowered;
  }
  return fallback;
}

function normalizeContract(value, fallback = 'passthrough') {
  const lowered = String(value || fallback).toLowerCase();
  if (SUPPORTED_CONTRACTS.has(lowered)) {
    return lowered;
  }
  return fallback;
}

function defaultContractForProvider(provider) {
  switch (provider) {
    case 'openai':
      return 'openai_chat_v1';
    case 'anthropic':
      return 'anthropic_messages_v1';
    case 'google':
      return 'google_generative_v1';
    default:
      return 'passthrough';
  }
}

function normalizeStaticHeaders(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {};
  }
  const headers = {};
  for (const [key, value] of Object.entries(input)) {
    if (!key) {
      continue;
    }
    if (value === null || value === undefined) {
      continue;
    }
    headers[String(key).toLowerCase()] = String(value);
  }
  return headers;
}

function getBaseUrlForProvider(provider) {
  if (provider === 'anthropic') {
    return process.env.SENTINEL_ANTHROPIC_URL || 'https://api.anthropic.com';
  }
  if (provider === 'google') {
    return process.env.SENTINEL_GOOGLE_URL || 'https://generativelanguage.googleapis.com';
  }
  if (provider === 'openai') {
    return process.env.SENTINEL_OPENAI_URL || 'https://api.openai.com';
  }
  return null;
}

function toDescriptor({
  targetName,
  provider,
  baseUrl,
  contract,
  resolvedIp,
  resolvedFamily,
  staticHeaders,
  source,
}) {
  const parsed = new URL(baseUrl);
  const normalizedProvider = normalizeProvider(provider);
  const normalizedTargetName = String(targetName || '').toLowerCase();
  const breakerKey =
    normalizedTargetName === normalizedProvider
      ? normalizedProvider
      : `${normalizedProvider}:${normalizedTargetName}`;
  return {
    targetName,
    provider: normalizedProvider,
    baseUrl,
    upstreamHostname: parsed.hostname,
    upstreamHostHeader: parsed.host,
    resolvedIp: resolvedIp || null,
    resolvedFamily: resolvedFamily || null,
    staticHeaders: normalizeStaticHeaders(staticHeaders),
    contract: normalizeContract(contract, defaultContractForProvider(normalizedProvider)),
    source: source || 'builtin',
    breakerKey,
  };
}

function normalizeMeshConfig(raw = {}) {
  const groups = raw.groups && typeof raw.groups === 'object' && !Array.isArray(raw.groups)
    ? raw.groups
    : {};
  const targets = raw.targets && typeof raw.targets === 'object' && !Array.isArray(raw.targets)
    ? raw.targets
    : {};

  const failoverOnStatus = Array.isArray(raw.failover_on_status)
    ? raw.failover_on_status
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value >= 100 && value <= 599)
    : DEFAULT_FAILOVER_STATUS;

  const failoverOnErrors = Array.isArray(raw.failover_on_error_types)
    ? raw.failover_on_error_types
        .map((value) => String(value).toLowerCase())
        .filter((value) => value === 'timeout' || value === 'transport' || value === 'circuit_open')
    : DEFAULT_FAILOVER_ERRORS;

  return {
    enabled: raw.enabled === true,
    maxFailoverHops: toPositiveInt(raw.max_failover_hops, 1),
    allowPostWithIdempotencyKey: raw.allow_post_with_idempotency_key === true,
    failoverOnStatus: failoverOnStatus.length > 0 ? failoverOnStatus : DEFAULT_FAILOVER_STATUS,
    failoverOnErrors: failoverOnErrors.length > 0 ? failoverOnErrors : DEFAULT_FAILOVER_ERRORS,
    defaultGroup: raw.default_group ? String(raw.default_group).toLowerCase() : '',
    contract: normalizeContract(raw.contract, 'passthrough'),
    groups,
    targets,
  };
}

function normalizeCanaryConfig(raw = {}) {
  return {
    enabled: raw.enabled === true,
    keyHeader: String(raw.key_header || 'x-sentinel-canary-key').toLowerCase(),
    fallbackHeaders: Array.isArray(raw.fallback_key_headers)
      ? raw.fallback_key_headers.map((item) => String(item).toLowerCase()).filter(Boolean)
      : ['x-sentinel-agent-id', 'x-forwarded-for', 'user-agent'],
    splits: Array.isArray(raw.splits) ? raw.splits : [],
  };
}

function hashToBucket(input, modulo) {
  const digest = crypto.createHash('sha256').update(String(input)).digest('hex').slice(0, 8);
  const numeric = Number.parseInt(digest, 16);
  if (!Number.isFinite(numeric) || modulo <= 0) {
    return 0;
  }
  return numeric % modulo;
}

function deriveCanaryKey(req, config) {
  const headers = req.headers || {};
  const direct = headers[config.keyHeader];
  if (direct) {
    return String(direct);
  }
  for (const headerName of config.fallbackHeaders) {
    const value = headers[headerName];
    if (!value) {
      continue;
    }
    if (headerName === 'x-forwarded-for') {
      return String(value).split(',')[0].trim();
    }
    return String(value);
  }
  return '';
}

function selectCanaryGroup(req, requestedTarget, canaryConfig) {
  if (!canaryConfig.enabled || canaryConfig.splits.length === 0) {
    return null;
  }

  const target = String(requestedTarget || 'openai').toLowerCase();
  const split = canaryConfig.splits.find((candidate) => {
    const matchTarget = String(candidate.match_target || '*').toLowerCase();
    return matchTarget === '*' || matchTarget === target;
  });

  if (!split) {
    return null;
  }

  const name = String(split.name || `${target}-split`);
  const groupA = String(split.group_a || '').toLowerCase();
  const groupB = String(split.group_b || '').toLowerCase();
  if (!groupA || !groupB) {
    return null;
  }

  const weightA = Math.max(0, Number(split.weight_a ?? 90));
  const weightB = Math.max(0, Number(split.weight_b ?? 10));
  const totalWeight = weightA + weightB;
  if (!(totalWeight > 0)) {
    return null;
  }

  const sticky = split.sticky !== false;
  const canaryKey = deriveCanaryKey(req, canaryConfig);
  const bucket = sticky
    ? hashToBucket(`${name}:${canaryKey || 'anonymous'}`, totalWeight)
    : Math.floor(Math.random() * totalWeight);

  const selectedGroup = bucket < weightA ? groupA : groupB;
  return {
    name,
    selectedGroup,
    sticky,
    bucket,
    totalWeight,
    canaryKeyHash: canaryKey
      ? crypto.createHash('sha256').update(canaryKey).digest('hex').slice(0, 12)
      : null,
    splitWeights: {
      groupA,
      weightA,
      groupB,
      weightB,
    },
  };
}

async function validateCustomTargetUrl(customUrl, customTargetsConfig = {}) {
  if (!customTargetsConfig.enabled) {
    throw new Error('Custom targets are disabled. Enable runtime.upstream.custom_targets.enabled in config.');
  }

  let urlObj;
  try {
    urlObj = new URL(String(customUrl));
  } catch {
    throw new Error('x-sentinel-custom-url must be a valid absolute URL');
  }

  if (!['http:', 'https:'].includes(urlObj.protocol)) {
    throw new Error(`Unsupported custom target protocol: ${urlObj.protocol}`);
  }

  if (urlObj.username || urlObj.password) {
    throw new Error('Custom target URL must not include credentials');
  }

  const allowlist = normalizeAllowlist(customTargetsConfig.allowlist);
  validateAllowlist(urlObj, allowlist);

  let resolvedIp = null;
  let resolvedFamily = null;

  if (customTargetsConfig.block_private_networks !== false) {
    if (isLocalHostname(urlObj.hostname)) {
      throw new Error(`Blocked private/local custom target hostname: ${urlObj.hostname}`);
    }

    const literalFamily = net.isIP(urlObj.hostname);
    if (literalFamily) {
      if (isPrivateAddress(urlObj.hostname)) {
        throw new Error(`Blocked private custom target IP: ${urlObj.hostname}`);
      }
      resolvedIp = urlObj.hostname;
      resolvedFamily = literalFamily;
    } else {
      try {
        const resolved = await dns.lookup(urlObj.hostname, { all: true, verbatim: true });
        if (resolved.some((entry) => isPrivateAddress(entry.address))) {
          throw new Error(`Blocked custom target hostname resolving to private IP: ${urlObj.hostname}`);
        }
        if (!resolved[0]) {
          throw new Error(`Unable to resolve custom target hostname: ${urlObj.hostname}`);
        }
        resolvedIp = resolved[0].address;
        resolvedFamily = resolved[0].family;
      } catch (error) {
        if (error.code === 'ENOTFOUND' || error.code === 'EAI_AGAIN') {
          throw new Error(`Unable to resolve custom target hostname: ${urlObj.hostname}`);
        }
        if (error.message && error.message.startsWith('Blocked custom target')) {
          throw error;
        }
        throw new Error(`Failed to validate custom target hostname: ${urlObj.hostname}`);
      }
    }
  } else {
    const literalFamily = net.isIP(urlObj.hostname);
    if (literalFamily) {
      resolvedIp = urlObj.hostname;
      resolvedFamily = literalFamily;
    } else {
      try {
        const resolved = await dns.lookup(urlObj.hostname, { all: true, verbatim: true });
        if (!resolved[0]) {
          throw new Error(`Unable to resolve custom target hostname: ${urlObj.hostname}`);
        }
        resolvedIp = resolved[0].address;
        resolvedFamily = resolved[0].family;
      } catch {
        throw new Error(`Unable to resolve custom target hostname: ${urlObj.hostname}`);
      }
    }
  }

  return {
    url: urlObj.toString(),
    hostname: urlObj.hostname,
    hostHeader: urlObj.host,
    resolvedIp,
    resolvedFamily,
  };
}

async function resolveMeshTargetDescriptor(targetName, targetConfig, config) {
  const normalizedTargetName = String(targetName || '').toLowerCase();
  const provider = normalizeProvider(targetConfig.provider || normalizedTargetName, 'custom');
  const enabled = targetConfig.enabled !== false;
  const staticHeaders = normalizeStaticHeaders(targetConfig.headers || {});
  const declaredContract = normalizeContract(
    targetConfig.contract,
    defaultContractForProvider(provider)
  );

  if (provider === 'custom') {
    const customTargetConfig = config.runtime?.upstream?.custom_targets || {};
    const rawCustomUrl = targetConfig.custom_url || targetConfig.base_url;
    if (!rawCustomUrl) {
      throw new Error(`Mesh target ${normalizedTargetName} requires custom_url or base_url`);
    }
    const validated = await validateCustomTargetUrl(rawCustomUrl, customTargetConfig);
    return {
      ...toDescriptor({
        targetName: normalizedTargetName,
        provider: 'custom',
        baseUrl: validated.url,
        contract: declaredContract,
        resolvedIp: validated.resolvedIp,
        resolvedFamily: validated.resolvedFamily,
        staticHeaders,
        source: 'mesh_target',
      }),
      enabled,
    };
  }

  const baseUrl = String(targetConfig.base_url || getBaseUrlForProvider(provider) || '');
  if (!baseUrl) {
    throw new Error(`Mesh target ${normalizedTargetName} has no resolvable base URL`);
  }

  return {
    ...toDescriptor({
      targetName: normalizedTargetName,
      provider,
      baseUrl,
      contract: declaredContract,
      staticHeaders,
      source: 'mesh_target',
    }),
    enabled,
  };
}

async function resolveBuiltinTargetDescriptor(target, req, config) {
  const normalizedTarget = String(target || 'openai').toLowerCase();

  if (normalizedTarget === 'custom') {
    const customUrl = req.headers['x-sentinel-custom-url'];
    if (!customUrl) {
      throw new Error('x-sentinel-custom-url is required when x-sentinel-target=custom');
    }
    const customTargetConfig = config.runtime?.upstream?.custom_targets || {};
    const validatedTarget = await validateCustomTargetUrl(customUrl, customTargetConfig);
    return toDescriptor({
      targetName: 'custom',
      provider: 'custom',
      baseUrl: validatedTarget.url,
      contract: 'passthrough',
      resolvedIp: validatedTarget.resolvedIp,
      resolvedFamily: validatedTarget.resolvedFamily,
      staticHeaders: {},
      source: 'header_target',
    });
  }

  const provider = normalizeProvider(normalizedTarget, 'openai');
  const baseUrl = getBaseUrlForProvider(provider);
  if (!baseUrl) {
    throw new Error(`Unknown upstream target: ${normalizedTarget}`);
  }

  return toDescriptor({
    targetName: provider,
    provider,
    baseUrl,
    contract: defaultContractForProvider(provider),
    staticHeaders: {},
    source: 'builtin',
  });
}

async function resolveTargetDescriptor(targetName, req, config, meshConfig) {
  const normalizedTargetName = String(targetName || '').toLowerCase();
  const meshTargets = meshConfig.targets || {};
  if (meshTargets[normalizedTargetName]) {
    return resolveMeshTargetDescriptor(normalizedTargetName, meshTargets[normalizedTargetName], config);
  }

  return resolveBuiltinTargetDescriptor(normalizedTargetName, req, config);
}

function getGroupConfig(meshConfig, groupName) {
  const groups = meshConfig.groups || {};
  const raw = groups[groupName];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }
  const targets = Array.isArray(raw.targets)
    ? raw.targets.map((value) => String(value).toLowerCase()).filter(Boolean)
    : [];
  return {
    name: groupName,
    enabled: raw.enabled !== false,
    contract: normalizeContract(raw.contract, ''),
    targets,
  };
}

function normalizeRequestedTarget(req) {
  return String(req.headers['x-sentinel-target'] || 'openai').toLowerCase();
}

function normalizeRequestedGroup(req) {
  const raw = req.headers['x-sentinel-target-group'];
  if (!raw) {
    return '';
  }
  return String(raw).toLowerCase();
}

function normalizeRequestedContract(req) {
  const raw = req.headers['x-sentinel-contract'];
  if (!raw) {
    return '';
  }
  return normalizeContract(raw, '');
}

async function resolveUpstreamPlan(req, config = {}) {
  const requestedTarget = normalizeRequestedTarget(req);
  const meshConfig = normalizeMeshConfig(config.runtime?.upstream?.resilience_mesh || {});
  const canaryConfig = normalizeCanaryConfig(config.runtime?.upstream?.canary || {});

  const explicitGroup = normalizeRequestedGroup(req);
  let selectedGroup = '';
  let routeSource = 'target';
  let canaryDecision = null;

  if (meshConfig.enabled && explicitGroup) {
    selectedGroup = explicitGroup;
    routeSource = 'group_header';
  } else if (meshConfig.enabled) {
    canaryDecision = selectCanaryGroup(req, requestedTarget, canaryConfig);
    if (canaryDecision) {
      selectedGroup = canaryDecision.selectedGroup;
      routeSource = 'canary';
    } else if (meshConfig.defaultGroup) {
      selectedGroup = meshConfig.defaultGroup;
      routeSource = 'default_group';
    }
  }

  let groupContract = '';
  let targetNames;

  if (meshConfig.enabled && selectedGroup) {
    const group = getGroupConfig(meshConfig, selectedGroup);
    if (!group || group.enabled === false) {
      throw new Error(`Unknown or disabled upstream group: ${selectedGroup}`);
    }
    if (group.targets.length === 0) {
      throw new Error(`Upstream group ${selectedGroup} has no targets`);
    }
    targetNames = group.targets;
    groupContract = group.contract;
  } else {
    targetNames = [requestedTarget];
  }

  const candidates = [];
  for (const targetName of targetNames) {
    const descriptor = await resolveTargetDescriptor(targetName, req, config, meshConfig);
    if (descriptor.enabled === false) {
      continue;
    }
    candidates.push(descriptor);
  }

  if (candidates.length === 0) {
    throw new Error('No enabled upstream targets available for selected route plan');
  }

  const requestedContract = normalizeRequestedContract(req);
  const desiredContract = normalizeContract(
    requestedContract || groupContract || meshConfig.contract || candidates[0].contract,
    'passthrough'
  );

  const failoverEnabled = meshConfig.enabled && candidates.length > 1;
  const maxFailoverHops = failoverEnabled
    ? Math.min(meshConfig.maxFailoverHops, Math.max(0, candidates.length - 1))
    : 0;

  return {
    requestedTarget,
    selectedGroup: selectedGroup || null,
    routeSource,
    desiredContract,
    canary: canaryDecision,
    candidates,
    primary: candidates[0],
    failover: {
      enabled: failoverEnabled,
      maxFailoverHops,
      allowPostWithIdempotencyKey: meshConfig.allowPostWithIdempotencyKey,
      onStatus: meshConfig.failoverOnStatus,
      onErrorTypes: meshConfig.failoverOnErrors,
    },
  };
}

async function resolveProvider(req, config = {}) {
  const plan = await resolveUpstreamPlan(req, config);
  const primary = plan.primary;
  return {
    provider: primary.provider,
    baseUrl: primary.baseUrl,
    upstreamHostname: primary.upstreamHostname,
    upstreamHostHeader: primary.upstreamHostHeader,
    resolvedIp: primary.resolvedIp,
    resolvedFamily: primary.resolvedFamily,
  };
}

module.exports = {
  resolveProvider,
  resolveUpstreamPlan,
  validateCustomTargetUrl,
  isPrivateAddress,
  normalizeMeshConfig,
  normalizeCanaryConfig,
  normalizeContract,
  defaultContractForProvider,
};
