const dns = require('dns').promises;
const net = require('net');

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

async function resolveProvider(req, config = {}) {
  const target = String(req.headers['x-sentinel-target'] || 'openai').toLowerCase();

  if (target === 'anthropic') {
    const baseUrl = process.env.SENTINEL_ANTHROPIC_URL || 'https://api.anthropic.com';
    const parsed = new URL(baseUrl);
    return {
      provider: 'anthropic',
      baseUrl,
      upstreamHostname: parsed.hostname,
      upstreamHostHeader: parsed.host,
      resolvedIp: null,
      resolvedFamily: null,
    };
  }
  if (target === 'google') {
    const baseUrl = process.env.SENTINEL_GOOGLE_URL || 'https://generativelanguage.googleapis.com';
    const parsed = new URL(baseUrl);
    return {
      provider: 'google',
      baseUrl,
      upstreamHostname: parsed.hostname,
      upstreamHostHeader: parsed.host,
      resolvedIp: null,
      resolvedFamily: null,
    };
  }
  if (target === 'custom') {
    const customUrl = req.headers['x-sentinel-custom-url'];
    if (!customUrl) {
      throw new Error('x-sentinel-custom-url is required when x-sentinel-target=custom');
    }
    const customTargetConfig = config.runtime?.upstream?.custom_targets || {};
    const validatedTarget = await validateCustomTargetUrl(customUrl, customTargetConfig);
    return {
      provider: 'custom',
      baseUrl: validatedTarget.url,
      upstreamHostname: validatedTarget.hostname,
      upstreamHostHeader: validatedTarget.hostHeader,
      resolvedIp: validatedTarget.resolvedIp,
      resolvedFamily: validatedTarget.resolvedFamily,
    };
  }

  const baseUrl = process.env.SENTINEL_OPENAI_URL || 'https://api.openai.com';
  const parsed = new URL(baseUrl);
  return {
    provider: 'openai',
    baseUrl,
    upstreamHostname: parsed.hostname,
    upstreamHostHeader: parsed.host,
    resolvedIp: null,
    resolvedFamily: null,
  };
}

module.exports = {
  resolveProvider,
  validateCustomTargetUrl,
  isPrivateAddress,
};
