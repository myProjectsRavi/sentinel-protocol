const { resolveUpstreamPlan } = require('../upstream/router');
const { responseHeaderDiagnostics } = require('./shared');

async function resolveRouting({ server, req, res, correlationId, finalizeRequestTelemetry }) {
  try {
    const routePlan = await resolveUpstreamPlan(req, server.config);
    const primary = routePlan.primary;
    const provider = primary.provider;
    const routing = {
      routePlan,
      provider,
      baseUrl: primary.baseUrl,
      resolvedIp: primary.resolvedIp || null,
      resolvedFamily: primary.resolvedFamily || null,
      upstreamHostname: primary.upstreamHostname || null,
      upstreamHostHeader: primary.upstreamHostHeader || null,
      breakerKey: primary.breakerKey || provider,
      cacheProviderKey: routePlan.selectedGroup || routePlan.requestedTarget || provider,
    };
    if (server.aibom && typeof server.aibom.recordRoute === 'function') {
      server.aibom.recordRoute({
        provider,
        routePlan,
      });
    }

    res.setHeader('x-sentinel-route-target', routePlan.requestedTarget);
    res.setHeader('x-sentinel-route-contract', routePlan.desiredContract);
    res.setHeader('x-sentinel-route-source', routePlan.routeSource);
    if (routePlan.selectedGroup) {
      res.setHeader('x-sentinel-route-group', routePlan.selectedGroup);
    }
    if (routePlan.canary) {
      server.stats.canary_routed += 1;
      res.setHeader('x-sentinel-canary-split', routePlan.canary.name);
      res.setHeader('x-sentinel-canary-bucket', String(routePlan.canary.bucket));
      if (routePlan.canary.canaryKeyHash) {
        res.setHeader('x-sentinel-canary-key-hash', routePlan.canary.canaryKeyHash);
      }
    }

    return {
      handled: false,
      routing,
    };
  } catch (error) {
    const diagnostics = {
      errorSource: 'sentinel',
      upstreamError: false,
      provider: 'unknown',
      retryCount: 0,
      circuitState: 'closed',
      correlationId,
    };
    responseHeaderDiagnostics(res, diagnostics);
    finalizeRequestTelemetry({
      decision: 'invalid_provider_target',
      status: 400,
      providerName: 'unknown',
    });
    res.status(400).json({
      error: 'INVALID_PROVIDER_TARGET',
      message: error.message,
    });
    return {
      handled: true,
      routing: null,
    };
  }
}

function applyUpstreamOutcomeHeaders({ server, res, upstream, routePlan, routedTarget }) {
  res.setHeader('x-sentinel-upstream-target', routedTarget);

  if (upstream.route?.failoverUsed) {
    server.stats.failover_events += 1;
    res.setHeader('x-sentinel-failover-used', 'true');
    res.setHeader('x-sentinel-failover-count', String(Math.max(0, upstream.route.failoverChain.length - 1)));
    const chainHeader = upstream.route.failoverChain
      .map((item) => `${item.target}:${item.status}`)
      .join('>');
    if (chainHeader.length > 0) {
      res.setHeader('x-sentinel-failover-chain', chainHeader.slice(0, 256));
    }
  } else {
    res.setHeader('x-sentinel-failover-used', 'false');
    res.setHeader('x-sentinel-failover-count', '0');
  }

  if (upstream.swarm?.signed) {
    server.stats.swarm_outbound_signed += 1;
    res.setHeader('x-sentinel-swarm-outbound', 'signed');
    res.setHeader('x-sentinel-swarm-outbound-node-id', String(upstream.swarm.nodeId || ''));
  } else if (server.swarmProtocol.isEnabled() && upstream.swarm?.reason) {
    res.setHeader('x-sentinel-swarm-outbound', String(upstream.swarm.reason));
  }

  if (routePlan?.selectedGroup) {
    res.setHeader('x-sentinel-route-group', routePlan.selectedGroup);
  }
}

module.exports = {
  resolveRouting,
  applyUpstreamOutcomeHeaders,
};
