function resolveProvider(req) {
  const target = String(req.headers['x-sentinel-target'] || 'openai').toLowerCase();

  if (target === 'anthropic') {
    return { provider: 'anthropic', baseUrl: process.env.SENTINEL_ANTHROPIC_URL || 'https://api.anthropic.com' };
  }
  if (target === 'google') {
    return {
      provider: 'google',
      baseUrl: process.env.SENTINEL_GOOGLE_URL || 'https://generativelanguage.googleapis.com',
    };
  }
  if (target === 'custom') {
    const customUrl = req.headers['x-sentinel-custom-url'];
    if (!customUrl) {
      throw new Error('x-sentinel-custom-url is required when x-sentinel-target=custom');
    }
    return { provider: 'custom', baseUrl: String(customUrl) };
  }

  return { provider: 'openai', baseUrl: process.env.SENTINEL_OPENAI_URL || 'https://api.openai.com' };
}

module.exports = {
  resolveProvider,
};
