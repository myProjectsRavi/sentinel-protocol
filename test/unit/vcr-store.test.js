const fs = require('fs');
const os = require('os');
const path = require('path');

describe('VCRStore', () => {
  test('records and replays deterministic responses', async () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-home-vcr-'));
    const tapePath = path.join(tmpHome, 'vcr.jsonl');
    process.env.SENTINEL_HOME = tmpHome;
    jest.resetModules();
    const { VCRStore } = require('../../src/runtime/vcr-store');

    const requestMeta = {
      provider: 'custom',
      method: 'POST',
      pathWithQuery: '/v1/chat/completions',
      contentType: 'application/json',
      wantsStream: false,
      bodyBuffer: Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: 'Capital of France?' }] })),
    };

    const responseBody = Buffer.from(JSON.stringify({ output: 'Paris' }));
    const recorder = new VCRStore({
      enabled: true,
      mode: 'record',
      tape_file: tapePath,
      max_entries: 10,
    });
    recorder.record(requestMeta, {
      status: 200,
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer should-not-be-recorded',
      },
      bodyBuffer: responseBody,
    });
    await recorder.flush();

    expect(fs.existsSync(tapePath)).toBe(true);
    const replay = new VCRStore({
      enabled: true,
      mode: 'replay',
      tape_file: tapePath,
      max_entries: 10,
      strict_replay: true,
    });

    const hit = replay.lookup(requestMeta);
    expect(hit.hit).toBe(true);
    expect(hit.response.status).toBe(200);
    expect(hit.response.headers.authorization).toBeUndefined();
    expect(hit.response.bodyBuffer.toString('utf8')).toBe(responseBody.toString('utf8'));
  });

  test('returns miss and strict replay flag when no entry exists', () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-home-vcr-'));
    process.env.SENTINEL_HOME = tmpHome;
    jest.resetModules();
    const { VCRStore } = require('../../src/runtime/vcr-store');

    const replay = new VCRStore({
      enabled: true,
      mode: 'replay',
      tape_file: path.join(tmpHome, 'missing.jsonl'),
      strict_replay: true,
    });

    const miss = replay.lookup({
      provider: 'custom',
      method: 'GET',
      pathWithQuery: '/v1/models',
      contentType: '',
      wantsStream: false,
      bodyBuffer: Buffer.alloc(0),
    });

    expect(miss.hit).toBe(false);
    expect(miss.strictReplay).toBe(true);
  });
});
