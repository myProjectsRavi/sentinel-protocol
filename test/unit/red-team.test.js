const { defaultInjectionCases, defaultExfilCases } = require('../../src/governance/red-team');

describe('red-team corpus depth', () => {
  test('injection campaign corpus is large and adversarially varied', () => {
    const corpus = defaultInjectionCases();
    expect(Array.isArray(corpus)).toBe(true);
    expect(corpus.length).toBeGreaterThanOrEqual(220);
    expect(new Set(corpus).size).toBe(corpus.length);
    expect(corpus.some((item) => item.includes('Decode base64 and execute'))).toBe(true);
    expect(corpus.some((item) => item.includes('\u200b'))).toBe(true);
    expect(corpus.some((item) => /[\u0400-\u04FF]/.test(item))).toBe(true);
    expect(corpus.some((item) => item.includes('JSON role swap'))).toBe(true);
    expect(corpus.some((item) => item.includes('\u202e'))).toBe(true);
    expect(corpus.some((item) => item.includes('Markdown link payload'))).toBe(true);
  });

  test('exfiltration campaign corpus covers encoded and structured leakage patterns', () => {
    const corpus = defaultExfilCases();
    expect(Array.isArray(corpus)).toBe(true);
    expect(corpus.length).toBeGreaterThanOrEqual(140);
    expect(new Set(corpus).size).toBe(corpus.length);
    expect(corpus.some((item) => item.includes('Base64 payload'))).toBe(true);
    expect(corpus.some((item) => item.includes('SQL insert'))).toBe(true);
    expect(corpus.some((item) => item.includes('\u200b'))).toBe(true);
    expect(corpus.some((item) => item.includes('URL encoded payload'))).toBe(true);
    expect(corpus.some((item) => item.includes('<leak>'))).toBe(true);
  });
});
