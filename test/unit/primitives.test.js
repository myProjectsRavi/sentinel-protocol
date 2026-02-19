const {
  clampPositiveInt,
  normalizeMode,
  normalizeSessionValue,
  cosineSimilarity,
  snippetHash,
} = require('../../src/utils/primitives');

describe('primitives', () => {
  test('clampPositiveInt enforces bounds', () => {
    expect(clampPositiveInt(10, 5, 1, 100)).toBe(10);
    expect(clampPositiveInt('x', 5, 1, 100)).toBe(5);
    expect(clampPositiveInt(200, 5, 1, 100)).toBe(5);
  });

  test('normalizeMode uses allowlist', () => {
    expect(normalizeMode('BLOCK', 'monitor', ['monitor', 'block'])).toBe('block');
    expect(normalizeMode('enforce', 'monitor', ['monitor', 'block'])).toBe('monitor');
  });

  test('normalizeSessionValue limits output length', () => {
    expect(normalizeSessionValue('  a  ', 3)).toBe('a');
    expect(normalizeSessionValue('abcdef', 4)).toBe('abcd');
  });

  test('cosineSimilarity returns bounded value', () => {
    expect(cosineSimilarity([1, 0], [1, 0])).toBeCloseTo(1, 5);
    expect(cosineSimilarity([1, 0], [0, 1])).toBeCloseTo(0, 5);
  });

  test('snippetHash returns deterministic prefix', () => {
    expect(snippetHash('sentinel', 12)).toHaveLength(12);
    expect(snippetHash('sentinel', 12)).toBe(snippetHash('sentinel', 12));
  });
});
