const { PIIScanner } = require('../../src/engines/pii-scanner');

function alphaToken(index) {
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  let value = index;
  let result = '';
  for (let i = 0; i < 8; i += 1) {
    result += chars[value % chars.length];
    value = Math.floor(value / chars.length);
  }
  return result;
}

function buildCorpus() {
  const criticalPositives = [];
  const mediumPositives = [];
  for (let i = 0; i < 120; i += 1) {
    criticalPositives.push(`openai key sk-proj-${alphaToken(i)}${alphaToken(i + 200)}ABCDEFGHIJKLMNOP`);
  }
  for (let i = 0; i < 90; i += 1) {
    criticalPositives.push(`user ssn is 123-45-${String(1000 + i)} and must stay private`);
  }
  for (let i = 0; i < 90; i += 1) {
    mediumPositives.push(`contact email sample${i}@example.org and phone +1415555${String(1000 + i)}`);
  }

  const positives = [...criticalPositives, ...mediumPositives];

  const negatives = [];
  for (let i = 0; i < 300; i += 1) {
    negatives.push(`harmless message ${alphaToken(i)} contains no secrets or personal fields`);
  }

  return { positives, criticalPositives, negatives };
}

describe('PII corpus quality gate', () => {
  test('meets minimum quality thresholds', () => {
    const scanner = new PIIScanner();
    const { positives, criticalPositives, negatives } = buildCorpus();

    let criticalTruePositives = 0;
    let criticalFalsePositives = 0;
    let positivesDetected = 0;
    let negativesFlagged = 0;

    positives.forEach((sample) => {
      const result = scanner.scan(sample);
      if (result.findings.length > 0) {
        positivesDetected += 1;
      }
      if (result.findings.some((item) => item.severity === 'critical')) {
        criticalTruePositives += 1;
      }
    });

    negatives.forEach((sample) => {
      const result = scanner.scan(sample);
      if (result.findings.length > 0) {
        negativesFlagged += 1;
      }
      if (result.findings.some((item) => item.severity === 'critical')) {
        criticalFalsePositives += 1;
      }
    });

    const criticalPrecision = criticalTruePositives / Math.max(criticalTruePositives + criticalFalsePositives, 1);
    let criticalDetectedFromCriticalSet = 0;
    criticalPositives.forEach((sample) => {
      const result = scanner.scan(sample);
      if (result.findings.some((item) => item.severity === 'critical')) {
        criticalDetectedFromCriticalSet += 1;
      }
    });

    const criticalRecall = criticalDetectedFromCriticalSet / criticalPositives.length;
    const overallFalsePositiveRate = negativesFlagged / negatives.length;

    expect(positives.length).toBe(300);
    expect(negatives.length).toBe(300);
    expect(criticalPrecision).toBeGreaterThanOrEqual(0.98);
    expect(criticalRecall).toBeGreaterThanOrEqual(0.95);
    expect(overallFalsePositiveRate).toBeLessThanOrEqual(0.015);

    expect(positivesDetected).toBeGreaterThanOrEqual(285);
  });
});
