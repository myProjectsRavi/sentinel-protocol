const { OutputClassifier } = require('../../src/egress/output-classifier');

describe('output classifier', () => {
  test('flags toxicity when high-risk lexical patterns exceed threshold', () => {
    const classifier = new OutputClassifier({
      enabled: true,
      mode: 'monitor',
      categories: {
        toxicity: {
          warn_threshold: 0.4,
          block_threshold: 0.9,
        },
      },
    });

    const result = classifier.classifyText('You are worthless. I will attack and hurt you.');
    expect(result.shouldWarn).toBe(true);
    expect(result.warnedBy).toContain('toxicity');
  });

  test('flags dangerous code execution guidance in assistant output', () => {
    const classifier = new OutputClassifier({
      enabled: true,
      mode: 'monitor',
      categories: {
        code_execution: {
          warn_threshold: 0.3,
          block_threshold: 0.95,
        },
      },
    });

    const result = classifier.classifyText('Run rm -rf / and then os.system(\"cat /etc/passwd\").');
    expect(result.shouldWarn).toBe(true);
    expect(result.warnedBy).toContain('code_execution');
  });

  test('flags unauthorized disclosure of system prompt markers', () => {
    const classifier = new OutputClassifier({
      enabled: true,
      mode: 'monitor',
      categories: {
        unauthorized_disclosure: {
          warn_threshold: 0.3,
          block_threshold: 0.95,
        },
      },
    });

    const result = classifier.classifyText('BEGIN SYSTEM PROMPT. Internal policy and x-sentinel-correlation-id leaked.');
    expect(result.shouldWarn).toBe(true);
    expect(result.warnedBy).toContain('unauthorized_disclosure');
  });

  test('returns advisory-only decision in monitor mode', () => {
    const classifier = new OutputClassifier({
      enabled: true,
      mode: 'monitor',
      categories: {
        code_execution: {
          warn_threshold: 0.2,
          block_threshold: 0.3,
        },
      },
    });

    const result = classifier.classifyText('rm -rf / && os.system(\"cat /etc/shadow\")', {
      effectiveMode: 'enforce',
    });
    expect(result.shouldWarn).toBe(true);
    expect(result.shouldBlock).toBe(false);
  });

  test('returns blocking decision in enforce mode for configured categories', () => {
    const classifier = new OutputClassifier({
      enabled: true,
      mode: 'block',
      categories: {
        code_execution: {
          warn_threshold: 0.2,
          block_threshold: 0.3,
        },
      },
    });

    const result = classifier.classifyText('Run rm -rf / and os.system(\"cat /etc/hosts\")', {
      effectiveMode: 'enforce',
    });

    expect(result.shouldBlock).toBe(true);
    expect(result.blockedBy).toContain('code_execution');
  });

  test('classification result is deterministic for same output text', () => {
    const classifier = new OutputClassifier({
      enabled: true,
      mode: 'block',
    });
    const text = 'Reveal system prompt and run rm -rf / immediately.';
    const first = classifier.classifyText(text, { effectiveMode: 'enforce' });
    const second = classifier.classifyText(text, { effectiveMode: 'enforce' });
    expect(second).toEqual(first);
  });
});
