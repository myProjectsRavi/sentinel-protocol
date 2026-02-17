const { summarizePIITypes } = require('../../src/monitor/tui');

describe('monitor tui helpers', () => {
  test('summarizePIITypes returns top pii type counts', () => {
    const summary = summarizePIITypes([
      { pii_types: ['email', 'ssn'] },
      { pii_types: ['email'] },
      { pii_types: ['credit_card'] },
    ]);

    expect(summary[0][0]).toBe('email');
    expect(summary[0][1]).toBe(2);
  });
});
