const { maskValueForPattern } = require('../../src/engines/masking');

describe('format-preserving masking', () => {
  test('masks emails with valid pseudonymous shape', () => {
    const masked = maskValueForPattern('email_address', 'ravi.teja@company.io', {
      mode: 'format_preserving',
      salt: 'unit-test',
    });
    expect(masked).toMatch(/^user_[a-z]{8}@example\.com$/);
  });

  test('masks phones while preserving separators', () => {
    const masked = maskValueForPattern('phone_us', '+1 (555) 123-9876', {
      mode: 'format_preserving',
      salt: 'unit-test',
    });
    expect(masked).toMatch(/^\+1 \(\d{3}\) \d{3}-\d{4}$/);
  });

  test('placeholder mode keeps explicit redaction marker', () => {
    const masked = maskValueForPattern('email_address', 'alice@example.com', {
      mode: 'placeholder',
    });
    expect(masked).toBe('[REDACTED_EMAIL_ADDRESS]');
  });
});
