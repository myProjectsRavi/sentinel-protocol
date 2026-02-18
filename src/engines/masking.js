const crypto = require('crypto');

function hashHex(input, salt = '') {
  return crypto.createHash('sha256').update(String(salt)).update('::').update(String(input)).digest('hex');
}

function hashDigits(input, count, salt = '') {
  const hex = hashHex(input, salt);
  let out = '';
  let idx = 0;
  while (out.length < count) {
    const code = Number.parseInt(hex[idx % hex.length], 16);
    out += String(code % 10);
    idx += 1;
  }
  return out;
}

function hashLetters(input, count, salt = '') {
  const hex = hashHex(input, salt);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  let out = '';
  let idx = 0;
  while (out.length < count) {
    const code = Number.parseInt(hex[idx % hex.length], 16);
    out += alphabet[code % alphabet.length];
    idx += 1;
  }
  return out;
}

function maskByShape(value, salt = '') {
  const digits = hashDigits(value, String(value).replace(/\D/g, '').length || 1, salt);
  const letters = hashLetters(value, String(value).replace(/[^A-Za-z]/g, '').length || 1, salt);
  let d = 0;
  let l = 0;
  let out = '';
  for (const ch of String(value)) {
    if (/[0-9]/.test(ch)) {
      out += digits[d] || '0';
      d += 1;
    } else if (/[A-Z]/.test(ch)) {
      out += (letters[l] || 'a').toUpperCase();
      l += 1;
    } else if (/[a-z]/.test(ch)) {
      out += letters[l] || 'a';
      l += 1;
    } else {
      out += ch;
    }
  }
  return out;
}

function formatPreservingEmail(value, salt = '') {
  const local = hashLetters(value, 8, salt);
  return `user_${local}@example.com`;
}

function formatPreservingPhone(value, salt = '') {
  const digitCount = String(value).replace(/\D/g, '').length;
  const digits = hashDigits(value, Math.max(7, digitCount), salt);
  let idx = 0;
  let out = '';
  for (const ch of String(value)) {
    if (/[0-9]/.test(ch)) {
      out += digits[idx] || '0';
      idx += 1;
    } else if (ch === '+') {
      out += '+';
    } else if (/[\-().\s]/.test(ch)) {
      out += ch;
    } else {
      out += ch;
    }
  }
  return out;
}

function formatPreservingIpv4(value, salt = '') {
  const seed = hashHex(value, salt);
  const octets = [];
  for (let i = 0; i < 3; i += 1) {
    const pair = seed.slice(i * 2, i * 2 + 2) || '00';
    const num = Number.parseInt(pair, 16) % 256;
    octets.push(String(num));
  }
  return `10.${octets[0]}.${octets[1]}.${octets[2]}`;
}

function formatPreservingIpv6(value, salt = '') {
  const seed = hashHex(value, salt);
  const a = seed.slice(0, 4) || '0000';
  const b = seed.slice(4, 8) || '0000';
  const c = seed.slice(8, 12) || '0000';
  const d = seed.slice(12, 16) || '0000';
  return `2001:db8:${a}:${b}:${c}:${d}:0:1`;
}

function formatPreservingMac(value, salt = '') {
  const seed = hashHex(value, salt).slice(0, 12).padEnd(12, '0');
  const pairs = [];
  for (let i = 0; i < 12; i += 2) {
    pairs.push(seed.slice(i, i + 2));
  }
  // Locally administered unicast.
  pairs[0] = '02';
  return pairs.join(':');
}

function maskValueForPattern(patternId, value, options = {}) {
  const mode = String(options.mode || 'placeholder').toLowerCase();
  const salt = String(options.salt || '');
  if (mode !== 'format_preserving') {
    return `[REDACTED_${String(patternId || 'UNKNOWN').toUpperCase()}]`;
  }

  const id = String(patternId || '').toLowerCase();
  if (id === 'email_address') {
    return formatPreservingEmail(value, salt);
  }
  if (id === 'phone_us' || id === 'phone_e164') {
    return formatPreservingPhone(value, salt);
  }
  if (id === 'ipv4_address') {
    return formatPreservingIpv4(value, salt);
  }
  if (id === 'ipv6_address') {
    return formatPreservingIpv6(value, salt);
  }
  if (id === 'mac_address') {
    return formatPreservingMac(value, salt);
  }

  return maskByShape(value, salt);
}

module.exports = {
  hashHex,
  maskValueForPattern,
  maskByShape,
  formatPreservingEmail,
  formatPreservingPhone,
  formatPreservingIpv4,
  formatPreservingIpv6,
  formatPreservingMac,
};
