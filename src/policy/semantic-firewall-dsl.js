const { clampPositiveInt } = require('../utils/primitives');

const KEYWORDS = new Set(['AND', 'OR', 'NOT', 'WHEN', 'BLOCK', 'WARN', 'ALLOW', 'IN', 'CONTAINS', 'TRUE', 'FALSE']);
const OPERATORS = new Set(['==', '!=', '>=', '<=', '>', '<', 'IN', 'CONTAINS']);

function tokenize(input = '') {
  const text = String(input || '');
  const tokens = [];
  let idx = 0;
  while (idx < text.length) {
    const ch = text[idx];
    if (/\s/.test(ch)) {
      idx += 1;
      continue;
    }
    const two = text.slice(idx, idx + 2);
    if (['==', '!=', '>=', '<='].includes(two)) {
      tokens.push({ type: 'OP', value: two });
      idx += 2;
      continue;
    }
    if (['(', ')', '>', '<'].includes(ch)) {
      tokens.push({ type: ch === '(' || ch === ')' ? ch : 'OP', value: ch });
      idx += 1;
      continue;
    }
    if (ch === '"' || ch === '\'') {
      const quote = ch;
      idx += 1;
      let out = '';
      while (idx < text.length) {
        const cur = text[idx];
        if (cur === '\\') {
          const next = text[idx + 1];
          if (next) {
            out += next;
            idx += 2;
            continue;
          }
        }
        if (cur === quote) {
          idx += 1;
          break;
        }
        out += cur;
        idx += 1;
      }
      tokens.push({ type: 'STRING', value: out });
      continue;
    }
    const ident = /^[A-Za-z_][A-Za-z0-9_.-]*/.exec(text.slice(idx));
    if (ident) {
      const raw = ident[0];
      const upper = raw.toUpperCase();
      if (KEYWORDS.has(upper)) {
        tokens.push({ type: 'KW', value: upper });
      } else {
        tokens.push({ type: 'IDENT', value: raw });
      }
      idx += raw.length;
      continue;
    }
    const num = /^[0-9]+(?:\.[0-9]+)?/.exec(text.slice(idx));
    if (num) {
      tokens.push({ type: 'NUMBER', value: Number(num[0]) });
      idx += num[0].length;
      continue;
    }
    throw new Error(`dsl_token_invalid:${ch}@${idx}`);
  }
  return tokens;
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek() {
    return this.tokens[this.pos] || null;
  }

  consume() {
    const tok = this.peek();
    this.pos += 1;
    return tok;
  }

  expect(type, value = undefined) {
    const tok = this.peek();
    if (!tok || tok.type !== type || (value !== undefined && tok.value !== value)) {
      throw new Error(`dsl_parse_expected:${type}${value ? `:${value}` : ''}@${this.pos}`);
    }
    return this.consume();
  }

  parseRule() {
    const actionToken = this.expect('KW');
    if (!['BLOCK', 'WARN', 'ALLOW'].includes(actionToken.value)) {
      throw new Error(`dsl_parse_action_invalid:${actionToken.value}`);
    }
    this.expect('KW', 'WHEN');
    const expression = this.parseExpression();
    if (this.peek()) {
      throw new Error(`dsl_parse_trailing_tokens@${this.pos}`);
    }
    return {
      action: actionToken.value.toLowerCase(),
      expression,
    };
  }

  parseExpression() {
    return this.parseOr();
  }

  parseOr() {
    let left = this.parseAnd();
    while (this.peek()?.type === 'KW' && this.peek()?.value === 'OR') {
      this.consume();
      const right = this.parseAnd();
      left = { type: 'OR', left, right };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseNot();
    while (this.peek()?.type === 'KW' && this.peek()?.value === 'AND') {
      this.consume();
      const right = this.parseNot();
      left = { type: 'AND', left, right };
    }
    return left;
  }

  parseNot() {
    if (this.peek()?.type === 'KW' && this.peek()?.value === 'NOT') {
      this.consume();
      return { type: 'NOT', value: this.parseNot() };
    }
    return this.parsePrimary();
  }

  parsePrimary() {
    if (this.peek()?.type === '(') {
      this.consume();
      const expr = this.parseExpression();
      this.expect(')');
      return expr;
    }
    return this.parseComparison();
  }

  parseComparison() {
    const left = this.expect('IDENT').value;
    const opToken = this.consume();
    if (!opToken) {
      throw new Error('dsl_parse_operator_missing');
    }
    const operator = opToken.type === 'KW' ? opToken.value : opToken.value;
    if (!OPERATORS.has(operator)) {
      throw new Error(`dsl_parse_operator_invalid:${operator}`);
    }
    const rightToken = this.consume();
    if (!rightToken) {
      throw new Error('dsl_parse_value_missing');
    }
    let rightValue;
    if (rightToken.type === 'STRING' || rightToken.type === 'NUMBER') {
      rightValue = rightToken.value;
    } else if (rightToken.type === 'KW' && (rightToken.value === 'TRUE' || rightToken.value === 'FALSE')) {
      rightValue = rightToken.value === 'TRUE';
    } else if (rightToken.type === 'IDENT') {
      rightValue = { ref: rightToken.value };
    } else {
      throw new Error(`dsl_parse_value_invalid:${rightToken.type}`);
    }
    return {
      type: 'CMP',
      left,
      operator,
      right: rightValue,
    };
  }
}

function resolvePath(context, path) {
  const source = context && typeof context === 'object' ? context : {};
  const parts = String(path || '').split('.').filter(Boolean);
  let cur = source;
  for (const part of parts) {
    if (!cur || typeof cur !== 'object') {
      return undefined;
    }
    cur = cur[part];
  }
  return cur;
}

function compareValues(left, operator, right) {
  const l = left;
  const r = right && typeof right === 'object' && right.ref ? undefined : right;
  if (operator === '==') {
    return String(l) === String(r);
  }
  if (operator === '!=') {
    return String(l) !== String(r);
  }
  if (operator === '>') {
    return Number(l) > Number(r);
  }
  if (operator === '<') {
    return Number(l) < Number(r);
  }
  if (operator === '>=') {
    return Number(l) >= Number(r);
  }
  if (operator === '<=') {
    return Number(l) <= Number(r);
  }
  if (operator === 'IN') {
    if (Array.isArray(l)) {
      return l.map((item) => String(item)).includes(String(r));
    }
    return String(l).split(',').map((item) => item.trim()).includes(String(r));
  }
  if (operator === 'CONTAINS') {
    return String(l || '').toLowerCase().includes(String(r || '').toLowerCase());
  }
  return false;
}

function evaluateExpression(node, context) {
  if (!node || typeof node !== 'object') {
    return false;
  }
  if (node.type === 'OR') {
    return evaluateExpression(node.left, context) || evaluateExpression(node.right, context);
  }
  if (node.type === 'AND') {
    return evaluateExpression(node.left, context) && evaluateExpression(node.right, context);
  }
  if (node.type === 'NOT') {
    return !evaluateExpression(node.value, context);
  }
  if (node.type === 'CMP') {
    const left = resolvePath(context, node.left);
    const right = node.right && typeof node.right === 'object' && node.right.ref
      ? resolvePath(context, node.right.ref)
      : node.right;
    return compareValues(left, node.operator, right);
  }
  return false;
}

function compileRule(input) {
  const tokens = tokenize(input);
  const parser = new Parser(tokens);
  const parsed = parser.parseRule();
  return {
    source: String(input || ''),
    action: parsed.action,
    matches(context) {
      return evaluateExpression(parsed.expression, context);
    },
  };
}

function compileRules(rules, options = {}) {
  const source = Array.isArray(rules) ? rules : [];
  const maxRules = clampPositiveInt(options.maxRules, 128, 1, 4096);
  const out = [];
  for (const item of source.slice(0, maxRules)) {
    out.push(compileRule(item));
  }
  return out;
}

module.exports = {
  tokenize,
  compileRule,
  compileRules,
  evaluateExpression,
};
