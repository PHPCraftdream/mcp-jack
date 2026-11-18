const isDigit = (c) => c >= '0' && c <= '9';

export const parseStrictJson = (source) => {
  const text = typeof source === 'string' ? source : new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(source));
  let at = 0;
  const whitespace = () => { while (at < text.length && ' \t\r\n'.includes(text[at])) at += 1; };
  const fail = () => { throw new SyntaxError(`invalid strict JSON at ${at}`); };
  const parseString = () => {
    const start = at;
    if (text[at] !== '"') fail();
    at += 1;
    while (at < text.length) {
      const c = text[at++];
      if (c === '"') {
        const value = JSON.parse(text.slice(start, at));
        if (typeof value !== 'string' || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) fail();
        return value;
      }
      if (c === '\\') {
        if (at >= text.length) fail();
        if (text[at] === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(at + 1, at + 5))) fail();
          at += 5;
        } else {
          if (!'"\\/bfnrt'.includes(text[at])) fail();
          at += 1;
        }
      } else if (c.charCodeAt(0) < 0x20) fail();
    }
    fail();
  };
  const parseNumber = () => {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(at));
    if (!match) fail();
    at += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) fail();
    return { value, raw: match[0] };
  };
  const value = () => {
    whitespace();
    const c = text[at];
    if (c === '"') return parseString();
    if (c === '{') {
      at += 1;
      whitespace();
      const object = Object.create(null);
      const names = new Set();
      if (text[at] === '}') { at += 1; return object; }
      for (;;) {
        whitespace();
        const name = parseString();
        if (names.has(name)) throw new SyntaxError(`duplicate member ${name}`);
        names.add(name);
        whitespace();
        if (text[at++] !== ':') fail();
        object[name] = value();
        whitespace();
        if (text[at] === '}') { at += 1; return object; }
        if (text[at++] !== ',') fail();
      }
    }
    if (c === '[') {
      at += 1;
      whitespace();
      const array = [];
      if (text[at] === ']') { at += 1; return array; }
      for (;;) {
        array.push(value());
        whitespace();
        if (text[at] === ']') { at += 1; return array; }
        if (text[at++] !== ',') fail();
      }
    }
    if (text.startsWith('true', at)) { at += 4; return true; }
    if (text.startsWith('false', at)) { at += 5; return false; }
    if (text.startsWith('null', at)) { at += 4; return null; }
    return parseNumber();
  };
  const parsed = value();
  whitespace();
  if (at !== text.length) fail();
  return { value: parsed, text };
};

export const parsedNumberIsIntegerLiteral = (parsed) => parsed && typeof parsed === 'object' && Object.hasOwn(parsed, 'raw')
  ? !/[.eE]/.test(parsed.raw) && Number.isSafeInteger(parsed.value)
  : false;
