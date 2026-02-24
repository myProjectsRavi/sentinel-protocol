#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUT_PATH = path.resolve(__dirname, '..', 'docs', 'assets', 'sentinel-hero.gif');
const WIDTH = 480;
const HEIGHT = 270;
const FRAMES = 120;
const FRAME_DELAY_CS = 10; // 0.10s per frame

const PALETTE = [
  [0x08, 0x0d, 0x18], // 0 bg
  [0x12, 0x1c, 0x2f], // 1 panel
  [0x19, 0x27, 0x40], // 2 panel alt
  [0x63, 0xd7, 0xff], // 3 cyan
  [0x39, 0xf2, 0x9b], // 4 green
  [0xf9, 0xd4, 0x23], // 5 yellow
  [0xff, 0x5f, 0x74], // 6 red
  [0xe3, 0xec, 0xff], // 7 white
  [0x2c, 0x40, 0x67], // 8 muted
  [0x00, 0xd1, 0xb2], // 9 teal
  [0, 0, 0],
  [0, 0, 0],
  [0, 0, 0],
  [0, 0, 0],
  [0, 0, 0],
  [0, 0, 0],
];

class ByteWriter {
  constructor() {
    this.parts = [];
  }

  byte(value) {
    this.parts.push(Buffer.from([value & 0xff]));
  }

  bytes(values) {
    this.parts.push(Buffer.from(values.map((value) => value & 0xff)));
  }

  word(value) {
    this.parts.push(Buffer.from([value & 0xff, (value >> 8) & 0xff]));
  }

  text(value) {
    this.parts.push(Buffer.from(String(value), 'ascii'));
  }

  buffer(value) {
    this.parts.push(Buffer.from(value));
  }

  build() {
    return Buffer.concat(this.parts);
  }
}

function drawRect(frame, x, y, w, h, color) {
  const left = Math.max(0, x | 0);
  const top = Math.max(0, y | 0);
  const right = Math.min(WIDTH, (x + w) | 0);
  const bottom = Math.min(HEIGHT, (y + h) | 0);
  for (let yy = top; yy < bottom; yy += 1) {
    const row = yy * WIDTH;
    for (let xx = left; xx < right; xx += 1) {
      frame[row + xx] = color;
    }
  }
}

function drawFrame(frameIndex) {
  const pixels = new Uint8Array(WIDTH * HEIGHT);
  pixels.fill(0);

  // Shell background and panels.
  drawRect(pixels, 10, 12, 460, 246, 1);
  drawRect(pixels, 10, 12, 460, 20, 2);
  drawRect(pixels, 20, 40, 295, 206, 2);
  drawRect(pixels, 325, 40, 135, 206, 2);

  // Header status lights.
  drawRect(pixels, 24, 17, 8, 8, 6);
  drawRect(pixels, 36, 17, 8, 8, 5);
  drawRect(pixels, 48, 17, 8, 8, 4);

  // Left terminal stream lines.
  const lineCount = 24;
  for (let i = 0; i < lineCount; i += 1) {
    const y = 46 + i * 8;
    const phase = (frameIndex + i * 3) % 40;
    const active = phase < 26;
    const color = active ? (i % 5 === 0 ? 4 : 3) : 8;
    const width = active ? 150 + ((i * 23 + frameIndex * 7) % 130) : 80;
    drawRect(pixels, 26, y, width, 4, color);

    if (active && i % 7 === 0) {
      drawRect(pixels, 28 + width + 6, y, 22, 4, 5);
    }
  }

  // Animated "BLOCK" strip events.
  const alertWindow = frameIndex % 30;
  if (alertWindow >= 22) {
    const pulse = alertWindow % 2 === 0;
    drawRect(pixels, 22, 214, 289, 24, pulse ? 6 : 5);
    drawRect(pixels, 30, 220, 64, 4, 7);
    drawRect(pixels, 100, 220, 52, 4, 7);
    drawRect(pixels, 158, 220, 44, 4, 7);
    drawRect(pixels, 208, 220, 52, 4, 7);
    drawRect(pixels, 266, 220, 36, 4, 7);
  }

  // Right panel metrics bars.
  const bars = 10;
  for (let i = 0; i < bars; i += 1) {
    const y = 52 + i * 18;
    drawRect(pixels, 334, y, 118, 12, 8);
    const w = 26 + ((frameIndex * 11 + i * 37) % 88);
    const color = i % 3 === 0 ? 4 : i % 3 === 1 ? 3 : 9;
    drawRect(pixels, 334, y, w, 12, color);
  }

  // Moving p95 overhead marker.
  const markerX = 334 + ((frameIndex * 5) % 118);
  drawRect(pixels, markerX, 228, 4, 10, 7);
  drawRect(pixels, 334, 228, 118, 1, 5);

  return pixels;
}

function lzwEncode(indices, minCodeSize) {
  const clearCode = 1 << minCodeSize;
  const endCode = clearCode + 1;

  let dict = new Map();
  function resetDictionary() {
    dict = new Map();
    for (let i = 0; i < clearCode; i += 1) {
      dict.set(String(i), i);
    }
  }

  resetDictionary();
  let nextCode = endCode + 1;
  let codeSize = minCodeSize + 1;

  const outCodes = [];
  outCodes.push(clearCode);

  let prefix = String(indices[0]);
  for (let i = 1; i < indices.length; i += 1) {
    const value = indices[i];
    const key = `${prefix},${value}`;
    if (dict.has(key)) {
      prefix = key;
      continue;
    }

    outCodes.push(dict.get(prefix));
    if (nextCode < 4096) {
      dict.set(key, nextCode);
      nextCode += 1;
      if (nextCode === (1 << codeSize) && codeSize < 12) {
        codeSize += 1;
      }
    } else {
      outCodes.push(clearCode);
      resetDictionary();
      nextCode = endCode + 1;
      codeSize = minCodeSize + 1;
    }

    prefix = String(value);
  }

  outCodes.push(dict.get(prefix));
  outCodes.push(endCode);

  // Re-pack with dynamic code size while replaying code stream.
  const bytes = [];
  let bitBuffer = 0;
  let bitCount = 0;

  resetDictionary();
  nextCode = endCode + 1;
  codeSize = minCodeSize + 1;

  function writeCode(code) {
    bitBuffer |= (code << bitCount);
    bitCount += codeSize;
    while (bitCount >= 8) {
      bytes.push(bitBuffer & 0xff);
      bitBuffer >>= 8;
      bitCount -= 8;
    }
  }

  let replayPrefix = null;
  for (const code of outCodes) {
    writeCode(code);

    if (code === clearCode) {
      resetDictionary();
      nextCode = endCode + 1;
      codeSize = minCodeSize + 1;
      replayPrefix = null;
      continue;
    }
    if (code === endCode) {
      replayPrefix = null;
      continue;
    }

    if (replayPrefix === null) {
      replayPrefix = code;
      continue;
    }

    if (nextCode < 4096) {
      const firstSymbol = code < clearCode ? code : Number(String(code).split(',')[0] || 0);
      dict.set(`${replayPrefix},${firstSymbol}`, nextCode);
      nextCode += 1;
      if (nextCode === (1 << codeSize) && codeSize < 12) {
        codeSize += 1;
      }
    }
    replayPrefix = code;
  }

  if (bitCount > 0) {
    bytes.push(bitBuffer & 0xff);
  }

  return Buffer.from(bytes);
}

function buildGif(frames) {
  const writer = new ByteWriter();

  writer.text('GIF89a');
  writer.word(WIDTH);
  writer.word(HEIGHT);
  writer.byte(0xf3); // gct flag + 16-color table
  writer.byte(0x00); // background color index
  writer.byte(0x00); // pixel aspect

  for (const [r, g, b] of PALETTE) {
    writer.bytes([r, g, b]);
  }

  // Netscape loop extension.
  writer.bytes([0x21, 0xff, 0x0b]);
  writer.text('NETSCAPE2.0');
  writer.bytes([0x03, 0x01, 0x00, 0x00, 0x00]);

  const lzwMinCodeSize = 4;

  for (const frame of frames) {
    writer.bytes([0x21, 0xf9, 0x04, 0x00]);
    writer.word(FRAME_DELAY_CS);
    writer.byte(0x00);
    writer.byte(0x00);

    writer.byte(0x2c);
    writer.word(0);
    writer.word(0);
    writer.word(WIDTH);
    writer.word(HEIGHT);
    writer.byte(0x00);

    writer.byte(lzwMinCodeSize);

    const encoded = lzwEncode(frame, lzwMinCodeSize);
    for (let i = 0; i < encoded.length; i += 255) {
      const chunk = encoded.subarray(i, i + 255);
      writer.byte(chunk.length);
      writer.buffer(chunk);
    }
    writer.byte(0x00);
  }

  writer.byte(0x3b);
  return writer.build();
}

function ensureParentDir(filePath) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
}

function main() {
  const frames = [];
  for (let i = 0; i < FRAMES; i += 1) {
    frames.push(drawFrame(i));
  }

  const gif = buildGif(frames);
  ensureParentDir(OUT_PATH);
  fs.writeFileSync(OUT_PATH, gif);

  const digest = crypto.createHash('sha256').update(gif).digest('hex');
  console.log(`Wrote ${OUT_PATH}`);
  console.log(`size_bytes=${gif.length}`);
  console.log(`sha256=${digest}`);
  console.log(`duration_seconds=${(FRAMES * FRAME_DELAY_CS) / 100}`);
}

main();
