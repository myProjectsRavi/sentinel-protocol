'use strict';

async function main() {
  const transformers = await import('@xenova/transformers');
  const { RawImage, pipeline, env } = transformers;

  if (typeof pipeline !== 'function') {
    throw new Error('Transformers.js pipeline export is unavailable');
  }
  if (!env || typeof env !== 'object') {
    throw new Error('Transformers.js env export is unavailable');
  }
  if (typeof RawImage !== 'function') {
    throw new Error('Transformers.js RawImage export is unavailable');
  }

  const image = new RawImage(
    new Uint8ClampedArray([
      255, 0, 0,
      0, 255, 0,
      0, 0, 255,
      255, 255, 255,
    ]),
    2,
    2,
    3
  );

  const resized = await image.resize(1, 1, { resample: 'lanczos' });
  if (resized.width !== 1 || resized.height !== 1 || resized.channels !== 3) {
    throw new Error('Sharp-backed RawImage resize returned unexpected dimensions');
  }
  if (!(resized.data instanceof Uint8ClampedArray) || resized.data.length !== 3) {
    throw new Error('Sharp-backed RawImage resize returned unexpected pixel data');
  }

  console.log('Transformers.js dependency compatibility check passed');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
