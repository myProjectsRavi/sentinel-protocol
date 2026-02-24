# Demo Assets

`sentinel-hero.gif` is the top-of-README hero media file.

The current hero asset is generated deterministically from:

- `scripts/generate-hero-gif.js`
- output: `docs/assets/sentinel-hero.gif`
- size: `480x270`, `~12s`

Regenerate:

```bash
node ./scripts/generate-hero-gif.js
```

If you want a live terminal capture instead of the generated animation:

1. Record a short terminal/dashboard session (traffic flowing + injection blocked).
2. Convert to GIF (asciinema, ffmpeg, or Screen Studio export).
3. Save as `docs/assets/sentinel-hero.gif`.

Recommended target:
- Duration: 8-15 seconds
- Size: <= 12 MB
- Width: 1280 px
