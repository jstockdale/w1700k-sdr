# w1700k-sdr brand assets

The mark is the router pod – a rounded square with its status-LED slit – with a
spectrum trace inside. One mark, used everywhere; the only things that change
are the background and the colour it sits on.

## Files

| File | Use |
| --- | --- |
| `mark.svg` | The mark on its dark round disc. Discord server icon, GitHub avatar, anywhere a round or square avatar is wanted. Platforms crop the circle themselves; do not pre-crop. |
| `mark-transparent.svg` | The green mark alone, no disc. For dark surfaces that supply their own background. |
| `mark-on-light.svg` | The mark in the darker green, for white or light backgrounds. |
| `mark-mono.svg` | Single colour, drawn in `currentColor`. Favicons, stickers, print, anything one-colour. |
| `favicon.svg` | Tighter crop so the pod fills a 16/32 px square. |
| `lockup-dark.svg` | Mark + wordmark + tagline on the dark ground. Banners, social cards, dark READMEs. |
| `lockup-light.svg` | The same on white. GitHub README header. |
| `social-preview.svg` | 1280 × 640, GitHub repository social preview. |
| `png/` | Rasters of all of the above at the sizes platforms ask for. |

Text in the lockups is converted to outlines, so the SVGs render identically
without any font installed. The faces used were IBM Plex Mono (wordmark, spec
line) and IBM Plex Sans (tagline); IBM Plex is licensed under the SIL Open
Font License 1.1, which permits this embedding.

## Colours

| Token | Value | Where |
| --- | --- | --- |
| Ground | `#0b1612` | Disc and dark lockup background |
| Disc (on dark lockup) | `#121f1a` | A step lighter than the ground so the disc reads |
| Accent | `#5ff0b0` | The mark on dark grounds |
| Accent, ink | `#0f6e56` | The mark and spec line on light grounds |
| Text, dark ground | `#e9eee9` / `#9fb0a6` | Wordmark / tagline |
| Text, light ground | `#1a221e` / `#5a665f` | Wordmark / tagline |

## README header, both themes

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/lockup-dark.svg">
  <img alt="w1700k-sdr" src="assets/lockup-light.svg" width="776">
</picture>
```

## Clear space and minimum size

Keep clear space around the mark equal to the width of the LED slit (about 9 %
of the disc). The mark stays legible to 16 px; below 48 px prefer `favicon.svg`,
whose tighter crop uses the pixels better.

## Regenerating

`gen.py` writes the SVGs (needs `fonttools`, `uharfbuzz`, `brotli` and the
`@ibm/plex` npm package); `render.js` rasterises them with Playwright. Edit the
`TRACE` path or the colour constants in `gen.py` and run both.
