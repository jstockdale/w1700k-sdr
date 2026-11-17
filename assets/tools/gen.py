#!/usr/bin/env python3
"""Generate the w1700k-sdr brand assets as standalone SVGs.
Text is shaped with HarfBuzz and converted to outlines, so no viewer needs the fonts."""
import sys
from pathlib import Path
import uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

PLEX = Path('node_modules/@ibm/plex')
FONTS = {
    'mono-semibold': PLEX / 'IBM-Plex-Mono/fonts/complete/woff2/IBMPlexMono-SemiBold.woff2',
    'mono-regular':  PLEX / 'IBM-Plex-Mono/fonts/complete/woff2/IBMPlexMono-Regular.woff2',
    'sans-regular':  PLEX / 'IBM-Plex-Sans/fonts/complete/woff2/IBMPlexSans-Regular.woff2',
}
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else 'assets')
OUT.mkdir(parents=True, exist_ok=True)

GREEN = '#5ff0b0'
GREEN_INK = '#0f6e56'     # accent on white
GROUND = '#0b1612'
DISC = '#121f1a'
TEXT_DARK = '#e9eee9'
MUTED_DARK = '#9fb0a6'
TEXT_LIGHT = '#1a221e'
MUTED_LIGHT = '#5a665f'


class Face:
    def __init__(self, path):
        import io
        self.tt = TTFont(str(path))
        self.tt.flavor = None                 # woff2 -> plain sfnt for HarfBuzz
        buf = io.BytesIO(); self.tt.save(buf); data = buf.getvalue()
        self.upm = self.tt['head'].unitsPerEm
        self.glyphset = self.tt.getGlyphSet()
        self.order = self.tt.getGlyphOrder()
        blob = hb.Blob(data)
        face = hb.Face(blob)
        self.hb = hb.Font(face)
        self.hb.scale = (self.upm, self.upm)

    def text_path(self, text, size, x, y, letter_spacing_em=0.0):
        """SVG path data for `text` with its baseline at (x, y), in px."""
        buf = hb.Buffer()
        buf.add_str(text)
        buf.guess_segment_properties()
        hb.shape(self.hb, buf, {'kern': True, 'liga': True})
        s = size / self.upm
        pen = SVGPathPen(self.glyphset)
        cx = x
        tracking = letter_spacing_em * size
        for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
            name = self.order[info.codepoint]
            # glyph space -> px: scale, flip y, translate
            tp = TransformPen(pen, (s, 0, 0, -s, cx + pos.x_offset * s, y - pos.y_offset * s))
            self.glyphset[name].draw(tp)
            cx += pos.x_advance * s + tracking
        return pen.getCommands(), cx - x


faces = {k: Face(v) for k, v in FONTS.items()}

# ---- the mark --------------------------------------------------------------
TRACE = ('M300 672 L332 664 L352 676 L372 624 L388 676 L404 668 L420 548 L430 676 L450 666 '
         'L472 590 L484 676 L504 670 L522 446 L534 676 L560 666 L582 618 L598 676 L622 670 '
         'L642 520 L654 676 L682 666 L702 656 L724 672')


def mark_body(accent, fill_opacity='0.16'):
    return (
        f'<rect x="236" y="236" width="552" height="552" rx="104" ry="104" fill="none" '
        f'stroke="{accent}" stroke-width="30"/>\n'
        f'<rect x="468" y="318" width="88" height="16" rx="8" ry="8" fill="{accent}"/>\n'
        f'<path d="{TRACE}" fill="none" stroke="{accent}" stroke-width="16" '
        f'stroke-linejoin="round" stroke-linecap="round"/>\n'
        f'<path d="{TRACE} L724 690 L300 690 Z" fill="{accent}" fill-opacity="{fill_opacity}"/>\n'
    )


def svg(width, height, body, title, desc=None):
    d = f'<desc>{desc}</desc>\n' if desc else ''
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="t">\n'
            f'<title id="t">{title}</title>\n{d}{body}</svg>\n')


def write(name, content):
    (OUT / name).write_text(content)
    print(f'  {name}  ({len(content):,} bytes)')


print(f'writing to {OUT}/')

# mark.svg: round disc, for avatars
write('mark.svg', svg(1024, 1024,
    f'<circle cx="512" cy="512" r="512" fill="{GROUND}"/>\n' + mark_body(GREEN),
    'w1700k-sdr', 'Router pod outline with a spectrum trace inside, on a round dark disc.'))

# mark-transparent.svg: no disc, green mark, for dark surfaces
write('mark-transparent.svg', svg(1024, 1024, mark_body(GREEN),
    'w1700k-sdr', 'Router pod outline with a spectrum trace, no background.'))

# mark-mono.svg: currentColor, single colour, for favicons / stickers / print
write('mark-mono.svg', svg(1024, 1024, mark_body('currentColor', '0.2'),
    'w1700k-sdr', 'Single-colour mark; takes the colour of its context (currentColor).'))

# mark-on-light.svg: dark-ink mark for white paper / light UI
write('mark-on-light.svg', svg(1024, 1024, mark_body(GREEN_INK, '0.14'),
    'w1700k-sdr', 'Mark in the darker green for light backgrounds.'))

# favicon.svg: tighter crop so the pod fills a 16/32 px square
write('favicon.svg',
    f'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="192 192 640 640" role="img" aria-labelledby="t">\n'
    f'<title id="t">w1700k-sdr</title>\n'
    f'<rect x="192" y="192" width="640" height="640" rx="140" fill="{GROUND}"/>\n'
    + mark_body(GREEN) + '</svg>\n')

# ---- the lockups -----------------------------------------------------------
W, H = 1552, 560
MARK_X, MARK_Y, MARK_S = 96, 80, 400 / 1024   # mark at 400 px


def lockup(ground, disc, accent, text, muted, accent_text, name):
    word, word_w = faces['mono-semibold'].text_path('w1700k-sdr', 128, 0, 0, letter_spacing_em=-0.03)
    tag, _ = faces['sans-regular'].text_path('A Wi-Fi 7 router, turned into a 320 Msps wideband receiver.', 36, 0, 0)
    spec, _ = faces['mono-regular'].text_path('2.08–2.75 · 4.65–7.58 GHz · 14-bit IQ · 10 GbE', 24, 0, 0)
    tx = MARK_X + 400 + 72
    # baselines: wordmark cap-height ~ 0.7 em; vertical rhythm matches the canvas lockup
    body = (
        f'<rect width="{W}" height="{H}" fill="{ground}"/>\n'
        f'<g transform="translate({MARK_X} {MARK_Y}) scale({MARK_S:.6f})">\n'
        f'<circle cx="512" cy="512" r="512" fill="{disc}"/>\n' + mark_body(accent) + '</g>\n'
        f'<g fill="{text}"><path transform="translate({tx} 262)" d="{word}"/></g>\n'
        f'<g fill="{muted}"><path transform="translate({tx} 336)" d="{tag}"/></g>\n'
        f'<g fill="{accent_text}"><path transform="translate({tx} 392)" d="{spec}"/></g>\n'
    )
    write(name, svg(W, H, body, 'w1700k-sdr',
                    'Wordmark lockup: the mark beside the project name, tagline and tuning range.'))
    return word_w


ww = lockup(GROUND, DISC, GREEN, TEXT_DARK, MUTED_DARK, GREEN, 'lockup-dark.svg')
lockup('#ffffff', GROUND, GREEN, TEXT_LIGHT, MUTED_LIGHT, GREEN_INK, 'lockup-light.svg')
print(f'  wordmark advance {ww:.0f} px at 128 px; text column starts at {MARK_X + 400 + 72}, right edge {MARK_X + 400 + 72 + ww:.0f} of {W}')

# ---- GitHub social preview 1280x640 ----------------------------------------
SW, SH = 1280, 640
word, word_w = faces['mono-semibold'].text_path('w1700k-sdr', 112, 0, 0, letter_spacing_em=-0.03)
tag, _ = faces['sans-regular'].text_path('A Wi-Fi 7 router, turned into a 320 Msps wideband receiver.', 32, 0, 0)
spec, _ = faces['mono-regular'].text_path('2.08–2.75 · 4.65–7.58 GHz · 14-bit IQ · 10 GbE', 22, 0, 0)
ms = 360 / 1024
block_w = 360 + 64 + word_w
x0 = (SW - block_w) / 2
tx = x0 + 360 + 64
body = (
    f'<rect width="{SW}" height="{SH}" fill="{GROUND}"/>\n'
    f'<g transform="translate({x0:.1f} {(SH-360)/2:.1f}) scale({ms:.6f})">\n'
    f'<circle cx="512" cy="512" r="512" fill="{DISC}"/>\n' + mark_body(GREEN) + '</g>\n'
    f'<g fill="{TEXT_DARK}"><path transform="translate({tx:.1f} 300)" d="{word}"/></g>\n'
    f'<g fill="{MUTED_DARK}"><path transform="translate({tx:.1f} 362)" d="{tag}"/></g>\n'
    f'<g fill="{GREEN}"><path transform="translate({tx:.1f} 412)" d="{spec}"/></g>\n'
)
write('social-preview.svg', svg(SW, SH, body, 'w1700k-sdr', 'GitHub social preview, 1280 by 640.'))
print('done')
