import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
ICONS = json.load(open(os.path.join(HERE, 'icons.json')))

INK = '#0B1220'; INK2 = '#232B37'; MUTED = '#4C5768'; MUTED2 = '#6C788B'
LINE = '#C7CFDA'; RULE = '#DFE4EC'; PAPER = '#F6F8FB'
IND = '#C98F12'; IND7 = '#8A5A06'; IND8 = '#5C3D05'; IND50 = '#FFF8E6'; IND100 = '#FDEDC4'; IND200 = '#F0CF7E'
TEAL = '#3F3F46'; TEAL7 = '#27272A'; TEAL50 = '#F4F4F5'; TEAL100 = '#E4E4E7'; TEAL200 = '#C9C9CF'; TEAL9 = '#0C0C0D'
OK = '#16A34A'; OK50 = '#DCFCE7'; OK7 = '#15803D'
WARN = '#D97706'; WARN50 = '#FEF3C7'; WARN7 = '#B45309'
BAD = '#DC2626'; BAD50 = '#FEE2E2'; BAD7 = '#B91C1C'

F = "font-family:Inter,sans-serif"
M = "font-family:'JetBrains Mono',monospace"
D = "font-family:'Space Grotesk',sans-serif"


def ic(name, x, y, s, color, sw=2):
    return (f'<svg x="{x}" y="{y}" width="{s}" height="{s}" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" color="{color}" stroke-width="{sw}" stroke-linecap="round" '
            f'stroke-linejoin="round">{ICONS[name]}</svg>')


def ih(name, cls='i'):
    return (f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{ICONS[name]}</svg>')


# simplify: t(x,y,txt,...) signature fix
def T(x, y, txt, size=11, w=400, fill=INK, anchor='start', fam=F, halo=False):
    # The halo is a white backing rect, not a stroked glyph outline: stroked text embeds as Type 3 in the PDF.
    bg = ''
    if halo:
        wd = tw(txt, size, 0.56) + 6
        bx = x - 3 if anchor == 'start' else x - wd / 2 if anchor == 'middle' else x - wd + 3
        bg = f'<rect x="{bx:.1f}" y="{y - size * 0.82:.1f}" width="{wd:.1f}" height="{size * 1.1:.1f}" rx="2" fill="#fff"/>'
    return (bg + f'<text x="{x}" y="{y}" style="{fam};font-size:{size}px;font-weight:{w}" fill="{fill}" '
            f'text-anchor="{anchor}">{txt}</text>')


def L(x, y, arr, size=11, lh=None, fill=MUTED, w=400, fam=F, anchor='start'):
    lh = lh or round(size * 1.4, 1)
    return ''.join(T(x, y + i * lh, a, size, w, fill, anchor, fam) for i, a in enumerate(arr))


def defs():
    out = '<defs>'
    for nm, c in [('a', MUTED), ('ai', IND7), ('at', TEAL7), ('ar', BAD), ('ag', OK), ('aw', WARN7)]:
        out += (f'<marker id="{nm}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                f'orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{c}"/></marker>')
    out += ('<pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
            f'<rect width="6" height="6" fill="{IND100}"/><line x1="0" y1="0" x2="0" y2="6" stroke="{IND}" stroke-width="2.4"/></pattern>')
    return out + '</defs>'


def svg(w, h, body, label):
    return (f'<svg class="fig-svg" viewBox="-2 -2 {w + 4} {h + 4}" role="img" aria-label="{label}" '
            f'xmlns="http://www.w3.org/2000/svg">{defs()}{body}</svg>')


def arrow(x1, y1, x2, y2, color=MUTED, m='a', dash=None, sw=1.6):
    d = f' stroke-dasharray="{dash}"' if dash else ''
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}"{d} marker-end="url(#{m})"/>'


def path(d, color=MUTED, m='a', dash=None, sw=1.6):
    da = f' stroke-dasharray="{dash}"' if dash else ''
    mk = f' marker-end="url(#{m})"' if m else ''
    return f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}"{da}{mk}/>'


def rect(x, y, w, h, fill='#fff', stroke=LINE, rx=8, sw=1.2, dash=None):
    d = f' stroke-dasharray="{dash}"' if dash else ''
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>'


def tw(s, size, k=0.58):
    return len(s) * size * k


