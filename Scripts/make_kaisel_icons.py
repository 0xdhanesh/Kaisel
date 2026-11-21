#!/usr/bin/env python3
"""Kaisel app icons: original stylised shadow-wyvern guardian artwork.

  pip install Pillow && python3 Scripts/make_kaisel_icons.py

Writes:
  Apps/KaiselJBCheck/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png
  Apps/KaiselIntegrityCheck/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png
  Branding/KaiselJBCheck-1024.png, Branding/KaiselIntegrityCheck-1024.png
  Branding/KaiselIconPreview.png

A front-facing horned wyvern with glowing eyes looms over a shield, its wings
spread behind it. JB Check carries a padlock in violet; Integrity Check carries
a checkmark in ice blue. All shapes are drawn procedurally here (no third-party
artwork). Masters are 1024x1024, opaque RGB, square corners.
"""
import os
import sys
from PIL import Image, ImageChops, ImageDraw, ImageFilter

S = 4096
OUT = 1024
K = S / 1024.0          # design space is 1024; scale to the canvas
CX = 512
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def vertical_gradient(size, top, bottom):
    g = Image.new("RGB", (1, 256))
    for y in range(256):
        g.putpixel((0, y), lerp(top, bottom, y / 255))
    return g.resize(size, Image.BICUBIC)


def bezier(p0, p1, p2, p3, n=60):
    pts = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        x = u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0]
        y = u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def shield_path(cx, top, w, h):
    """Classic heater shield: gently arched top, straight sides, curved point."""
    l, r = cx - w / 2, cx + w / 2
    shoulder = top + h * 0.10
    side_end = top + h * 0.50
    bottom = top + h
    pts = []
    pts += bezier((l, shoulder), (cx - w * 0.25, top + h * 0.02), (cx - w * 0.08, top - h * 0.015), (cx, top))
    pts += bezier((cx, top), (cx + w * 0.08, top - h * 0.015), (cx + w * 0.25, top + h * 0.02), (r, shoulder))[1:]
    pts += [(r, side_end)]
    pts += bezier((r, side_end), (r, top + h * 0.78), (cx + w * 0.22, top + h * 0.92), (cx, bottom))[1:]
    pts += bezier((cx, bottom), (cx - w * 0.22, top + h * 0.92), (l, top + h * 0.78), (l, side_end))[1:]
    return pts


def scale_path(pts, cx, cy, k):
    return [(cx + (x - cx) * k, cy + (y - cy) * k) for x, y in pts]


def padlock(d, cx, cy, S, accent):
    white = (245, 248, 250)
    bw, bh = S * 0.20, S * 0.16
    body = [cx - bw / 2, cy - bh * 0.15, cx + bw / 2, cy + bh * 0.85]
    # shackle
    sw = S * 0.028
    r = bw * 0.34
    d.arc([cx - r, cy - bh * 0.15 - r * 1.55, cx + r, cy - bh * 0.15 + r * 0.45], 180, 360, fill=white, width=int(sw))
    d.line([cx - r + sw / 2 - 1, cy - bh * 0.15 - r * 0.55, cx - r + sw / 2 - 1, cy - bh * 0.12], fill=white, width=int(sw))
    d.line([cx + r - sw / 2, cy - bh * 0.15 - r * 0.55, cx + r - sw / 2, cy - bh * 0.12], fill=white, width=int(sw))
    d.rounded_rectangle(body, radius=S * 0.028, fill=white)
    # keyhole
    kr = S * 0.022
    ky = cy + bh * 0.28
    d.ellipse([cx - kr, ky - kr, cx + kr, ky + kr], fill=accent)
    d.polygon([(cx - kr * 0.55, ky), (cx + kr * 0.55, ky), (cx + kr * 0.35, ky + kr * 2.3), (cx - kr * 0.35, ky + kr * 2.3)], fill=accent)


def checkmark_with_pulse(d, cx, cy, S, accent):
    white = (245, 248, 250)
    w = int(S * 0.038)
    pts = [(cx - S * 0.105, cy + S * 0.005), (cx - S * 0.03, cy + S * 0.08), (cx + S * 0.12, cy - S * 0.085)]
    d.line(pts, fill=white, width=w, joint="curve")
    for p in (pts[0], pts[-1]):
        d.ellipse([p[0] - w / 2, p[1] - w / 2, p[0] + w / 2, p[1] + w / 2], fill=white)
    # scan arcs above
    for i, rr in enumerate((0.17, 0.215)):
        rad = S * rr
        d.arc([cx - rad, cy - rad - S * 0.02, cx + rad, cy + rad - S * 0.02], 205, 335,
              fill=lerp(white, accent, 0.35 + i * 0.25), width=int(S * 0.012))




def P(pts):
    return [(x * K, y * K) for x, y in pts]


def mirror(half):
    """half: right-side points (dx, y) from top centre to bottom centre."""
    right = [(CX + dx, y) for dx, y in half]
    left = [(CX - dx, y) for dx, y in reversed(half)]
    return right + left


# Right half of a front-facing horned wyvern head, (dx, y) in design units.
HEAD = [
    (0, 150),
    (30, 146),
    (58, 132),                              # brow ridge
    *bezier((58, 132), (100, 92), (160, 52), (230, 40), 14)[1:],      # swept horn
    *bezier((230, 40), (172, 78), (130, 118), (98, 160), 14)[1:],
    (136, 170), (102, 192),                 # frill spike
    (122, 228), (90, 236),                  # cheek spike
    (76, 272),
    (60, 320),
    (46, 366),                              # long snout
    (40, 398), (24, 410),                   # nostril flare
    (0, 416),
]

# Right wing, behind the shield.
WING = [
    (120, 360),
    *bezier((120, 360), (200, 260), (290, 210), (392, 236), 20)[1:],   # wing arm
    (420, 292),                                                         # wing tip claw
    *bezier((420, 292), (408, 380), (388, 470), (360, 560), 12)[1:],
    *bezier((360, 560), (338, 520), (312, 506), (290, 512), 8)[1:],    # membrane scallops
    *bezier((290, 512), (284, 580), (268, 640), (244, 690), 10)[1:],
    *bezier((244, 690), (226, 650), (204, 632), (180, 628), 8)[1:],
    *bezier((180, 628), (176, 680), (168, 720), (150, 760), 8)[1:],
    (130, 600),
]


def eye_polys():
    # angry slanted slits: inner end low, outer end high
    r = [(22, 214), (48, 199), (86, 184), (72, 207), (40, 218)]
    return [[(CX + dx, y) for dx, y in r], [(CX - dx, y) for dx, y in r]]


def mask_of(polys, blur=0.0):
    m = Image.new("L", (S, S), 0)
    d = ImageDraw.Draw(m)
    for p in polys:
        d.polygon(P(p), fill=255)
    if blur:
        m = m.filter(ImageFilter.GaussianBlur(blur * K))
    return m


def rim(mask, dx, dy, strength):
    """Edge light: the mask minus itself shifted, softened."""
    shifted = ImageChops.offset(mask, int(dx * K), int(dy * K))
    edge = ImageChops.subtract(mask, shifted)
    edge = edge.filter(ImageFilter.GaussianBlur(2.0 * K))
    return edge.point(lambda v: min(255, int(v * strength)))


def paint(img, colour, mask):
    return Image.composite(Image.new("RGB", (S, S), colour), img, mask)


def draw_icon(accent, accent_deep, eye, glyph):
    bg_top, bg_bottom = (14, 8, 26), (3, 2, 8)
    img = vertical_gradient((S, S), bg_top, bg_bottom)

    # shadow-smoke aura behind everything
    aura = Image.new("L", (S, S), 0)
    ad = ImageDraw.Draw(aura)
    ad.ellipse(P([(170, 140), (854, 860)]), fill=120)
    ad.ellipse(P([(330, 60), (694, 420)]), fill=90)
    aura = aura.filter(ImageFilter.GaussianBlur(120 * K))
    img = paint(img, lerp(accent_deep, (0, 0, 0), 0.25), aura)

    shadow_fill = (9, 5, 16)

    # wings
    wings = [mirror_wing(WING, +1), mirror_wing(WING, -1)]
    wmask = mask_of(wings)
    img = paint(img, shadow_fill, wmask)
    img = paint(img, lerp(accent, (0, 0, 0), 0.35), rim(wmask, 0, 6, 1.4))
    # wing bones
    bones = Image.new("L", (S, S), 0)
    bd = ImageDraw.Draw(bones)
    for sgn in (1, -1):
        root = (CX + sgn * 392, 238)            # wrist: finger bones fan out
        for tip in ((360, 560), (290, 512), (244, 690), (180, 628)):
            bd.line(P([root, (CX + sgn * tip[0], tip[1])]), fill=70, width=int(5 * K))
    bones = Image.composite(bones, Image.new("L", (S, S), 0), wmask)
    img = paint(img, lerp(accent, (0, 0, 0), 0.45), bones)

    # head (behind the shield top, in front of the wings)
    head = mirror(HEAD)
    hmask = mask_of([head])
    hglow = mask_of([head], blur=18).point(lambda v: v // 2)
    img = paint(img, accent_deep, hglow)
    img = paint(img, shadow_fill, hmask)
    img = paint(img, lerp(accent, (255, 255, 255), 0.1), rim(hmask, 0, 5, 1.8))
    img = paint(img, lerp(accent, (0, 0, 0), 0.2), rim(hmask, 4, -2, 1.0))

    # snout ridge
    ridge = Image.new("L", (S, S), 0)
    ImageDraw.Draw(ridge).line(P([(CX, 236), (CX, 404)]), fill=90, width=int(4 * K))
    img = paint(img, lerp(accent, (0, 0, 0), 0.3), ridge.filter(ImageFilter.GaussianBlur(2 * K)))

    # glowing eyes
    eyes = eye_polys()
    img = paint(img, eye, mask_of(eyes, blur=22))
    img = paint(img, eye, mask_of(eyes, blur=8))
    img = paint(img, lerp(eye, (255, 255, 255), 0.75), mask_of(eyes))

    # shield
    cx, top, w, h = S * 0.5, S * 0.425, S * 0.40, S * 0.47
    outer = shield_path(cx, top, w, h)
    sh = Image.new("L", (S, S), 0)
    ImageDraw.Draw(sh).polygon([(x, y + S * 0.015) for x, y in outer], fill=170)
    img = paint(img, (0, 0, 0), sh.filter(ImageFilter.GaussianBlur(S * 0.02)))
    smask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(smask).polygon(outer, fill=255)
    sglow = smask.filter(ImageFilter.GaussianBlur(S * 0.02)).point(lambda v: v // 3)
    img = paint(img, accent, sglow)
    body = vertical_gradient((S, S), lerp(accent, (255, 255, 255), 0.15), accent_deep)
    img = Image.composite(body, img, smask)
    inner = scale_path(outer, cx, top + h * 0.5, 0.84)
    imask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(imask).polygon(inner, fill=255)
    img = Image.composite(vertical_gradient((S, S), (22, 12, 38), (8, 4, 16)), img, imask)

    d = ImageDraw.Draw(img)
    glyph(d, cx, top + h * 0.47, S * 0.68, accent)
    return img.resize((OUT, OUT), Image.LANCZOS).convert("RGB")


def mirror_wing(wing, sgn):
    return [(CX + sgn * dx, y) for dx, y in wing]


def squircle(icon, size):
    m = Image.new("L", (size * 4, size * 4), 0)
    ImageDraw.Draw(m).rounded_rectangle([0, 0, size * 4 - 1, size * 4 - 1], radius=int(size * 4 * 0.2237), fill=255)
    return icon.resize((size, size), Image.LANCZOS), m.resize((size, size), Image.LANCZOS)


def main():
    out = os.path.join(ROOT, "Branding")
    os.makedirs(out, exist_ok=True)
    jb = draw_icon((178, 96, 255), (88, 30, 160), (196, 130, 255), padlock)
    ic = draw_icon((96, 150, 255), (36, 60, 170), (120, 225, 255), checkmark_with_pulse)
    jb.save(os.path.join(out, "KaiselJBCheck-1024.png"), optimize=True)
    ic.save(os.path.join(out, "KaiselIntegrityCheck-1024.png"), optimize=True)
    for app, img in (("KaiselJBCheck", jb), ("KaiselIntegrityCheck", ic)):
        img.save(os.path.join(ROOT, "Apps", app, "Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png"), optimize=True)

    pv = Image.new("RGB", (1400, 820), (242, 242, 247))
    d = ImageDraw.Draw(pv)
    for i, (icon, label) in enumerate(((jb, "Kaisel JB Check"), (ic, "Kaisel Integrity Check"))):
        x0 = 80 + i * 680
        big, m = squircle(icon, 512)
        pv.paste(big, (x0, 50), m)
        for j, sz in enumerate((180, 120, 60)):
            small, sm = squircle(icon, sz)
            pv.paste(small, (x0 + [0, 210, 360][j], 600 + (180 - sz) // 2), sm)
        d.text((x0, 795), label, fill=(30, 30, 35))
    pv.save(os.path.join(out, "KaiselIconPreview.png"))
    print("icons written")


if __name__ == "__main__":
    main()
