from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "media"
OUT.mkdir(exist_ok=True)

W, H = 1800, 1200


def font(size, bold=False):
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial Bold.ttf" if bold else "/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Helvetica.ttf",
    ]
    for path in candidates:
        if path and Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


F = {
    "title": font(92, True),
    "subtitle": font(42),
    "h2": font(52, True),
    "h3": font(32, True),
    "body": font(28),
    "small": font(22),
    "mono": font(25),
    "metric": font(58, True),
}


COLORS = {
    "bg": "#eef2f3",
    "ink": "#182026",
    "muted": "#5b6872",
    "navy": "#111827",
    "panel": "#ffffff",
    "line": "#cbd5dc",
    "teal": "#0f766e",
    "teal2": "#99f6e4",
    "red": "#b91c1c",
    "slate": "#334155",
    "green": "#166534",
    "gold": "#a16207",
    "terminal": "#0b1220",
}


def draw_text(draw, xy, text, fill, font_obj, max_width=None, line_spacing=8):
    x, y = xy
    if max_width is None:
        draw.text((x, y), text, fill=fill, font=font_obj)
        return draw.textbbox((x, y), text, font=font_obj)[3]

    words = text.split()
    lines = []
    current = ""
    for word in words:
        test = f"{current} {word}".strip()
        if draw.textlength(test, font=font_obj) <= max_width:
            current = test
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)

    for line in lines:
        draw.text((x, y), line, fill=fill, font=font_obj)
        y += font_obj.size + line_spacing
    return y


def rect(draw, box, fill, outline=None, width=1):
    draw.rectangle(box, fill=fill, outline=outline, width=width)


def pill(draw, box, text, fill, stroke, text_fill):
    rect(draw, box, fill, stroke, 2)
    draw.text((box[0] + 24, box[1] + 15), text, fill=text_fill, font=F["small"])


def save(img, name):
    path = OUT / name
    img.save(path, "PNG", optimize=True)
    print(path)


def base():
    img = Image.new("RGB", (W, H), COLORS["bg"])
    draw = ImageDraw.Draw(img)
    rect(draw, (0, 0, 280, H), COLORS["navy"])
    rect(draw, (38, 48, 100, 110), "#172033", COLORS["teal2"], 2)
    draw.text((53, 64), "SS", fill=COLORS["teal2"], font=F["h3"])
    draw.text((120, 48), "SIFT", fill="#f8fafc", font=F["h3"])
    draw.text((120, 84), "Sentinel", fill="#f8fafc", font=F["h3"])
    draw.text((38, 160), "Protocol SIFT defender", fill="#a7b4c2", font=F["small"])
    for i, label in enumerate(["Typed MCP tools", "Evidence policy", "Self-correction", "Audit logs"]):
        y = 250 + i * 70
        rect(draw, (38, y, 242, y + 46), "#172033", "#263241", 1)
        draw.text((54, y + 12), label, fill="#dbeafe", font=F["small"])
    return img, draw


def thumbnail():
    img, draw = base()
    pill(draw, (340, 54, 850, 106), "Evidence integrity checked on every run", "#ccfbf1", COLORS["teal2"], "#064e3b")
    draw_text(draw, (340, 170), "Evidence-safe autonomous DFIR", COLORS["ink"], F["title"], max_width=1050, line_spacing=4)
    draw_text(
        draw,
        (340, 390),
        "A custom MCP server and self-correcting triage agent for Protocol SIFT.",
        COLORS["muted"],
        F["subtitle"],
        max_width=1120,
        line_spacing=10,
    )
    metrics = [("1.0", "precision"), ("1.0", "recall"), ("0", "hallucinations"), ("9/9", "tests")]
    for i, (value, label) in enumerate(metrics):
        x = 340 + i * 300
        rect(draw, (x, 620, x + 260, 760), COLORS["panel"], COLORS["line"], 2)
        draw.text((x + 24, 650), value, fill=COLORS["ink"], font=F["metric"])
        draw.text((x + 24, 716), label, fill=COLORS["muted"], font=F["body"])
    rect(draw, (340, 845, 1560, 1070), COLORS["terminal"], "#1f2937", 2)
    terminal = [
        "$ sift_sentinel benchmark --case demo --max-iterations 3",
        "{ precision: 1.0, recall: 1.0, hallucination_count: 0 }",
        "F-002 refuted: Prefetch-only lead lacked corroboration",
    ]
    for i, line in enumerate(terminal):
        draw.text((380, 890 + i * 55), line, fill="#d1fae5" if i else "#8ea4b8", font=F["mono"])
    save(img, "devpost-thumbnail.png")


def architecture():
    img, draw = base()
    draw.text((340, 72), "Architecture", fill=COLORS["ink"], font=F["title"])
    draw_text(draw, (340, 178), "Typed tools, enforced boundaries, traceable findings.", COLORS["muted"], F["subtitle"], 1180)
    nodes = [
        ("MCP Host", 360, 360, "#e0f2fe"),
        ("SIFT Sentinel\nMCP Server", 650, 360, "#ccfbf1"),
        ("Self-correcting\nAgent Loop", 980, 360, "#fef3c7"),
        ("Typed Forensic\nTools", 1280, 360, "#e2e8f0"),
        ("Read-only\nEvidence", 650, 690, "#fee2e2"),
        ("Outputs:\nlogs, reports,\naccuracy", 980, 690, "#dcfce7"),
        ("SIFT wrappers:\nVolatility, EZ Tools,\nTSK, YARA", 1280, 690, "#ede9fe"),
    ]
    for label, x, y, color in nodes:
        rect(draw, (x, y, x + 240, y + 150), color, COLORS["line"], 2)
        yy = y + 30
        for line in label.split("\n"):
            draw.text((x + 24, yy), line, fill=COLORS["ink"], font=F["h3"] if yy == y + 30 else F["body"])
            yy += 38
    arrows = [
        (600, 435, 650, 435),
        (890, 435, 980, 435),
        (1220, 435, 1280, 435),
        (770, 510, 770, 690),
        (1100, 510, 1100, 690),
        (1400, 510, 1400, 690),
    ]
    for x1, y1, x2, y2 in arrows:
        draw.line((x1, y1, x2, y2), fill=COLORS["slate"], width=5)
        draw.ellipse((x2 - 7, y2 - 7, x2 + 7, y2 + 7), fill=COLORS["slate"])
    save(img, "devpost-architecture.png")


def benchmark():
    img, draw = base()
    draw.text((340, 72), "Benchmark Run", fill=COLORS["ink"], font=F["title"])
    draw_text(draw, (340, 178), "Self-correction is logged, scored, and reproducible.", COLORS["muted"], F["subtitle"], 1120)
    rows = [
        ("F-001", "Winupdate external callback", "confirmed", COLORS["green"]),
        ("F-002", "Prefetch-only svchost lead", "refuted", COLORS["red"]),
        ("F-003", "Run key loads SyncCache.dll", "confirmed", COLORS["green"]),
        ("F-004", "Encoded PowerShell staging", "confirmed", COLORS["green"]),
    ]
    rect(draw, (340, 320, 1570, 720), COLORS["panel"], COLORS["line"], 2)
    draw.text((380, 350), "Finding", fill=COLORS["muted"], font=F["small"])
    draw.text((560, 350), "Signal", fill=COLORS["muted"], font=F["small"])
    draw.text((1250, 350), "Status", fill=COLORS["muted"], font=F["small"])
    for i, (fid, title, status, color) in enumerate(rows):
        y = 410 + i * 70
        draw.line((380, y - 18, 1530, y - 18), fill="#e5e7eb", width=2)
        draw.text((380, y), fid, fill=COLORS["ink"], font=F["h3"])
        draw.text((560, y + 2), title, fill=COLORS["ink"], font=F["body"])
        rect(draw, (1250, y - 4, 1460, y + 42), "#f8fafc", color, 2)
        draw.text((1272, y + 8), status, fill=color, font=F["small"])
    metrics = [("Precision", "1.0"), ("Recall", "1.0"), ("F1", "1.0"), ("Evidence changed", "0")]
    for i, (label, value) in enumerate(metrics):
        x = 340 + i * 300
        rect(draw, (x, 810, x + 260, 985), COLORS["panel"], COLORS["line"], 2)
        draw.text((x + 24, 845), value, fill=COLORS["ink"], font=F["metric"])
        draw.text((x + 24, 930), label, fill=COLORS["muted"], font=F["body"])
    save(img, "devpost-benchmark.png")


if __name__ == "__main__":
    thumbnail()
    architecture()
    benchmark()
