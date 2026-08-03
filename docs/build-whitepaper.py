#!/usr/bin/env python3
"""
Render docs/WHITEPAPER.md to a typeset PDF.

    python docs/build-whitepaper.py

Deliberately a purpose-built renderer rather than a generic Markdown->PDF
pipeline. The whitepaper uses a known, small subset of Markdown, and hand-rolling
the mapping buys exact control over typography — which is the entire reason to
ship a PDF instead of just linking the Markdown.

Fonts: Bitstream Vera, bundled with reportlab and freely licensed for
redistribution. Avoids embedding a proprietary system font in a public artefact.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

HERE = Path(__file__).resolve().parent
SRC = HERE / "WHITEPAPER.md"
OUT = HERE / "DeckxCoin-Whitepaper.pdf"

# ── palette ───────────────────────────────────────────────────────────────
INK = colors.HexColor("#14181F")
BODY = colors.HexColor("#23282F")
MUTED = colors.HexColor("#5C6673")
RULE = colors.HexColor("#D4D9E0")
REKT = colors.HexColor("#D6003C")
DEEP = colors.HexColor("#0A0C11")
PANEL = colors.HexColor("#F4F6F9")
CODEBG = colors.HexColor("#F0F2F6")


def register_fonts() -> tuple[str, str, str, str]:
    """Register Bitstream Vera. Returns (regular, bold, italic, mono)."""
    root = Path(os.path.dirname(sys.modules["reportlab"].__file__)) / "fonts"
    faces = {
        "Vera": "Vera.ttf",
        "Vera-Bold": "VeraBd.ttf",
        "Vera-Italic": "VeraIt.ttf",
    }
    for name, filename in faces.items():
        pdfmetrics.registerFont(TTFont(name, str(root / filename)))
    pdfmetrics.registerFontFamily(
        "Vera", normal="Vera", bold="Vera-Bold", italic="Vera-Italic", boldItalic="Vera-Bold"
    )
    # Vera has no monospace variant shipped; Courier is a PDF base-14 font and
    # is guaranteed present in every reader.
    return "Vera", "Vera-Bold", "Vera-Italic", "Courier"


REG, BOLD, ITAL, MONO = register_fonts()


# ── character normalisation ───────────────────────────────────────────────
# Superscripts and subscripts become reportlab markup: the glyphs exist in few
# fonts and render as solid boxes when they are missing.
SUPERSUB = [
    ("2²⁵⁶", "2<super>256</super>"),
    ("2⁻¹⁶", "2<super>-16</super>"),
    ("²⁵⁶", "<super>256</super>"),
    ("h₁", "h<sub>1</sub>"),
    ("h₂", "h<sub>2</sub>"),
]

# Symbols Vera does not carry, mapped to unambiguous ASCII.
FALLBACK = {
    "⌊": "",
    "⌋": "",
    "⇔": "<=>",
    "≥": ">=",
    "≤": "<=",
    "‖": "||",
    "≈": "~",
}


def normalise(text: str) -> str:
    for src, dst in SUPERSUB:
        text = text.replace(src, dst)
    for src, dst in FALLBACK.items():
        text = text.replace(src, dst)
    return text


def esc(text: str) -> str:
    """XML-escape, leaving our own markup tags to be re-inserted afterwards."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


INLINE_CODE = re.compile(r"`([^`]+)`")
BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")
ITAL_RE = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
AUTOLINK_RE = re.compile(r"<(https?://[^>]+)>")


def inline(text: str) -> str:
    """Markdown inline formatting -> reportlab paragraph markup."""
    text = normalise(text)

    # Protect the markup we generate from the XML escaper.
    slots: list[str] = []

    def stash(html: str) -> str:
        slots.append(html)
        return f"\x00{len(slots) - 1}\x00"

    text = AUTOLINK_RE.sub(lambda m: stash(f'<font name="{MONO}" size="8.5">{esc(m.group(1))}</font>'), text)
    text = LINK_RE.sub(
        lambda m: stash(f'<font color="#0B5FA5">{esc(m.group(1))}</font>'), text
    )
    text = INLINE_CODE.sub(
        lambda m: stash(f'<font name="{MONO}" size="9">{esc(m.group(1))}</font>'), text
    )
    text = BOLD_RE.sub(lambda m: stash(f"<b>{esc(m.group(1))}</b>"), text)
    text = ITAL_RE.sub(lambda m: stash(f"<i>{esc(m.group(1))}</i>"), text)

    # Re-apply the super/sub markup produced by normalise().
    for tag in ("super", "sub"):
        text = re.sub(
            rf"<{tag}>([^<]*)</{tag}>",
            lambda m, t=tag: stash(f"<{t}>{esc(m.group(1))}</{t}>"),
            text,
        )

    text = esc(text)
    for i, html in enumerate(slots):
        text = text.replace(f"\x00{i}\x00", html)
    return text


# ── styles ────────────────────────────────────────────────────────────────
ss = getSampleStyleSheet()

S = {
    "title": ParagraphStyle(
        "dxTitle", parent=ss["Title"], fontName=BOLD, fontSize=27, leading=32,
        textColor=colors.white, alignment=TA_LEFT, spaceAfter=0,
    ),
    "subtitle": ParagraphStyle(
        "dxSubtitle", fontName=REG, fontSize=12.5, leading=18,
        textColor=colors.HexColor("#9AA6B8"), alignment=TA_LEFT,
    ),
    "coverMeta": ParagraphStyle(
        "dxCoverMeta", fontName=MONO, fontSize=8.5, leading=14,
        textColor=colors.HexColor("#7C8899"), alignment=TA_LEFT,
    ),
    "h1": ParagraphStyle(
        "dxH1", fontName=BOLD, fontSize=17, leading=22, textColor=INK,
        spaceBefore=22, spaceAfter=9,
    ),
    "h2": ParagraphStyle(
        "dxH2", fontName=BOLD, fontSize=12.5, leading=17, textColor=INK,
        spaceBefore=15, spaceAfter=6,
    ),
    "h3": ParagraphStyle(
        "dxH3", fontName=BOLD, fontSize=10.5, leading=15, textColor=colors.HexColor("#3A424E"),
        spaceBefore=11, spaceAfter=4,
    ),
    "body": ParagraphStyle(
        "dxBody", fontName=REG, fontSize=9.7, leading=15.2, textColor=BODY,
        alignment=TA_JUSTIFY, spaceAfter=8,
    ),
    "bullet": ParagraphStyle(
        "dxBullet", fontName=REG, fontSize=9.7, leading=15, textColor=BODY,
        alignment=TA_LEFT, leftIndent=14, bulletIndent=4, spaceAfter=4,
    ),
    "quote": ParagraphStyle(
        "dxQuote", fontName=BOLD, fontSize=9.5, leading=15, textColor=colors.HexColor("#8A0026"),
        leftIndent=10, rightIndent=8, spaceBefore=6, spaceAfter=10,
    ),
    "code": ParagraphStyle(
        "dxCode", fontName=MONO, fontSize=8.6, leading=12.4, textColor=colors.HexColor("#1B2530"),
    ),
    "abstractLead": ParagraphStyle(
        "dxAbstract", fontName=REG, fontSize=10.2, leading=16, textColor=colors.HexColor("#2A3038"),
        alignment=TA_JUSTIFY, spaceAfter=8,
    ),
    "th": ParagraphStyle(
        "dxTh", fontName=BOLD, fontSize=8.4, leading=11.5, textColor=colors.white,
    ),
    "td": ParagraphStyle(
        "dxTd", fontName=REG, fontSize=8.4, leading=11.5, textColor=BODY,
    ),
    "footer": ParagraphStyle(
        "dxFooter", fontName=REG, fontSize=7.4, textColor=MUTED, alignment=TA_CENTER,
    ),
}


# ── page furniture ────────────────────────────────────────────────────────
def cover_page(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(DEEP)
    canvas.rect(0, h - 128 * mm, w, 128 * mm, stroke=0, fill=1)
    canvas.setFillColor(REKT)
    canvas.rect(0, h - 128 * mm, w, 2.2 * mm, stroke=0, fill=1)
    # Faint grid, echoing the website.
    canvas.setStrokeColor(colors.HexColor("#1B2130"))
    canvas.setLineWidth(0.3)
    for x in range(0, int(w), 24):
        canvas.line(x, h - 128 * mm, x, h)
    for y in range(int(h - 128 * mm), int(h), 24):
        canvas.line(0, y, w, y)
    canvas.restoreState()


def body_page(canvas, doc):
    canvas.saveState()
    w, _ = A4
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(20 * mm, 16 * mm, w - 20 * mm, 16 * mm)
    canvas.setFont(REG, 7.4)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, 11 * mm, "DeckxCoin — Covenant Outputs for a Peer-to-Peer Electronic Cash System")
    canvas.drawRightString(w - 20 * mm, 11 * mm, str(canvas.getPageNumber()))
    canvas.restoreState()


# ── markdown -> flowables ─────────────────────────────────────────────────
def build_table(rows: list[list[str]]) -> Table:
    header, *body_rows = rows
    data = [[Paragraph(inline(c), S["th"]) for c in header]]
    data += [[Paragraph(inline(c), S["td"]) for c in r] for r in body_rows]

    ncols = len(header)
    avail = A4[0] - 40 * mm
    # First column narrower for two-column key/value tables, otherwise even.
    if ncols == 2:
        widths = [avail * 0.34, avail * 0.66]
    elif ncols == 3:
        widths = [avail * 0.22, avail * 0.20, avail * 0.58]
    else:
        widths = [avail / ncols] * ncols

    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#242B36")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("GRID", (0, 0), (-1, -1), 0.4, RULE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
            ]
        )
    )
    return t


# Preformatted blocks render literally — no markup, so <super>/<sub> are not an
# option and every character must exist in Courier. Map to plain ASCII.
CODE_FALLBACK = {
    "⌊": "floor(",
    "⌋": ")",
    "‖": "||",
    "₁": "1",
    "₂": "2",
    "⇔": "<=>",
    "≥": ">=",
    "≤": "<=",
    "·": "*",
    "×": "x",
    "²⁵⁶": "^256",
    "⁻¹⁶": "^-16",
    "→": "->",
}


def normalise_code(text: str) -> str:
    for src, dst in CODE_FALLBACK.items():
        text = text.replace(src, dst)
    return text


def code_block(lines: list[str]):
    text = normalise_code("\n".join(lines).rstrip())
    inner = Preformatted(text, S["code"])
    t = Table([[inner]], colWidths=[A4[0] - 40 * mm], hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CODEBG),
                ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t


def quote_block(lines: list[str]):
    text = " ".join(l.lstrip("> ").strip() for l in lines)
    p = Paragraph(inline(text), S["quote"])
    t = Table([[p]], colWidths=[A4[0] - 40 * mm], hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FDF1F4")),
                ("LINEBEFORE", (0, 0), (0, -1), 2.4, REKT),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    return t


def parse(md: str) -> list:
    lines = md.split("\n")
    flow: list = []
    i = 0
    seen_title = False
    para: list[str] = []

    def flush_para():
        nonlocal para
        if para:
            flow.append(Paragraph(inline(" ".join(para)), S["body"]))
            para = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # fenced/indented code
        if line.startswith("    ") and stripped:
            flush_para()
            block = []
            while i < len(lines) and (lines[i].startswith("    ") or not lines[i].strip()):
                if lines[i].strip() or block:
                    block.append(lines[i][4:])
                i += 1
            while block and not block[-1].strip():
                block.pop()
            flow.append(Spacer(1, 4))
            flow.append(code_block(block))
            flow.append(Spacer(1, 9))
            continue

        if not stripped:
            flush_para()
            i += 1
            continue

        if stripped.startswith("> "):
            flush_para()
            block = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                block.append(lines[i].strip())
                i += 1
            flow.append(quote_block(block))
            continue

        if stripped.startswith("|"):
            flush_para()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            if rows:
                flow.append(Spacer(1, 4))
                flow.append(build_table(rows))
                flow.append(Spacer(1, 11))
            continue

        if re.fullmatch(r"-{3,}", stripped):
            flush_para()
            flow.append(Spacer(1, 5))
            flow.append(HRFlowable(width="100%", thickness=0.5, color=RULE))
            flow.append(Spacer(1, 5))
            i += 1
            continue

        m = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        if m:
            flush_para()
            level, text = len(m.group(1)), m.group(2)
            if level == 1 and not seen_title:
                seen_title = True  # the cover carries it
                i += 1
                continue
            style = S["h1"] if level == 1 else S["h2"] if level == 2 else S["h3"]
            flow.append(KeepTogether(Paragraph(inline(text), style)))
            i += 1
            continue

        m = re.match(r"^[-*]\s+(.*)$", stripped)
        if m:
            flush_para()
            flow.append(Paragraph(inline(m.group(1)), S["bullet"], bulletText="•"))
            i += 1
            continue

        m = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if m:
            flush_para()
            flow.append(Paragraph(inline(m.group(2)), S["bullet"], bulletText=f"{m.group(1)}."))
            i += 1
            continue

        para.append(stripped)
        i += 1

    flush_para()
    return flow


def cover(md: str) -> list:
    """The title page. Hand-built rather than derived from the Markdown."""
    w = A4[0] - 40 * mm
    out: list = [Spacer(1, 26 * mm)]

    out.append(Paragraph("DeckxCoin", S["title"]))
    out.append(Spacer(1, 3 * mm))
    out.append(
        Paragraph(
            "Covenant Outputs for a Peer-to-Peer<br/>Electronic Cash System",
            ParagraphStyle("dxCoverSub", parent=S["title"], fontSize=15.5, leading=21,
                           textColor=colors.HexColor("#C9D2E0")),
        )
    )
    out.append(Spacer(1, 9 * mm))
    out.append(
        Paragraph(
            "Bitcoin's unspent-output value layer, an Ethereum-style contract layer that "
            "holds no balance, and a Lightning-style channel network — in one chain.",
            ParagraphStyle("dxCoverLede", parent=S["subtitle"]),
        )
    )
    out.append(Spacer(1, 12 * mm))

    meta = [
        "Version 1.0  ·  August 2026",
        "github.com/xyb3rpunq/deckxcoin",
        "xyb3rpunq.github.io/deckxcoin",
        "",
        "genesis  000033be141b2fc85b4df117dc41c733f2b4d83c29b9d55d84ac8db96670985c",
        "supply   21,000,000 DECKX  ·  halving every 365 days",
        "tests    110 passing",
        "licence  MIT",
    ]
    out.append(Paragraph("<br/>".join(esc(m) for m in meta), S["coverMeta"]))

    out.append(Spacer(1, 30 * mm))

    warn = Paragraph(
        "<b>Not audited. No live network. DECKX is not available for purchase and has no price. "
        "Nothing in this document is financial, investment, tax, or legal advice.</b>",
        ParagraphStyle("dxWarn", fontName=REG, fontSize=8.6, leading=13,
                       textColor=colors.HexColor("#8A0026")),
    )
    box = Table([[warn]], colWidths=[w], hAlign="LEFT")
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FDF1F4")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#F0BCC8")),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    out.append(box)
    out.append(NextPageTemplate("body"))
    out.append(PageBreak())
    return out


def main() -> int:
    md = SRC.read_text(encoding="utf-8")

    doc = BaseDocTemplate(
        str(OUT),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=22 * mm,
        title="DeckxCoin — Covenant Outputs for a Peer-to-Peer Electronic Cash System",
        author="xyb3rpunq",
        subject="DeckxCoin protocol whitepaper v1.0",
        keywords="blockchain, UTXO, covenant, smart contract, payment channel, proof of work",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[frame], onPage=cover_page),
            PageTemplate(id="body", frames=[frame], onPage=body_page),
        ]
    )

    story = cover(md) + parse(md)
    doc.build(story)

    size = OUT.stat().st_size
    print(f"wrote {OUT}  ({size / 1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
