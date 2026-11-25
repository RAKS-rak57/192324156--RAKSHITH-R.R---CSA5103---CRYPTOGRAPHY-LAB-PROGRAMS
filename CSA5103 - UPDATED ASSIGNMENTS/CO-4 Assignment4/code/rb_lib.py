#!/usr/bin/env python3
"""rb_lib.py - helpers that append formatted content to the given CO4 front-page document."""
import re, os, json
import docx
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

BASE = os.path.join(os.path.dirname(__file__), "..")
FRONT = "/mnt/user-data/uploads/CO4_Assignment_FRONT_PAGE_GCR_GIVEN.docx"
doc = docx.Document(FRONT)
FONT = "Arial"; DARK = RGBColor(0x1F, 0x3A, 0x5F); N = dict(tbl=0, fig=0); LABELS = {}; PENDING = []
TEXTW = 6.6        # usable width in inches
J = lambda n: json.load(open(f"{BASE}/results/{n}.json"))


def _font(r, size=10, bold=None, italic=None, color=None, name=FONT, mono=False):
    r.font.name = "Consolas" if mono else name; r.font.size = Pt(size)
    rpr = r._element.get_or_add_rPr(); rf = rpr.find(qn("w:rFonts"))
    if rf is None: rf = OxmlElement("w:rFonts"); rpr.insert(0, rf)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"): rf.set(qn(a), "Consolas" if mono else name)
    if bold is not None: r.bold = bold
    if italic is not None: r.italic = italic
    if color is not None: r.font.color.rgb = color


def _runs(p, text, size=10, bold=False, italic=False, color=None):
    """Inline markup: **bold**, `code`, __italic__."""
    for part in re.split(r"(\*\*.+?\*\*|`.+?`|__.+?__)", text):
        if not part: continue
        if part.startswith("**"): r = p.add_run(part[2:-2]); _font(r, size, True, italic, color)
        elif part.startswith("`"): r = p.add_run(part[1:-1]); _font(r, size - 0.5, bold, italic, color or RGBColor(0x8B, 0x1A, 0x1A), mono=True)
        elif part.startswith("__"): r = p.add_run(part[2:-2]); _font(r, size, bold, True, color)
        else: r = p.add_run(part); _font(r, size, bold, italic, color)
    PENDING.append(p)


def _fmt(p, after=4, before=0, line=1.08, align=None, left=None, hang=None, keep=False):
    pf = p.paragraph_format; pf.space_after = Pt(after); pf.space_before = Pt(before); pf.line_spacing = line; pf.keep_with_next = keep
    if left is not None: pf.left_indent = Inches(left)
    if hang is not None: pf.first_line_indent = Inches(-hang)
    if align == "c": p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    elif align == "j": p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY


def P(text, size=10, bold=False, italic=False, align="j", after=5, before=0, color=None, keep=False):
    p = doc.add_paragraph(); _runs(p, text, size, bold, italic, color); _fmt(p, after, before, align=align, keep=keep); return p


def PB():
    p = doc.add_paragraph(); p.add_run().add_break(WD_BREAK.PAGE); _fmt(p, 0)


def _heading(text, level, size, before, after, pagebreak=False, color=DARK):
    p = doc.add_paragraph(style=f"Heading {level}"); r = p.add_run(text); _font(r, size, True, False, color)
    pf = p.paragraph_format; pf.space_before = Pt(before); pf.space_after = Pt(after); pf.keep_with_next = True; pf.page_break_before = pagebreak; pf.line_spacing = 1.0
    ppr = p._element.get_or_add_pPr(); num = ppr.find(qn("w:numPr"))
    if num is not None: ppr.remove(num)
    return p
def H1(t, pagebreak=True): return _heading(t, 1, 15, 4, 8, pagebreak)
def H2(t, pagebreak=False): return _heading(t, 2, 12, 12, 5, pagebreak)
def H3(t): return _heading(t, 3, 10.5, 8, 3, False, RGBColor(0x2B, 0x5C, 0x8A))


def BUL(items, size=10, left=0.28, after=2):
    for t in items:
        p = doc.add_paragraph(); _runs(p, "•\u00A0\u00A0" + t, size); _fmt(p, after, 0, align="j", left=left, hang=0.18)


def NUM(items, size=10, left=0.3, after=2):
    for i, t in enumerate(items, 1):
        p = doc.add_paragraph(); _runs(p, f"{i}.\u00A0\u00A0" + t, size); _fmt(p, after, 0, align="j", left=left, hang=0.22)


def _shade(cell_or_p, fill):
    el = cell_or_p._tc if hasattr(cell_or_p, "_tc") else cell_or_p._element
    pr = el.get_or_add_tcPr() if hasattr(cell_or_p, "_tc") else el.get_or_add_pPr()
    shd = OxmlElement("w:shd"); shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), fill); pr.append(shd)


def _borders(tbl, color="9AA5B1", sz=4):
    tblPr = tbl._tbl.tblPr; b = OxmlElement("w:tblBorders")
    for e in ("top", "left", "bottom", "right", "insideH", "insideV"):
        x = OxmlElement(f"w:{e}"); x.set(qn("w:val"), "single"); x.set(qn("w:sz"), str(sz)); x.set(qn("w:space"), "0"); x.set(qn("w:color"), color); b.append(x)
    tblPr.append(b)
    m = OxmlElement("w:tblCellMar")
    for e, v in (("top", 30), ("left", 70), ("bottom", 30), ("right", 70)):
        x = OxmlElement(f"w:{e}"); x.set(qn("w:w"), str(v)); x.set(qn("w:type"), "dxa"); m.append(x)
    tblPr.append(m)
    lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"), "fixed"); tblPr.append(lay)


def TBL(headers, rows, widths, fs=8.5, fill="1F3A5F", zebra=True, firstbold=False, align=None, keep=True):
    t = doc.add_table(rows=1 + len(rows), cols=len(headers)); t.alignment = WD_TABLE_ALIGNMENT.CENTER; _borders(t)
    tot = sum(widths); widths = [w * TEXTW / tot for w in widths]
    t.autofit = False
    for i, col in enumerate(t.columns): col.width = Inches(widths[i])
    tw = OxmlElement("w:tblW"); tw.set(qn("w:w"), str(int(TEXTW * 1440))); tw.set(qn("w:type"), "dxa")
    old = t._tbl.tblPr.find(qn("w:tblW"))
    if old is not None: t._tbl.tblPr.remove(old)
    t._tbl.tblPr.append(tw)
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]; c.width = Inches(widths[i]); _shade(c, fill); p = c.paragraphs[0]; _runs(p, h, fs, True, False, RGBColor(255, 255, 255)); _fmt(p, 0, 0, line=1.0)
    trPr = t.rows[0]._tr.get_or_add_trPr(); th = OxmlElement("w:tblHeader"); th.set(qn("w:val"), "true"); trPr.append(th)
    for ri, row in enumerate(rows, 1):
        tr = t.rows[ri]; cs = OxmlElement("w:cantSplit"); cs.set(qn("w:val"), "true"); tr._tr.get_or_add_trPr().append(cs)
        for ci, v in enumerate(row):
            c = tr.cells[ci]; c.width = Inches(widths[ci]); lines = str(v).split("\n")
            if zebra and ri % 2 == 0: _shade(c, "F2F6FA")
            for li, ln in enumerate(lines):
                p = c.paragraphs[0] if li == 0 else c.add_paragraph(); _runs(p, ln, fs, bold=(firstbold and ci == 0)); _fmt(p, 0, 0, line=1.0)
                if align and align[ci] == "c": p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sp = doc.add_paragraph(); _fmt(sp, 3, 0); sp.paragraph_format.line_spacing = 0.6
    return t


def CAPT(label, text):
    N["tbl"] += 1; LABELS[label] = f"Table {N['tbl']}"
    p = doc.add_paragraph(); _runs(p, f"**Table {N['tbl']}.** {text}", 9, False, False, DARK); _fmt(p, 2, 4, align="l", keep=True)


def FIG(name, width, text, label=None):
    N["fig"] += 1; LABELS[label or name] = f"Figure {N['fig']}"
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER; p.paragraph_format.keep_with_next = True; p.paragraph_format.space_before = Pt(4); p.paragraph_format.space_after = Pt(2)
    p.add_run().add_picture(f"{BASE}/fig/{name}.png", width=Inches(width))
    c = doc.add_paragraph(); _runs(c, f"**Figure {N['fig']}.** {text}", 8.5, False, True); _fmt(c, 6, 0, align="c")


def CODE(text, size=7.8, fill="F4F6F8", title=None):
    if title:
        p = doc.add_paragraph(); _runs(p, title, 8.5, True, False, DARK); _fmt(p, 1, 3, align="l", keep=True)
    maxc = int(TEXTW * 72 / (size * 0.60)) - 3; lines = []
    for ln in text.rstrip("\n").split("\n"):
        while len(ln) > maxc:
            k = ln.rfind("//", 20)
            if k > 0 and k < len(ln) and len(ln[:k].rstrip()) <= maxc:
                ind = len(ln) - len(ln.lstrip()); lines.append(ln[:k].rstrip()); ln = " " * (ind + 3) + ln[k:]; 
                if len(ln) <= maxc: break
                continue
            cut = ln.rfind(" ", 40, maxc); cut = cut if cut > 0 else maxc
            ind = len(ln) - len(ln.lstrip()); lines.append(ln[:cut]); ln = " " * (ind + 4) + ln[cut:].lstrip()
        lines.append(ln)
    step = 48
    for i in range(0, len(lines), step):
        p = doc.add_paragraph(); chunk = "\n".join(lines[i:i + step]); r = p.add_run(chunk); _font(r, size, mono=True)
        _fmt(p, 0, 0, line=1.0, align="l", left=0.08); ppr = p._element.get_or_add_pPr(); shd = OxmlElement("w:shd"); shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), fill); ppr.append(shd)
        bd = OxmlElement("w:pBdr")
        for e in ("left",):
            x = OxmlElement(f"w:{e}"); x.set(qn("w:val"), "single"); x.set(qn("w:sz"), "12"); x.set(qn("w:space"), "4"); x.set(qn("w:color"), "2B5C8A"); bd.append(x)
        ppr.append(bd)
    sp = doc.add_paragraph(); _fmt(sp, 4, 0); sp.paragraph_format.line_spacing = 0.6


def BOX(title, lines, fill="EAF3EA", color="2E7D32"):
    t = doc.add_table(rows=1, cols=1); t.alignment = WD_TABLE_ALIGNMENT.CENTER; _borders(t, color, 8); t.autofit = False; t.columns[0].width = Inches(TEXTW); c = t.rows[0].cells[0]; c.width = Inches(TEXTW); _shade(c, fill)
    p = c.paragraphs[0]; _runs(p, title, 9, True); _fmt(p, 2, 0, align="l")
    for ln in lines: q = c.add_paragraph(); _runs(q, ln, 8.8); _fmt(q, 1, 0, align="j")
    sp = doc.add_paragraph(); _fmt(sp, 4, 0); sp.paragraph_format.line_spacing = 0.6


def REF(label): return "{{" + label + "}}"


def resolve():
    """Replace {{label}} tokens with the numbered caption names in every paragraph (body and tables)."""
    def fix(p):
        for r in p.runs:
            if "{{" in r.text:
                r.text = re.sub(r"\{\{(.+?)\}\}", lambda m: LABELS.get(m.group(1), "??" + m.group(1)), r.text)
    for p in doc.paragraphs: fix(p)
    for t in doc.tables:
        for row in t.rows:
            for c in row.cells:
                for p in c.paragraphs: fix(p)
    miss = [r.text for p in doc.paragraphs for r in p.runs if "??" in r.text]
    return miss
