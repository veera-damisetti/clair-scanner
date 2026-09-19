#!/usr/bin/env python3
"""
Clair CVE PDF Report Generator
Zero dependencies — Python stdlib only (json, textwrap, os, datetime).
Produces valid PDF 1.4 using raw PDF primitives.

Individual report sections:
  1. Cover page  – image ref, architecture, digest, created, OS, total layers
  2. Image metadata – all skopeo inspect fields
  3. Layer list  – every layer digest + size
  4. Severity summary table
  5. Full CVE table – ID, package, version, severity, CVSS, description, fix
Diff report:
  1. Comparison overview table
  2. s390x-only CVEs (full detail)
  3. x86_64-only CVEs (full detail)
  4. Common CVEs list
"""
import os
import sys
import json
import argparse
import textwrap
from datetime import datetime

# ---------------------------------------------------------------------------
# Severity config
# ---------------------------------------------------------------------------
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
SEV_COLOR = {
    "Critical":   (0.81, 0.13, 0.18),
    "High":       (0.74, 0.30, 0.00),
    "Medium":     (0.75, 0.53, 0.00),
    "Low":        (0.04, 0.41, 0.85),
    "Negligible": (0.22, 0.60, 0.29),
    "Unknown":    (0.34, 0.38, 0.42),
}

# ---------------------------------------------------------------------------
# Minimal raw-PDF writer (zero deps)
# ---------------------------------------------------------------------------
class PDF:
    """
    PDF 1.4 writer using only Python stdlib.
    Page size: A4 portrait (595 x 842 pt).
    Coordinate origin: bottom-left; y increases upward.
    """
    PW, PH   = 595, 842
    ML, MR   = 42, 42
    MT, MB   = 45, 45

    def __init__(self):
        self._objects       = []
        self._pages         = []
        self._page_streams  = {}
        self._cur_page      = None
        self._cur_stream    = b""
        self._y             = 0
        self._page_no       = 0
        self._setup()

    # ------------------------------------------------------------------ objects
    def _add_obj(self, data) -> int:
        self._objects.append(data)
        return len(self._objects)

    def _setup(self):
        self._cat_idx   = self._add_obj(b"")   # 1 catalog
        self._pages_idx = self._add_obj(b"")   # 2 pages
        self._fn_idx    = self._add_obj(       # 3 Helvetica
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>")
        self._fb_idx    = self._add_obj(       # 4 Helvetica-Bold
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
            b"/Encoding /WinAnsiEncoding >>")

    # ------------------------------------------------------------------ pages
    def add_page(self):
        if self._cur_page is not None:
            self._page_streams[self._cur_page] = self._cur_stream
        self._cur_stream = b""
        idx = self._add_obj(b"")
        self._pages.append(idx)
        self._cur_page = idx
        self._y = self.PH - self.MT - 10
        self._page_no += 1

    def _flush(self):
        if self._cur_page is not None:
            self._page_streams[self._cur_page] = self._cur_stream

    # ------------------------------------------------------------------ stream ops
    def _w(self, s: str):
        self._cur_stream += (s + "\n").encode("latin-1", errors="replace")

    def _esc(self, s: str) -> str:
        return (str(s)
                .replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replace("\r", "")
                .replace("\n", " "))

    def _font(self, bold=False, size=9):
        ref = self._fb_idx if bold else self._fn_idx
        self._w(f"/F{ref} {size} Tf")

    def _rgb(self, r, g, b):
        self._w(f"{r:.3f} {g:.3f} {b:.3f} rg")

    def _srgb(self, r, g, b):
        self._w(f"{r:.3f} {g:.3f} {b:.3f} RG")

    def _dark(self):
        self._rgb(0.12, 0.14, 0.16)

    def _muted(self):
        self._rgb(0.34, 0.38, 0.42)

    def _text(self, x, y, s):
        self._w(f"BT {x:.1f} {y:.1f} Td ({self._esc(s)}) Tj ET")

    def _line(self, x1, y1, x2, y2, w=0.4):
        self._w(f"{w:.2f} w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S")

    def _hrule(self, y, r=0.85, g=0.86, b=0.87):
        self._srgb(r, g, b)
        self._line(self.ML, y, self.PW - self.MR, y)

    def _fillrect(self, x, y, w, h, r, g, b):
        self._rgb(r, g, b)
        self._w(f"{x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")
        self._dark()

    def _strokerect(self, x, y, w, h):
        self._srgb(0.82, 0.84, 0.86)
        self._w(f"0.3 w {x:.1f} {y:.1f} {w:.1f} {h:.1f} re S")

    # ------------------------------------------------------------------ char width
    @staticmethod
    def _cw(ch, size) -> float:
        if ch in "iIl1|!.,;: '\"":
            return size * 0.29
        if ch in "mMwW@%":
            return size * 0.72
        return size * 0.53

    def _sw(self, s, size) -> float:
        return sum(self._cw(c, size) for c in str(s))

    # ------------------------------------------------------------------ printable width
    @property
    def _pw(self):
        return self.PW - self.ML - self.MR

    # ------------------------------------------------------------------ need-page guard
    def _need(self, h):
        if self._y - h < self.MB + 14:
            self._draw_footer()
            self.add_page()
            self._draw_header()

    # ------------------------------------------------------------------ header / footer
    def _draw_header(self):
        self._font(bold=True, size=7)
        self._muted()
        self._text(self.ML, self.PH - 30, "Clair CVE Security Scan Report  |  IBM Z Platform Security")
        ts = datetime.now().strftime("%Y-%m-%d")
        self._text(self.PW - self.MR - self._sw(ts, 7) - 2, self.PH - 30, ts)
        self._hrule(self.PH - 34)
        self._y = self.PH - 46

    def _draw_footer(self):
        self._hrule(self.MB + 10)
        self._font(bold=False, size=7)
        self._muted()
        self._text(self.ML, self.MB, "CONFIDENTIAL — IBM Z Platform Security | Powered by Clair & IBM Bob")
        pn = f"Page {self._page_no}"
        self._text(self.PW - self.MR - self._sw(pn, 7) - 2, self.MB, pn)

    # ------------------------------------------------------------------ typography helpers
    def _wrap_lines(self, s, max_w, size) -> list:
        avg = size * 0.53
        chars = max(1, int(max_w / avg))
        result = []
        for raw in str(s).splitlines():
            if not raw.strip():
                result.append("")
            else:
                result.extend(textwrap.wrap(raw, width=chars) or [""])
        return result

    def _multiline(self, s, x, y, max_w, size=8, bold=False, color=None, lh=None):
        """Draw wrapped text. Returns final y after last line."""
        if color:
            self._rgb(*color)
        else:
            self._dark()
        self._font(bold=bold, size=size)
        lh = lh or (size + 3)
        for ln in self._wrap_lines(s, max_w, size):
            self._text(x, y, ln)
            y -= lh
        self._dark()
        return y

    def _line_height(self, s, max_w, size, lh=None) -> float:
        """Measure how tall wrapped text will be."""
        lh = lh or (size + 3)
        return len(self._wrap_lines(s, max_w, size)) * lh

    # ================================================================== public layout
    def cover_rule(self):
        self._fillrect(0, self.PH - 6, self.PW, 6, 0.13, 0.13, 0.13)

    def h1(self, s):
        self._need(36)
        self._font(bold=True, size=22)
        self._dark()
        self._text(self.ML, self._y - 22, s)
        self._y -= 30

    def h2(self, s):
        self._need(24)
        self._y -= 6
        self._font(bold=True, size=13)
        self._dark()
        self._text(self.ML, self._y - 13, s)
        self._y -= 20

    def h3(self, s):
        self._need(18)
        self._font(bold=True, size=10)
        self._dark()
        self._text(self.ML, self._y - 10, s)
        self._y -= 15

    def body(self, s, size=9, color=None, indent=0):
        self._need(13)
        lh = size + 3
        for ln in self._wrap_lines(s, self._pw - indent, size):
            if color:
                self._rgb(*color)
            else:
                self._muted()
            self._text(self.ML + indent, self._y - size, ln)
            self._y -= lh
        self._dark()

    def kv(self, key, val, key_w=130):
        """Key: Value line."""
        self._need(14)
        self._font(bold=True, size=8)
        self._dark()
        self._text(self.ML, self._y - 8, f"{key}:")
        self._font(bold=False, size=8)
        self._muted()
        # wrap value in remaining width
        val_x   = self.ML + key_w
        val_w   = self._pw - key_w
        lines   = self._wrap_lines(str(val), val_w, 8)
        y_start = self._y
        for ln in lines:
            self._text(val_x, self._y - 8, ln)
            self._y -= 11
        if len(lines) <= 1:
            self._y = y_start - 11
        self._dark()

    def spacer(self, h=6):
        self._y -= h

    def hrule(self):
        self._hrule(self._y)
        self._y -= 5

    def sev_badge(self, sev, x, y, size=7):
        col = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
        self._font(bold=True, size=size)
        self._rgb(*col)
        self._text(x, y, sev)
        self._dark()

    # ------------------------------------------------------------------ summary table
    def sev_table(self, counts):
        # cw sums to 125 — narrow, left-aligned block
        cw = [90, 35]
        rh = 13
        ty = 4   # text y-offset from cell bottom
        self._need(rh * (len(SEV_ORDER) + 2))
        x0 = self.ML
        y  = self._y

        # Header row
        self._fillrect(x0, y - rh, sum(cw), rh, 0.945, 0.953, 0.965)
        self._font(bold=True, size=8); self._dark()
        self._text(x0 + 3,          y - rh + ty, "Severity")
        self._text(x0 + cw[0] + 3,  y - rh + ty, "Count")
        self._strokerect(x0,         y - rh, cw[0], rh)
        self._strokerect(x0 + cw[0], y - rh, cw[1], rh)
        y -= rh

        for sev in SEV_ORDER:
            self._need(rh)
            y = self._y
            col = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
            self._font(bold=True, size=8); self._rgb(*col)
            self._text(x0 + 3,          y - rh + ty, sev)
            self._font(bold=False, size=8); self._dark()
            self._text(x0 + cw[0] + 3,  y - rh + ty, str(counts.get(sev, 0)))
            self._strokerect(x0,         y - rh, cw[0], rh)
            self._strokerect(x0 + cw[0], y - rh, cw[1], rh)
            self._y -= rh

        self._y -= 8

    # ------------------------------------------------------------------ layer table
    def layer_table(self, layers):
        """layers: list of dicts with 'digest' and optionally 'size'"""
        # cw sums to 411 — digest gets most space, size column on right
        cw = [381, 130]   # 381 + 130 = 511 = full printable width
        rh = 12
        ty = 3
        x0 = self.ML

        self._need(rh * 2)
        y = self._y
        self._fillrect(x0, y - rh, sum(cw), rh, 0.945, 0.953, 0.965)
        self._font(bold=True, size=7); self._dark()
        self._text(x0 + 3,          y - rh + ty, "Layer Digest")
        self._text(x0 + cw[0] + 3,  y - rh + ty, "Size")
        self._strokerect(x0,         y - rh, cw[0], rh)
        self._strokerect(x0 + cw[0], y - rh, cw[1], rh)
        self._y -= rh

        for idx, layer in enumerate(layers):
            self._need(rh)
            y = self._y
            dig  = str(layer.get("digest") or layer.get("Digest") or f"layer-{idx}")
            size = layer.get("size") or layer.get("Size") or ""
            if size:
                try:
                    size = f"{int(size)/1024/1024:.2f} MB"
                except Exception:
                    size = str(size)
            bg = (0.975, 0.975, 0.975) if idx % 2 == 0 else (1.0, 1.0, 1.0)
            self._fillrect(x0, y - rh, sum(cw), rh, *bg)
            self._font(bold=False, size=6.5); self._muted()
            self._text(x0 + 3,          y - rh + ty, dig[:80])
            self._text(x0 + cw[0] + 3,  y - rh + ty, str(size))
            self._strokerect(x0,         y - rh, cw[0], rh)
            self._strokerect(x0 + cw[0], y - rh, cw[1], rh)
            self._y -= rh

        self._y -= 6

    # ------------------------------------------------------------------ full CVE table
    def cve_table(self, cves_by_sev):
        """
        Full detail CVE table with all fields from the clairctl RHEL report:
        Advisory | Sev | Package/Arch | Full description + CVE IDs + issued + fixed + errata
        col widths MUST sum to exactly 511 pt (595 - 42 - 42 = 511).
        """
        # 128 + 50 + 80 + 253 = 511
        cw = [128, 50, 80, 253]

        def _draw_header():
            self._need(14)
            y = self._y; x0 = self.ML
            self._fillrect(x0, y - 13, sum(cw), 13, 0.945, 0.953, 0.965)
            self._font(bold=True, size=7.5); self._dark()
            self._text(x0 + 3,                          y - 9, "Advisory / CVE IDs")
            self._text(x0 + cw[0] + 3,                  y - 9, "Severity")
            self._text(x0 + cw[0] + cw[1] + 3,          y - 9, "Package")
            self._text(x0 + cw[0] + cw[1] + cw[2] + 3,  y - 9, "Details")
            self._strokerect(x0, y - 13, sum(cw), 13)
            self._y -= 13

        _draw_header()

        for sev in SEV_ORDER:
            col = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
            for c in sorted(cves_by_sev.get(sev, []), key=lambda x: x["id"]):
                advisory    = c["id"]           # RHSA-YYYY:NNNN: pkg ...
                cve_ids     = c.get("cve_ids") or []
                pkg         = c["package"]
                ver         = c.get("version") or ""
                arch        = c.get("arch") or ""
                sev_raw     = c.get("severity_raw") or sev
                desc        = c.get("description") or "No description provided."
                fixed       = c.get("fixed_in") or ""
                issued      = c.get("issued") or ""
                dist_name   = c.get("dist_name") or ""
                dist_ver    = c.get("dist_version") or ""
                repo        = c.get("repo") or ""
                errata_url  = c.get("errata_url") or ""

                # ---- Col 1: Advisory short name + CVE IDs ----
                # Trim advisory to just the RHSA-YYYY:NNNN part + first 40 chars of title
                adv_short = advisory[:60]
                cve_line  = "  ".join(cve_ids) if cve_ids else ""
                col1_text = adv_short + ("\n" + cve_line if cve_line else "")

                # ---- Col 2: Severity ----
                # "High (Important)" style
                sev_line = sev if sev_raw.lower() == sev.lower() else f"{sev}\n({sev_raw})"

                # ---- Col 3: Package + version + arch ----
                pkg_lines = pkg
                if ver:
                    pkg_lines += f"\n{ver}"
                if arch:
                    # arch field is pipe/bar-separated list in real data
                    pkg_lines += f"\n{arch[:30]}"

                # ---- Col 4: Detail cell ----
                # Description (trimmed) + issued + fixed + dist + errata
                detail  = desc[:350]
                extras  = []
                if issued:
                    extras.append(f"Issued: {issued}")
                if fixed:
                    extras.append(f"Fixed: {fixed}")
                if dist_name:
                    dv = f" {dist_ver}" if dist_ver else ""
                    extras.append(f"OS: {dist_name}{dv}")
                if repo:
                    extras.append(f"Repo: {repo}")
                if errata_url:
                    extras.append(f"Errata: {errata_url}")
                if extras:
                    detail += "\n" + "  |  ".join(extras)

                # Measure row height across all 4 cols
                h1 = self._line_height(col1_text, cw[0] - 6, 7)
                h2 = self._line_height(sev_line,  cw[1] - 6, 7)
                h3 = self._line_height(pkg_lines, cw[2] - 6, 7)
                h4 = self._line_height(detail,    cw[3] - 6, 7)
                row_h = max(h1, h2, h3, h4, 14) + 4

                # Page break with repeated header
                if self._y - row_h < self.MB + 14:
                    self._draw_footer()
                    self.add_page()
                    self._draw_header()
                    _draw_header()

                y = self._y; x0 = self.ML

                # Alternating row background
                self._fillrect(x0, y - row_h, sum(cw), row_h, 0.995, 0.995, 0.995)

                # Col 1: Advisory + CVE IDs
                self._multiline(col1_text, x0 + 3, y - 5, cw[0] - 6,
                                size=7, bold=False, color=(0.12, 0.14, 0.16))

                # Col 2: Severity badge
                self._font(bold=True, size=7); self._rgb(*col)
                self._text(x0 + cw[0] + 3, y - 6, sev)
                if sev_raw.lower() != sev.lower():
                    self._font(bold=False, size=6.5); self._muted()
                    self._text(x0 + cw[0] + 3, y - 14, f"({sev_raw})")
                self._dark()

                # Col 3: Package + version + arch
                self._multiline(pkg_lines, x0 + cw[0] + cw[1] + 3, y - 5,
                                cw[2] - 6, size=7, bold=False,
                                color=(0.20, 0.22, 0.24))

                # Col 4: Full detail
                self._multiline(detail, x0 + cw[0] + cw[1] + cw[2] + 3, y - 5,
                                cw[3] - 6, size=7, bold=False,
                                color=(0.30, 0.33, 0.36))

                # Cell borders
                self._strokerect(x0,                            y - row_h, cw[0], row_h)
                self._strokerect(x0 + cw[0],                    y - row_h, cw[1], row_h)
                self._strokerect(x0 + cw[0] + cw[1],            y - row_h, cw[2], row_h)
                self._strokerect(x0 + cw[0] + cw[1] + cw[2],    y - row_h, cw[3], row_h)

                self._y -= row_h

        self._y -= 8

    # ------------------------------------------------------------------ simple N-col table
    def simple_table(self, headers, rows, col_widths):
        """
        Draw a bordered table where each cell gets its own border stroke.
        col_widths: list of pt widths; caller is responsible for correct total.
        Text baseline is placed at cell_bottom + 4pt (consistent with rh=13).
        """
        rh = 13
        ty = 4   # text y-offset from cell bottom
        x0 = self.ML
        self._need(rh * 2)
        y = self._y

        # Header row
        self._fillrect(x0, y - rh, sum(col_widths), rh, 0.945, 0.953, 0.965)
        self._font(bold=True, size=8); self._dark()
        cx = x0
        for i, h in enumerate(headers):
            self._text(cx + 3, y - rh + ty, h)
            self._strokerect(cx, y - rh, col_widths[i], rh)
            cx += col_widths[i]
        self._y -= rh

        for row in rows:
            self._need(rh)
            y = self._y
            cx = x0
            for i, cell in enumerate(row):
                if isinstance(cell, tuple):
                    val, col = cell
                    self._font(bold=True, size=8); self._rgb(*col)
                    self._text(cx + 3, y - rh + ty, str(val))
                    self._dark()
                else:
                    self._font(bold=False, size=8); self._dark()
                    self._text(cx + 3, y - rh + ty, str(cell))
                self._strokerect(cx, y - rh, col_widths[i], rh)
                cx += col_widths[i]
            self._y -= rh

        self._y -= 8

    # ================================================================== save
    def save(self, path: str):
        self._flush()
        self._draw_footer()

        page_content_idx = {}
        for pg_idx in self._pages:
            stream = self._page_streams.get(pg_idx, b"")
            ci = self._add_obj(None)
            page_content_idx[pg_idx] = ci
            self._objects[ci - 1] = stream

        fi, fbi = self._fn_idx, self._fb_idx
        for pg_idx in self._pages:
            ci = page_content_idx[pg_idx]
            raw = self._objects[ci - 1]
            self._objects[ci - 1] = (
                f"<< /Length {len(raw)} >>\nstream\n".encode() +
                raw + b"\nendstream"
            )
            self._objects[pg_idx - 1] = (
                f"<< /Type /Page /Parent {self._pages_idx} 0 R "
                f"/MediaBox [0 0 {self.PW} {self.PH}] "
                f"/Contents {ci} 0 R "
                f"/Resources << /Font << /F{fi} {fi} 0 R /F{fbi} {fbi} 0 R >> >> >>"
            ).encode()

        kids = " ".join(f"{i} 0 R" for i in self._pages)
        self._objects[self._pages_idx - 1] = (
            f"<< /Type /Pages /Kids [{kids}] /Count {len(self._pages)} >>"
        ).encode()
        self._objects[self._cat_idx - 1] = (
            f"<< /Type /Catalog /Pages {self._pages_idx} 0 R >>"
        ).encode()

        out = b"%PDF-1.4\n"
        offsets = []
        for i, obj in enumerate(self._objects):
            offsets.append(len(out))
            if isinstance(obj, bytes):
                out += f"{i+1} 0 obj\n".encode() + obj + b"\nendobj\n"
            else:
                out += f"{i+1} 0 obj\n{obj}\nendobj\n".encode()

        xref_pos = len(out)
        out += f"xref\n0 {len(self._objects)+1}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (
            f"trailer\n<< /Size {len(self._objects)+1} /Root {self._cat_idx} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode()

        with open(path, "wb") as f:
            f.write(out)
        print(f"  Generated: {path}  ({len(out)//1024} KB)")


# ===========================================================================
# Data parsing helpers
# ===========================================================================
def load_json(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"  Warning: could not read {path}: {e}")
        return {}


import re as _re

def _extract_cve_ids(links: str) -> list:
    """Pull CVE-YYYY-NNNNN identifiers out of a links string."""
    return _re.findall(r"CVE-\d{4}-\d+", links)


def get_cves(report: dict) -> dict:
    """
    Parse a clairctl --out json report.

    Real clairctl RHEL schema (confirmed from live output):
      Top-level dict keyed by image ref  →  { "vulnerabilities": { id: vuln }, ... }
      Each vuln has:
        name            – RHSA/RHBA advisory ID  (e.g. "RHSA-2026:8873: libarchive ...")
        description     – full advisory text
        issued          – ISO date string
        links           – space-separated URLs including CVE refs
        severity        – "Important" / "Moderate" / "Low" / "Critical"
        normalized_severity – "High" / "Medium" / "Low" / "Critical"
        package         – { name, version, kind, arch, cpe }
        distribution    – { name, version, pretty_name, cpe, ... }
        repository      – { name, key, cpe }
        fixed_in_version – RPM NVR  e.g. "0:3.5.3-5.el9_4"

    One advisory entry covers multiple CVEs listed in its links.
    We emit one record per (advisory_id, package_name) combination,
    storing all CVE IDs extracted from links for display.
    """
    vulns = {}
    packages = {}

    if "vulnerabilities" in report:
        vulns    = report.get("vulnerabilities") or {}
        packages = report.get("packages") or {}
    else:
        for v in report.values():
            if isinstance(v, dict) and "vulnerabilities" in v:
                vulns    = v.get("vulnerabilities") or {}
                packages = v.get("packages") or {}
                break

    cves = {}
    for vid, v in vulns.items():
        advisory   = v.get("name") or vid          # RHSA-YYYY:NNNN: pkg summary
        sev_raw    = v.get("normalized_severity") or v.get("severity") or "Unknown"
        sev        = sev_raw.capitalize()
        if sev not in SEV_COLOR:
            sev = "Unknown"

        # Package — embedded dict in real reports
        pkg_info   = v.get("package") or {}
        if isinstance(pkg_info, str):
            pkg_info = packages.get(pkg_info, {})

        # Distribution info
        dist       = v.get("distribution") or {}
        repo       = v.get("repository") or {}

        # Links / CVE IDs
        links_raw  = v.get("links") or ""
        if isinstance(links_raw, list):
            links_raw = " ".join(links_raw)
        cve_ids    = _extract_cve_ids(links_raw)
        # Advisory URL (first https://access.redhat.com/errata/... link)
        errata_url = ""
        for tok in links_raw.split():
            if "errata" in tok:
                errata_url = tok
                break

        # Issued date
        issued     = fmt_ts(v.get("issued") or "")

        # Fixed-in version
        fixed      = v.get("fixed_in_version") or v.get("fixed_in") or ""

        # Use advisory + package as unique key (multiple arches share same advisory)
        pkg_name   = pkg_info.get("name") or "unknown"
        key        = f"{vid}"   # numeric clairctl internal ID is already unique

        cves[key] = {
            "id":           advisory,           # RHSA advisory name
            "cve_ids":      cve_ids,            # list of CVE-YYYY-NNNN extracted
            "severity":     sev,
            "severity_raw": v.get("severity") or sev,  # "Important" / "Moderate" etc.
            "package":      pkg_name,
            "version":      pkg_info.get("version") or "",
            "arch":         pkg_info.get("arch") or "",
            "pkg_kind":     pkg_info.get("kind") or "",
            "description":  (v.get("description") or "No description provided.").strip(),
            "fixed_in":     fixed,
            "issued":       issued,
            "dist_name":    dist.get("pretty_name") or dist.get("name") or "",
            "dist_version": dist.get("version") or "",
            "repo":         repo.get("name") or "",
            "errata_url":   errata_url,
            "links":        links_raw,
        }
    return cves


def count_by_sev(cves: dict) -> dict:
    counts = {s: 0 for s in SEV_ORDER}
    for c in cves.values():
        sev = c["severity"]
        counts[sev if sev in counts else "Unknown"] += 1
    return counts


def group_by_sev(cves: dict) -> dict:
    groups = {s: [] for s in SEV_ORDER}
    for c in cves.values():
        sev = c["severity"] if c["severity"] in groups else "Unknown"
        groups[sev].append(c)
    return groups


def fmt_ts(ts: str) -> str:
    """Normalise ISO timestamp to readable form."""
    if not ts:
        return "N/A"
    return ts.replace("T", "  ").replace("Z", " UTC")[:30]


# ===========================================================================
# Individual image PDF
# ===========================================================================
def build_individual_pdf(report_path, meta_path, image_ref, label, output_path):
    report = load_json(report_path)
    meta   = load_json(meta_path)   # skopeo inspect output
    cves   = get_cves(report)
    counts = count_by_sev(cves)

    pdf = PDF()

    # ---------------------------------------------------------------  Page 1: Cover
    pdf.add_page()
    pdf.cover_rule()
    pdf.spacer(16)

    pdf.h1(f"Clair CVE Scan Report")
    pdf.spacer(4)

    pdf.body(f"Architecture: {label}", size=13, color=(0.22, 0.24, 0.27))
    pdf.spacer(8)

    pdf.hrule()
    pdf.spacer(4)

    # Image reference (long — wrap it)
    pdf.kv("Image Ref",    image_ref or meta.get("Name") or "N/A", key_w=90)
    pdf.kv("Digest",       meta.get("Digest") or "N/A",             key_w=90)
    pdf.kv("Architecture", meta.get("Architecture") or label,       key_w=90)
    pdf.kv("OS",           meta.get("Os") or "N/A",                 key_w=90)
    pdf.kv("Created",      fmt_ts(meta.get("Created") or ""),       key_w=90)
    pdf.kv("Docker Ver",   meta.get("DockerVersion") or "N/A",      key_w=90)
    pdf.kv("Total Layers", str(len(meta.get("Layers") or meta.get("LayersData") or [])), key_w=90)
    pdf.kv("Total CVEs",   str(len(cves)),                          key_w=90)
    pdf.kv("Scan Time",    datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"), key_w=90)

    pdf.spacer(10)
    pdf.hrule()
    pdf.spacer(6)

    # Author / labels from image
    labels = meta.get("Labels") or {}
    if labels:
        pdf.h3("Image Labels")
        for k, v in list(labels.items())[:20]:
            pdf.kv(k, v, key_w=160)

    # ---------------------------------------------------------------  Page 2: Severity Summary + Layers
    pdf.spacer(12)
    pdf.h2("Vulnerability Summary")
    pdf.sev_table(counts)

    pdf.spacer(8)
    pdf.h2("Image Layers")
    layers_raw = meta.get("LayersData") or []
    if not layers_raw:
        # Fallback: layers might be a list of digest strings
        plain = meta.get("Layers") or []
        layers_raw = [{"digest": d} for d in plain]

    if layers_raw:
        pdf.layer_table(layers_raw)
    else:
        pdf.body("No layer information available from skopeo inspect.", color=(0.5, 0.5, 0.5))

    # ---------------------------------------------------------------  Environment / Config
    cfg = meta.get("Env") or []
    if cfg:
        pdf.spacer(6)
        pdf.h2("Environment Variables")
        for env in cfg:
            pdf.body(str(env), size=7.5, color=(0.25, 0.27, 0.30), indent=6)

    # ---------------------------------------------------------------  Full CVE listing
    pdf.spacer(10)
    pdf.h2(f"Full Vulnerability Listing  ({len(cves)} CVEs)")
    if not cves:
        pdf.body("No vulnerabilities detected in this image.", color=(0.22, 0.60, 0.29))
    else:
        pdf.cve_table(group_by_sev(cves))

    pdf.save(output_path)


# ===========================================================================
# Diff / comparison PDF
# ===========================================================================
def build_diff_pdf(report_a, meta_a, image_a, label_a,
                   report_b, meta_b, image_b, label_b,
                   output_path):
    ra     = load_json(report_a)
    rb     = load_json(report_b)
    ma     = load_json(meta_a)
    mb     = load_json(meta_b)
    cves_a = get_cves(ra)
    cves_b = get_cves(rb)

    only_a  = {k: v for k, v in cves_a.items() if k not in cves_b}
    only_b  = {k: v for k, v in cves_b.items() if k not in cves_a}
    common  = {k: cves_a[k] for k in cves_a if k in cves_b}

    ca = count_by_sev(cves_a)
    cb = count_by_sev(cves_b)

    pdf = PDF()

    # --------------------------------------------------------------- Cover
    pdf.add_page()
    pdf.cover_rule()
    pdf.spacer(16)
    pdf.h1("Clair CVE Diff Report")
    pdf.body(f"{label_a}  vs  {label_b}", size=13, color=(0.22, 0.24, 0.27))
    pdf.spacer(8)
    pdf.hrule()
    pdf.spacer(4)

    pdf.kv(f"{label_a} Ref",    image_a or ma.get("Name") or "N/A",  key_w=100)
    pdf.kv(f"{label_a} Digest", ma.get("Digest") or "N/A",           key_w=100)
    pdf.kv(f"{label_a} OS",     ma.get("Os") or "N/A",               key_w=100)
    pdf.kv(f"{label_a} Created",fmt_ts(ma.get("Created") or ""),     key_w=100)
    pdf.spacer(6)
    pdf.kv(f"{label_b} Ref",    image_b or mb.get("Name") or "N/A",  key_w=100)
    pdf.kv(f"{label_b} Digest", mb.get("Digest") or "N/A",           key_w=100)
    pdf.kv(f"{label_b} OS",     mb.get("Os") or "N/A",               key_w=100)
    pdf.kv(f"{label_b} Created",fmt_ts(mb.get("Created") or ""),     key_w=100)
    pdf.spacer(8)
    pdf.hrule()
    pdf.spacer(4)
    pdf.kv("Scan Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"), key_w=100)

    # --------------------------------------------------------------- Overview table
    pdf.h2("Comparison Overview")
    # 251 + 130 + 130 = 511
    pdf.simple_table(
        headers=["Metric", label_a, label_b],
        rows=[
            ["Total CVEs",      str(len(cves_a)),   str(len(cves_b))],
            ["Common CVEs",     str(len(common)),   str(len(common))],
            [(f"Exclusive CVEs", SEV_COLOR["Low"]),  str(len(only_a)), str(len(only_b))],
            *[
                [sev,
                 (str(ca[sev]), SEV_COLOR[sev]) if ca[sev] else "0",
                 (str(cb[sev]), SEV_COLOR[sev]) if cb[sev] else "0"]
                for sev in SEV_ORDER
            ]
        ],
        col_widths=[251, 130, 130],
    )

    # --------------------------------------------------------------- Only-A
    pdf.h2(f"Vulnerabilities Exclusive to {label_a}  ({len(only_a)})")
    if not only_a:
        pdf.body(f"No exclusive vulnerabilities found for {label_a}.",
                 color=(0.22, 0.60, 0.29))
    else:
        pdf.cve_table(group_by_sev(only_a))

    # --------------------------------------------------------------- Only-B
    pdf.h2(f"Vulnerabilities Exclusive to {label_b}  ({len(only_b)})")
    if not only_b:
        pdf.body(f"No exclusive vulnerabilities found for {label_b}.",
                 color=(0.22, 0.60, 0.29))
    else:
        pdf.cve_table(group_by_sev(only_b))

    # --------------------------------------------------------------- Common (list only, no repeat detail)
    pdf.h2(f"CVEs Present in Both Images  ({len(common)})")
    if not common:
        pdf.body("No common vulnerabilities.", color=(0.22, 0.60, 0.29))
    else:
        # Compact table: Advisory ID | Sev | Package + CVE IDs
        # 170 + 52 + 289 = 511
        cw  = [170, 52, 289]
        rh  = 11
        ty  = 3
        x0  = pdf.ML
        # max chars that fit in each col at size 7 (usable = col - 6pt padding)
        # avg char width at size 7 = 7 * 0.53 = 3.71 pt
        max1 = int((cw[0] - 6) / (7 * 0.53))   # ≈ 44 chars
        max3 = int((cw[2] - 6) / (7 * 0.53))   # ≈ 73 chars

        pdf._need(14)
        y = pdf._y
        pdf._fillrect(x0, y - 13, sum(cw), 13, 0.945, 0.953, 0.965)
        pdf._font(bold=True, size=7.5); pdf._dark()
        pdf._text(x0 + 3,                   y - 9, "Advisory ID")
        pdf._text(x0 + cw[0] + 3,           y - 9, "Severity")
        pdf._text(x0 + cw[0] + cw[1] + 3,   y - 9, "Package / CVE IDs")
        pdf._strokerect(x0,                  y - 13, cw[0], 13)
        pdf._strokerect(x0 + cw[0],          y - 13, cw[1], 13)
        pdf._strokerect(x0 + cw[0] + cw[1],  y - 13, cw[2], 13)
        pdf._y -= 13

        for sev in SEV_ORDER:
            col = SEV_COLOR.get(sev, SEV_COLOR["Unknown"])
            for c in sorted((v for v in common.values() if v["severity"] == sev),
                            key=lambda x: x["id"]):
                pdf._need(rh)
                y = pdf._y

                # Col 1: just the RHSA-YYYY:NNNN part
                adv_full = c["id"]
                m = _re.match(r"(RH[A-Z]+-\d+:\d+)", adv_full)
                adv_short = m.group(1) if m else adv_full[:max1]

                # Col 3: package name + CVE IDs on same line, truncated to fit
                cve_ids = " ".join(c.get("cve_ids") or [])
                pkg_ver = f"{c['package']} {c.get('version','')}"
                col3    = f"{pkg_ver}  |  {cve_ids}" if cve_ids else pkg_ver
                col3    = col3[:max3]

                pdf._font(bold=False, size=7); pdf._dark()
                pdf._text(x0 + 3,                   y - rh + ty, adv_short[:max1])
                pdf._font(bold=True,  size=7); pdf._rgb(*col)
                pdf._text(x0 + cw[0] + 3,           y - rh + ty, sev)
                pdf._font(bold=False, size=7); pdf._muted()
                pdf._text(x0 + cw[0] + cw[1] + 3,   y - rh + ty, col3)
                pdf._strokerect(x0,                  y - rh, cw[0], rh)
                pdf._strokerect(x0 + cw[0],          y - rh, cw[1], rh)
                pdf._strokerect(x0 + cw[0] + cw[1],  y - rh, cw[2], rh)
                pdf._y -= rh

    pdf.save(output_path)


# ===========================================================================
# Entry point
# ===========================================================================
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--report-a",   required=True,  help="clairctl JSON for s390x")
    p.add_argument("--report-b",   required=True,  help="clairctl JSON for x86_64")
    p.add_argument("--label-a",    default="s390x")
    p.add_argument("--label-b",    default="x86_64")
    p.add_argument("--meta-a",     default="",     help="skopeo inspect JSON for s390x")
    p.add_argument("--meta-b",     default="",     help="skopeo inspect JSON for x86_64")
    p.add_argument("--image-a",    default="",     help="Original pull spec for s390x")
    p.add_argument("--image-b",    default="",     help="Original pull spec for x86_64")
    p.add_argument("--output-dir", default=".")
    args = p.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    out_a    = os.path.join(args.output_dir, f"{args.label_a.lower()}_report.pdf")
    out_b    = os.path.join(args.output_dir, f"{args.label_b.lower()}_report.pdf")
    out_diff = os.path.join(args.output_dir, "diff_report.pdf")

    print(f"Building {args.label_a} report...")
    build_individual_pdf(args.report_a, args.meta_a, args.image_a, args.label_a, out_a)

    print(f"Building {args.label_b} report...")
    build_individual_pdf(args.report_b, args.meta_b, args.image_b, args.label_b, out_b)

    print("Building diff report...")
    build_diff_pdf(
        args.report_a, args.meta_a, args.image_a, args.label_a,
        args.report_b, args.meta_b, args.image_b, args.label_b,
        out_diff,
    )

    print(f"\nAll reports saved to: {args.output_dir}")


if __name__ == "__main__":
    main()
