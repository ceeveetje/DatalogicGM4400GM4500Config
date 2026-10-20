"""
Extract the base64-encoded images (vcom, unlink, honeywell barcodes and
the icon) from the original PowerShell script and save them into images/.

Usage:  python extract_barcodes.py DatalogicGM4500Configr10VoorHelpdesk.ps1

The barcodes must be pixel-perfect, so we take them verbatim from the
source instead of re-encoding anything.
"""

import base64
import os
import re
import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: python extract_barcodes.py <originele_script.ps1>")
        sys.exit(1)
    src = sys.argv[1]
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    outdir = os.path.join(os.path.dirname(os.path.abspath(src)), "images")
    os.makedirs(outdir, exist_ok=True)

    targets = [
        ("vcom", 'if ($image -eq "vcom")', "vcom.jpg"),
        ("unlink", 'if ($image -eq "unlink")', "unlink.jpg"),
        ("honeywell", 'if ($image -eq "Honeywell")', "honeywell.png"),
    ]

    b64re = re.compile(r'"([A-Za-z0-9+/=]{200,})"')
    found = 0
    for label, marker, fname in targets:
        mi = text.find(marker)
        if mi == -1:
            print(f"  marker niet gevonden voor {label}")
            continue
        m = b64re.search(text, mi)
        if not m:
            print(f"  geen base64 string gevonden voor {label}")
            continue
        data = base64.b64decode(m.group(1))
        path = os.path.join(outdir, fname)
        with open(path, "wb") as f:
            f.write(data)
        print(f"  {label}: {len(data)} bytes -> {path}")
        found += 1

    # icon: the base64 starting with iVBORw0KGgoAAAANSUhEUgAAAEAAAABA
    # right after $iconBase64String =
    mi = text.find("$iconBase64String =")
    if mi != -1:
        m = b64re.search(text, mi)
        if m:
            data = base64.b64decode(m.group(1))
            path = os.path.join(outdir, "icon.png")
            with open(path, "wb") as f:
                f.write(data)
            print(f"  icon: {len(data)} bytes -> {path}")
            found += 1

    if found == 0:
        print("  Niets geextraheerd - klopt het pad naar het .ps1 bestand?")
        sys.exit(1)


if __name__ == "__main__":
    main()
