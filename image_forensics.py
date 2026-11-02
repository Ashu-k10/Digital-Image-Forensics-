"""
Image Forensics Tool  (CSDF Mini Project)
-----------------------------------------
Usage:  python image_forensics.py <image_file>

What it does:
  1. File information (name, size, timestamps)
  2. Cryptographic hashes (MD5, SHA-1, SHA-256) for evidence integrity
  3. File signature (magic number) vs extension check
  4. Hidden / appended data check (data after JPEG end marker)
  5. EXIF metadata extraction (camera, date, software, GPS)
  6. Error Level Analysis (ELA) to highlight possible tampering
  7. Writes a text report + ELA image

Requires:  pip install pillow
"""
import sys
import os
import io
import hashlib
import datetime

from PIL import Image, ImageChops, ImageEnhance
from PIL.ExifTags import TAGS, GPSTAGS

try:  # optional: lets Pillow open iPhone .heic photos
    from pillow_heif import register_heif_opener
    register_heif_opener()
except ImportError:
    pass

SIGNATURES = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"BM": "BMP",
}
EXT_MAP = {".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".gif": "GIF", ".bmp": "BMP"}


def file_info(path):
    st = os.stat(path)
    fmt = "%Y-%m-%d %H:%M:%S"
    return {
        "File name": os.path.basename(path),
        "Size (bytes)": st.st_size,
        "Last modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime(fmt),
        "Last accessed": datetime.datetime.fromtimestamp(st.st_atime).strftime(fmt),
    }


def hashes(path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"MD5": md5.hexdigest(), "SHA-1": sha1.hexdigest(), "SHA-256": sha256.hexdigest()}


def signature_check(path):
    with open(path, "rb") as f:
        head = f.read(16)
    real = "Unknown"
    for sig, name in SIGNATURES.items():
        if head.startswith(sig):
            real = name
            break
    ext = os.path.splitext(path)[1].lower()
    claimed = EXT_MAP.get(ext, "Unknown")
    status = "MATCH" if real == claimed else "MISMATCH (possible renamed/disguised file)"
    return {"Extension says": claimed, "Actual signature": real, "Result": status}


def hidden_data_check(path):
    with open(path, "rb") as f:
        data = f.read()
    if data.startswith(b"\xff\xd8"):
        end = data.rfind(b"\xff\xd9")
        extra = len(data) - (end + 2)
        if end == -1:
            return {"Result": "JPEG end marker not found (file may be corrupted)"}
        if extra > 0:
            return {"Result": f"SUSPICIOUS: {extra} bytes found after JPEG end marker"}
        return {"Result": "No data appended after JPEG end marker"}
    if data.startswith(b"\x89PNG"):
        end = data.rfind(b"IEND")
        extra = len(data) - (end + 8)
        if extra > 0:
            return {"Result": f"SUSPICIOUS: {extra} bytes found after PNG IEND chunk"}
        return {"Result": "No data appended after PNG IEND chunk"}
    return {"Result": "Check not applicable for this format"}


def _gps_to_deg(value, ref):
    d, m, s = [float(x) for x in value]
    deg = d + m / 60 + s / 3600
    return -deg if ref in ("S", "W") else deg


def exif_data(img):
    """Reads EXIF from JPEG/PNG/TIFF/WebP (and HEIC if pillow-heif is installed)."""
    out = {}
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    if not exif:
        return {"EXIF": "No EXIF metadata found (stripped, screenshot, or edited/re-saved image)"}
    tags = {}
    tags.update(exif)                      # main IFD: Make, Model, Software, DateTime
    try:
        tags.update(exif.get_ifd(0x8769))  # Exif IFD: DateTimeOriginal, ISO, exposure
    except Exception:
        pass
    wanted = ["Make", "Model", "Software", "DateTime", "DateTimeOriginal",
              "ExposureTime", "FNumber", "ISOSpeedRatings", "Orientation"]
    for tag_id, val in tags.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag in wanted:
            out[tag] = str(val)
    try:
        gps_raw = exif.get_ifd(0x8825)     # GPS IFD
    except Exception:
        gps_raw = {}
    if gps_raw:
        gps = {GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
        try:
            lat = _gps_to_deg(gps["GPSLatitude"], gps["GPSLatitudeRef"])
            lon = _gps_to_deg(gps["GPSLongitude"], gps["GPSLongitudeRef"])
            out["GPS"] = f"{lat:.6f}, {lon:.6f}"
        except Exception:
            out["GPS"] = "Present but could not be decoded"
    if "Software" in out:
        out["Note"] = "Software tag present - image may have been edited/processed"
    return out or {"EXIF": "EXIF present but no common tags found"}


def ela(img, out_path, quality=90, block=32):
    rgb = img.convert("RGB")
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = Image.open(buf)
    diff = ImageChops.difference(rgb, resaved)
    gray = diff.convert("L")
    w, h = gray.size
    px = gray.load()
    max_diff = max(e[1] for e in diff.getextrema())

    # mean error of every block x block tile
    means = []
    for by in range(0, h - block + 1, block):
        for bx in range(0, w - block + 1, block):
            tot = 0
            for y in range(by, by + block, 2):
                for x in range(bx, bx + block, 2):
                    tot += px[x, y]
            means.append(tot / ((block // 2) ** 2))
    n = len(means)
    avg = sum(means) / n
    std = (sum((m - avg) ** 2 for m in means) / n) ** 0.5
    limit = avg + 4 * std
    suspicious = sum(1 for m in means if m > limit and m > 0.5)
    pct = suspicious / n * 100

    # amplified ELA picture (brightened so errors are visible)
    gain = min(255.0 / max(max_diff, 1), 60)
    ImageEnhance.Brightness(diff).enhance(gain).save(out_path)

    if pct > 8:
        verdict = "HIGH - large regions with very different error levels; manual inspection advised"
    elif pct >= 1:
        verdict = "MEDIUM - localised regions differ (possible paste/clone); inspect the ELA image"
    else:
        verdict = "LOW - uniform error levels; no obvious tampering"
    return {"Max error difference": max_diff, "Average block error": round(avg, 3),
            "Suspicious blocks": f"{suspicious} of {n} ({pct:.2f}%)", "Tampering suspicion": verdict}


def section(title, d):
    lines = [f"\n=== {title} ==="]
    for k, v in d.items():
        lines.append(f"{k:28}: {v}")
    return "\n".join(lines)


def main():
    if len(sys.argv) != 2 or not os.path.isfile(sys.argv[1]):
        print("Usage: python image_forensics.py <image_file>")
        sys.exit(1)
    path = sys.argv[1]
    base = os.path.splitext(os.path.basename(path))[0]
    ela_path = f"ela_{base}.png"
    report_path = f"forensic_report_{base}.txt"

    img = Image.open(path)
    img_props = {"Format": img.format, "Mode": img.mode, "Dimensions": f"{img.width} x {img.height}"}

    parts = [
        "DIGITAL IMAGE FORENSIC REPORT",
        f"Generated on: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
        section("1. FILE INFORMATION", file_info(path)),
        section("2. IMAGE PROPERTIES", img_props),
        section("3. HASH VALUES (integrity)", hashes(path)),
        section("4. FILE SIGNATURE CHECK", signature_check(path)),
        section("5. HIDDEN DATA CHECK", hidden_data_check(path)),
        section("6. EXIF METADATA", exif_data(img)),
        section("7. ERROR LEVEL ANALYSIS", ela(img, ela_path)),
        f"\nELA image saved as: {ela_path}",
    ]
    report = "\n".join(parts)
    print(report)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\nReport saved as: {report_path}")


if __name__ == "__main__":
    main()
