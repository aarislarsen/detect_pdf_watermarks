#!/usr/bin/env python3
"""
Detect likely visible/text-layer and metadata PDF watermarks.

Usage:
    python detect_pdf_watermarks.py "input.pdf"

Requires:
    pip install pypdf
"""

import re
import sys
from pathlib import Path

from pypdf import PdfReader


PATTERNS = {
    "licensed_footer_or_diagonal": re.compile(
        r"Licensed\s+To:\s+.*?<.*?>.*?\d{4}", re.IGNORECASE
    ),
    "email_like": re.compile(
        r"[A-Za-z0-9._%+-]+(?:@|_at_|_)[A-Za-z0-9._%+-]+(?:\.|_)[A-Za-z]{2,}",
        re.IGNORECASE,
    ),
    "hex_hash_32_plus": re.compile(r"\b[a-fA-F0-9]{32,}\b"),
    "long_token": re.compile(r"\b[A-Za-z0-9]{24,}\b"),
    "numeric_license_id": re.compile(r"\b\d{6,}\b"),
    "copyright": re.compile(r"©|Copyright|All rights reserved", re.IGNORECASE),
}


def redact(value: str) -> str:
    """Lightly redact sensitive-looking values for console output."""
    value = value.strip()

    if "@" in value or "_com" in value or "_gmail" in value:
        return re.sub(r"([A-Za-z0-9._%+-]{2})[A-Za-z0-9._%+-]*(@|_)", r"\1***\2", value)

    if len(value) > 18:
        return value[:6] + "..." + value[-6:]

    return value


def extract_metadata(reader: PdfReader) -> None:
    print("\n=== PDF Document Metadata ===")

    metadata = reader.metadata
    if metadata:
        for key, value in metadata.items():
            print(f"{key}: {redact(str(value))}")
    else:
        print("No standard metadata found.")

    print("\n=== XMP Metadata ===")
    try:
        xmp = reader.xmp_metadata
        if not xmp:
            print("No XMP metadata found.")
            return

        raw = getattr(xmp, "xmpmeta", None)
        if raw:
            print(raw)
        else:
            attrs = [
                "dc_title",
                "dc_creator",
                "pdf_producer",
                "xmp_create_date",
                "xmp_metadata_date",
                "xmpmm_document_id",
                "xmpmm_instance_id",
            ]
            for attr in attrs:
                value = getattr(xmp, attr, None)
                if value:
                    print(f"{attr}: {redact(str(value))}")
    except Exception as exc:
        print(f"Could not read XMP metadata: {exc}")


def scan_pages(reader: PdfReader) -> None:
    print("\n=== Page Text-Layer Watermark Candidates ===")

    total_hits = 0

    for page_index, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:
            print(f"Page {page_index}: text extraction failed: {exc}")
            continue

        page_hits = []

        for label, pattern in PATTERNS.items():
            for match in pattern.findall(text):
                if isinstance(match, tuple):
                    match = "".join(match)

                match = match.strip()
                if not match:
                    continue

                page_hits.append((label, match))

        if page_hits:
            total_hits += len(page_hits)
            print(f"\nPage {page_index}:")
            for label, match in page_hits[:20]:
                print(f"  [{label}] {redact(match)}")

            if len(page_hits) > 20:
                print(f"  ... {len(page_hits) - 20} more hits on this page")

    if total_hits == 0:
        print("No obvious text-layer watermark candidates found.")
    else:
        print(f"\nTotal candidate text-layer hits: {total_hits}")


def scan_xmp_raw(path: Path) -> None:
    print("\n=== Raw Metadata / Fingerprint-Like Strings ===")

    data = path.read_bytes()

    raw_patterns = {
        "xmp_pdfx_hash": rb"<pdfx:[^>]*>[^<]+</pdfx:[^>]*>",
        "uuid": rb"uuid:[A-Fa-f0-9-]{20,}",
        "long_hex": rb"\b[a-fA-F0-9]{32,}\b",
    }

    found = False

    for label, pattern in raw_patterns.items():
        matches = re.findall(pattern, data)
        if not matches:
            continue

        found = True
        print(f"\n{label}:")
        for match in matches[:20]:
            decoded = match.decode("utf-8", errors="replace")
            print(f"  {redact(decoded)}")

        if len(matches) > 20:
            print(f"  ... {len(matches) - 20} more")

    if not found:
        print("No obvious raw metadata/fingerprint strings found.")


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python detect_pdf_watermarks.py input.pdf")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    reader = PdfReader(str(path))

    print(f"File: {path}")
    print(f"Pages: {len(reader.pages)}")
    print(f"Encrypted: {reader.is_encrypted}")

    extract_metadata(reader)
    scan_pages(reader)
    scan_xmp_raw(path)


if __name__ == "__main__":
    main()
