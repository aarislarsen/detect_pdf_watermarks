# PDF Watermark Detection Script

This folder contains `detect_pdf_watermarks.py`, a small Python utility for auditing likely PDF watermarks and forensic copy identifiers.

The script is detection-only. It does not remove, alter, rewrite, or sanitize PDF content.

## What It Detects

The script checks for several common watermark and fingerprint types:

- Visible or text-layer `Licensed To:` style watermarks
- Email-like identifiers in extracted page text
- Long hexadecimal hash-like values
- Long random-looking tokens
- Numeric license/customer IDs
- Copyright strings
- Standard PDF metadata
- XMP metadata, including custom `pdfx:*` fields
- Raw embedded UUIDs and long hash-like strings in the PDF bytes

## Requirements

- Python 3.8+
- `pypdf`

Install the dependency with:

```bash
pip install pypdf
```

## Usage

From this directory, run:

```bash
python detect_pdf_watermarks.py "input.pdf"
```

Example:

```bash
python detect_pdf_watermarks.py "FOR585 - Smartphone Forensic Analysis In-Depth.pdf"
```

## Output Sections

### PDF Document Metadata

Shows standard PDF metadata such as title, author, producer, and creation date.

Example fields:

```text
/Title: Example Document
/Author: Example Publisher
/Producer: Example PDF Generator
```

### XMP Metadata

Shows embedded XMP metadata if present. This may include custom metadata fields used as hidden fingerprints.

Example fields:

```xml
<pdfx:Hash>...</pdfx:Hash>
<pdfx:Hash2>...</pdfx:Hash2>
```

### Page Text-Layer Watermark Candidates

Extracts text from each page and reports strings that look like visible or text-layer watermarks.

These are often visible in the PDF viewer or selectable/extractable as text.

### Raw Metadata / Fingerprint-Like Strings

Scans the raw PDF bytes for metadata-like strings, UUIDs, and long hash-like identifiers.

These may not appear in normal PDF viewers.

## Interpreting Results

Use the output as a triage report:

- If a value appears in page text, it is likely part of the visible or extractable text layer.
- If a value appears only in metadata, it is hidden from normal reading view but easy to find with metadata tools.
- If a value appears only in raw byte scanning, it may be embedded in PDF internals, metadata streams, or compressed objects.

The script redacts some sensitive-looking values in console output, such as email addresses and long tokens.

## Limitations

- This is a heuristic detector, not a full forensic PDF parser.
- It does not decompress every possible PDF object stream manually.
- It does not detect image steganography or invisible vector marks with certainty.
- Some watermarks are graphical only and may not be extractable as text.
- Scanned PDFs may require OCR before text-layer analysis is useful.

For deeper analysis, combine this script with tools such as `pdfinfo`, `qpdf`, `mutool`, `pdftotext`, or a professional PDF forensic workflow.

## Legal And Ethical Use

Use this script only to inspect PDFs you own, administer, or are authorized to analyze.

Do not use watermark or fingerprint analysis to bypass licensing, attribution, access controls, or document protection mechanisms.
