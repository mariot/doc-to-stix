"""Documents -> plain text with page markers.

PDF text comes from PDFium (pypdfium2, BSD/Apache: no AGPL in a connector).
Pages are kept as "=== page N ===" markers so evidence quotes can be located
and long documents can be cut into chunks on page and paragraph boundaries.
"""

import html
import re
from pathlib import Path

PAGE = "=== page {} ==="


def pdf_text(path: Path) -> str:
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(str(path))
    pages = []
    for i in range(len(pdf)):
        text = pdf[i].get_textpage().get_text_range()
        pages.append(f"{PAGE.format(i + 1)}\n{clean(text)}")
    return "\n\n".join(pages)


def html_text(path: Path) -> str:
    raw = path.read_text(errors="ignore")
    raw = re.sub(r"(?is)<(script|style|nav|header|footer)\b.*?</\1>", " ", raw)
    raw = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h[1-6]|table)>", "\n", raw)
    raw = re.sub(r"(?s)<[^>]+>", " ", raw)
    return f"{PAGE.format(1)}\n{main_content(clean(html.unescape(raw)))}"


# Site chrome around an advisory page (cisa.gov): navigation before the title,
# related advisories and feedback forms after the body. Other advisories' titles
# in that footer would be extracted as if the page reported them.
START = re.compile(r"(?m)^(Cybersecurity Advisory|Analysis Report|Alert)\n")
END = re.compile(r"(?m)^(Related Advisories|Please share your thoughts|Return to top)\b")


def main_content(text: str) -> str:
    m = START.search(text)
    if m:
        text = text[m.start() :]
    m = END.search(text)
    if m:
        text = text[: m.start()]
    return text.strip()


def clean(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("­", "")
    text = re.sub(r"[ \t ]+", " ", text)
    text = re.sub(r"-\n(?=[a-z])", "", text)  # words hyphenated across lines
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def document_text(path: Path) -> str:
    if path.suffix.lower() == ".pdf":
        return pdf_text(path)
    if path.suffix.lower() in (".html", ".htm"):
        return html_text(path)
    return f"{PAGE.format(1)}\n{clean(path.read_text(errors='ignore'))}"


def chunks(text: str, max_chars: int = 12_000, overlap: int = 600) -> list[str]:
    """Cut on paragraph boundaries into pieces of at most max_chars, each starting
    with the end of the previous one, so a sentence split across a boundary is
    seen whole once."""
    paras = re.split(r"\n\s*\n", text)
    out: list[str] = []
    cur = ""
    for p in paras:
        if len(p) > max_chars:  # one huge paragraph (an IOC table): cut on lines
            for line in p.split("\n"):
                if len(cur) + len(line) + 1 > max_chars and cur:
                    out.append(cur)
                    cur = cur[-overlap:]
                cur += line + "\n"
            continue
        if len(cur) + len(p) + 2 > max_chars and cur:
            out.append(cur)
            cur = cur[-overlap:]
        cur += p + "\n\n"
    if cur.strip():
        out.append(cur)
    return out


def squash(text: str) -> str:
    """For finding a quote in the text whatever the line breaks and spacing."""
    return re.sub(r"\s+", " ", text).strip().lower()


def contains_quote(text_squashed: str, quote: str) -> bool:
    q = squash(quote).strip(" .\"'“”")
    return bool(q) and q in text_squashed
