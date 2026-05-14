"""PDF audit report.

Wraps `write_html_report` and runs it through weasyprint to produce a
publication-ready PDF. weasyprint is an optional dependency: `pip install
-e ".[pdf]"` plus a system Pango install (Homebrew `pango` on macOS,
apt-get `libpango-1.0-0` on Debian/Ubuntu).

Lazy-imports weasyprint so the rest of the package loads even when the
extra is absent. Raises a clear, actionable error message on import
failure rather than letting weasyprint's dlopen traceback escape.
"""

from __future__ import annotations

from pathlib import Path

from afterlife.reporting.html_report import write_html_report


class PdfDependencyError(RuntimeError):
    """Raised when PDF generation is requested but weasyprint cannot import."""


PDF_INSTALL_HINT = (
    "PDF export requires the optional 'pdf' extra and a system Pango install.\n"
    "  pip install -e '.[pdf]'\n"
    "  macOS:  brew install pango\n"
    "          export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib\n"
    "  Linux:  apt-get install libpango-1.0-0 libpangoft2-1.0-0"
)


def write_pdf_report(db_path: Path) -> bytes:
    try:
        import weasyprint
    except (ImportError, OSError) as e:
        raise PdfDependencyError(
            f"Cannot generate PDF: {e}\n\n{PDF_INSTALL_HINT}"
        ) from e

    html = write_html_report(db_path)
    return weasyprint.HTML(string=html).write_pdf()
