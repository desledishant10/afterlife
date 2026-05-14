import pytest

from afterlife import db
from afterlife.models import Finding, Severity
from afterlife.reporting.pdf_report import (
    PdfDependencyError,
    write_pdf_report,
)

try:
    import weasyprint  # noqa: F401
    HAVE_WEASYPRINT = True
except (ImportError, OSError):
    HAVE_WEASYPRINT = False

pytestmark = pytest.mark.skipif(
    not HAVE_WEASYPRINT,
    reason="weasyprint (and its system Pango deps) not available",
)


def test_pdf_report_produces_pdf_bytes(fresh_db):
    with db.connect(fresh_db) as conn:
        db.insert_finding(
            conn,
            Finding(
                rule_id="OFFBOARDED-OWNER",
                severity=Severity.CRITICAL,
                title="example finding",
                description="example description",
                evidence={"credential_id": "AKIA-1"},
            ),
        )

    pdf = write_pdf_report(fresh_db)
    assert isinstance(pdf, bytes)
    # PDF files start with the %PDF- header followed by a version number.
    assert pdf.startswith(b"%PDF-")
    # Sanity check: at least a kilobyte of content for a non-trivial report.
    assert len(pdf) > 1024


def test_pdf_dependency_error_message_is_actionable():
    """Even if the user has weasyprint installed, the error message
    documented in the module should mention pip install and brew install."""
    from afterlife.reporting.pdf_report import PDF_INSTALL_HINT

    assert "pip install" in PDF_INSTALL_HINT
    assert "pango" in PDF_INSTALL_HINT.lower()
