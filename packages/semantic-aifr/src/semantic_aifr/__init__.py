"""Semantic AI Flaw Reporting (AIFR) package."""

__version__ = "0.1.0"

from semantic_aifr.main import FlawReport, create_flaw_report, load_ontology

__all__ = ["FlawReport", "create_flaw_report", "load_ontology"]

# Add a warning about the prototype status
import warnings

warnings.warn(
    "The semantic-aifr package is currently in prototype stage. ",
    UserWarning,
    stacklevel=2
)