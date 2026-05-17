"""LogShield AI detector package."""

from .canonicalizer import canonicalize
from .inference import ProductDetector

__all__ = ["canonicalize", "ProductDetector"]
