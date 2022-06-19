"""Aliases for modules: ('cve_scrapper', 'sites_finder')."""

__all__ = (
    "GoogleSitesFinder",
    "SuitableCVEFinder",
)

from .cve_scrapper import SuitableCVEFinder
from .sites_finder import GoogleSitesFinder
