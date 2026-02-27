import json
from pathlib import Path
from collections import defaultdict
from typing import Generator


class IdentifierCorrelator:
    """
    Builds a bidirectional graph: identifier → [sites] and site → [identifiers].
    A single shared identifier between two sites is a soft link.
    Two or more shared identifiers is a high-confidence attribution flag.
    
    Reference: Caronte (Matic et al., CCS 2015)
    """

    CONFIDENCE_THRESHOLDS = {
        1: "LOW    — single shared identifier (possible coincidence)",
        2: "MEDIUM — two shared identifiers (likely same operator)",
        3: "HIGH   — three+ identifiers (near-certain attribution)"
    }

    def __init__(self):
        self.index: dict[str, set[str]] = defaultdict(set)
        self.sites: dict[str, set[str]] = defaultdict(set)

    def ingest(self, bundle_path: str | Path) -> None:
        """Load a JSON ArtifactBundle from disk and index its identifiers."""
        data = json.loads(Path(bundle_path).read_text())
        site = data["target"]
        artifacts = data.get("artifacts", {})

        for category in ["bitcoin_wallets", "monero_wallets",
                          "google_analytics", "pgp_fingerprints",
                          "email_addresses"]:
            for identifier in artifacts.get(category, []):
                self.index[identifier].add(site)
                self.sites[site].add(identifier)

        if artifacts.get("server_banner"):
            banner = artifacts["server_banner"]
            self.index[banner].add(site)
            self.sites[site].add(banner)

    def find_links(self, target_site: str) -> Generator[dict, None, None]:
        """Find all sites sharing at least one identifier with target."""
        target_ids = self.sites.get(target_site, set())
        link_counts: dict[str, list[str]] = defaultdict(list)

        for identifier in target_ids:
            for linked_site in self.index[identifier]:
                if linked_site != target_site:
                    link_counts[linked_site].append(identifier)

        for linked_site, shared_ids in sorted(
            link_counts.items(), key=lambda x: len(x[1]), reverse=True
        ):
            n = len(shared_ids)
            yield {
                "linked_site": linked_site,
                "shared_identifiers": shared_ids,
                "count": n,
                "confidence": self.CONFIDENCE_THRESHOLDS[min(n, 3)]
            }

    def summary(self) -> dict:
        return {
            "total_sites_indexed": len(self.sites),
            "unique_identifiers":  len(self.index),
            "shared_identifiers":  sum(1 for ids in self.index.values() if len(ids) > 1),
        }
