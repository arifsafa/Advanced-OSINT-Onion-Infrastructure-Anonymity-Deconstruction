# 🕸️ Project Erebus
### *Dark Web CTI & Attribution Framework*

<div align="center">

```
███████╗██████╗ ███████╗██████╗ ██╗   ██╗███████╗
██╔════╝██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝
█████╗  ██████╔╝█████╗  ██████╔╝██║   ██║███████╗
██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║
███████╗██║  ██║███████╗██████╔╝╚██████╔╝███████║
╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝
```

**Research-grade Cyber Threat Intelligence framework for dark web attribution**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Research Grade](https://img.shields.io/badge/Status-Research%20Grade-8b0000?style=flat-square)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](https://opensource.org/licenses/MIT)
[![OPSEC](https://img.shields.io/badge/Requires-VM%20Isolation-ff6b35?style=flat-square)]()
[![Academic](https://img.shields.io/badge/Grounded%20in-Peer--Reviewed%20Research-6366f1?style=flat-square)]()

*Tor is mathematically robust. Operators are not.*

</div>

---

## The Core Thesis

Cryptographic anonymity networks like Tor are **operationally fragile** even when they are mathematically sound. This repository synthesizes academic deanonymization research with practical OSINT tooling to demonstrate a singular, consistent finding across 136 court cases, 7 major research papers, and dozens of documented law enforcement operations:

> **Threat actors are not arrested because we broke the encryption. They are arrested because they broke their OPSEC.**

Project Erebus maps that gap — systematically, reproducibly, and without touching Tor's cryptographic layer.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       EREBUS OSINT PIPELINE                             │
│                                                                         │
│  ┌──────────────┐    ┌───────────────────┐    ┌──────────────────────┐  │
│  │  SEED LAYER  │───▶│  COLLECTION LAYER │───▶│  EXTRACTION LAYER    │  │
│  │              │    │                   │    │                      │  │
│  │ • Ahmia API  │    │ • Tor SOCKS5 proxy│    │ • BTC/XMR wallets    │  │
│  │ • DarkSearch │    │ • Circuit rotation│    │ • PGP fingerprints   │  │
│  │ • Leak feeds │    │ • Rate limiting   │    │ • Analytics IDs      │  │
│  │ • HSDir logs │    │ • JS-disabled UA  │    │ • Email addresses    │  │
│  │ • Threat INT │    │ • TLS fingerprint │    │ • Server banners     │  │
│  └──────────────┘    └───────────────────┘    └──────────┬───────────┘  │
│                                                          │              │
│                                                          ▼              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      CORRELATION ENGINE                          │  │
│  │                                                                  │  │
│  │  [Raw Artifacts] ──▶ [Graph Database] ──▶ [Attribution Engine]  │  │
│  │                           │                      │              │  │
│  │                           ├── Cross-service ID   ├── Blockchain │  │
│  │                           ├── Temporal analysis  ├── Stylometry │  │
│  │                           └── Infra fingerprint  └── HUMINT     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Academic Foundation

Every module in this framework is grounded in peer-reviewed research. We attack the **operator layer**, not the cryptographic layer.

| Attack Vector | Paper | Mechanism | Real-World Accuracy |
|---|---|---|---|
| **Traffic Correlation** | [DeepCorr — Nasr et al., ACM CCS 2018](https://dl.acm.org/doi/10.1145/3243734.3243868) | Deep learning on Tor flow timing & volume features | **~96%** with ~900 packets |
| **Circuit Fingerprinting** | [Kwon et al., USENIX Security 2015](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/kwon) | Passive detection of HS introduction & rendezvous patterns | **>98% TPR** / <0.1% FPR |
| **Website Fingerprinting** | [Herrmann et al., ACM CCS 2009](https://dl.acm.org/doi/10.1145/1655027.1655031) | Packet-size distribution analysis via passive observer | **97%** closed-world accuracy |
| **DHT Enumeration** | [Biryukov et al., IEEE S&P 2013](https://ieeexplore.ieee.org/document/6547103) | HSDir takeover for full hidden service mapping | Network-wide enumeration |
| **Identifier Leakage** | [Caronte — Matic et al., ACM CCS 2015](https://dl.acm.org/doi/10.1145/2810103.2813640) | Cross-correlating Analytics IDs, BTC wallets, PGP keys | **~5%** of sites leaked real IPs |
| **HSDir Snooping** | [Honey Onions — Polino et al.](https://www.usenix.org/system/files/conference/foci16/foci16-paper-sanchez-rola.pdf) | Malicious relay operators probing stored descriptors | **100+** snooping relays confirmed |
| **OPSEC Failure Analysis** | [Tippe et al., PoPETs 2024](https://petsymposium.org/) | Retrospective analysis of 136 Tor-related court cases | **Dominant** arrest factor in all cases |

---

## Core Modules

### `extractor.py` — Artifact Harvester

Routes all requests through a local Tor daemon. Extracts actionable CTI artifacts without leaving clearnet traces.

```python
import requests
import re
from dataclasses import dataclass, field
from typing import Optional
import hashlib
import time

@dataclass
class ArtifactBundle:
    target: str
    timestamp: float = field(default_factory=time.time)
    bitcoin_wallets: list[str] = field(default_factory=list)
    monero_wallets: list[str] = field(default_factory=list)
    google_analytics: list[str] = field(default_factory=list)
    pgp_fingerprints: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    server_banner: Optional[str] = None
    pgp_detected: bool = False
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "sha256_fingerprint": hashlib.sha256(self.target.encode()).hexdigest()[:16],
            "artifacts": {
                "bitcoin_wallets": self.bitcoin_wallets,
                "monero_wallets": self.monero_wallets,
                "google_analytics": self.google_analytics,
                "pgp_fingerprints": self.pgp_fingerprints,
                "email_addresses": self.email_addresses,
                "server_banner": self.server_banner,
                "pgp_detected": self.pgp_detected
            }
        }


class ErebusExtractor:
    """
    Safely routes all requests through local Tor SOCKS5 proxy.
    Uses socks5h:// to ensure DNS resolution happens inside Tor — 
    critical to avoid DNS leaks that expose the analyst.
    """
    
    BITCOIN_P2PKH   = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    BITCOIN_BECH32  = r'\bbc1[a-z0-9]{39,59}\b'
    MONERO          = r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
    ANALYTICS_UA    = r'UA-\d{4,10}-\d{1,4}'
    ANALYTICS_GA4   = r'G-[A-Z0-9]{10}'
    PGP_FINGERPRINT = r'[0-9A-F]{4}[\s][0-9A-F]{4}[\s][0-9A-F]{4}[\s][0-9A-F]{4}[\s][0-9A-F]{4}'
    EMAIL           = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    def __init__(self, tor_port: int = 9050, timeout: int = 25):
        # socks5h = hostname resolution inside Tor. Never use socks5 here.
        self.proxies = {
            'http':  f'socks5h://127.0.0.1:{tor_port}',
            'https': f'socks5h://127.0.0.1:{tor_port}'
        }
        # Mimic Tor Browser UA to blend with legitimate traffic
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        self.timeout = timeout

    def harvest(self, onion_url: str) -> ArtifactBundle:
        """
        Scrape a .onion URL and return a structured ArtifactBundle.
        All regex patterns applied against raw HTML to maximize recall.
        """
        bundle = ArtifactBundle(target=onion_url)
        
        try:
            resp = requests.get(
                onion_url,
                proxies=self.proxies,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            html = resp.text
            bundle.server_banner = resp.headers.get('Server', None)
            
            # Deduplicate via set() before assigning
            bundle.bitcoin_wallets  = list(set(
                re.findall(self.BITCOIN_P2PKH, html) +
                re.findall(self.BITCOIN_BECH32, html)
            ))
            bundle.monero_wallets   = list(set(re.findall(self.MONERO, html)))
            bundle.google_analytics = list(set(
                re.findall(self.ANALYTICS_UA, html) +
                re.findall(self.ANALYTICS_GA4, html)
            ))
            bundle.pgp_fingerprints = list(set(re.findall(self.PGP_FINGERPRINT, html)))
            bundle.email_addresses  = list(set(re.findall(self.EMAIL, html)))
            bundle.pgp_detected     = "BEGIN PGP PUBLIC KEY" in html
            
        except requests.exceptions.ConnectTimeout:
            bundle.server_banner = "TIMEOUT — service may be offline or RP selection failed"
        except requests.exceptions.RequestException as e:
            bundle.server_banner = f"ERROR: {type(e).__name__}"
            
        return bundle


# ── USAGE ──────────────────────────────────────────────────────────────
# extractor = ErebusExtractor(tor_port=9050)
# bundle    = extractor.harvest("http://target.onion")
# import json
# print(json.dumps(bundle.to_dict(), indent=2))
```

---

### `correlator.py` — Cross-Service Identifier Linker

Implements the Caronte methodology: given a set of artifacts, find every other surface (clearnet or onion) where the same identifier appears.

```python
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
        # identifier_value → set of sites where it appears
        self.index: dict[str, set[str]] = defaultdict(set)
        # site → set of all its identifiers
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
        """
        For a given target site, find all other sites sharing at least one identifier.
        Yields attribution reports sorted by confidence.
        """
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
            confidence_key = min(n, 3)
            yield {
                "linked_site": linked_site,
                "shared_identifiers": shared_ids,
                "count": n,
                "confidence": self.CONFIDENCE_THRESHOLDS[confidence_key]
            }

    def summary(self) -> dict:
        return {
            "total_sites_indexed":       len(self.sites),
            "unique_identifiers":        len(self.index),
            "shared_identifiers":        sum(1 for ids in self.index.values() if len(ids) > 1),
            "high_confidence_clusters":  sum(
                1 for s in self.sites
                for report in self.find_links(s)
                if report["count"] >= 3
            ) // 2  # bidirectional, divide by 2
        }
```

---

### Output Schema

All results are standardized for ingestion into Maltego, Elastic SIEM, MISP, or OpenCTI.

```json
{
  "target_onion": "http://example.onion",
  "timestamp": 1735000000.0,
  "sha256_fingerprint": "a3f8d2c19e4b7081",
  "artifacts": {
    "bitcoin_wallets": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
    "monero_wallets": [],
    "google_analytics": ["UA-12345678-1"],
    "pgp_fingerprints": ["3048 1EE3 42C5 AF8A 5C8C"],
    "email_addresses": [],
    "server_banner": "nginx/1.18.0",
    "pgp_detected": true
  },
  "attribution_flags": [
    {
      "confidence": "HIGH — three+ identifiers (near-certain attribution)",
      "linked_site": "http://clearnet-target.com",
      "shared_identifiers": ["UA-12345678-1", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3048 1EE3 42C5 AF8A 5C8C"],
      "assessment": "Operator almost certainly maintains both properties"
    }
  ]
}
```

---

## Tor Architecture Reference

### The 3-Hop Circuit

```
CLIENT ──[AES-256]──▶ ENTRY GUARD ──[AES-256]──▶ MIDDLE NODE ──[AES-256]──▶ EXIT NODE ──▶ DESTINATION
                           │                           │                          │
                     knows: client                knows: guard              knows: middle
                            + middle                   + exit                     + dest
                     blind: dest                  blind: source             blind: source
```

### The 6-Hop Hidden Service Rendezvous

```
Phase 1 — Service Setup:
  SERVER ──(3 hops)──▶ INTRO POINT 1 ─┐
  SERVER ──(3 hops)──▶ INTRO POINT 2   ├── Published to HSDir DHT
  SERVER ──(3 hops)──▶ INTRO POINT 3 ─┘    (signed descriptor, public key)

Phase 2 — Client Connection:
  CLIENT ──── fetches descriptor from HSDir
  CLIENT ──── selects RENDEZVOUS POINT ─── sends cookie via INTRO POINT
  SERVER ──(3 hops)──▶ RENDEZVOUS POINT ◀──(3 hops)── CLIENT
                              ↑
                     6-hop encrypted tunnel
                     Neither side knows the other's IP
                     But the DHT structure is exploitable metadata
```

---

## Deanonymization Taxonomy

### Layer 1 — Network Level (Adversary needs relay visibility)

| Technique | Prerequisite | Reference |
|---|---|---|
| End-to-end traffic correlation | Observe entry + exit simultaneously | Tor Project, Danezis et al. |
| Flow correlation via deep learning | Trained model + partial traffic view | DeepCorr (Nasr et al. 2018) |
| Circuit fingerprinting | Passive relay on circuit path | Kwon et al. USENIX 2015 |
| Website fingerprinting | Local passive observer (ISP/WiFi) | Herrmann et al. 2009 |

### Layer 2 — Infrastructure Level (Adversary needs HSDir access)

| Technique | Prerequisite | Reference |
|---|---|---|
| Hidden service enumeration | Run malicious HSDir nodes | Biryukov et al. IEEE S&P 2013 |
| Descriptor snooping | Position as legitimate HSDir relay | Honey Onions (Polino et al.) |
| Introduction point correlation | Monitor IntroPoint relay traffic | Kwon et al. circuit analysis |

### Layer 3 — Operator Level (No special access required)

| Technique | Prerequisite | Reference |
|---|---|---|
| Identifier cross-correlation | Public OSINT tooling | Caronte (Matic et al. 2015) |
| Blockchain tracing | Block explorer + exchange subpoena | Multiple ransomware cases |
| Stylometric attribution | Sufficient text corpus | Academic authorship attribution |
| Infrastructure fingerprinting | HTTP headers, TLS certs, asset hashes | OnionScan, active enumeration |
| OPSEC failure analysis | Pattern recognition | Tippe et al. PoPETs 2024 |

> **Finding from Tippe et al. (2024):** Of 136 Tor-related prosecutions analyzed, Layer 3 techniques (human error and behavioral analysis) were the dominant factor in virtually every case. Layer 1 attacks requiring sophisticated network-level access were rare. The cryptography held. The operators did not.

---

## Operational Security Requirements

> ⚠️ **Non-negotiable prerequisites before any dark web interaction.**

```bash
# Minimum viable isolation stack
# ─────────────────────────────
# 1. Dedicated VM (KVM/VirtualBox/VMware)
#    └─ Snapshot BEFORE session. Revert AFTER.
#
# 2. Tor daemon running locally
#    └─ Verify: curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
#
# 3. No personal accounts. No personal credentials. Ever.
#
# 4. JavaScript disabled (Tor Browser Security Level: Safest)
#    └─ OR: requests with JS-disabled UA + no cookie persistence
#
# 5. Verify .onion addresses from minimum two independent sources
#    └─ Phishing clones are common and sophisticated
#
# 6. Downloaded files: execute only in air-gapped sandbox
#    └─ Malware delivery via dark web files is routine
#
# 7. Rotate Tor circuits between distinct targets
#    └─ stem library for programmatic circuit management:

from stem import Signal
from stem.control import Controller

def rotate_circuit(password: str = "") -> None:
    """Request a fresh Tor circuit. Call between distinct target investigations."""
    with Controller.from_port(port=9051) as controller:
        controller.authenticate(password=password)
        controller.signal(Signal.NEWNYM)
```

---

## Case Studies

### Silk Road — The IP Leak That Ended It

Ross Ulbricht's fatal mistake was not a cryptographic one. A misconfigured CAPTCHA on the Silk Road login page made an HTTP request to a **clearnet IP address** — 205.185.112.211 — before the Tor request completed. A senior FBI investigator queried that IP, traced it to an Icelandic data center, subpoenaed the records, and followed the chain to a Chicago server, then to San Francisco. The entire multi-billion-dollar operation ended because of a single CAPTCHA misconfiguration. Tor was never touched.

### AlphaBay — The Email in the Welcome Message

Alexandre Cazes, operating as "Alpha02," sent thousands of welcome emails from the AlphaBay platform using a personal Hotmail address: **pimp_alex_91@hotmail.com**. This address was linked to his real name, his LinkedIn profile, and ultimately his location in Bangkok. A personal email address in an automated registration message — that was the thread that unraveled a $1 billion darknet empire.

### Operation Playpen — The Browser Was the Surface

The FBI seized a child exploitation hidden service in February 2015 and operated it covertly for 13 days. Rather than attempting to deanonymize Tor users via traffic analysis, they deployed a Flash-based **Network Investigative Technique (NIT)** to every visitor. The exploit caused victim machines to contact a clearnet FBI server, leaking real IP addresses and MAC addresses. 1,300+ suspects identified. Zero Tor vulnerabilities exploited.

---

## References

```bibtex
@inproceedings{nasr2018deepcorr,
  title     = {DeepCorr: Strong Flow Correlation Attacks on Tor Using Deep Learning},
  author    = {Nasr, Milad and Bahramali, Alireza and Houmansadr, Amir},
  booktitle = {Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security},
  year      = {2018}
}

@inproceedings{kwon2015circuit,
  title     = {Circuit Fingerprinting Attacks: Passive Deanonymization of Tor Hidden Services},
  author    = {Kwon, Albert and AlSabah, Mashael and Lazar, David and Dacier, Marc and Devadas, Srinivas},
  booktitle = {24th USENIX Security Symposium},
  year      = {2015}
}

@inproceedings{matic2015caronte,
  title     = {CARONTE: Detecting Location Leaks for Deanonymizing Tor Hidden Services},
  author    = {Matic, Srdjan and Kotzias, Platon and Caballero, Juan},
  booktitle = {Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security},
  year      = {2015}
}

@inproceedings{biryukov2013trawling,
  title     = {Trawling for Tor Hidden Services: Detection, Measurement, Deanonymization},
  author    = {Biryukov, Alex and Pustogarov, Ivan and Weinmann, Ralf-Philipp},
  booktitle = {2013 IEEE Symposium on Security and Privacy},
  year      = {2013}
}

@inproceedings{herrmann2009website,
  title     = {Website Fingerprinting: Attacking Popular Privacy Enhancing Technologies},
  author    = {Herrmann, Dominik and Wendolsky, Rolf and Federrath, Hannes},
  booktitle = {ACM Workshop on Cloud Computing Security},
  year      = {2009}
}

@article{tippe2024torcases,
  title   = {How Tor Users Get Caught: A Study of 136 Cases},
  author  = {Tippe, G. and others},
  journal = {Proceedings on Privacy Enhancing Technologies (PoPETs)},
  year    = {2024}
}
```

---

## Contributing

Contributions are welcome from the CTI and academic communities.

```bash
git clone https://github.com/yourhandle/project-erebus
cd project-erebus
git checkout -b feature/your-module
git commit -m 'feat: add stylometric analysis module'
git push origin feature/your-module
# → Open Pull Request
```

Please ensure contributions are:
- Grounded in published academic research
- Documented with relevant paper citations  
- Tested against synthetic/controlled data only
- Intended for defensive CTI and academic purposes

---

<div align="center">

```
// The encryption held.
// The operators did not.
```

**Engineered for Proactive Threat Hunting & Defensive Intelligence**

*For academic, research, and authorized security operations only.*

</div>
